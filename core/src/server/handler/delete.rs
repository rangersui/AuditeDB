//! DELETE verb implementation + its blocking-SQLite helpers.
//!
//! Extracted from `handler.rs` so DELETE's intent / commit /
//! commit_failed two-step audit dance -- and the blocking-spawn
//! helpers it needs (`AuditAppendJob`, `world_exists_blocking`,
//! `audit_append_blocking`) -- live in their own file. This is the
//! first of two post-PR-4c extractions that bring `handler.rs`
//! back under the 500-line ceiling; the second
//! (`crate::handler::post`) lands the same shape.
//!
//! `pub(crate) use` re-exports `execute_delete` from `handler.rs`
//! so callers (`handler::execute(verb=Delete, ...)` and the
//! white-box tests in `main.rs`) keep their import path stable.

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::{
    auth,
    engine::EngineError,
    engine_trace::{DeleteMetadata, EngineDeleteTraceHooks},
    engine_types::ValidatedWorldPath,
    http_semantics as hs, insufficient_storage, not_found,
    server::ServerState,
    server_error, storage_temporarily_unavailable, unauthorized, AuthGate, ErrorReason, Phase,
    TraceCtx,
};

pub(crate) async fn execute_delete(
    headers: HeaderMap,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    state: &ServerState,
    trace: &TraceCtx,
) -> Phase {
    let persist_header_allowlist = state.persist_header_allowlist();
    let persist_header_user_deny = state.persist_header_user_deny();
    let delete_meta = hs::request_meta_headers(
        &headers,
        &persist_header_allowlist,
        &persist_header_user_deny,
    );
    let delete_content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let hooks = HttpDeleteTrace::new(trace);

    match state
        .engine()
        .delete_traced(
            &world,
            DeleteMetadata::new(delete_content_type, delete_meta),
            hs::request_preconditions(&headers).into(),
            tier.into(),
            &hooks,
        )
        .await
    {
        Ok(()) => Phase::CommittedWrite((StatusCode::NO_CONTENT, "").into_response()),
        Err(err) => delete_error_phase(err, hooks.last_step()),
    }
}

struct HttpDeleteTrace<'a> {
    trace: &'a TraceCtx,
    last_step: DeleteStepCell,
}

/// HTTP DELETE stage tracking via the trace-hook side channel.
///
/// `Engine::delete_traced` returns the public, coarse `EngineError` shape so
/// adapter-facing errors stay protocol-neutral and do not expose `DeleteError`
/// internals. HTTP still needs the legacy wire body precision for catastrophic
/// DELETE stages. Each hook advances `last_step`, then `delete_error_phase`
/// matches `(EngineError, last_step)` to reconstruct the old HTTP rendering.
///
/// State machine:
/// `NONE -> AUDIT_INTENT_FAILED | INTENT -> PHYSICAL_DELETED -> NOTIFY_SENT`.
/// The atomic stores compact discriminants; the adapter immediately restores
/// the typed enum before rendering so future stages force exhaustive handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum DeleteStep {
    None = 0,
    AuditIntentFailed = 1,
    Intent = 2,
    PhysicalDeleted = 3,
    NotifySent = 4,
}

impl DeleteStep {
    fn from_u8(value: u8) -> Self {
        match value {
            value if value == Self::None as u8 => Self::None,
            value if value == Self::AuditIntentFailed as u8 => Self::AuditIntentFailed,
            value if value == Self::Intent as u8 => Self::Intent,
            value if value == Self::PhysicalDeleted as u8 => Self::PhysicalDeleted,
            value if value == Self::NotifySent as u8 => Self::NotifySent,
            _ => unreachable!("DeleteStepCell only stores DeleteStep discriminants"),
        }
    }
}

/// Sealed transport cell for DELETE trace stages.
///
/// All writes must go through `DeleteStepCell::store`, which accepts only the
/// typed `DeleteStep` enum. The raw `AtomicU8` is a private implementation
/// detail, not an adapter-facing integer slot.
struct DeleteStepCell(AtomicU8);

impl DeleteStepCell {
    fn new(step: DeleteStep) -> Self {
        Self(AtomicU8::new(step as u8))
    }

    fn store(&self, step: DeleteStep) {
        self.0.store(step as u8, Ordering::Relaxed);
    }

    fn load(&self) -> DeleteStep {
        DeleteStep::from_u8(self.0.load(Ordering::Relaxed))
    }
}

impl<'a> HttpDeleteTrace<'a> {
    fn new(trace: &'a TraceCtx) -> Self {
        Self {
            trace,
            last_step: DeleteStepCell::new(DeleteStep::None),
        }
    }

    fn last_step(&self) -> DeleteStep {
        self.last_step.load()
    }
}

impl EngineDeleteTraceHooks for HttpDeleteTrace<'_> {
    fn lock_acquired(&self, world: &str) {
        self.trace
            .emit_aux_kv("lock_acquired", &format!("target={world}"));
    }

    fn audit_intent(&self) {
        self.last_step.store(DeleteStep::Intent);
        self.trace.emit_aux("audit_intent");
    }

    fn audit_intent_failed(&self, err: &str) {
        self.last_step.store(DeleteStep::AuditIntentFailed);
        self.trace
            .emit_aux_kv("audit_intent_failed", &format!("err={err}"));
    }

    fn read_cache_drained(&self) {
        self.trace.emit_aux("read_cache_drained");
    }

    fn physical_deleted(&self) {
        self.last_step.store(DeleteStep::PhysicalDeleted);
        self.trace.emit_aux("physical_deleted");
    }

    fn counter_decremented(&self) {
        self.trace.emit_aux("counter_decremented");
    }

    fn notify_sent(&self) {
        self.last_step.store(DeleteStep::NotifySent);
        self.trace.emit_aux("notify_sent");
    }

    fn audit_commit_failed(&self, err: &str) {
        self.trace
            .emit_aux_kv("audit_commit_failed", &format!("err={err}"));
    }

    fn audit_commit_failed_event_logged(&self) {
        self.trace.emit_aux("audit_commit_failed_event_logged");
    }

    fn audit_commit_failed_event_failed(&self, err: &str) {
        self.trace
            .emit_aux_kv("audit_commit_failed_event_failed", &format!("err={err}"));
    }

    fn audit_commit(&self) {
        self.trace.emit_aux("audit_commit");
    }
}

fn delete_error_phase(err: EngineError, last_step: DeleteStep) -> Phase {
    match err {
        EngineError::AppendOnly => Phase::Error {
            resp: unauthorized("delete ledger is append-only"),
            reason: ErrorReason::Auth(AuthGate::Delete),
        },
        EngineError::Auth(gate) => Phase::Error {
            resp: unauthorized("delete requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(gate),
        },
        EngineError::PreconditionFailed { message } => Phase::Error {
            resp: crate::precondition_failed(message),
            reason: ErrorReason::PreconditionFailed,
        },
        EngineError::NotFound => Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        },
        EngineError::TransientStorage { .. } | EngineError::ShuttingDown => {
            transient_delete_error_phase(last_step)
        }
        EngineError::InsufficientStorage { .. } => insufficient_delete_error_phase(last_step),
        EngineError::Storage { .. } => storage_delete_error_phase(last_step),
        EngineError::InternalInvariant(message) => invariant_delete_error_phase(message, last_step),
        EngineError::InvalidWorldName
        | EngineError::PayloadTooLarge { .. }
        | EngineError::QuotaExceeded { .. }
        | EngineError::SubscriptionLimit => Phase::Error {
            resp: server_error("unexpected delete error".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

fn transient_delete_error_phase(last_step: DeleteStep) -> Phase {
    match last_step {
        DeleteStep::AuditIntentFailed => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::None => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageRead,
        },
        DeleteStep::Intent => Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::PhysicalDeleted | DeleteStep::NotifySent => Phase::Error {
            resp: server_error("delete succeeded but audit commit failed".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

fn insufficient_delete_error_phase(last_step: DeleteStep) -> Phase {
    match last_step {
        DeleteStep::AuditIntentFailed => Phase::Error {
            resp: insufficient_storage(),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::None => Phase::Error {
            resp: insufficient_storage(),
            reason: ErrorReason::InsufficientStorage,
        },
        DeleteStep::Intent => Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::PhysicalDeleted | DeleteStep::NotifySent => Phase::Error {
            resp: server_error("delete succeeded but audit commit failed".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

fn storage_delete_error_phase(last_step: DeleteStep) -> Phase {
    match last_step {
        DeleteStep::AuditIntentFailed => Phase::Error {
            resp: server_error("storage failure".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::None => Phase::Error {
            resp: server_error("storage failure".to_string()),
            reason: ErrorReason::StorageRead,
        },
        DeleteStep::Intent => Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::PhysicalDeleted | DeleteStep::NotifySent => Phase::Error {
            resp: server_error("delete succeeded but audit commit failed".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

fn invariant_delete_error_phase(message: &'static str, last_step: DeleteStep) -> Phase {
    match last_step {
        DeleteStep::AuditIntentFailed => Phase::Error {
            resp: server_error(format!("delete audit intent {message}")),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::None => Phase::Error {
            resp: server_error("storage failure".to_string()),
            reason: ErrorReason::StorageRead,
        },
        DeleteStep::Intent => Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteStep::PhysicalDeleted | DeleteStep::NotifySent => Phase::Error {
            resp: server_error("delete succeeded but audit commit failed".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn error_parts(phase: Phase) -> (StatusCode, ErrorReason, String) {
        let Phase::Error { resp, reason } = phase else {
            panic!("expected error phase");
        };
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body should buffer");
        let body = String::from_utf8(bytes.to_vec()).expect("response body should be utf-8");
        (status, reason, body)
    }

    #[tokio::test]
    async fn delete_error_phase_preserves_audit_intent_worker_failure_body() {
        let (status, reason, body) = error_parts(delete_error_phase(
            EngineError::InternalInvariant("sqlite worker failed"),
            DeleteStep::AuditIntentFailed,
        ))
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(matches!(reason, ErrorReason::StorageWriteAudit));
        assert_eq!(
            body,
            "internal error: delete audit intent sqlite worker failed\n"
        );
    }

    #[tokio::test]
    async fn delete_error_phase_preserves_intent_succeeded_failure_body() {
        let (status, reason, body) = error_parts(delete_error_phase(
            EngineError::Storage { sqlite_code: None },
            DeleteStep::Intent,
        ))
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(matches!(reason, ErrorReason::StorageWriteAudit));
        assert_eq!(body, "internal error: delete failed after audit intent\n");
    }

    #[tokio::test]
    async fn delete_error_phase_preserves_append_only_body_without_world_inference() {
        let (status, reason, body) = error_parts(delete_error_phase(
            EngineError::AppendOnly,
            DeleteStep::None,
        ))
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(matches!(reason, ErrorReason::Auth(AuthGate::Delete)));
        assert_eq!(body, "auth required: delete ledger is append-only\n");
    }
}
