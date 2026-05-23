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
    response::{IntoResponse, Response},
};

use crate::{
    auth,
    delete_ops::{DeleteError, DeleteRequest, DeleteTraceHooks},
    engine_ops::EngineOps,
    engine_types::ValidatedWorldPath,
    http_semantics as hs, not_found, server_error, storage_error, unauthorized, AuthGate,
    BlockingSqliteError, Core, ErrorReason, Phase, TraceCtx,
};

pub(crate) async fn execute_delete(
    headers: HeaderMap,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let delete_meta = hs::request_meta_headers(
        &headers,
        &core.persist_header_allowlist,
        &core.persist_header_user_deny,
    );
    let delete_content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    match EngineOps::new(core)
        .delete(
            &world,
            DeleteRequest {
                preconditions: hs::request_preconditions(&headers).into(),
                content_type: delete_content_type,
                headers: delete_meta,
            },
            tier,
            &HttpDeleteTrace { trace },
        )
        .await
    {
        Ok(()) => Phase::CommittedWrite((StatusCode::NO_CONTENT, "").into_response()),
        Err(err) => delete_error_phase(err),
    }
}

struct HttpDeleteTrace<'a> {
    trace: &'a TraceCtx,
}

impl DeleteTraceHooks for HttpDeleteTrace<'_> {
    fn lock_acquired(&self, world: &str) {
        self.trace
            .emit_aux_kv("lock_acquired", &format!("target={world}"));
    }

    fn audit_intent(&self) {
        self.trace.emit_aux("audit_intent");
    }

    fn read_cache_drained(&self) {
        self.trace.emit_aux("read_cache_drained");
    }

    fn physical_deleted(&self) {
        self.trace.emit_aux("physical_deleted");
    }

    fn counter_decremented(&self) {
        self.trace.emit_aux("counter_decremented");
    }

    fn notify_sent(&self) {
        self.trace.emit_aux("notify_sent");
    }

    fn audit_commit_failed(&self, err: &BlockingSqliteError) {
        self.trace
            .emit_aux_kv("audit_commit_failed", &format!("err={err:?}"));
    }

    fn audit_commit_failed_event_logged(&self) {
        self.trace.emit_aux("audit_commit_failed_event_logged");
    }

    fn audit_commit_failed_event_failed(&self, err: &BlockingSqliteError) {
        self.trace
            .emit_aux_kv("audit_commit_failed_event_failed", &format!("err={err:?}"));
    }

    fn audit_commit(&self) {
        self.trace.emit_aux("audit_commit");
    }
}

fn delete_error_phase(err: DeleteError) -> Phase {
    match err {
        DeleteError::Auth(gate) => Phase::Error {
            resp: unauthorized("delete requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(gate),
        },
        DeleteError::AppendOnlyLedger => Phase::Error {
            resp: unauthorized("delete ledger is append-only"),
            reason: ErrorReason::Auth(AuthGate::Delete),
        },
        DeleteError::PreconditionFailed { message } => Phase::Error {
            resp: crate::precondition_failed(message),
            reason: ErrorReason::PreconditionFailed,
        },
        DeleteError::NotFound => Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        },
        DeleteError::TransientStorage { scope, err, .. }
        | DeleteError::StorageRead { scope, err, .. } => Phase::Error {
            resp: storage_error(scope, err),
            reason: ErrorReason::StorageRead,
        },
        DeleteError::InsufficientStorage { scope, err, .. } => Phase::Error {
            resp: storage_error(scope, err),
            reason: ErrorReason::InsufficientStorage,
        },
        DeleteError::AuditIntent { err, .. } => Phase::Error {
            resp: blocking_storage_error("delete audit intent", err),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteError::DeleteFailedAfterIntent => Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        DeleteError::AuditCommitFailed => Phase::Error {
            resp: server_error("delete succeeded but audit commit failed".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

// --- DELETE blocking helpers --------------------------------------
//
// `AuditAppendJob` and `BlockingSqliteError` moved to `state.rs` --
// they're used by `Core::append_to_ledger` (the cached-writer entry
// point that replaced the pre-cache `audit_append_blocking` here)
// and re-exported via `pub(crate) use crate::state::*;` in `main.rs`.
// `world_exists_blocking` is gone too: ledger existence is tracked
// by the `delete_ledger_created` AtomicBool, swapped to true on the
// first successful append in this process.

fn blocking_storage_error(scope: &str, err: BlockingSqliteError) -> Response {
    match err {
        BlockingSqliteError::Sqlite(err) => storage_error(scope, err),
        BlockingSqliteError::Worker => server_error(format!("{scope} worker failed")),
    }
}
