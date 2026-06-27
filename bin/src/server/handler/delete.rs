//! DELETE verb implementation + its blocking-SQLite helpers.
//!
//! Extracted from `handler.rs` so DELETE's intent / commit /
//! commit_failed two-step audit dance -- and the blocking-spawn
//! helpers it needs (`AuditAppendJob`, `world_exists_blocking`,
//! `audit_append_blocking`) -- live in their own file. This is the
//! first of two post-PR-4c extractions that bring `handler.rs`
//! back under the 500-line ceiling; the second
//! (`crate::server::handler::post`) lands the same shape.
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
    engine::EngineError,
    engine_trace::{DeleteMetadata, EngineDeleteTraceHooks},
    engine_types::{AccessTier, ValidatedWorldPath},
    server::{
        bad_request, http::semantics as hs, insufficient_storage, not_found, precondition_failed,
        server_error, storage_temporarily_unavailable, unauthorized, ErrorReason, Phase,
        ServerState, TraceCtx,
    },
    AuthGate,
};

pub(crate) async fn execute_delete(
    headers: HeaderMap,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    state: &ServerState,
    trace: &TraceCtx,
) -> Phase {
    let tier = tier.into();
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
            hs::request_preconditions(&headers),
            tier,
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
            resp: precondition_failed(message),
            reason: ErrorReason::PreconditionFailed,
        },
        EngineError::NotFound => Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        },
        EngineError::TransientStorage | EngineError::ShuttingDown => {
            transient_delete_error_phase(last_step)
        }
        EngineError::InsufficientStorage => insufficient_delete_error_phase(last_step),
        EngineError::Storage => storage_delete_error_phase(last_step),
        EngineError::InternalInvariant(message) => invariant_delete_error_phase(message, last_step),
        EngineError::InvalidMetadata { message } => Phase::Error {
            resp: bad_request(message),
            reason: ErrorReason::PathInvalid(message),
        },
        EngineError::InvalidWorldName
        | EngineError::PayloadTooLarge { .. }
        | EngineError::QuotaExceeded { .. }
        | EngineError::SubscriptionLimit => Phase::Error {
            resp: server_error("unexpected delete error".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        _ => Phase::Error {
            resp: server_error("unknown delete error".to_string()),
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(feature = "multi-thread")]
    use crate::server::handler::execute_put;
    use crate::{
        engine_types::{Preconditions, Representation},
        server::{
            http::semantics::HeaderAllowlist,
            test_support::{
                server_state_for_engine_for_tests, server_state_with_headers_for_engine_for_tests,
                test_engine_for_server_with_auth_tokens, world_db_path_for_server_tests,
            },
        },
    };
    use axum::body::{to_bytes, Bytes};
    use axum::{http::HeaderValue, response::Response};

    fn unwrap_response(phase: Phase) -> Response {
        match phase {
            Phase::ExecutedRead(r) | Phase::CommittedWrite(r) | Phase::Done(r) => r,
            Phase::Error { resp, .. } => resp,
            Phase::Received { .. }
            | Phase::Authenticated { .. }
            | Phase::PathValidated { .. }
            | Phase::Dispatched { .. }
            | Phase::TimelineDispatched { .. } => {
                panic!("execute_* returned a non-terminal Phase variant")
            }
        }
    }

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

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
        let (status, reason, body) =
            error_parts(delete_error_phase(EngineError::Storage, DeleteStep::Intent)).await;

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

    #[tokio::test]
    async fn delete_honors_if_match_before_audit_or_remove() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("delete-if-match");
        let state = server_state_for_engine_for_tests(engine.clone());
        let world = world_path("home/delete-cas");
        let write = engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"alive"),
                    "text/plain; charset=utf-8",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        let resp = unwrap_response(
            execute_delete(
                stale.clone(),
                AccessTier::Approve,
                world_path("home/delete-cas"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_some());

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", write.etag)).unwrap(),
        );
        let resp = unwrap_response(
            execute_delete(
                good.clone(),
                AccessTier::Approve,
                world_path("home/delete-cas"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_none());
        let delete_ledger = world_path("var/log/deletes");
        assert!(engine
            .read(&delete_ledger, AccessTier::Read)
            .unwrap()
            .is_some());
        assert!(matches!(
            engine
                .verify_audit(&delete_ledger, AccessTier::Read)
                .unwrap(),
            crate::engine_introspection::AuditVerify::Valid(_)
        ));
        let ledger =
            rusqlite::Connection::open(world_db_path_for_server_tests(&dir, "var/log/deletes"))
                .unwrap();
        let mut stmt = ledger
            .prepare("SELECT event_type FROM events ORDER BY id")
            .unwrap();
        let events: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(events, vec!["delete_intent", "delete_commit"]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_rejects_reserved_subject_metadata_even_if_header_is_allowlisted() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("delete-reserved-header");
        let state = server_state_with_headers_for_engine_for_tests(
            engine.clone(),
            crate::defaults::DEFAULT_MAX_WORLD_BYTES,
            HeaderAllowlist::parse("auditedb-delete-subject-*"),
            HeaderAllowlist::empty(),
        );
        let world = world_path("home/delete-reserved-header");
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"alive"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "auditedb-delete-subject-seq",
            HeaderValue::from_static("fake"),
        );
        let (status, reason, body) = error_parts(
            execute_delete(
                headers,
                AccessTier::Approve,
                world.clone(),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(matches!(reason, ErrorReason::PathInvalid(_)));
        assert_eq!(body, "bad request: reserved-delete-subject-header\n");
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_some());
        assert!(!world_db_path_for_server_tests(&dir, "var/log/deletes").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_returns_500_when_commit_audit_fails_after_physical_delete() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("delete-commit-audit-fail");
        let state = server_state_for_engine_for_tests(engine.clone());
        let warmup = world_path("home/delete-ledger-warmup");
        engine
            .replace(
                &warmup,
                Representation::new(Bytes::from_static(b"warmup"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let warmup_resp = unwrap_response(
            execute_delete(
                HeaderMap::new(),
                AccessTier::Approve,
                warmup.clone(),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(warmup_resp.status(), StatusCode::NO_CONTENT);
        assert!(engine.read(&warmup, AccessTier::Read).unwrap().is_none());

        let world = world_path("home/delete-degraded");
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"alive"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        {
            let c =
                rusqlite::Connection::open(world_db_path_for_server_tests(&dir, "var/log/deletes"))
                    .unwrap();
            c.execute_batch(
                r#"
                CREATE TRIGGER fail_delete_commit
                BEFORE INSERT ON events
                WHEN NEW.event_type='delete_commit'
                BEGIN
                    SELECT RAISE(FAIL, 'delete_commit blocked');
                END;
                "#,
            )
            .unwrap();
        }

        let resp = unwrap_response(
            execute_delete(
                HeaderMap::new(),
                AccessTier::Approve,
                world_path("home/delete-degraded"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_none());
        let ledger =
            rusqlite::Connection::open(world_db_path_for_server_tests(&dir, "var/log/deletes"))
                .unwrap();
        let events = ledger
            .prepare("SELECT event_type FROM events ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            events,
            vec![
                "delete_intent",
                "delete_commit",
                "delete_intent",
                "delete_commit_failed"
            ]
        );
        assert_eq!(
            engine.df(AccessTier::Read).unwrap().worlds,
            0,
            "failed delete commit must not leave phantom durable worlds"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_rejects_auth_token_and_append_only_ledger() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("delete-policy");
        let state = server_state_for_engine_for_tests(engine.clone());
        let protected_world = world_path("home/delete-policy");
        engine
            .replace(
                &protected_world,
                Representation::new(
                    Bytes::from_static(b"alive"),
                    "text/plain; charset=utf-8",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let delete_ledger = world_path("var/log/deletes");
        engine
            .replace(
                &delete_ledger,
                Representation::new(
                    Bytes::from_static(b"ledger"),
                    "text/plain; charset=utf-8",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Approve,
            )
            .await
            .unwrap();
        let headers = HeaderMap::new();

        let auth_delete = unwrap_response(
            execute_delete(
                headers.clone(),
                AccessTier::Write,
                world_path("home/delete-policy"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(auth_delete.status(), StatusCode::UNAUTHORIZED);
        assert!(engine
            .read(&protected_world, AccessTier::Read)
            .unwrap()
            .is_some());

        let ledger_delete = unwrap_response(
            execute_delete(
                headers.clone(),
                AccessTier::Approve,
                world_path("var/log/deletes"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(ledger_delete.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ledger_delete
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer realm=\"elastik\""
        );
        assert_eq!(
            ledger_delete.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response_text(ledger_delete).await,
            "auth required: delete ledger is append-only\n"
        );
        assert!(engine
            .read(&delete_ledger, AccessTier::Read)
            .unwrap()
            .is_some());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_missing_world_does_not_write_delete_ledger() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("delete-missing");
        let state = server_state_for_engine_for_tests(engine.clone());
        let headers = HeaderMap::new();
        let resp = unwrap_response(
            execute_delete(
                headers.clone(),
                AccessTier::Approve,
                world_path("home/missing"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(engine
            .read(&world_path("var/log/deletes"), AccessTier::Read)
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "multi-thread")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_deletes_create_one_valid_delete_ledger() {
        // Bug 16 race coverage. Three concurrent DELETEs on a fresh engine
        // create the delete ledger through the first successful DELETE only.
        // The public invariant is that the three target worlds disappear and
        // the single delete ledger is readable and audit-valid.
        let (engine, dir) = test_engine_for_server_with_auth_tokens("concurrent-first-deletes");
        let server_state = server_state_for_engine_for_tests(engine.clone());
        let headers = HeaderMap::new();
        for w in ["home/a", "home/b", "home/c"] {
            let put = unwrap_response(
                execute_put(
                    headers.clone(),
                    Bytes::from_static(b"x"),
                    AccessTier::Write,
                    world_path(w),
                    &server_state,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(put.status(), StatusCode::CREATED);
        }
        assert_eq!(engine.df(AccessTier::Read).unwrap().worlds, 3);
        assert!(engine
            .read(&world_path("var/log/deletes"), AccessTier::Read)
            .unwrap()
            .is_none());

        let s1 = server_state.clone();
        let s2 = server_state.clone();
        let s3 = server_state.clone();
        let h1 = headers.clone();
        let h2 = headers.clone();
        let h3 = headers.clone();
        let trace1 = TraceCtx::disabled();
        let trace2 = TraceCtx::disabled();
        let trace3 = TraceCtx::disabled();
        let (r1, r2, r3) = tokio::join!(
            execute_delete(h1, AccessTier::Approve, world_path("home/a"), &s1, &trace1),
            execute_delete(h2, AccessTier::Approve, world_path("home/b"), &s2, &trace2),
            execute_delete(h3, AccessTier::Approve, world_path("home/c"), &s3, &trace3),
        );
        assert_eq!(unwrap_response(r1).status(), StatusCode::NO_CONTENT);
        assert_eq!(unwrap_response(r2).status(), StatusCode::NO_CONTENT);
        assert_eq!(unwrap_response(r3).status(), StatusCode::NO_CONTENT);

        let delete_ledger = world_path("var/log/deletes");
        assert!(engine
            .read(&delete_ledger, AccessTier::Read)
            .unwrap()
            .is_some());
        assert!(matches!(
            engine
                .verify_audit(&delete_ledger, AccessTier::Read)
                .unwrap(),
            crate::engine_introspection::AuditVerify::Valid(_)
        ));
        let ledger =
            rusqlite::Connection::open(world_db_path_for_server_tests(&dir, "var/log/deletes"))
                .unwrap();
        let events = ledger
            .prepare(
                "SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY event_type",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            events,
            vec![
                ("delete_commit".to_string(), 3),
                ("delete_intent".to_string(), 3)
            ]
        );
        for w in ["home/a", "home/b", "home/c"] {
            assert!(engine
                .read(&world_path(w), AccessTier::Read)
                .unwrap()
                .is_none());
        }
        assert_eq!(
            engine.df(AccessTier::Read).unwrap().worlds,
            0,
            "racing first deletes must not leave phantom durable worlds"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    async fn response_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}
