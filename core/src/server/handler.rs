//! Per-verb handlers driven by the FSM pipeline.
//!
//! `handler::execute(verb, ...)` is called from `pipeline::run` after
//! the driver has handled authentication, path canonicalization /
//! validation, and method-to-verb dispatch. Each `execute_*` function:
//!
//! 1. Runs its verb-specific authorization gate (`can_read` /
//!    `can_write` / `can_delete`). Authentication is the driver's
//!    job; authorization lives next to the verb because the gate is
//!    verb-and-path-specific.
//! 2. Performs the verb's actual work -- including, for write verbs,
//!    the lock acquire / preconditions / SQLite write+audit append /
//!    counter update / notify sequence. The verb owns audit + notify
//!    ordering; the FSM only models the request envelope.
//! 3. Returns either `Phase::ExecutedRead(Response)` (GET / HEAD),
//!    `Phase::CommittedWrite(Response)` (PUT / POST / DELETE), or
//!    `Phase::Error { resp, reason }`.
//!
//! Verb handlers call `trace.emit_aux(...)` and
//! `trace.emit_aux_kv(...)` to surface sub-step timings: `lock_acquired`,
//! `quota_check used=N quota=M`, `sqlite_committed etag=...`,
//! `notify_sent`. DELETE additionally emits the
//! `audit_intent` / `audit_commit` / `audit_commit_failed[_event_failed]`
//! sequence so an operator reading `grep req-N` can reconstruct the
//! intent / commit dance -- including the honest double-failure case
//! where the commit append AND the subsequent failure-event append
//! both fail (e.g. persistent DiskFull).
//!
//! ## CoAP coexistence
//!
//! HTTP and CoAP do not share the request lifecycle, but both now call public
//! Engine methods. Each adapter keeps owning its wire rendering.

#[path = "handler/delete.rs"]
mod delete;
#[path = "handler/post.rs"]
mod post;
pub(crate) use delete::execute_delete;
pub(crate) use post::execute_post;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

#[cfg(test)]
use crate::Core;
use crate::{
    auth, content_range_value, decimal_header_value,
    engine::{Engine, EngineError},
    engine_trace::EngineWriteTraceHooks,
    engine_types::{Representation, ValidatedWorldPath, WriteKind},
    http_semantics as hs,
    http_semantics::HeaderAllowlist,
    insufficient_storage, not_found, payload_too_large, precondition_failed,
    server::ServerState,
    server_error, storage_quota_exceeded, storage_temporarily_unavailable, to_header_map,
    unauthorized, ErrorReason, Phase, TraceCtx, Verb,
};

pub(crate) trait HandlerEngineState {
    fn engine(&self) -> Engine;
    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist>;
    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist>;
}

impl HandlerEngineState for &ServerState {
    fn engine(&self) -> Engine {
        ServerState::engine(self).clone()
    }

    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        ServerState::persist_header_allowlist(self)
    }

    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        ServerState::persist_header_user_deny(self)
    }
}

#[cfg(test)]
impl HandlerEngineState for &Arc<Core> {
    fn engine(&self) -> Engine {
        Engine::from_core_for_tests((*self).clone())
    }

    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        // Legacy white-box tests that pass Core directly use the default HTTP
        // adapter policy. Tests for custom policy should construct ServerState.
        Arc::new(HeaderAllowlist::empty())
    }

    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        Arc::new(HeaderAllowlist::empty())
    }
}

#[cfg(test)]
impl HandlerEngineState for &Core {
    fn engine(&self) -> Engine {
        Engine::from_core_for_tests(Arc::new((*self).clone()))
    }

    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        // Legacy white-box tests that pass Core directly use the default HTTP
        // adapter policy. Tests for custom policy should construct ServerState.
        Arc::new(HeaderAllowlist::empty())
    }

    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        Arc::new(HeaderAllowlist::empty())
    }
}

/// Dispatch from `Phase::Dispatched` to the verb-specific handler.
/// Called from inside `pipeline::run`'s match arm.
pub(crate) async fn execute(
    verb: Verb,
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    state: &ServerState,
    trace: &TraceCtx,
) -> Phase {
    match verb {
        Verb::Get => execute_get(headers, tier, world, state, trace).await,
        Verb::Head => execute_head(headers, tier, world, state, trace).await,
        Verb::Put => execute_put(headers, body, tier, world, state, trace).await,
        Verb::Post => execute_post(headers, body, tier, world, state, trace).await,
        Verb::Delete => execute_delete(headers, tier, world, state, trace).await,
    }
}

pub(crate) async fn execute_get<S: HandlerEngineState>(
    headers: HeaderMap,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    state: S,
    trace: &TraceCtx,
) -> Phase {
    let result = match state.engine().read(&world, tier.into()) {
        Ok(Some(result)) => result,
        Ok(None) => {
            return Phase::Error {
                resp: not_found(),
                reason: ErrorReason::NotFound,
            };
        }
        Err(err) => return read_error_phase(err),
    };
    let stage = result.representation;
    let etag = result.etag;
    if hs::read_not_modified(&headers, &etag) {
        // 304: no body, but emit body_size for diagnostic clarity
        // ("the cached body would be N bytes if the client revalidated").
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(
            world.as_str(),
            &etag,
            &stage.content_type,
            &stage.headers,
        ));
    }
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(world.as_str(), &mut resp_headers);
    hs::apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            let chunk = stage.body[start..=end].to_vec();
            resp_headers.push((header::CONTENT_LENGTH, decimal_header_value(chunk.len())));
            resp_headers.push((
                header::CONTENT_RANGE,
                content_range_value(start, end, stage.body.len()),
            ));
            trace.emit_aux_kv("body_size", &chunk.len().to_string());
            Phase::ExecutedRead(
                (
                    StatusCode::PARTIAL_CONTENT,
                    to_header_map(resp_headers),
                    chunk,
                )
                    .into_response(),
            )
        }
        Ok(None) => {
            resp_headers.push((
                header::CONTENT_LENGTH,
                decimal_header_value(stage.body.len()),
            ));
            trace.emit_aux_kv("body_size", &stage.body.len().to_string());
            Phase::ExecutedRead(
                (StatusCode::OK, to_header_map(resp_headers), stage.body).into_response(),
            )
        }
        Err(()) => Phase::Error {
            resp: hs::range_not_satisfiable(stage.body.len()),
            reason: ErrorReason::RangeNotSatisfiable,
        },
    }
}

pub(crate) async fn execute_head<S: HandlerEngineState>(
    headers: HeaderMap,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    state: S,
    trace: &TraceCtx,
) -> Phase {
    let result = match state.engine().read(&world, tier.into()) {
        Ok(Some(result)) => result,
        Ok(None) => {
            return Phase::Error {
                resp: not_found(),
                reason: ErrorReason::NotFound,
            };
        }
        Err(err) => return read_error_phase(err),
    };
    let stage = result.representation;
    let etag = result.etag;
    if hs::read_not_modified(&headers, &etag) {
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(
            world.as_str(),
            &etag,
            &stage.content_type,
            &stage.headers,
        ));
    }
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_LENGTH,
            decimal_header_value(stage.body.len()),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(world.as_str(), &mut resp_headers);
    hs::apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            resp_headers.retain(|(name, _)| name != header::CONTENT_LENGTH);
            let chunk_len = end - start + 1;
            resp_headers.push((header::CONTENT_LENGTH, decimal_header_value(chunk_len)));
            resp_headers.push((
                header::CONTENT_RANGE,
                content_range_value(start, end, stage.body.len()),
            ));
            trace.emit_aux_kv("body_size", &chunk_len.to_string());
            Phase::ExecutedRead(
                (StatusCode::PARTIAL_CONTENT, to_header_map(resp_headers), "").into_response(),
            )
        }
        Ok(None) => {
            trace.emit_aux_kv("body_size", &stage.body.len().to_string());
            Phase::ExecutedRead((StatusCode::OK, to_header_map(resp_headers), "").into_response())
        }
        Err(()) => Phase::Error {
            resp: hs::range_not_satisfiable(stage.body.len()),
            reason: ErrorReason::RangeNotSatisfiable,
        },
    }
}

pub(crate) async fn execute_put<S: HandlerEngineState>(
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: ValidatedWorldPath,
    state: S,
    trace: &TraceCtx,
) -> Phase {
    let content_type = hs::request_content_type(&headers);
    let persist_header_allowlist = state.persist_header_allowlist();
    let persist_header_user_deny = state.persist_header_user_deny();
    let meta = hs::request_meta_headers(
        &headers,
        &persist_header_allowlist,
        &persist_header_user_deny,
    );
    let representation = Representation {
        body,
        content_type,
        headers: meta,
    };
    let outcome = match state
        .engine()
        .replace_traced(
            &world,
            representation,
            hs::request_preconditions(&headers).into(),
            tier.into(),
            &HttpWriteTrace { trace },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => return write_error_phase(err),
    };
    let status = match outcome.kind {
        WriteKind::Created => StatusCode::CREATED,
        WriteKind::Updated => StatusCode::OK,
    };
    let mut resp_headers = vec![(header::ETAG, hs::etag_header(&outcome.etag))];
    if status == StatusCode::CREATED {
        resp_headers.push((
            header::LOCATION,
            HeaderValue::from_str(&hs::world_url(world.as_str()))
                .unwrap_or_else(|_| HeaderValue::from_static("/")),
        ));
    }
    Phase::CommittedWrite((status, to_header_map(resp_headers), "").into_response())
}

/// First 16 chars of an etag string for compact aux trace lines.
/// Etags are HMAC-SHA256 hex (64 chars) or `sha256-<64 chars>`; a
/// 16-char prefix is enough to disambiguate while staying readable.
///
/// Visibility is `pub(in crate::handler)` so the sibling `post.rs`
/// module can reuse it (PUT and POST both emit the same
/// `sqlite_committed etag=...` aux line). Not visible outside
/// `crate::handler` -- etag presentation is a verb-handler concern,
/// not a crate-wide utility.
pub(in crate::handler) fn etag_preview(etag: &str) -> String {
    etag.chars().take(16).collect()
}

pub(in crate::handler) struct HttpWriteTrace<'a> {
    pub(in crate::handler) trace: &'a TraceCtx,
}

impl EngineWriteTraceHooks for HttpWriteTrace<'_> {
    fn lock_acquired(&self) {
        self.trace.emit_aux("lock_acquired");
    }

    fn quota_check(&self, used: usize, quota: usize) {
        self.trace
            .emit_aux_kv("quota_check", &format!("used={used} quota={quota}"));
    }

    fn sqlite_committed(&self, etag: &str) {
        self.trace
            .emit_aux_kv("sqlite_committed", &format!("etag={}", etag_preview(etag)));
    }

    fn notify_sent(&self) {
        self.trace.emit_aux("notify_sent");
    }
}

fn read_error_phase(err: EngineError) -> Phase {
    match err {
        EngineError::Auth(gate) => Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(gate),
        },
        EngineError::TransientStorage { .. } => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageRead,
        },
        EngineError::InsufficientStorage { .. } => Phase::Error {
            resp: insufficient_storage(),
            reason: ErrorReason::InsufficientStorage,
        },
        EngineError::Storage { .. } | EngineError::InternalInvariant(_) => Phase::Error {
            resp: server_error("storage failure".to_string()),
            reason: ErrorReason::StorageRead,
        },
        EngineError::ShuttingDown => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageRead,
        },
        EngineError::SubscriptionLimit => Phase::Error {
            resp: server_error("unexpected read subscription limit".to_string()),
            reason: ErrorReason::StorageRead,
        },
        EngineError::InvalidWorldName
        | EngineError::NotFound
        | EngineError::AppendOnly
        | EngineError::PayloadTooLarge { .. }
        | EngineError::PreconditionFailed { .. }
        | EngineError::QuotaExceeded { .. } => Phase::Error {
            resp: server_error("unexpected read error".to_string()),
            reason: ErrorReason::StorageRead,
        },
    }
}

pub(in crate::handler) fn write_error_phase(err: EngineError) -> Phase {
    match err {
        EngineError::Auth(gate) => Phase::Error {
            resp: unauthorized("write requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(gate),
        },
        EngineError::PayloadTooLarge { max } => Phase::Error {
            resp: payload_too_large(max),
            reason: ErrorReason::PayloadTooLarge,
        },
        EngineError::PreconditionFailed { message } => Phase::Error {
            resp: precondition_failed(message),
            reason: ErrorReason::PreconditionFailed,
        },
        EngineError::NotFound => Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        },
        EngineError::QuotaExceeded {
            used,
            quota,
            projected,
        } => Phase::Error {
            resp: storage_quota_exceeded(used, quota, projected),
            reason: ErrorReason::QuotaExceeded,
        },
        EngineError::TransientStorage { .. } => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageWriteAudit,
        },
        EngineError::InsufficientStorage { .. } => Phase::Error {
            resp: insufficient_storage(),
            reason: ErrorReason::InsufficientStorage,
        },
        EngineError::Storage { .. } => Phase::Error {
            resp: server_error("storage failure".to_string()),
            reason: ErrorReason::StorageRead,
        },
        EngineError::InternalInvariant(message) => Phase::Error {
            resp: server_error(message.to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        EngineError::ShuttingDown => Phase::Error {
            resp: storage_temporarily_unavailable(),
            reason: ErrorReason::StorageWriteAudit,
        },
        EngineError::SubscriptionLimit => Phase::Error {
            resp: server_error("unexpected write subscription limit".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        EngineError::InvalidWorldName | EngineError::AppendOnly => Phase::Error {
            resp: server_error("invalid world reached write adapter".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}
