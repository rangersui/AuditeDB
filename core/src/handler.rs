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
//! HTTP and CoAP do not share the request lifecycle, but they do share
//! disk transitions through `world_ops`. That keeps auth, locks,
//! preconditions, quota, audit, and notify in one place while each
//! adapter owns its wire rendering.

mod delete;
mod post;
pub(crate) use delete::execute_delete;
pub(crate) use post::execute_post;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};

use crate::{
    auth, content_range_value, decimal_header_value, http_semantics as hs, not_found,
    payload_too_large, precondition_failed, server_error, storage_error, storage_quota_exceeded,
    to_header_map, unauthorized, world_ops, Core, ErrorReason, Phase, TraceCtx, Verb,
};

/// Dispatch from `Phase::Dispatched` to the verb-specific handler.
/// Called from inside `pipeline::run`'s match arm.
pub(crate) async fn execute(
    verb: Verb,
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    match verb {
        Verb::Get => execute_get(headers, tier, world, core, trace).await,
        Verb::Head => execute_head(headers, tier, world, core, trace).await,
        Verb::Put => execute_put(headers, body, tier, world, core, trace).await,
        Verb::Post => execute_post(headers, body, tier, world, core, trace).await,
        Verb::Delete => execute_delete(headers, tier, world, core, trace).await,
    }
}

pub(crate) async fn execute_get(
    headers: HeaderMap,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let permit = match world_ops::authorize_read(core, &world, tier) {
        Ok(permit) => permit,
        Err(err) => return read_error_phase(err),
    };
    let (stage, etag) = match world_ops::read_world(core, &permit) {
        Ok(world_ops::ReadOutcome::Found { stage, etag }) => (stage, etag),
        Ok(world_ops::ReadOutcome::Missing) => {
            return Phase::Error {
                resp: not_found(),
                reason: ErrorReason::NotFound,
            };
        }
        Err(err) => return read_error_phase(err),
    };
    if hs::read_not_modified(&headers, &etag) {
        // 304: no body, but emit body_size for diagnostic clarity
        // ("the cached body would be N bytes if the client revalidated").
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(&world, &etag, &stage));
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
    hs::apply_world_links(&world, &mut resp_headers);
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

pub(crate) async fn execute_head(
    headers: HeaderMap,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let permit = match world_ops::authorize_read(core, &world, tier) {
        Ok(permit) => permit,
        Err(err) => return read_error_phase(err),
    };
    let (stage, etag) = match world_ops::read_world(core, &permit) {
        Ok(world_ops::ReadOutcome::Found { stage, etag }) => (stage, etag),
        Ok(world_ops::ReadOutcome::Missing) => {
            return Phase::Error {
                resp: not_found(),
                reason: ErrorReason::NotFound,
            };
        }
        Err(err) => return read_error_phase(err),
    };
    if hs::read_not_modified(&headers, &etag) {
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(&world, &etag, &stage));
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
    hs::apply_world_links(&world, &mut resp_headers);
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

pub(crate) async fn execute_put(
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let permit = match world_ops::authorize_write(&world, tier) {
        Ok(permit) => permit,
        Err(err) => return write_error_phase(err),
    };
    let content_type = hs::request_content_type(&headers);
    let meta = hs::request_meta_headers(
        &headers,
        &core.persist_header_allowlist,
        &core.persist_header_user_deny,
    );
    let req = world_ops::ReplaceRequest {
        world,
        body,
        content_type,
        headers: meta,
        preconditions: hs::request_preconditions(&headers),
    };
    let outcome =
        match world_ops::replace_write(core, &permit, req, &HttpWriteTrace { trace }).await {
            Ok(outcome) => outcome,
            Err(err) => return write_error_phase(err),
        };
    let status = match outcome.status_kind {
        world_ops::WriteStatusKind::Created => StatusCode::CREATED,
        world_ops::WriteStatusKind::Updated => StatusCode::OK,
    };
    let mut resp_headers = vec![(header::ETAG, hs::etag_header(&outcome.etag))];
    if status == StatusCode::CREATED {
        resp_headers.push((
            header::LOCATION,
            HeaderValue::from_str(&hs::world_url(permit.world()))
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

impl world_ops::WriteTraceHooks for HttpWriteTrace<'_> {
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

fn read_error_phase(err: world_ops::ReadError) -> Phase {
    match err {
        world_ops::ReadError::Auth(gate) => Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(gate),
        },
        world_ops::ReadError::TransientStorage { scope, err }
        | world_ops::ReadError::InsufficientStorage { scope, err }
        | world_ops::ReadError::StorageRead { scope, err } => Phase::Error {
            resp: storage_error(scope, err),
            reason: ErrorReason::StorageRead,
        },
        world_ops::ReadError::PermitWorldMismatch => Phase::Error {
            resp: server_error("read permit world mismatch".to_string()),
            reason: ErrorReason::StorageRead,
        },
    }
}

pub(in crate::handler) fn write_error_phase(err: world_ops::WriteError) -> Phase {
    match err {
        world_ops::WriteError::Auth(gate) => Phase::Error {
            resp: unauthorized("write requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(gate),
        },
        world_ops::WriteError::PayloadTooLarge { max } => Phase::Error {
            resp: payload_too_large(max),
            reason: ErrorReason::PayloadTooLarge,
        },
        world_ops::WriteError::PreconditionFailed { message } => Phase::Error {
            resp: precondition_failed(message),
            reason: ErrorReason::PreconditionFailed,
        },
        world_ops::WriteError::NotFound => Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        },
        world_ops::WriteError::QuotaExceeded {
            used,
            quota,
            projected,
        } => Phase::Error {
            resp: storage_quota_exceeded(used, quota, projected),
            reason: ErrorReason::QuotaExceeded,
        },
        world_ops::WriteError::TransientStorage { scope, err, op } => Phase::Error {
            resp: storage_error(scope, err),
            reason: transient_storage_reason(op),
        },
        world_ops::WriteError::InsufficientStorage { scope, err, op } => Phase::Error {
            resp: storage_error(scope, err),
            reason: match op {
                world_ops::StorageOp::Read => ErrorReason::StorageRead,
                world_ops::StorageOp::WriteAudit => ErrorReason::InsufficientStorage,
            },
        },
        world_ops::WriteError::StorageRead { scope, err } => Phase::Error {
            resp: storage_error(scope, err),
            reason: ErrorReason::StorageRead,
        },
        world_ops::WriteError::StorageWriteAudit { scope, err } => Phase::Error {
            resp: storage_error(scope, err),
            reason: ErrorReason::StorageWriteAudit,
        },
        world_ops::WriteError::Internal(message) => Phase::Error {
            resp: server_error(message.to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
        world_ops::WriteError::PermitWorldMismatch => Phase::Error {
            resp: server_error("write permit world mismatch".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        },
    }
}

fn transient_storage_reason(op: world_ops::StorageOp) -> ErrorReason {
    match op {
        world_ops::StorageOp::Read => ErrorReason::StorageRead,
        world_ops::StorageOp::WriteAudit => ErrorReason::StorageWriteAudit,
    }
}
