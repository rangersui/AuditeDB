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
//! 2. Performs the verb's actual work — including, for write verbs,
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
//! intent / commit dance — including the honest double-failure case
//! where the commit append AND the subsequent failure-event append
//! both fail (e.g. persistent DiskFull).
//!
//! ## CoAP coexistence
//!
//! `Core::put_bytes` is kept around because `coap.rs` still calls it
//! for CoAP `Method::Put`. CoAP requests do not flow through the FSM
//! pipeline (they have their own protocol), so they never reach
//! `execute_put`. PR 7+ migrates CoAP onto the FSM and `put_bytes`
//! can be removed at that point.

mod delete;
mod post;
pub(crate) use delete::execute_delete;
pub(crate) use post::execute_post;

use std::sync::atomic::Ordering;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};

use crate::{
    apply_meta_headers, auth, can_read, can_write, http_semantics as hs,
    is_insufficient_storage_error, needs_write_approve, not_found, payload_too_large, server_error,
    storage_error, store, to_header_map, unauthorized, world, AuthGate, Core, ErrorReason, Phase,
    TraceCtx, Verb,
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
    if !can_read(core, tier) {
        return Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(AuthGate::Read),
        };
    }
    let Some((stage, etag)) = (match core.read_world_with_etag(&world) {
        Ok(current) => current,
        Err(e) => {
            return Phase::Error {
                resp: storage_error("storage read", e),
                reason: ErrorReason::StorageRead,
            };
        }
    }) else {
        return Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        };
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
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            let chunk = stage.body[start..=end].to_vec();
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&chunk.len().to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
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
                HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
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
    if !can_read(core, tier) {
        return Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(AuthGate::Read),
        };
    }
    let Some((stage, etag)) = (match core.read_world_with_etag(&world) {
        Ok(current) => current,
        Err(e) => {
            return Phase::Error {
                resp: storage_error("storage read", e),
                reason: ErrorReason::StorageRead,
            };
        }
    }) else {
        return Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        };
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
            HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(&world, &mut resp_headers);
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            resp_headers.retain(|(name, _)| name != header::CONTENT_LENGTH);
            let chunk_len = end - start + 1;
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&chunk_len.to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
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
    // 1. Auth gate (verb-and-path-specific). Driver authenticated;
    //    the verb authorizes — the gate kind drives the trace
    //    `Auth(Write)` vs `Auth(WriteApprove)` distinction so an
    //    operator sees which token tier was insufficient.
    if !can_write(&world, tier) {
        let gate = if needs_write_approve(&world) {
            AuthGate::WriteApprove
        } else {
            AuthGate::Write
        };
        return Phase::Error {
            resp: unauthorized("write requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(gate),
        };
    }
    // 2. Per-world body cap (413 — never confuse with quota / 507).
    if body.len() > core.max_world_bytes {
        return Phase::Error {
            resp: payload_too_large(core.max_world_bytes),
            reason: ErrorReason::PayloadTooLarge,
        };
    }
    let content_type = hs::request_content_type(&headers);
    let meta = hs::request_meta_headers(&headers);
    // 3. Per-world write lock — serializes same-world writers so
    //    preconditions and write are atomic w.r.t. concurrent PUTs
    //    on this world. Different worlds run concurrently.
    let _write_guard = core.acquire_world_lock(&world).await;
    trace.emit_aux("lock_acquired");
    // 4. If-Match / If-None-Match preconditions (412 on mismatch).
    //    Storage-error during precondition read maps to StorageRead
    //    (500); the 412 path is the optimistic-concurrency signal.
    if let Err(resp) = hs::check_write_preconditions(core, &world, &headers) {
        let reason = if resp.status() == StatusCode::PRECONDITION_FAILED {
            ErrorReason::PreconditionFailed
        } else {
            ErrorReason::StorageRead
        };
        return Phase::Error { resp, reason };
    }
    // 5. Write + audit (durable vs memory branch).
    let (existed, etag) = if store::is_persistent(&world) {
        // Read prev_len under the per-world lock so the value cannot
        // change before reservation.
        let prev_len_opt = match world::body_len(&core.data, &world) {
            Ok(v) => v,
            Err(e) => {
                return Phase::Error {
                    resp: storage_error("storage metadata", e),
                    reason: ErrorReason::StorageRead,
                };
            }
        };
        let existed = prev_len_opt.is_some();
        let prev_len = prev_len_opt.unwrap_or(0);
        if let Some(quota) = core.max_storage_bytes {
            let used = core.storage_body_bytes.load(Ordering::Relaxed);
            trace.emit_aux_kv("quota_check", &format!("used={used} quota={quota}"));
        }
        // Atomic CAS reservation; rolled back on write failure below.
        if let Err(boxed) = core.reserve_storage(prev_len, body.len()) {
            return Phase::Error {
                resp: *boxed,
                reason: ErrorReason::QuotaExceeded,
            };
        }
        match world::write_with_audit_checked(
            &core.data,
            &world,
            &body,
            &content_type,
            &meta,
            &core.hmac_key,
            None,
        ) {
            Ok(result) => {
                if !existed {
                    core.durable_world_count.fetch_add(1, Ordering::Relaxed);
                }
                let etag = hs::hmac_etag(&result.hmac);
                trace.emit_aux_kv("sqlite_committed", &format!("etag={}", etag_preview(&etag)));
                (existed, etag)
            }
            Err(world::WriteAuditError::Quota { .. }) => {
                // Unreachable: quota=None passed above. Defensive.
                core.rollback_storage_reservation(prev_len, body.len());
                return Phase::Error {
                    resp: server_error("unexpected quota error".to_string()),
                    reason: ErrorReason::StorageWriteAudit,
                };
            }
            Err(world::WriteAuditError::Sqlite(e)) => {
                core.rollback_storage_reservation(prev_len, body.len());
                let reason = if is_insufficient_storage_error(&e) {
                    ErrorReason::InsufficientStorage
                } else {
                    ErrorReason::StorageWriteAudit
                };
                return Phase::Error {
                    resp: storage_error("storage/audit", e),
                    reason,
                };
            }
        }
    } else {
        match core
            .mem
            .write_with_quota(&world, &body, &content_type, &meta, core.max_memory_bytes)
        {
            Ok(outcome) => {
                let etag = hs::body_etag(&body);
                trace.emit_aux_kv("sqlite_committed", &format!("etag={}", etag_preview(&etag)));
                (outcome.existed, etag)
            }
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Phase::Error {
                    resp: payload_too_large(quota),
                    reason: ErrorReason::PayloadTooLarge,
                };
            }
        }
    };
    // 6. Notify reactors (best-effort, never blocks the response).
    core.notify("PUT", &world, &etag);
    trace.emit_aux("notify_sent");
    // 7. Build response.
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut resp_headers = vec![(header::ETAG, hs::etag_header(&etag))];
    if status == StatusCode::CREATED {
        resp_headers.push((
            header::LOCATION,
            HeaderValue::from_str(&hs::world_url(&world))
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
/// `crate::handler` — etag presentation is a verb-handler concern,
/// not a crate-wide utility.
pub(in crate::handler) fn etag_preview(etag: &str) -> String {
    etag.chars().take(16).collect()
}
