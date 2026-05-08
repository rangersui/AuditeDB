//! POST verb implementation -- append to an existing world.
//!
//! Extracted from `handler.rs` so the four verb implementations
//! (GET / HEAD / PUT / POST) plus the dispatcher fit comfortably
//! inside the 500-line ceiling. POST is structurally similar to
//! PUT (both write under per-world lock, both reserve quota, both
//! notify) but semantically distinct: POST appends rather than
//! replaces, never updates `X-Meta-*` (PUT-only), and 404s when
//! the world is absent. Keeping POST in its own file makes that
//! distinction visible at the module level rather than buried in
//! a long shared file.
//!
//! `pub(crate) use` re-exports `execute_post` from `handler.rs`
//! so callers (`handler::execute(verb=Post, ...)` and the
//! white-box tests in `main.rs`) keep their import path stable.

use std::sync::atomic::Ordering;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};

use super::etag_preview;
use crate::{
    auth, can_write, http_semantics as hs, is_insufficient_storage_error, needs_write_approve,
    not_found, payload_too_large, storage_error, store, unauthorized, world, AuthGate, Core,
    ErrorReason, Phase, TraceCtx,
};

pub(crate) async fn execute_post(
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    // POST appends to an existing world. PUT is the create/replace
    // path -- POST returns 404 if the world is absent and never
    // updates X-Meta-* headers (which are PUT-only).
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
    let _write_guard = core.acquire_world_lock(&world).await;
    trace.emit_aux("lock_acquired");
    // Defence-in-depth tombstone clear (Bug 19). Mirrors the same
    // call in `execute_put`. See that doc-comment for rationale.
    core.clear_tombstone(&world);
    if let Err(resp) = hs::check_write_preconditions(core, &world, &headers) {
        let reason = if resp.status() == StatusCode::PRECONDITION_FAILED {
            ErrorReason::PreconditionFailed
        } else {
            ErrorReason::StorageRead
        };
        return Phase::Error { resp, reason };
    }
    let Some((body_len, content_type, stored_headers)) = (match core.world_metadata(&world) {
        Ok(meta) => meta,
        Err(e) => {
            return Phase::Error {
                resp: storage_error("storage metadata", e),
                reason: ErrorReason::StorageRead,
            };
        }
    }) else {
        return Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        };
    };
    let Some(projected_len) = body_len.checked_add(body.len()) else {
        return Phase::Error {
            resp: payload_too_large(core.max_world_bytes),
            reason: ErrorReason::PayloadTooLarge,
        };
    };
    if projected_len > core.max_world_bytes {
        return Phase::Error {
            resp: payload_too_large(core.max_world_bytes),
            reason: ErrorReason::PayloadTooLarge,
        };
    }
    let new_etag = if store::is_persistent(&world) {
        // POST adds bytes on top; existing bytes already counted.
        // prev_len = 0 so the reservation only sizes the delta.
        if let Some(quota) = core.max_storage_bytes {
            let used = core.storage_body_bytes.load(Ordering::Relaxed);
            trace.emit_aux_kv("quota_check", &format!("used={used} quota={quota}"));
        }
        if let Err(boxed) = core.reserve_storage(0, body.len()) {
            return Phase::Error {
                resp: *boxed,
                reason: ErrorReason::QuotaExceeded,
            };
        }
        match world::append_with_audit(
            &core.data,
            &world,
            &body,
            &content_type,
            &stored_headers,
            &core.hmac_key,
        ) {
            Ok(Some((_result, h))) => {
                let etag = hs::hmac_etag(&h);
                trace.emit_aux_kv("sqlite_committed", &format!("etag={}", etag_preview(&etag)));
                etag
            }
            Ok(None) => {
                // World disappeared between metadata read and append.
                core.rollback_storage_reservation(0, body.len());
                return Phase::Error {
                    resp: not_found(),
                    reason: ErrorReason::NotFound,
                };
            }
            Err(e) => {
                core.rollback_storage_reservation(0, body.len());
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
            .append_with_quota(&world, &body, core.max_memory_bytes)
        {
            Ok(Some(result)) => {
                let etag = format!("sha256-{}", result.body_sha256_after);
                trace.emit_aux_kv("sqlite_committed", &format!("etag={}", etag_preview(&etag)));
                etag
            }
            Ok(None) => {
                return Phase::Error {
                    resp: not_found(),
                    reason: ErrorReason::NotFound,
                };
            }
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Phase::Error {
                    resp: payload_too_large(quota),
                    reason: ErrorReason::PayloadTooLarge,
                };
            }
        }
    };
    core.notify("POST", &world, &new_etag);
    trace.emit_aux("notify_sent");
    let resp_headers = [(header::ETAG, hs::etag_header(&new_etag))];
    Phase::CommittedWrite((StatusCode::OK, resp_headers, "").into_response())
}
