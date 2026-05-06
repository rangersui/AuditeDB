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

use std::sync::atomic::Ordering;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    apply_meta_headers, audit, auth, can_delete, can_read, can_write, http_semantics as hs,
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

pub(crate) async fn execute_post(
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    // POST appends to an existing world. PUT is the create/replace
    // path — POST returns 404 if the world is absent and never
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

pub(crate) async fn execute_delete(
    headers: HeaderMap,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    // DELETE is approve-only across all paths — no harvard split.
    if !can_delete(tier) {
        return Phase::Error {
            resp: unauthorized("delete requires token; system worlds need approve token"),
            reason: ErrorReason::Auth(AuthGate::Delete),
        };
    }
    // The delete ledger is append-only; deleting it would erase its
    // own audit chain. Refuse before acquiring any locks.
    if world == "var/log/deletes" {
        return Phase::Error {
            resp: unauthorized("delete ledger is append-only"),
            reason: ErrorReason::Auth(AuthGate::Delete),
        };
    }
    let _write_guard = core.acquire_world_lock(&world).await;
    trace.emit_aux_kv("lock_acquired", &format!("target={world}"));
    if let Err(resp) = hs::check_write_preconditions(core, &world, &headers) {
        let reason = if resp.status() == StatusCode::PRECONDITION_FAILED {
            ErrorReason::PreconditionFailed
        } else {
            ErrorReason::StorageRead
        };
        return Phase::Error { resp, reason };
    }

    // Capture body hash BEFORE the world disappears. A missing world
    // is not a delete event; do not mutate the ledger for a 404.
    let Some(stage) = (match core.read_world(&world) {
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
    let body_sha256_before = world::sha256_hex(&stage.body);

    // WAL rule: record `delete_intent` BEFORE the physical delete.
    // If we crash after intent and before commit, recovery sees an
    // explicit intent that needs reconciliation rather than a
    // vanished world with no causal record.
    let delete_meta = hs::request_meta_headers(&headers);
    let delete_content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Acquire the ledger lock briefly around the existence check +
    // intent append so two concurrent DELETEs don't double-count
    // ledger creation. Lock ordering: target world FIRST (already
    // held), then ledger lock. See Core::acquire_world_lock docs.
    let intent_outcome = {
        let _ledger_guard = core.acquire_world_lock("var/log/deletes").await;
        trace.emit_aux("ledger_lock_acquired");
        let existed = match world_exists_blocking(core.data.clone(), "var/log/deletes").await {
            Ok(existed) => existed,
            Err(e) => {
                trace.emit_aux("ledger_lock_released");
                return Phase::Error {
                    resp: blocking_storage_error("delete audit intent", e),
                    reason: ErrorReason::StorageWriteAudit,
                };
            }
        };
        if let Err(e) = audit_append_blocking(
            core.data.clone(),
            AuditAppendJob {
                ledger_world: "var/log/deletes",
                event_type: "delete_intent",
                target: world.clone(),
                body_sha256: body_sha256_before.clone(),
                size: 0,
                content_type: delete_content_type.clone(),
                headers: delete_meta.clone(),
                key: core.hmac_key.clone(),
            },
        )
        .await
        {
            trace.emit_aux("ledger_lock_released");
            return Phase::Error {
                resp: blocking_storage_error("delete audit intent", e),
                reason: ErrorReason::StorageWriteAudit,
            };
        }
        trace.emit_aux("audit_intent");
        trace.emit_aux("ledger_lock_released");
        existed
    };
    if !intent_outcome {
        core.durable_world_count.fetch_add(1, Ordering::Relaxed);
        core.delete_ledger_created.store(true, Ordering::Relaxed);
    }

    let ok = core.delete_world_blocking(&world).await;
    if !ok {
        return Phase::Error {
            resp: server_error("delete failed after audit intent".to_string()),
            reason: ErrorReason::StorageWriteAudit,
        };
    }
    trace.emit_aux("physical_deleted");

    if store::is_persistent(&world) {
        core.storage_body_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(stage.body.len()))
            })
            .ok();
        core.durable_world_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            })
            .ok();
    }
    trace.emit_aux("counter_decremented");
    core.notify("DELETE", &world, "");
    trace.emit_aux("notify_sent");

    // Re-acquire the ledger lock for the commit / commit_failed
    // appends. Each append is one SQLite tx; the lock serializes
    // ordering of *audit chain entries* across concurrent DELETEs on
    // different target worlds. Intent and commit from the same DELETE
    // may interleave with a different DELETE's intent — intentional;
    // the chain is HMAC-linked, not grouped by target world.
    let _ledger_guard = core.acquire_world_lock("var/log/deletes").await;
    trace.emit_aux("ledger_lock_acquired");
    if let Err(commit_err) = audit_append_blocking(
        core.data.clone(),
        AuditAppendJob {
            ledger_world: "var/log/deletes",
            event_type: "delete_commit",
            target: world.clone(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: delete_content_type.clone(),
            headers: delete_meta.clone(),
            key: core.hmac_key.clone(),
        },
    )
    .await
    {
        // Honest cascade-failure trace. The world is already gone, so
        // we still return 204 — the write side of the DELETE
        // succeeded — but the audit chain is now in a degraded state
        // and the operator MUST see exactly which kind. eprintln stays
        // (PR 0 contract): even with trace disabled, stderr carries
        // the failure.
        eprintln!("  WARNING: delete_commit audit append failed for {world}: {commit_err:?}");
        trace.emit_aux_kv("audit_commit_failed", &format!("err={commit_err:?}"));
        match audit_append_blocking(
            core.data.clone(),
            AuditAppendJob {
                ledger_world: "var/log/deletes",
                event_type: "delete_commit_failed",
                target: world.clone(),
                body_sha256: body_sha256_before,
                size: 0,
                content_type: delete_content_type,
                headers: delete_meta,
                key: core.hmac_key.clone(),
            },
        )
        .await
        {
            Ok(_) => {
                // Sub-case A: commit failed but the failure event
                // itself was logged. Audit chain has
                // `delete_intent` + `delete_commit_failed`, so an
                // operator reading the chain sees a coherent
                // best-effort recovery record.
                trace.emit_aux("audit_commit_failed_event_logged");
            }
            Err(failed_event_err) => {
                // Sub-case B: BOTH appends failed (e.g. persistent
                // DiskFull). Audit chain has only `delete_intent`,
                // indistinguishable from "process crashed between
                // intent and commit" by chain alone — but the trace
                // and the eprintln preserve the truth that the
                // commit was attempted and failed twice.
                eprintln!(
                    "  WARNING: delete_commit_failed audit append also failed for {world}: {failed_event_err:?}"
                );
                trace.emit_aux_kv(
                    "audit_commit_failed_event_failed",
                    &format!("err={failed_event_err:?}"),
                );
            }
        }
    } else {
        trace.emit_aux("audit_commit");
    }
    trace.emit_aux("ledger_lock_released");

    Phase::CommittedWrite((StatusCode::NO_CONTENT, "").into_response())
}

/// First 16 chars of an etag string for compact aux trace lines.
/// Etags are HMAC-SHA256 hex (64 chars) or `sha256-<64 chars>`; a
/// 16-char prefix is enough to disambiguate while staying readable.
fn etag_preview(etag: &str) -> String {
    etag.chars().take(16).collect()
}

// ─── DELETE blocking helpers (moved from main.rs in PR 4c) ──────────
//
// These wrap `audit::append` and `world::open_existing` in
// `tokio::task::spawn_blocking` so a slow SQLite call cannot stall
// the runtime. They live next to `execute_delete` (their only
// caller) rather than on `Core`, to keep Core's API surface
// orthogonal to verb-internal sequencing.

#[derive(Debug)]
pub(crate) enum BlockingSqliteError {
    Sqlite(rusqlite::Error),
    Worker,
}

pub(crate) struct AuditAppendJob {
    pub(crate) ledger_world: &'static str,
    pub(crate) event_type: &'static str,
    pub(crate) target: String,
    pub(crate) body_sha256: String,
    pub(crate) size: i64,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) key: Vec<u8>,
}

pub(crate) fn blocking_storage_error(scope: &str, err: BlockingSqliteError) -> Response {
    match err {
        BlockingSqliteError::Sqlite(err) => storage_error(scope, err),
        BlockingSqliteError::Worker => server_error(format!("{scope} worker failed")),
    }
}

pub(crate) async fn world_exists_blocking(
    data: std::path::PathBuf,
    world_name: &'static str,
) -> Result<bool, BlockingSqliteError> {
    match tokio::task::spawn_blocking(move || {
        world::open_existing(&data, world_name).map(|existing| existing.is_some())
    })
    .await
    {
        Ok(Ok(existed)) => Ok(existed),
        Ok(Err(err)) => Err(BlockingSqliteError::Sqlite(err)),
        Err(_) => Err(BlockingSqliteError::Worker),
    }
}

pub(crate) async fn audit_append_blocking(
    data: std::path::PathBuf,
    job: AuditAppendJob,
) -> Result<String, BlockingSqliteError> {
    match tokio::task::spawn_blocking(move || {
        audit::append(
            &data,
            job.ledger_world,
            job.event_type,
            &job.target,
            &job.body_sha256,
            job.size,
            &job.content_type,
            &job.headers,
            &job.key,
        )
    })
    .await
    {
        Ok(Ok(h)) => Ok(h),
        Ok(Err(err)) => Err(BlockingSqliteError::Sqlite(err)),
        Err(_) => Err(BlockingSqliteError::Worker),
    }
}
