//! DELETE verb implementation + its blocking-SQLite helpers.
//!
//! Extracted from `handler.rs` (PR followup to 4c) to keep
//! `handler.rs` under the 500-line ceiling. DELETE is the most
//! involved verb — intent / commit / commit_failed two-step audit
//! dance plus the blocking-spawn helpers — so it carries enough
//! weight to deserve its own file.
//!
//! `pub(crate) use` re-exports `execute_delete` from `handler.rs`
//! so callers (`handler::execute(verb=Delete, ...)` and the
//! white-box tests in `main.rs`) keep their import path stable.

use std::sync::atomic::Ordering;

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    audit, auth, can_delete, http_semantics as hs, not_found, server_error, storage_error, store,
    unauthorized, world, AuthGate, Core, ErrorReason, Phase, TraceCtx,
};

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

// ─── DELETE blocking helpers ──────────────────────────────────────
//
// These wrap `audit::append` and `world::open_existing` in
// `tokio::task::spawn_blocking` so a slow SQLite call cannot stall
// the runtime. They live next to `execute_delete` (their only
// caller) rather than on `Core`, to keep Core's API surface
// orthogonal to verb-internal sequencing.

#[derive(Debug)]
enum BlockingSqliteError {
    Sqlite(rusqlite::Error),
    Worker,
}

struct AuditAppendJob {
    ledger_world: &'static str,
    event_type: &'static str,
    target: String,
    body_sha256: String,
    size: i64,
    content_type: String,
    headers: Vec<(String, String)>,
    key: Vec<u8>,
}

fn blocking_storage_error(scope: &str, err: BlockingSqliteError) -> Response {
    match err {
        BlockingSqliteError::Sqlite(err) => storage_error(scope, err),
        BlockingSqliteError::Worker => server_error(format!("{scope} worker failed")),
    }
}

async fn world_exists_blocking(
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

async fn audit_append_blocking(
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
