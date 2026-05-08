//! DELETE verb implementation + its blocking-SQLite helpers.
//!
//! Extracted from `handler.rs` so DELETE's intent / commit /
//! commit_failed two-step audit dance — and the blocking-spawn
//! helpers it needs (`AuditAppendJob`, `world_exists_blocking`,
//! `audit_append_blocking`) — live in their own file. This is the
//! first of two post-PR-4c extractions that bring `handler.rs`
//! back under the 500-line ceiling; the second
//! (`crate::handler::post`) lands the same shape.
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
    auth, can_delete, http_semantics as hs, not_found, server_error, storage_error, store,
    unauthorized, world, AuditAppendJob, AuthGate, BlockingSqliteError, Core, ErrorReason, Phase,
    TraceCtx,
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
    // The cached `ledger_writer` Mutex serializes ledger appends, so
    // the prior `acquire_world_lock("var/log/deletes")` calls are
    // gone — this Mutex provides the same ordering guarantee with no
    // extra async hop. Ledger existence is tracked by
    // `delete_ledger_created` AtomicBool: initialized at startup from
    // `world::sizes`, and atomically swapped to true on the first
    // successful append in this process run. The previous
    // `world_exists_blocking` RO open per DELETE is gone.
    if let Err(e) = core
        .append_to_ledger(AuditAppendJob {
            ledger_world: "var/log/deletes",
            event_type: "delete_intent",
            target: world.clone(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: delete_content_type.clone(),
            headers: delete_meta.clone(),
            key: core.hmac_key.clone(),
        })
        .await
    {
        return Phase::Error {
            resp: blocking_storage_error("delete audit intent", e),
            reason: ErrorReason::StorageWriteAudit,
        };
    }
    trace.emit_aux("audit_intent");
    // Bump the durable_world_count exactly once — the first append in
    // this process run that observes the flag still false is the one
    // that "created" the ledger world (or first observed it after
    // startup). `swap` returns the *prior* value, so `was_first` is
    // true only for that one caller; concurrent DELETEs racing on the
    // same false→true edge are serialized by the ledger_writer Mutex
    // inside `append_to_ledger`, so the swap here always runs after
    // a successful append. AcqRel matches the load-on-startup pattern
    // in main.rs (Acquire) and keeps the durable_world_count bump
    // visible to subsequent observers.
    let was_first = !core.delete_ledger_created.swap(true, Ordering::AcqRel);
    if was_first {
        core.durable_world_count.fetch_add(1, Ordering::Relaxed);
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

    // commit / commit_failed appends — same `ledger_writer` Mutex
    // serializes ordering of audit chain entries across concurrent
    // DELETEs on different target worlds. Intent and commit from the
    // same DELETE may interleave with a different DELETE's intent —
    // intentional; the chain is HMAC-linked, not grouped by target
    // world.
    if let Err(commit_err) = core
        .append_to_ledger(AuditAppendJob {
            ledger_world: "var/log/deletes",
            event_type: "delete_commit",
            target: world.clone(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: delete_content_type.clone(),
            headers: delete_meta.clone(),
            key: core.hmac_key.clone(),
        })
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
        match core
            .append_to_ledger(AuditAppendJob {
                ledger_world: "var/log/deletes",
                event_type: "delete_commit_failed",
                target: world.clone(),
                body_sha256: body_sha256_before,
                size: 0,
                content_type: delete_content_type,
                headers: delete_meta,
                key: core.hmac_key.clone(),
            })
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

    Phase::CommittedWrite((StatusCode::NO_CONTENT, "").into_response())
}

// ─── DELETE blocking helpers ──────────────────────────────────────
//
// `AuditAppendJob` and `BlockingSqliteError` moved to `state.rs` —
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
