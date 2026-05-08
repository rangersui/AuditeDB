//! `Core` -- the application state shared across all routes.
//!
//! Holds tokens, the per-world lock map, the in-memory store handle,
//! storage counters, the SSE broadcast channel, the shutdown
//! receiver, and the durable-data path. Construction lives in
//! `main.rs` (one struct-literal initializer in `main()`); this
//! module owns the type definition + the small set of primitive
//! methods (`acquire_world_lock`, `read_world`, `notify`,
//! `reserve_storage`, ...) that verb handlers and other modules
//! call through.
//!
//! All fields are `pub(crate)` so siblings can read and (in tests)
//! mutate them. The struct itself is `pub(crate)` and re-exported
//! at the crate root via `pub(crate) use crate::state::*;` in
//! `main.rs`, so existing callers keep using `crate::Core` /
//! `crate::WriteOutcome` without per-extraction import churn.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Mutex, OwnedMutexGuard, Semaphore};

use crate::http_semantics as hs;
use crate::world::Stage;
use crate::{
    audit, auth, can_write, listen, payload_too_large, server_error, storage_error,
    storage_quota_exceeded, store, unauthorized, world,
};

pub(crate) type BoxedResponse = Box<Response>;

pub(crate) struct WriteOutcome {
    pub status: StatusCode,
    /// Etag is part of `put_bytes`'s contract for any future caller
    /// that wants to include it in a response. The current CoAP
    /// caller in `coap.rs` only reads `status`; HTTP writes flow
    /// through `handler::execute_put` (which does not call
    /// `put_bytes`). Allow until CoAP migrates to the FSM (PR 7+),
    /// at which point `put_bytes` and `WriteOutcome` can be retired.
    #[allow(dead_code)]
    pub etag: String,
}

#[derive(Clone)]
pub(crate) struct Core {
    pub(crate) data: PathBuf,
    pub(crate) tokens: auth::Tokens,
    pub(crate) hmac_key: Vec<u8>,
    pub(crate) mem: Arc<store::MemoryStore>,
    pub(crate) max_world_bytes: usize,
    pub(crate) max_memory_bytes: usize,
    pub(crate) max_storage_bytes: Option<usize>,
    pub(crate) storage_body_bytes: Arc<AtomicUsize>,
    pub(crate) durable_world_count: Arc<AtomicUsize>,
    pub(crate) delete_ledger_created: Arc<AtomicBool>,
    pub(crate) events: broadcast::Sender<listen::ChangeEvent>,
    pub(crate) listen_slots: Arc<Semaphore>,
    pub(crate) listen_replay_max: usize,
    pub(crate) event_log: Arc<StdMutex<VecDeque<listen::ChangeEvent>>>,
    pub(crate) shutdown: watch::Receiver<bool>,
    pub(crate) next_event: Arc<AtomicU64>,
    pub(crate) next_request: Arc<AtomicU64>,
    /// Per-world async write lock. Replaces the previous global
    /// write_lock. Writes to different worlds run concurrently;
    /// writes to the same world serialize (preserving
    /// If-Match/If-None-Match + write atomicity). Locks are created
    /// lazily on first write and never evicted while the process
    /// runs. See `acquire_world_lock` for the rationale (eviction is
    /// unsafe when waiters hold a clone of the Arc). DashMap shards
    /// reads, so lookup is mostly lock-free.
    pub(crate) world_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// Cached writer for the `var/log/deletes` audit ledger. The
    /// ledger is the hottest open() in the codebase — every DELETE
    /// opens it 2-3 times under the pre-cache flow (existence
    /// check, intent append, commit append). One cached connection
    /// covers all of them.
    ///
    /// The inner `StdMutex<Option<Connection>>` is the SOLE
    /// serializer for ledger appends. Earlier drafts of `Core`
    /// also held the per-world lock at `var/log/deletes` for the
    /// same purpose; that lock is removed by this PR as redundant
    /// with this Mutex. Don't re-add it.
    ///
    /// Lazy init: `None` until the first `append_to_ledger`
    /// succeeds; from then on, every append reuses the cached
    /// connection. Never invalidated (the ledger world is never
    /// deleted by user-facing DELETE — `var/log/*` is reserved).
    pub(crate) ledger_writer: Arc<StdMutex<Option<rusqlite::Connection>>>,
}

/// Result of an audit append run inside `spawn_blocking`. Shared
/// between `Core::append_to_ledger` (this module) and
/// `handler::delete::execute_delete` (which is the only caller in
/// the FSM today).
#[derive(Debug)]
pub(crate) enum BlockingSqliteError {
    Sqlite(rusqlite::Error),
    Worker,
}

/// One audit append's input. Owns its strings/buffers because the
/// `spawn_blocking` closure that runs the SQL must be `'static`.
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

impl Core {
    /// Acquire the per-world write lock. Different worlds run concurrent
    /// writes; same-world writes serialize. Lazy creation: the lock is
    /// inserted on first acquire and never evicted while the process runs.
    ///
    /// We deliberately do NOT remove the entry on DELETE. Removing while
    /// another waiter holds a clone of the Arc would let the next acquirer
    /// create a fresh Arc<Mutex<()>> for the same world, breaking mutual
    /// exclusion (two concurrent writers, two different mutexes). The map
    /// grows by one entry per distinct world ever written -- bounded in
    /// practice by total world cardinality.
    ///
    /// Lock ordering rule for callers that need more than one world lock
    /// (currently only DELETE, which also touches the shared `var/log/deletes`
    /// ledger): always acquire the target world lock FIRST, then any shared
    /// ledger lock(s). This avoids cycles. See `handler::execute_delete`
    /// for the only current example.
    ///
    /// The DashMap entry guard is dropped before `.await`, so we never
    /// hold a sync shard lock across an await.
    pub(crate) async fn acquire_world_lock(&self, world: &str) -> OwnedMutexGuard<()> {
        let lock = {
            self.world_locks
                .entry(world.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    pub(crate) fn read_world(&self, world: &str) -> rusqlite::Result<Option<Stage>> {
        Ok(self.read_world_with_etag(world)?.map(|(stage, _)| stage))
    }

    pub(crate) fn read_world_with_etag(
        &self,
        world: &str,
    ) -> rusqlite::Result<Option<(Stage, String)>> {
        if store::is_memory_world(world) {
            Ok(self
                .mem
                .read_with_hash(world)
                .map(|(stage, hash)| (stage, format!("sha256-{hash}"))))
        } else {
            Ok(
                world::read_with_hmac(&self.data, world)?.map(|(stage, hmac)| {
                    let etag = hmac
                        .map(|h| hs::hmac_etag(&h))
                        .unwrap_or_else(|| hs::body_etag(&stage.body));
                    (stage, etag)
                }),
            )
        }
    }

    /// Test-only fixture: seed a world directly without going through
    /// auth/preconditions/audit. Production writes go through `put_bytes`
    /// (durable: `world::write_with_audit_checked` + `reserve_storage`;
    /// memory: `MemoryStore::write_with_quota`). Kept for the existing
    /// 80+ unit tests that build small fixture worlds before exercising
    /// handler paths.
    #[cfg(test)]
    pub(crate) fn write_world(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) -> rusqlite::Result<()> {
        if store::is_memory_world(world) {
            self.mem.write(world, body, content_type, headers);
            Ok(())
        } else {
            let current_len = world::body_len(&self.data, world)?;
            world::write(&self.data, world, body, content_type, headers)?;
            let prev = current_len.unwrap_or(0);
            let _ = self.storage_body_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |used| Some(used.saturating_sub(prev).saturating_add(body.len())),
            );
            if current_len.is_none() {
                self.durable_world_count.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    pub(crate) fn world_metadata(
        &self,
        world: &str,
    ) -> rusqlite::Result<Option<world::WorldMetadata>> {
        if store::is_memory_world(world) {
            Ok(self.mem.metadata(world))
        } else {
            world::metadata(&self.data, world)
        }
    }

    /// Append one row to the `var/log/deletes` audit ledger using the
    /// cached `ledger_writer` connection. Lazy-initializes the
    /// connection on first call (`world::open` creates the schema if
    /// needed; idempotent on subsequent restarts because of
    /// `CREATE TABLE IF NOT EXISTS`).
    ///
    /// Replaces the prior pattern of `world::open` per append (2-3
    /// opens per DELETE today). The inner `StdMutex` serializes
    /// concurrent appends — appends happen inside a blocking task,
    /// so this parks an OS thread when contended; the surrounding
    /// per-world write lock at `var/log/deletes` is gone, traded for
    /// this single mutex.
    pub(crate) async fn append_to_ledger(
        &self,
        job: AuditAppendJob,
    ) -> Result<String, BlockingSqliteError> {
        let data = self.data.clone();
        let writer = self.ledger_writer.clone();
        let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<String> {
            let mut guard = writer.lock().unwrap_or_else(|p| p.into_inner());
            if guard.is_none() {
                // Lazy init. `world::open` creates the schema; safe to
                // call whether or not the ledger DB exists on disk.
                *guard = Some(world::open(&data, job.ledger_world)?);
            }
            let conn = guard.as_mut().expect("ledger_writer initialized above");
            audit::append_with_conn(
                conn,
                job.event_type,
                &job.target,
                &job.body_sha256,
                job.size,
                &job.content_type,
                &job.headers,
                &job.key,
            )
        })
        .await;
        match result {
            Ok(Ok(h)) => Ok(h),
            Ok(Err(err)) => Err(BlockingSqliteError::Sqlite(err)),
            Err(_) => Err(BlockingSqliteError::Worker),
        }
    }

    pub(crate) async fn delete_world_blocking(&self, world: &str) -> bool {
        if store::is_memory_world(world) {
            self.mem.delete(world)
        } else {
            let data = self.data.clone();
            let world = world.to_string();
            tokio::task::spawn_blocking(move || world::delete(&data, &world))
                .await
                .unwrap_or(false)
        }
    }

    pub(crate) fn notify(&self, method: &'static str, world: &str, etag: &str) {
        let id = self.next_event.fetch_add(1, Ordering::Relaxed) + 1;
        let change = listen::ChangeEvent {
            id,
            method,
            path: format!("/{world}"),
            etag: etag.to_owned(),
        };
        {
            let mut log = self
                .event_log
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            log.push_back(change.clone());
            while log.len() > self.listen_replay_max {
                log.pop_front();
            }
        }
        let _ = self.events.send(change);
    }

    /// Atomic reservation: check the quota and reserve `new_len - prev_len`
    /// in a single CAS step. Replaces the old "snapshot then write then
    /// adjust" pattern, which raced under per-world locking when two
    /// concurrent writes on different worlds both observed usage below
    /// quota and only afterwards pushed it past.
    ///
    /// Caller must hold `acquire_world_lock(world)` so that `prev_len`
    /// reflects the world's true current body length (cannot change
    /// underneath us). On success the global counter has already been
    /// updated; on success of the subsequent storage write, no further
    /// counter change is needed. On failure of the storage write, call
    /// `rollback_storage_reservation` to credit back.
    ///
    /// `prev_len` is 0 for new worlds and for append (where the existing
    /// bytes stay and we only add `new_len` new).
    pub(crate) fn reserve_storage(
        &self,
        prev_len: usize,
        new_len: usize,
    ) -> Result<(), BoxedResponse> {
        if let Some(quota) = self.max_storage_bytes {
            let result = self.storage_body_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |used| {
                    let projected = used.saturating_sub(prev_len).saturating_add(new_len);
                    if projected > quota {
                        None
                    } else {
                        Some(projected)
                    }
                },
            );
            match result {
                Ok(_) => Ok(()),
                Err(used) => {
                    let projected = used.saturating_sub(prev_len).saturating_add(new_len);
                    Err(Box::new(storage_quota_exceeded(used, quota, projected)))
                }
            }
        } else {
            // No quota: still keep the counter coherent for /proc/df.
            let _ = self.storage_body_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |used| Some(used.saturating_sub(prev_len).saturating_add(new_len)),
            );
            Ok(())
        }
    }

    /// Inverse of `reserve_storage`. Call when the reserved write
    /// subsequently fails so we credit the bytes back into available quota.
    pub(crate) fn rollback_storage_reservation(&self, prev_len: usize, new_len: usize) {
        let _ =
            self.storage_body_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    Some(used.saturating_sub(new_len).saturating_add(prev_len))
                });
    }

    /// CoAP-only write entry point. The HTTP path goes through
    /// `handler::execute_put` (which inlines this logic plus the FSM
    /// trace lines and structured `ErrorReason` mapping). Both paths
    /// produce the same audit chain entry and the same notify event.
    /// PR 7+ migrates CoAP onto the FSM and retires `put_bytes` +
    /// `WriteOutcome` together.
    pub(crate) async fn put_bytes(
        &self,
        world_name: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
        tier: auth::Tier,
        preconditions: Option<&HeaderMap>,
    ) -> Result<WriteOutcome, Response> {
        if !can_write(world_name, tier) {
            return Err(unauthorized(
                "write requires token; system worlds need approve token",
            ));
        }
        if body.len() > self.max_world_bytes {
            return Err(payload_too_large(self.max_world_bytes));
        }
        let _write_guard = self.acquire_world_lock(world_name).await;
        if let Some(req_headers) = preconditions {
            hs::check_write_preconditions(self, world_name, req_headers)?;
        }
        let existed;
        let new_etag = if store::is_persistent(world_name) {
            // Read previous body length under the per-world lock; cannot
            // change while we hold the guard. None means new world.
            let prev_len_opt = world::body_len(&self.data, world_name)
                .map_err(|e| storage_error("storage metadata", e))?;
            existed = prev_len_opt.is_some();
            let prev_len = prev_len_opt.unwrap_or(0);

            // Atomic CAS quota reservation. Race-free across worlds: two
            // writes on different worlds cannot both observe usage below
            // quota and then push it past, because the CAS sees the latest
            // counter value. On reservation failure no write happens.
            self.reserve_storage(prev_len, body.len()).map_err(|b| *b)?;

            // Quota already enforced by reservation; pass None to skip the
            // (now redundant and racy) snapshot check inside world.rs.
            match world::write_with_audit_checked(
                &self.data,
                world_name,
                body,
                content_type,
                headers,
                &self.hmac_key,
                None,
            ) {
                Ok(result) => {
                    if !existed {
                        self.durable_world_count.fetch_add(1, Ordering::Relaxed);
                    }
                    hs::hmac_etag(&result.hmac)
                }
                Err(world::WriteAuditError::Quota { .. }) => {
                    // Unreachable: we passed quota=None above.
                    self.rollback_storage_reservation(prev_len, body.len());
                    return Err(server_error("unexpected quota error".to_string()));
                }
                Err(world::WriteAuditError::Sqlite(e)) => {
                    self.rollback_storage_reservation(prev_len, body.len());
                    return Err(storage_error("storage/audit", e));
                }
            }
        } else {
            // Memory worlds: the existence check, the quota check, and the
            // actual insert all happen under one MemoryStore HashMap mutex
            // acquisition. That mutex was the implicit serializer the global
            // write_lock used to provide; per-world locks alone don't help
            // here because the budget is shared across all memory worlds.
            match self.mem.write_with_quota(
                world_name,
                body,
                content_type,
                headers,
                self.max_memory_bytes,
            ) {
                Ok(outcome) => {
                    existed = outcome.existed;
                    hs::body_etag(body)
                }
                Err(store::MemoryQuotaError { quota, .. }) => {
                    return Err(payload_too_large(quota));
                }
            }
        };
        self.notify("PUT", world_name, &new_etag);
        Ok(WriteOutcome {
            status: if existed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            etag: new_etag,
        })
    }
}
