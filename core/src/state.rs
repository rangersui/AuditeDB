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
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};

#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;

#[cfg(feature = "coap")]
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Mutex, OwnedMutexGuard, Semaphore};

use crate::http_semantics as hs;
use crate::http_semantics::HeaderAllowlist;
use crate::ledger::LedgerWriter;
pub(crate) use crate::ledger::{AuditAppendJob, BlockingSqliteError};
use crate::read_cache::ReadCache;
use crate::world::Stage;
use crate::{audit, auth, listen, storage_quota_exceeded, store, world};
#[cfg(feature = "coap")]
use crate::{can_write, payload_too_large, server_error, storage_error, unauthorized};

pub(crate) type BoxedResponse = Box<Response>;

#[cfg(target_has_atomic = "64")]
pub(crate) type EventCounter = AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub(crate) type EventCounter = StdMutex<u64>;

#[inline]
pub(crate) fn new_event_counter() -> Arc<EventCounter> {
    #[cfg(target_has_atomic = "64")]
    {
        Arc::new(AtomicU64::new(0))
    }
    #[cfg(not(target_has_atomic = "64"))]
    {
        Arc::new(StdMutex::new(0))
    }
}

#[cfg(target_has_atomic = "64")]
#[inline]
fn next_event_id(counter: &EventCounter) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

#[cfg(not(target_has_atomic = "64"))]
#[inline]
fn next_event_id(counter: &EventCounter) -> u64 {
    let mut next = counter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *next = next.saturating_add(1);
    *next
}

#[cfg(feature = "coap")]
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
    /// Listen ids stay u64-monotonic because replay uses `>` comparisons
    /// against Last-Event-ID. 64-bit targets use `AtomicU64`; 32-bit targets
    /// fall back to a tiny mutex because they lack native 64-bit atomics.
    pub(crate) next_event: Arc<EventCounter>,
    /// Request ids are diagnostic only; `AtomicUsize` keeps 32-bit targets on
    /// native atomics.
    pub(crate) next_request: Arc<AtomicUsize>,
    /// Per-world async write lock. Replaces the previous global
    /// write_lock. Writes to different worlds run concurrently;
    /// writes to the same world serialize (preserving
    /// If-Match/If-None-Match + write atomicity). Locks are created
    /// lazily on first write and never evicted while the process
    /// runs. See `acquire_world_lock` for the rationale (eviction is
    /// unsafe when waiters hold a clone of the Arc). DashMap shards
    /// reads, so lookup is mostly lock-free.
    pub(crate) world_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// Cached writer + init counter for the `var/log/deletes` audit
    /// ledger. See `crate::ledger::LedgerWriter` for the semantics
    /// (lazy init, `inits` counter, no `acquire_world_lock` needed
    /// because the inner StdMutex is the sole serializer).
    pub(crate) ledger: Arc<LedgerWriter>,
    /// Per-world read connection cache. Implements the slot-before-open,
    /// tombstone, and drain-before-remove protocols. See
    /// `crate::read_cache` for the full design and the v7.1 design
    /// doc for the ten-round review history. All read paths route
    /// through `Core::read_world_with_etag`, which delegates to
    /// `read_cache.cached_read_with_hmac`. DELETE installs a tombstone
    /// before `delete_world_blocking` and clears it on both success
    /// and failure paths.
    pub(crate) read_cache: Arc<ReadCache>,
    /// User-configured allowlist for custom representation
    /// headers. Layer 3 of the four-layer persist policy:
    /// L1 hard deny > L1.5 user deny > L2 default allow > L3 user
    /// allow. Built once at startup from `ELASTIK_PERSIST_HEADERS`;
    /// default empty means "only the built-in
    /// `DEFAULT_PERSIST_HEADERS` round-trip; nothing custom unless
    /// the operator opts in." See
    /// `crate::http_semantics::HeaderAllowlist`.
    pub(crate) persist_header_allowlist: Arc<HeaderAllowlist>,
    /// User-configured deny set that subtracts from the built-in
    /// `DEFAULT_PERSIST_HEADERS` (Layer 1.5). Lets an operator say
    /// "I don't want `cache-control` to round-trip in my
    /// deployment" without recompiling. Built once at startup from
    /// `ELASTIK_DENY_HEADERS`; default empty means "no L2 entries
    /// are subtracted." Same matcher shape as the allowlist; L1
    /// hard deny still wins over this.
    pub(crate) persist_header_user_deny: Arc<HeaderAllowlist>,
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

    /// Read body + meta + ETag. Routes durable worlds through the
    /// `read_cache` (slot-before-open, tombstone-aware) so GET / HEAD
    /// don't pay `Connection::open_with_flags` per request. Memory
    /// worlds bypass the cache. Synchronous: the cache uses
    /// `std::sync::RwLock`, matching the existing handler call shape.
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
            Ok(self
                .read_cache
                .cached_read_with_hmac(&self.data, world)?
                .map(|(stage, hmac)| {
                    let etag = hmac
                        .map(|h| hs::hmac_etag(&h))
                        .unwrap_or_else(|| hs::body_etag(&stage.body));
                    (stage, etag)
                }))
        }
    }

    /// DELETE-side: drain in-flight readers, close the cached
    /// connection inside the slot's write guard window, install a
    /// tombstone slot. After this returns, no fd is alive on
    /// `world`'s DB -- `delete_world_blocking` is safe to call.
    /// Memory worlds: no-op. The blocking drain runs inside
    /// `spawn_blocking` so it doesn't stall a Tokio worker.
    pub(crate) async fn install_tombstone(&self, world: &str) {
        if store::is_memory_world(world) {
            return;
        }
        let cache = self.read_cache.clone();
        let world = world.to_string();
        let _ = tokio::task::spawn_blocking(move || cache.install_tombstone_blocking(&world)).await;
    }

    /// Remove the tombstone after `delete_world_blocking` returns.
    /// Called on BOTH success and failure (Bug 20): on failure the
    /// world is still on disk, and the next read must lazy-init a
    /// fresh slot rather than seeing a phantom 404.
    pub(crate) fn clear_tombstone(&self, world: &str) {
        if store::is_memory_world(world) {
            return;
        }
        self.read_cache.clear_tombstone(world);
    }

    /// Verify the audit chain through the read-cache SlotState
    /// protocol (Bug 58). Closes the gap that the bare
    /// `audit::verify_chain` path left: DELETE on the same world
    /// drains in-flight verifies via the slot's write guard, just
    /// like a regular GET. Memory worlds have no audit chain;
    /// callers (proc_audit_verify) filter those before reaching
    /// here.
    pub(crate) fn cached_verify_chain(
        &self,
        world: &str,
    ) -> rusqlite::Result<Option<audit::VerifyReport>> {
        debug_assert!(
            !store::is_memory_world(world),
            "cached_verify_chain only applies to durable worlds"
        );
        self.read_cache
            .cached_verify_chain(&self.data, world, &self.hmac_key)
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
            world::write_with_audit(
                &self.data,
                world,
                body,
                content_type,
                headers,
                &self.hmac_key,
            )?;
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

    /// Append one row to the `var/log/deletes` audit ledger using
    /// the cached `LedgerWriter`. Thin wrapper that runs the
    /// blocking append on the spawn_blocking pool -- the inner
    /// StdMutex on `LedgerWriter::conn` serializes concurrent
    /// appends without holding a Tokio worker.
    pub(crate) async fn append_to_ledger(
        &self,
        job: AuditAppendJob,
    ) -> Result<String, BlockingSqliteError> {
        let data = self.data.clone();
        let ledger = self.ledger.clone();
        match tokio::task::spawn_blocking(move || ledger.append(&data, job)).await {
            Ok(result) => result,
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
        let id = next_event_id(&self.next_event);
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
    #[cfg(feature = "coap")]
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
        // Defence-in-depth tombstone clear (Bug 19). Same rationale
        // as `handler::execute_put`'s clear: PUT/POST and DELETE
        // serialize on the same per-world lock, so a prior DELETE
        // either cleared its own tombstone (success/failure path)
        // or panicked. This call covers the panic case.
        self.clear_tombstone(world_name);
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
