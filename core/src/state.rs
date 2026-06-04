//! `Core` -- the application state shared across all routes.
//!
//! Holds tokens, the per-world lock map, the in-memory store handle,
//! storage counters, the SSE broadcast channel, the shutdown
//! receiver, and the durable-data path. Construction lives in
//! `EngineBuilder`; this module owns the type definition + the small set of
//! primitive methods (`acquire_world_lock`, `read_world`, `notify`,
//! `reserve_storage`, ...) that storage-facing modules call through.
//!
//! All fields are `pub(crate)` so siblings can read and (in tests)
//! mutate them. The struct itself is `pub(crate)` and re-exported
//! at the crate root via `pub(crate) use crate::state::*;` in
//! the crate root, so existing callers keep using `crate::Core` without
//! per-extraction import churn.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};

#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;

use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Mutex, OwnedMutexGuard, Semaphore};

use crate::engine_types::ValidatedWorldPath;
use crate::ledger::LedgerWriter;
pub(crate) use crate::ledger::{AuditAppendJob, BlockingSqliteError};
use crate::read_cache::ReadCache;
use crate::world::Stage;
use crate::{audit, auth, event, store, world};

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

pub(crate) struct StorageReservationError {
    pub(crate) used: usize,
    pub(crate) quota: usize,
    pub(crate) projected: usize,
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
    pub(crate) events: broadcast::Sender<event::ChangeEvent>,
    pub(crate) listen_slots: Arc<Semaphore>,
    pub(crate) listen_replay_max: usize,
    pub(crate) event_log: Arc<StdMutex<VecDeque<event::ChangeEvent>>>,
    pub(crate) shutdown: watch::Receiver<bool>,
    /// Listen ids stay u64-monotonic because replay uses `>` comparisons
    /// against Last-Event-ID. 64-bit targets use `AtomicU64`; 32-bit targets
    /// fall back to a tiny mutex because they lack native 64-bit atomics.
    pub(crate) next_event: Arc<EventCounter>,
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
    /// `read_cache.cached_read_with_hmac`. Delete installs a tombstone
    /// before `delete_world_blocking` and clears it on both success
    /// and failure paths.
    pub(crate) read_cache: Arc<ReadCache>,
}

impl Core {
    /// Acquire the per-world write lock. Different worlds run concurrent
    /// writes; same-world writes serialize. Lazy creation: the lock is
    /// inserted on first acquire and never evicted while the process runs.
    ///
    /// We deliberately do NOT remove the entry on delete. Removing while
    /// another waiter holds a clone of the Arc would let the next acquirer
    /// create a fresh Arc<Mutex<()>> for the same world, breaking mutual
    /// exclusion (two concurrent writers, two different mutexes). The map
    /// grows by one entry per distinct world ever written -- bounded in
    /// practice by total world cardinality.
    ///
    /// Lock ordering rule for callers that need more than one world lock
    /// (currently only delete, which also touches the shared `var/log/deletes`
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
    /// `read_cache` (slot-before-open, tombstone-aware) so repeated reads
    /// don't pay `Connection::open_with_flags` per operation. Memory
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
                        .map(|h| crate::etag::hmac_etag(&h))
                        .unwrap_or_else(|| crate::etag::body_etag(&stage.body));
                    (stage, etag)
                }))
        }
    }

    /// Delete-side: drain in-flight readers, close the cached
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
    /// `audit::verify_chain` path left: delete on the same world
    /// drains in-flight verifies via the slot's write guard, just
    /// like a regular read. Memory worlds have no audit chain;
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
    /// auth/preconditions/audit. Production writes go through `world_ops`
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

    pub(crate) fn notify(
        &self,
        verb: crate::engine_types::ChangeVerb,
        world: &ValidatedWorldPath,
        etag: &str,
    ) {
        let id = next_event_id(&self.next_event);
        let change = event::ChangeEvent {
            id,
            verb,
            path: format!("/{}", world.as_str()),
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
    ) -> Result<(), StorageReservationError> {
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
                    Err(StorageReservationError {
                        used,
                        quota,
                        projected,
                    })
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
}
