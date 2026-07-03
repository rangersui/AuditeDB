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
    Arc, Condvar, Mutex as StdMutex,
};

#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;

use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Mutex, OwnedMutexGuard, Semaphore};

use crate::engine_types::{AuditHmacKey, ValidatedWorldPath};
use crate::event::ChangeDeliveryId;
use crate::ledger::AppendedLedgerEvent;
use crate::ledger::LedgerWriter;
pub(crate) use crate::ledger::{AuditAppendJob, BlockingSqliteError};
use crate::read_cache::ReadCache;
use crate::subscription_cursor::SubscriptionEpoch;
use crate::subscription_event_id::{ChangeTarget, SubscriptionEventId};
use crate::timeline::{TimelineAddress, TimelineRead};
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

const WRITE_CONN_CACHE_MAX_ENTRIES: usize = 64;

pub(crate) struct FileOpGate {
    shutting_down: AtomicBool,
    active: StdMutex<usize>,
    idle: Condvar,
}

#[must_use]
pub(crate) struct FileOpPermit {
    gate: Arc<FileOpGate>,
}

impl FileOpGate {
    pub(crate) fn new() -> Self {
        Self {
            shutting_down: AtomicBool::new(false),
            active: StdMutex::new(0),
            idle: Condvar::new(),
        }
    }

    pub(crate) fn begin(self: &Arc<Self>) -> Option<FileOpPermit> {
        if self.shutting_down.load(Ordering::Acquire) {
            return None;
        }
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.shutting_down.load(Ordering::Acquire) {
            return None;
        }
        *active = active.saturating_add(1);
        Some(FileOpPermit {
            gate: Arc::clone(self),
        })
    }

    fn shutdown_and_wait(&self) {
        self.shutting_down.store(true, Ordering::Release);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *active != 0 {
            active = self
                .idle
                .wait(active)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }
}

impl Drop for FileOpPermit {
    fn drop(&mut self) {
        let mut active = self
            .gate
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active = active.saturating_sub(1);
        if *active == 0 {
            self.gate.idle.notify_all();
        }
    }
}

#[cfg(target_has_atomic = "64")]
#[inline]
fn next_event_id(counter: &EventCounter) -> ChangeDeliveryId {
    ChangeDeliveryId::new(counter.fetch_add(1, Ordering::Relaxed) + 1)
}

/// Newest event id this process has issued, or 0 before the first event.
///
/// Listen ids are process-local: the counter resets on every engine start.
/// A resume cursor greater than this value must come from another process
/// lifetime and cannot be used as a live-stream floor.
#[cfg(target_has_atomic = "64")]
#[cfg(test)]
#[inline]
pub(crate) fn last_issued_event_id(counter: &EventCounter) -> ChangeDeliveryId {
    ChangeDeliveryId::new(counter.load(Ordering::Relaxed))
}

#[cfg(not(target_has_atomic = "64"))]
#[inline]
fn next_event_id(counter: &EventCounter) -> ChangeDeliveryId {
    let mut next = counter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *next = next.saturating_add(1);
    ChangeDeliveryId::new(*next)
}

/// Newest event id this process has issued, or 0 before the first event.
///
/// Listen ids are process-local: the counter resets on every engine start.
/// A resume cursor greater than this value must come from another process
/// lifetime and cannot be used as a live-stream floor.
#[cfg(not(target_has_atomic = "64"))]
#[cfg(test)]
#[inline]
pub(crate) fn last_issued_event_id(counter: &EventCounter) -> ChangeDeliveryId {
    ChangeDeliveryId::new(
        *counter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
}

/// Test-only counter minting bypass. Production ids advance only through
/// `next_event_id`.
#[cfg(test)]
pub(crate) fn test_only_set_event_counter(counter: &EventCounter, value: u64) {
    #[cfg(target_has_atomic = "64")]
    {
        counter.store(value, Ordering::Relaxed);
    }
    #[cfg(not(target_has_atomic = "64"))]
    {
        *counter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }
}

pub(crate) struct StorageReservationError {
    pub(crate) used: usize,
    pub(crate) quota: usize,
    pub(crate) projected: usize,
}

pub(crate) struct Core {
    pub(crate) data: PathBuf,
    pub(crate) tokens: auth::Tokens,
    pub(crate) hmac_key: AuditHmacKey,
    pub(crate) mem: Arc<store::MemoryStore>,
    pub(crate) max_world_bytes: usize,
    pub(crate) max_memory_bytes: usize,
    pub(crate) max_storage_bytes: Option<usize>,
    pub(crate) retained_body_count: world::RetainedBodyCount,
    pub(crate) storage_body_bytes: Arc<AtomicUsize>,
    pub(crate) storage_current_body_bytes: Arc<AtomicUsize>,
    pub(crate) storage_retained_cas_body_bytes: Arc<AtomicUsize>,
    pub(crate) storage_audit_chain_events: Arc<AtomicUsize>,
    pub(crate) file_ops: Arc<FileOpGate>,
    /// Per-world writer connections used only while the caller holds the
    /// matching `world_locks` guard.
    ///
    /// This is a performance cache, not the concurrency primitive. Same-world
    /// write ordering still comes from `acquire_world_lock`. The cache is
    /// deliberately small: it exists to keep one hot world from paying
    /// `Connection::open` and PRAGMA setup on every write, not to hold one fd
    /// for every world ever touched. DELETE removes the cached connection
    /// before unlinking the database so Windows never sees a live writer fd
    /// during physical removal.
    pub(crate) write_conns:
        Arc<DashMap<ValidatedWorldPath, Arc<StdMutex<world::OpenedWriteConnection>>>>,
    pub(crate) durable_world_count: Arc<AtomicUsize>,
    pub(crate) delete_ledger_created: Arc<AtomicBool>,
    pub(crate) events: broadcast::Sender<event::ChangeEvent>,
    pub(crate) listen_slots: Arc<Semaphore>,
    pub(crate) listen_replay_max: usize,
    pub(crate) listen_epoch: SubscriptionEpoch,
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
    pub(crate) world_locks: Arc<DashMap<ValidatedWorldPath, Arc<Mutex<()>>>>,
    /// Cached writer + init counter for the `var/log/deletes` audit
    /// ledger. See `crate::ledger::LedgerWriter` for the semantics
    /// (lazy init, `inits` counter, no `acquire_world_lock` needed
    /// because the inner StdMutex is the sole serializer).
    pub(crate) ledger: Arc<LedgerWriter>,
    /// Serializes delete-ledger append plus live notification as one ordered
    /// transition. `LedgerWriter` alone serializes SQLite row creation, but a
    /// task switch between append and notify could otherwise publish seq N+1
    /// before seq N.
    pub(crate) delete_ledger_stream_lock: Arc<Mutex<()>>,
    /// Per-world read connection cache. Implements the slot-before-open,
    /// tombstone, and drain-before-remove protocols. See
    /// `crate::read_cache` for the full design and the v7.1 design
    /// doc for the ten-round review history. All read paths route
    /// through `Core::read_world_with_etag`, which delegates to
    /// `read_cache.cached_read_with_hmac`. Delete installs a tombstone
    /// before physical removal and clears it on both success and
    /// failure paths.
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
    /// ledger lock(s). This avoids cycles. See `delete_ops::delete`
    /// for the current example.
    ///
    /// The DashMap entry guard is dropped before `.await`, so we never
    /// hold a sync shard lock across an await.
    pub(crate) async fn acquire_world_lock(
        &self,
        world: &ValidatedWorldPath,
    ) -> OwnedMutexGuard<()> {
        let lock = {
            self.world_locks
                .entry(world.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    pub(crate) fn read_world(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        file_op: &FileOpPermit,
    ) -> audit::AuditResult<Option<Stage>> {
        Ok(self
            .read_world_with_etag(proof, world, file_op)?
            .map(|(stage, _)| stage))
    }

    /// Read body + meta + ETag. Routes durable worlds through the
    /// `read_cache` (slot-before-open, tombstone-aware) so repeated reads
    /// don't pay `Connection::open_with_flags` per operation. Memory
    /// worlds bypass the cache. Synchronous: the cache uses
    /// `std::sync::RwLock`, matching the existing handler call shape.
    pub(crate) fn read_world_with_etag(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> audit::AuditResult<Option<(Stage, String)>> {
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            Ok(self
                .mem
                .read_with_hash(memory_world)
                .map(|(stage, hash)| (stage, format!("sha256-{hash}"))))
        } else {
            Ok(self
                .read_cache
                .cached_read_with_hmac(proof, &self.data, world, &self.hmac_key)?
                .transpose()?
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
    /// tombstone slot. After this returns, no read-cache fd is alive on
    /// `world`'s DB -- physical removal is safe to call. Memory worlds:
    /// no-op. This async test helper wraps the blocking drain in
    /// `spawn_blocking`; production delete calls the blocking form only
    /// after all async locks have been acquired.
    #[cfg(test)]
    pub(crate) async fn install_tombstone(&self, world: &ValidatedWorldPath) {
        if store::is_memory_world(world) {
            return;
        }
        let cache = self.read_cache.clone();
        let world = world.clone();
        let _ = tokio::task::spawn_blocking(move || cache.install_tombstone_blocking(&world)).await;
    }

    /// Remove the tombstone after physical removal returns.
    /// Called on BOTH success and failure (Bug 20): on failure the
    /// world is still on disk, and the next read must lazy-init a
    /// fresh slot rather than seeing a phantom 404.
    pub(crate) fn clear_tombstone(&self, world: &ValidatedWorldPath) {
        if store::is_memory_world(world) {
            return;
        }
        self.read_cache.clear_tombstone(world);
    }

    pub(crate) fn begin_file_op(&self) -> Option<FileOpPermit> {
        self.file_ops.begin()
    }

    /// Verified chain-head read through the read-cache SlotState protocol.
    /// Outer `None` = world DB missing (callers map to NotFound); inner
    /// `None` = empty bootstrap-shape chain (nothing to anchor). Memory
    /// worlds have no audit chain; callers filter those before reaching
    /// here, same as `cached_verify_chain`.
    pub(crate) fn cached_chain_head(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> rusqlite::Result<Option<audit::AuditResult<Option<audit::VerifiedChainHead>>>> {
        debug_assert!(
            !store::is_memory_world(world),
            "cached_chain_head only applies to durable worlds"
        );
        self.read_cache
            .cached_chain_head(proof, &self.data, world, &self.hmac_key)
    }

    /// Verified chain-stamp lookup through the read-cache SlotState protocol.
    pub(crate) fn cached_chain_stamp(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        seq: crate::chain_stamp::ChainSeq,
        _file_op: &FileOpPermit,
    ) -> rusqlite::Result<Option<audit::AuditResult<crate::chain_stamp::ChainStampRead>>> {
        debug_assert!(
            !store::is_memory_world(world),
            "cached_chain_stamp only applies to durable worlds"
        );
        self.read_cache
            .cached_chain_stamp(proof, &self.data, world, seq, &self.hmac_key)
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
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> rusqlite::Result<Option<audit::VerifyReport>> {
        debug_assert!(
            !store::is_memory_world(world),
            "cached_verify_chain only applies to durable worlds"
        );
        self.read_cache
            .cached_verify_chain(proof, &self.data, world, &self.hmac_key)
    }

    /// Historical body read through the read-cache SlotState protocol.
    /// Durable timeline reads are fd-lifetime sensitive for the same reason
    /// ordinary reads and audit verifies are: delete must drain the cached
    /// connection before removing the world database.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_timeline_body(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        address: &TimelineAddress,
        _file_op: &FileOpPermit,
    ) -> audit::AuditResult<Option<TimelineRead>> {
        debug_assert!(
            !store::is_memory_world(address.world()),
            "read_timeline_body only applies to durable worlds"
        );
        let read = self
            .read_cache
            .cached_read_timeline_body(proof, &self.data, address, &self.hmac_key)
            .map_err(audit::AuditError::from)?;
        match read {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn replay_chain_events_after(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        event_id: &SubscriptionEventId,
        limit: usize,
        _file_op: &FileOpPermit,
    ) -> audit::AuditResult<Option<audit::VerifiedReplayAfter>> {
        debug_assert!(
            !store::is_memory_world(event_id.world()),
            "replay_chain_events_after only applies to durable worlds"
        );
        let replay = self
            .read_cache
            .cached_replay_chain_events_after(proof, &self.data, event_id, limit, &self.hmac_key)
            .map_err(audit::AuditError::from)?;
        match replay {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Delete-side final subject anchor through the read-cache SlotState
    /// protocol. Durable delete uses this before installing a tombstone so the
    /// delete ledger can identify the exact body event being removed.
    pub(crate) fn latest_body_head(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> audit::AuditResult<Option<audit::VerifiedBodyHead>> {
        debug_assert!(
            !store::is_memory_world(world),
            "latest_body_head only applies to durable worlds"
        );
        let head = self
            .read_cache
            .cached_latest_body_head(proof, &self.data, world, &self.hmac_key)
            .map_err(audit::AuditError::from)?;
        match head {
            Some(result) => result,
            None => Ok(None),
        }
    }

    /// Test-only fixture: seed a world directly without going through
    /// auth/preconditions/audit. Production writes go through `world_ops`
    /// (durable: `world::write_with_audit_checked` + `reserve_storage`;
    /// memory: `MemoryStore::write_with_quota`). Kept for the existing
    /// 80+ unit tests that build small fixture worlds before exercising
    /// handler paths.
    #[cfg(test)]
    pub(crate) fn test_only_write_world(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) -> Result<(), world::WriteAuditError> {
        let world_path = ValidatedWorldPath::new(world)
            .map_err(|_| world::WriteAuditError::StorageInvariant("invalid fixture world path"))?;
        if let Some(memory_world) = store::MemoryWorldPath::new(&world_path) {
            self.mem.write(memory_world, body, content_type, headers);
            Ok(())
        } else {
            let file_op = self
                .begin_file_op()
                .ok_or(world::WriteAuditError::StorageInvariant(
                    "fixture file operation gate closed",
                ))?;
            let before = crate::blocking_sqlite::run_scoped(|proof| {
                world::storage_usage(proof, &self.data, &world_path, &file_op)
            })?;
            let existed = before.is_some();
            let before = before.unwrap_or_default();
            world::write_with_audit(
                &self.data,
                &world_path,
                body,
                content_type,
                headers,
                &self.hmac_key,
            )?;
            let after = crate::blocking_sqlite::run_scoped(|proof| {
                world::storage_usage(proof, &self.data, &world_path, &file_op)
            })?
            .unwrap_or_default();
            self.replace_storage_usage(before, after);
            if !existed {
                self.durable_world_count.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    pub(crate) fn append_to_ledger_blocking(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        job: AuditAppendJob,
        _file_op: &FileOpPermit,
    ) -> Result<AppendedLedgerEvent, BlockingSqliteError> {
        self.ledger.append(proof, &self.data, job, _file_op)
    }

    pub(crate) fn install_tombstone_blocking(
        &self,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) {
        if store::is_memory_world(world) {
            return;
        }
        self.read_cache.install_tombstone_blocking(world);
    }

    pub(crate) fn delete_world_now(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> bool {
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            self.mem.delete(memory_world)
        } else {
            world::delete(proof, &self.data, world, _file_op)
        }
    }

    pub(crate) fn cached_write_conn(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> rusqlite::Result<Arc<StdMutex<world::OpenedWriteConnection>>> {
        if let Some(conn) = self.write_conns.get(world) {
            let conn = conn.clone();
            verify_cached_writer_shape(proof, &conn)?;
            return Ok(conn);
        }
        let conn = world::open_cached_writer(proof, &self.data, world, _file_op)?;
        let conn = Arc::new(StdMutex::new(conn));
        let entry = self
            .write_conns
            .entry(world.clone())
            .or_insert_with(|| conn.clone())
            .clone();
        self.evict_cached_write_conn_if_needed(world);
        Ok(entry)
    }

    pub(crate) fn cached_existing_write_conn(
        &self,
        proof: &mut crate::blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) -> rusqlite::Result<Option<Arc<StdMutex<world::OpenedWriteConnection>>>> {
        if let Some(conn) = self.write_conns.get(world) {
            let conn = conn.clone();
            verify_cached_writer_shape(proof, &conn)?;
            return Ok(Some(conn));
        }
        let Some(conn) = world::open_existing_cached_writer(proof, &self.data, world, _file_op)?
        else {
            return Ok(None);
        };
        let conn = Arc::new(StdMutex::new(conn));
        let entry = self
            .write_conns
            .entry(world.clone())
            .or_insert_with(|| conn.clone())
            .clone();
        self.evict_cached_write_conn_if_needed(world);
        Ok(Some(entry))
    }

    pub(crate) fn clear_cached_write_conn(
        &self,
        world: &ValidatedWorldPath,
        _file_op: &FileOpPermit,
    ) {
        self.write_conns.remove(world);
    }

    pub(crate) fn drain_cached_file_handles(&self) {
        self.read_cache.drain_all_blocking();
        self.ledger.close();
        let conns: Vec<_> = self
            .write_conns
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        for (world, conn) in conns {
            let guard = conn.lock().unwrap_or_else(|poison| poison.into_inner());
            self.write_conns.remove(&world);
            drop(guard);
        }
    }

    pub(crate) fn shutdown_file_ops_and_drain(&self) {
        self.file_ops.shutdown_and_wait();
        self.drain_cached_file_handles();
    }

    fn evict_cached_write_conn_if_needed(&self, protected: &ValidatedWorldPath) {
        if self.write_conns.len() <= WRITE_CONN_CACHE_MAX_ENTRIES {
            return;
        }
        let victim = self
            .write_conns
            .iter()
            .find(|entry| entry.key() != protected)
            .map(|entry| entry.key().clone());
        if let Some(victim) = victim {
            self.write_conns.remove(&victim);
        }
    }

    pub(crate) fn notify_with_aux(
        &self,
        verb: crate::engine_types::ChangeVerb,
        target: ChangeTarget,
        etag: &str,
        aux: crate::event::ChangeEventAux,
    ) {
        let id = next_event_id(&self.next_event);
        let change = event::ChangeEvent::new_with_aux(
            id,
            self.listen_epoch.clone(),
            verb,
            target,
            etag.to_owned(),
            aux,
        );
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
    /// in a single CAS step. `new_len` includes current durable body bytes
    /// plus any candidate retained CAS body bytes for this write.
    /// Replaces the old "snapshot then write then
    /// adjust" pattern, which raced under per-world locking when two
    /// concurrent writes on different worlds both observed usage below
    /// quota and only afterwards pushed it past.
    ///
    /// Caller must hold `acquire_world_lock(world)` so that `prev_len`
    /// reflects the world's true current accounted length (cannot change
    /// underneath us). On success the global counter has already been
    /// updated; on success of the subsequent storage write, refund any
    /// pessimistically reserved CAS bytes that were already present. On
    /// failure of the storage write, call `rollback_storage_reservation` to
    /// credit back the whole reservation.
    ///
    /// `prev_len` is 0 for new worlds and for append (where the existing
    /// bytes stay and we only add `new_len` new).
    pub(crate) fn reserve_storage_after_prune(
        &self,
        prev_len: usize,
        new_len: usize,
        pruned_len: usize,
    ) -> Result<(), StorageReservationError> {
        if let Some(quota) = self.max_storage_bytes {
            let result = self.storage_body_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |used| {
                    let projected = used
                        .saturating_sub(prev_len)
                        .saturating_add(new_len)
                        .saturating_sub(pruned_len);
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
                    let projected = used
                        .saturating_sub(prev_len)
                        .saturating_add(new_len)
                        .saturating_sub(pruned_len);
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
                |used| {
                    Some(
                        used.saturating_sub(prev_len)
                            .saturating_add(new_len)
                            .saturating_sub(pruned_len),
                    )
                },
            );
            Ok(())
        }
    }

    /// Inverse of `reserve_storage`. Call when the reserved write
    /// subsequently fails so we credit the bytes back into available quota.
    pub(crate) fn rollback_storage_reservation(&self, prev_len: usize, new_len: usize) {
        self.rollback_storage_reservation_after_prune(prev_len, new_len, 0);
    }

    pub(crate) fn rollback_storage_reservation_after_prune(
        &self,
        prev_len: usize,
        new_len: usize,
        pruned_len: usize,
    ) {
        let _ =
            self.storage_body_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    Some(
                        used.saturating_sub(new_len)
                            .saturating_add(prev_len)
                            .saturating_add(pruned_len),
                    )
                });
    }

    pub(crate) fn note_current_body_replaced(&self, previous_len: usize, next_len: usize) {
        adjust_counter(&self.storage_current_body_bytes, previous_len, next_len);
    }

    pub(crate) fn note_retained_cas_inserted(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        adjust_counter(&self.storage_retained_cas_body_bytes, 0, bytes);
    }

    pub(crate) fn note_audit_events_appended(&self, events: usize) {
        if events == 0 {
            return;
        }
        adjust_counter(&self.storage_audit_chain_events, 0, events);
    }

    /// Credits bytes physically pruned from retained CAS storage after a
    /// successful write transaction commits. `reserve_storage_after_prune`
    /// already subtracted the predicted prune amount from the quota counter;
    /// this method credits only the extra total bytes while the retained-CAS
    /// gauge sees the full physical prune.
    pub(crate) fn credit_pruned_storage_after_estimate(
        &self,
        pruned: world::PrunedCas,
        estimated_pruned_len: usize,
    ) {
        let bytes = pruned.bytes();
        adjust_counter(&self.storage_retained_cas_body_bytes, bytes, 0);
        let extra = bytes.saturating_sub(estimated_pruned_len);
        if extra != 0 {
            adjust_counter(&self.storage_body_bytes, extra, 0);
        }
    }

    pub(crate) fn subtract_storage_usage(
        &self,
        world: &ValidatedWorldPath,
        usage: world::AccountedStorageUsage,
    ) -> Result<(), world::AccountedStorageUsageMismatch> {
        let usage = usage.into_snapshot_for(&self.data, world)?;
        adjust_counter(&self.storage_body_bytes, usage.total_body_bytes(), 0);
        adjust_counter(
            &self.storage_current_body_bytes,
            usage.current_body_bytes(),
            0,
        );
        adjust_counter(
            &self.storage_retained_cas_body_bytes,
            usage.retained_cas_body_bytes(),
            0,
        );
        adjust_counter(
            &self.storage_audit_chain_events,
            usage.audit_chain_events(),
            0,
        );
        Ok(())
    }

    #[cfg(test)]
    fn replace_storage_usage(
        &self,
        before: world::StorageUsageSnapshot,
        after: world::StorageUsageSnapshot,
    ) {
        adjust_counter(
            &self.storage_body_bytes,
            before.total_body_bytes(),
            after.total_body_bytes(),
        );
        adjust_counter(
            &self.storage_current_body_bytes,
            before.current_body_bytes(),
            after.current_body_bytes(),
        );
        adjust_counter(
            &self.storage_retained_cas_body_bytes,
            before.retained_cas_body_bytes(),
            after.retained_cas_body_bytes(),
        );
        adjust_counter(
            &self.storage_audit_chain_events,
            before.audit_chain_events(),
            after.audit_chain_events(),
        );
    }
}

fn verify_cached_writer_shape(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    conn: &StdMutex<world::OpenedWriteConnection>,
) -> rusqlite::Result<()> {
    let guard = conn
        .lock()
        .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
    guard.verify_shape(proof)
}

fn adjust_counter(counter: &AtomicUsize, subtract: usize, add: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
        Some(used.saturating_sub(subtract).saturating_add(add))
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use bytes::Bytes;

    use crate::{
        engine_types::{AuditHmacKey, ValidatedWorldPath},
        timeline::{BodySha256, TimelineAddress, TimelineRead, TimelineSeq},
        world, world_schema,
    };

    #[test]
    fn core_hmac_key_is_stored_as_audit_hmac_key() {
        let (core, dir) = crate::test_support::test_core("core-secret-key-type");

        fn assert_audit_hmac_key(_: &AuditHmacKey) {}
        assert_audit_hmac_key(&core.hmac_key);

        drop(core);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn core_timeline_body_read_uses_read_cache_tombstone_protocol() {
        let (core, dir) = crate::test_support::test_core("core-timeline-read-cache");
        let world = ValidatedWorldPath::new("home/timeline-cache").unwrap();

        world::write_with_audit_checked(
            &core.data,
            &world,
            b"old",
            "text/plain",
            &[("x-meta-version".to_owned(), "old".to_owned())],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit_checked(
            &core.data,
            &world,
            b"new",
            "application/octet-stream",
            &[("x-meta-version".to_owned(), "new".to_owned())],
            &core.hmac_key,
        )
        .unwrap();

        let conn = rusqlite::Connection::open(world::world_db(&core.data, world.as_str())).unwrap();
        let gen =
            world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &conn)
                .unwrap();
        drop(conn);
        let address = TimelineAddress::test_only_new(
            world.clone(),
            gen,
            TimelineSeq::new(2).unwrap(),
            BodySha256::for_body(b"old"),
        );

        let file_op = core.begin_file_op().unwrap();
        match core
            .read_timeline_body(
                &mut crate::blocking_sqlite::test_only_mint(),
                &address,
                &file_op,
            )
            .unwrap()
            .unwrap()
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
                assert_eq!(
                    body.representation().headers,
                    vec![("x-meta-version".to_owned(), "old".to_owned())]
                );
            }
            _ => panic!("expected retained historical body"),
        }

        core.install_tombstone(&world).await;
        let file_op = core.begin_file_op().unwrap();
        assert!(
            core.read_timeline_body(
                &mut crate::blocking_sqlite::test_only_mint(),
                &address,
                &file_op,
            )
            .unwrap()
            .is_none(),
            "timeline reads must route through the read-cache tombstone gate"
        );

        core.clear_tombstone(&world);
        let file_op = core.begin_file_op().unwrap();
        match core
            .read_timeline_body(
                &mut crate::blocking_sqlite::test_only_mint(),
                &address,
                &file_op,
            )
            .unwrap()
            .unwrap()
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
            }
            _ => panic!("expected retained historical body after tombstone clear"),
        }

        drop(core);
        std::fs::remove_dir_all(dir).ok();
    }
}
