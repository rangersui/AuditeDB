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

use crate::engine_types::{AuditHmacKey, ValidatedWorldPath};
use crate::ledger::LedgerWriter;
pub(crate) use crate::ledger::{AuditAppendJob, BlockingSqliteError};
use crate::read_cache::ReadCache;
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

#[cfg(target_has_atomic = "64")]
#[inline]
fn next_event_id(counter: &EventCounter) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

/// Newest event id this process has issued, or 0 before the first event.
///
/// Listen ids are process-local: the counter resets on every engine start.
/// A resume cursor greater than this value must come from another process
/// lifetime and cannot be used as a live-stream floor.
#[cfg(target_has_atomic = "64")]
#[inline]
pub(crate) fn last_issued_event_id(counter: &EventCounter) -> u64 {
    counter.load(Ordering::Relaxed)
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

/// Newest event id this process has issued, or 0 before the first event.
///
/// Listen ids are process-local: the counter resets on every engine start.
/// A resume cursor greater than this value must come from another process
/// lifetime and cannot be used as a live-stream floor.
#[cfg(not(target_has_atomic = "64"))]
#[inline]
pub(crate) fn last_issued_event_id(counter: &EventCounter) -> u64 {
    *counter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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

    pub(crate) fn read_world(&self, world: &ValidatedWorldPath) -> rusqlite::Result<Option<Stage>> {
        Ok(self.read_world_with_etag(world)?.map(|(stage, _)| stage))
    }

    /// Read body + meta + ETag. Routes durable worlds through the
    /// `read_cache` (slot-before-open, tombstone-aware) so repeated reads
    /// don't pay `Connection::open_with_flags` per operation. Memory
    /// worlds bypass the cache. Synchronous: the cache uses
    /// `std::sync::RwLock`, matching the existing handler call shape.
    pub(crate) fn read_world_with_etag(
        &self,
        world: &ValidatedWorldPath,
    ) -> rusqlite::Result<Option<(Stage, String)>> {
        let world_name = world.as_str();
        if store::is_memory_world(world_name) {
            Ok(self
                .mem
                .read_with_hash(world_name)
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

    /// Chain-head read through the read-cache SlotState protocol.
    /// Outer `None` = world DB missing (callers map to NotFound); inner
    /// `None` = empty bootstrap-shape chain (nothing to anchor). Memory
    /// worlds have no audit chain; callers filter those before reaching
    /// here, same as `cached_verify_chain`.
    pub(crate) fn cached_chain_head(
        &self,
        world: &ValidatedWorldPath,
    ) -> rusqlite::Result<Option<Option<(i64, String)>>> {
        debug_assert!(
            !store::is_memory_world(world.as_str()),
            "cached_chain_head only applies to durable worlds"
        );
        self.read_cache.cached_chain_head(&self.data, world)
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
        world: &ValidatedWorldPath,
    ) -> rusqlite::Result<Option<audit::VerifyReport>> {
        debug_assert!(
            !store::is_memory_world(world.as_str()),
            "cached_verify_chain only applies to durable worlds"
        );
        self.read_cache
            .cached_verify_chain(&self.data, world, &self.hmac_key)
    }

    /// Historical body read through the read-cache SlotState protocol.
    /// Durable timeline reads are fd-lifetime sensitive for the same reason
    /// ordinary reads and audit verifies are: delete must drain the cached
    /// connection before removing the world database.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_timeline_body(
        &self,
        address: &TimelineAddress,
    ) -> audit::AuditResult<Option<TimelineRead>> {
        debug_assert!(
            !store::is_memory_world(address.world().as_str()),
            "read_timeline_body only applies to durable worlds"
        );
        let read = self
            .read_cache
            .cached_read_timeline_body(&self.data, address, &self.hmac_key)
            .map_err(audit::AuditError::from)?;
        match read {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Delete-side final subject anchor through the read-cache SlotState
    /// protocol. Durable delete uses this before installing a tombstone so the
    /// delete ledger can identify the exact body event being removed.
    pub(crate) fn latest_body_head(
        &self,
        world: &ValidatedWorldPath,
    ) -> audit::AuditResult<Option<audit::VerifiedBodyHead>> {
        debug_assert!(
            !store::is_memory_world(world.as_str()),
            "latest_body_head only applies to durable worlds"
        );
        let head = self
            .read_cache
            .cached_latest_body_head(&self.data, world, &self.hmac_key)
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
    pub(crate) fn write_world(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) -> Result<(), world::WriteAuditError> {
        if store::is_memory_world(world) {
            self.mem.write(world, body, content_type, headers);
            Ok(())
        } else {
            let current_len = world::storage_len(&self.data, world)?;
            let world_path = ValidatedWorldPath::new(world).map_err(|_| {
                world::WriteAuditError::StorageInvariant("invalid fixture world path")
            })?;
            world::write_with_audit(
                &self.data,
                &world_path,
                body,
                content_type,
                headers,
                &self.hmac_key,
            )?;
            let prev = current_len.unwrap_or(0);
            let new_len = world::storage_len(&self.data, world)?.unwrap_or(0);
            let _ = self.storage_body_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |used| Some(used.saturating_sub(prev).saturating_add(new_len)),
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
        timeline_address: Option<TimelineAddress>,
    ) {
        let id = next_event_id(&self.next_event);
        let change = event::ChangeEvent {
            id,
            verb,
            path: format!("/{}", world.as_str()),
            etag: etag.to_owned(),
            timeline_address,
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

#[cfg(test)]
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
        let gen = world_schema::generation(&conn).unwrap();
        drop(conn);
        let address = TimelineAddress::test_only_new(
            world.clone(),
            gen,
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"old"),
        );

        match core.read_timeline_body(&address).unwrap().unwrap() {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
                assert_eq!(
                    body.representation().headers,
                    vec![("x-meta-version".to_owned(), "old".to_owned())]
                );
            }
            _ => panic!("expected retained historical body"),
        }

        core.install_tombstone(world.as_str()).await;
        assert!(
            core.read_timeline_body(&address).unwrap().is_none(),
            "timeline reads must route through the read-cache tombstone gate"
        );

        core.clear_tombstone(world.as_str());
        match core.read_timeline_body(&address).unwrap().unwrap() {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
            }
            _ => panic!("expected retained historical body after tombstone clear"),
        }

        drop(core);
        std::fs::remove_dir_all(dir).ok();
    }
}
