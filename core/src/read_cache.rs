//! Per-world read connection cache.
//!
//! Caches one open SQLite connection per recently-read world so repeated
//! reads don't re-pay the ~456-700us `Connection::open_with_flags`
//! cost on every operation. The naive approach -- `DashMap<String,
//! Mutex<Connection>>` -- has a race: delete removes the map entry,
//! but in-flight readers holding cloned Arcs continue using their
//! cached fd. Linux gets an orphan inode (harmless); Windows fails
//! the unlink with sharing-violation.
//!
//! This module is the v7.1 design distilled from ten review rounds
//! (see `docs/architecture/sqlite-connection-pool.md`). The
//! invariants encoded here:
//!
//! 1. **Slot-before-open** -- a reader reserves a slot in
//!    `SlotState::Opening` via the DashMap Entry API BEFORE calling
//!    `Connection::open_with_flags`, and holds the slot's
//!    `inner.write()` guard for the duration of the open. Delete's
//!    drain blocks behind that guard. fd lifetime is tracked by the
//!    synchronization primitive, not by chance.
//! 2. **Tombstone protocol** -- delete replaces the slot's state with
//!    `Tombstone` inside the write guard window, so the previous
//!    `Ready(Mutex<Connection>)`'s Connection drops INSIDE the guard.
//!    No fd is alive when `delete_world_blocking` runs.
//! 3. **Drain before remove** -- at-cap "transient" slots (cap reached,
//!    we install a slot for one read and then remove it) drain the
//!    slot before removing -- `arc.inner.write()` waits for any
//!    Phase-1-cache-hit clones to release their read guards, then
//!    `mem::replace` Evicted closes the fd. `Evicted` is not a
//!    404/tombstone signal: concurrent readers retry through the
//!    miss/open path because the world may still exist. The map entry
//!    is then safe to remove. See AGENTS.md section "Drain before
//!    remove."
//! 4. **Type-system enforcement** -- `TrackedReadConnection` wraps
//!    `rusqlite::Connection`. Its constructor (`from_raw`) is
//!    module-private and called only from `OpeningTransition::promote`.
//!    Read functions in `world.rs` consume `&mut TrackedReadConnection`,
//!    so opening a bare `Connection` and reading through it is a
//!    type error. See AGENTS.md section "Physics, not policy."
//!
//! Sync vs async -- the cache uses `std::sync::RwLock` so the read
//! path stays sync and matches the existing
//! `Core::read_world_with_etag` signature (no caller churn). Callers
//! that need to install a tombstone wrap `install_tombstone_blocking`
//! in `tokio::task::spawn_blocking` so the drain doesn't stall a
//! Tokio worker (the same pattern delete already uses for
//! `delete_world_blocking`).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use dashmap::DashMap;
use rusqlite::{ffi::ErrorCode, Connection, OpenFlags};

use crate::{world, world_schema};

/// Default ceiling on the number of cached read slots. Per-conn
/// memory is bounded to ~250KB (PRAGMA cache_size=-200), so 5000
/// caps resident at ~1.25 GB. Embedders with larger working sets can
/// raise this through `EngineBuilder::read_cache_max_entries`.
#[cfg(test)]
pub(crate) const DEFAULT_READ_CACHE_MAX_ENTRIES: usize = 5000;

/// SQLite busy_timeout for cached read connections. Tighter than
/// the 5000ms `world::open` default because queued readers under
/// writer contention compound the deadline; a per-conn 1000ms keeps
/// the Mutex-queue tail bounded.
const READ_CONN_BUSY_TIMEOUT_MS: u64 = 1000;

/// Approximate-LRU sample size.
///
/// We deliberately avoid exact LRU: no global linked list, no per-hit lock, no
/// cache-wide ordering structure. On cap-full misses we inspect a small sample,
/// try the oldest evictable slot first, and fall back to a transient read when
/// no candidate can be drained safely.
///
/// Current sampling is deliberately cheap: a rotating offset over DashMap's
/// bucket-order iterator, not a random sample. That avoids pinning eviction to
/// the same prefix forever while keeping correctness tied to the transient-read
/// fallback and the drain-before-remove safety gate.
const READ_CACHE_EVICTION_SAMPLE_SIZE: usize = 8;

/// Defensive cap on internal retry loops.
///
/// Normal reads should converge in one or two passes. This budget is only a
/// fail-safe for future state-machine regressions or extreme contention: when
/// it fires, tracked reads degrade to the safe transient path rather than
/// spinning. Transient reads return a SQLite BUSY error if their own retry
/// budget is exhausted.
const READ_CACHE_RETRY_BUDGET: usize = 16;

fn log_read_cache_retry_budget_exhausted(world: &str, mode: &str) {
    #[cfg(feature = "unstable-engine")]
    tracing::warn!(
        world,
        mode,
        "read cache retry budget exhausted; falling back"
    );

    #[cfg(not(feature = "unstable-engine"))]
    eprintln!("elastik-core internal read cache {mode} retry budget exhausted for {world}");
}

fn read_cache_retry_budget_error(world: &str, mode: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        Some(format!(
            "read cache {mode} retry budget exhausted for {world}"
        )),
    )
}

fn open_verified_read_conn(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    c.busy_timeout(Duration::from_millis(READ_CONN_BUSY_TIMEOUT_MS))?;
    c.pragma_update(None, "cache_size", -200)?;
    world_schema::verify(&c)?;
    Ok(c)
}

/// Newtype around `rusqlite::Connection` that gates read access at
/// the type level. The only constructor (`from_raw`) is reachable
/// solely from `OpeningTransition::promote` below -- no other code
/// in the crate can mint one. `world::read_with_hmac_via_conn`
/// consumes `&mut TrackedReadConnection`, which means the bypass
/// "open a Connection and run the SQL on it" doesn't compile.
///
/// See AGENTS.md section "Physics, not policy."
pub(crate) struct TrackedReadConnection(Connection);

#[cfg_attr(not(test), allow(dead_code))]
type TimelineReadResult = crate::audit::AuditResult<crate::timeline::TimelineRead>;

impl TrackedReadConnection {
    /// Module-private constructor. The only call site in the crate
    /// is `OpeningTransition::promote`. Intentionally not exposed
    /// outside this file.
    fn from_raw(conn: Connection) -> Self {
        Self(conn)
    }

    /// Mutable access to the wrapped Connection for the SQL body of
    /// `world::read_with_hmac_via_conn`. `pub(crate)` -- callers must
    /// already hold a `&mut TrackedReadConnection`, and the only
    /// path to that is through `read_via_slot`. Future `world.rs`
    /// read helpers must also take `&mut TrackedReadConnection` to
    /// preserve the type gate.
    pub(crate) fn as_mut_conn(&mut self) -> &mut Connection {
        &mut self.0
    }

    fn verify_schema(&self) -> rusqlite::Result<()> {
        world_schema::verify(&self.0)
    }
}

/// Per-world read slot lifecycle state.
///
/// Visibility note (Codex P1): no `pub` modifier -- module-private.
/// Sibling modules cannot construct `SlotState::Opening` and feed
/// it through `OpeningTransition::promote` to mint a
/// `TrackedReadConnection`. The bypass that an earlier draft of this
/// PR allowed is now uncompilable from outside `read_cache.rs`.
enum SlotState {
    Opening,
    Ready(StdMutex<TrackedReadConnection>),
    /// Cache eviction marker.
    ///
    /// Unlike `Tombstone`, this is not a delete semantic. A reader that sees
    /// `Evicted` must retry through the miss/open path rather than returning
    /// `Ok(None)`, because the world may still exist on disk.
    Evicted,
    Tombstone,
}

/// Result envelope from a slot probe.
///
/// `Done(None)` is a definitive cache answer (currently Tombstone only).
/// `Opening` and `Evicted` are retry signals, not absence: the world may exist
/// on disk or become Ready once the owner finishes opening the connection.
/// Production inserts take the slot's write guard before publishing `Opening`,
/// so external readers should block until a final state is visible. The
/// `Opening` variant is a defensive backstop for white-box tests and future
/// state-machine regressions.
#[cfg_attr(test, derive(Debug))]
enum SlotRead<R> {
    Done(Option<R>),
    Opening,
    Evicted,
}

/// Same module-private treatment -- `Arc<ReadSlot>` is held inside
/// `ReadCache.read_conns` (a private field), and there is no public
/// API that exposes the inner `RwLock<SlotState>` to callers.
struct ReadSlot {
    inner: StdRwLock<SlotState>,
    /// Monotonic access tick used as an approximate-LRU hint.
    ///
    /// This is not a synchronization primitive. `Relaxed` reads/writes are
    /// enough because eviction will treat it as a best-effort ordering signal,
    /// never as proof that a slot is safe to remove. The safety proof is still
    /// `try_evict_ready_slot`: take the write guard, require Ready, replace
    /// with Evicted, then remove the same Arc from the map.
    last_access: AtomicU64,
}

/// RAII guard for the Opening -> Ready/Tombstone transition. Without
/// it, a panic during `Connection::open`, `busy_timeout`, or
/// `pragma_update` would leave the slot stuck in `Opening`.
///
/// Visibility (Codex P1): no `pub` modifier. The whole point of v10
/// is that `OpeningTransition::promote` is the only call site for
/// `TrackedReadConnection::from_raw`; if `OpeningTransition::new`
/// itself were `pub(crate)`, sibling modules could chain
/// `OpeningTransition::new(&mut SlotState::Opening).promote(c)` and
/// the type seal would be "ugly to write" rather than uncompilable.
struct OpeningTransition<'a> {
    state: &'a mut SlotState,
    finalized: bool,
}

impl<'a> OpeningTransition<'a> {
    fn new(state: &'a mut SlotState) -> Self {
        Self {
            state,
            finalized: false,
        }
    }

    /// Open succeeded. Wrap the connection (the ONLY
    /// `TrackedReadConnection::from_raw` call site in the crate).
    fn promote(mut self, conn: Connection) {
        let tracked = TrackedReadConnection::from_raw(conn);
        *self.state = SlotState::Ready(StdMutex::new(tracked));
        self.finalized = true;
    }

    fn fail(mut self) {
        *self.state = SlotState::Tombstone;
        self.finalized = true;
    }
}

impl<'a> Drop for OpeningTransition<'a> {
    fn drop(&mut self) {
        if !self.finalized {
            *self.state = SlotState::Tombstone;
        }
    }
}

/// Test-only constructor for `TrackedReadConnection`. Available
/// to other modules' `#[cfg(test)]` blocks (notably the schema-
/// corruption test in `world.rs`) so a raw `Connection` can be
/// wrapped without going through `OpeningTransition::promote`.
///
/// `pub(crate)` ONLY under `#[cfg(test)]`. In production builds
/// this function does not exist; the only path to a
/// `TrackedReadConnection` remains `OpeningTransition::promote`.
/// The function name is deliberately verbose so any future call
/// site is self-documenting as a test bypass.
///
/// See AGENTS.md section "Physics, not policy" -- production code path
/// has zero bypasses; test code is allowed a single, named
/// bypass that lives in `cfg(test)`.
#[cfg(test)]
pub(crate) fn test_only_wrap_raw_connection(conn: Connection) -> TrackedReadConnection {
    TrackedReadConnection::from_raw(conn)
}

/// Atomic counters for /proc/pool.
#[derive(Default)]
pub(crate) struct ReadCacheMetrics {
    pub(crate) read_cache_hits: AtomicUsize,
    pub(crate) read_cache_misses: AtomicUsize,
    pub(crate) read_cache_capped: AtomicUsize,
    pub(crate) read_cache_evictions: AtomicUsize,
    pub(crate) read_cache_open_fails: AtomicUsize,
}

/// Per-world read connection cache.
///
/// Visibility (Codex P1): `read_conns` is module-private. The slot
/// state machine is internal -- all mutations go through this
/// module's methods (`cached_read_with_hmac`, `read_transient`,
/// `install_tombstone_blocking`, `clear_tombstone`). Two
/// `pub(crate)` accessors (`max_entries` for /proc/pool's display;
/// `metrics` for /proc/pool's atomic reads) expose just the
/// observability surface -- never the slots themselves.
pub(crate) struct ReadCache {
    read_conns: DashMap<String, Arc<ReadSlot>>,
    /// Cache-global monotonic recency clock.
    ///
    /// This stays `AtomicU64` even though it is an internal hint. A 32-bit
    /// counter can wrap within weeks under sustained reads and invert the
    /// approximate-LRU ordering; a 64-bit clock makes wraparound irrelevant for
    /// practical deployments.
    access_clock: AtomicU64,
    /// Rotating cursor for approximate-LRU sampling.
    ///
    /// DashMap iteration is bucket ordered. A cursor keeps cap-full misses from
    /// repeatedly sampling the same prefix while still avoiding a cache-wide
    /// ordering structure.
    eviction_cursor: AtomicUsize,
    pub(crate) max_entries: usize,
    pub(crate) metrics: ReadCacheMetrics,
}

impl ReadCache {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            read_conns: DashMap::new(),
            access_clock: AtomicU64::new(0),
            eviction_cursor: AtomicUsize::new(0),
            max_entries,
            metrics: ReadCacheMetrics::default(),
        }
    }

    fn new_slot(&self, state: SlotState) -> Arc<ReadSlot> {
        Arc::new(ReadSlot {
            inner: StdRwLock::new(state),
            last_access: AtomicU64::new(self.next_access_tick()),
        })
    }

    fn next_access_tick(&self) -> u64 {
        self.access_clock.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn touch_slot(&self, slot: &ReadSlot) {
        slot.last_access
            .store(self.next_access_tick(), Ordering::Relaxed);
    }

    fn remove_evicted_entry(&self, world: &str, arc: &Arc<ReadSlot>) -> bool {
        self.read_conns
            .remove_if(world, |_k, v| Arc::ptr_eq(v, arc))
            .is_some()
    }

    /// Best-effort eviction primitive for cap-full misses.
    ///
    /// This is the safety gate. `last_access` only chooses candidates; a slot
    /// is actually evicted only if this method proves no reader holds the slot
    /// guard, replaces Ready with Evicted, and removes the same Arc from the
    /// map. If `remove_if` loses a race to a replacement entry, the stale Arc is
    /// drained but the eviction is not reported as successful.
    fn try_evict_ready_slot(&self, world: &str, arc: &Arc<ReadSlot>) -> bool {
        let Ok(mut guard) = arc.inner.try_write() else {
            return false;
        };
        if !matches!(&*guard, SlotState::Ready(_)) {
            return false;
        }
        let old = std::mem::replace(&mut *guard, SlotState::Evicted);
        drop(old);
        drop(guard);
        self.remove_evicted_entry(world, arc)
    }

    /// Try to evict the oldest Ready slot from a small rotating sample.
    ///
    /// `target_world` is excluded so we do not evict the world this external
    /// read is trying to obtain; a concurrent installer may have placed it in
    /// cache between our Phase 1 miss and this sample. Candidate order is only
    /// a quality hint; actual safety is delegated to
    /// `try_evict_ready_slot`.
    fn try_evict_oldest_sample(&self, target_world: &str) -> bool {
        let len = self.read_conns.len();
        if len == 0 {
            return false;
        }
        let start = self
            .eviction_cursor
            .fetch_add(READ_CACHE_EVICTION_SAMPLE_SIZE, Ordering::Relaxed)
            % len;
        let mut candidates = Vec::with_capacity(READ_CACHE_EVICTION_SAMPLE_SIZE);
        for entry in self.read_conns.iter().skip(start) {
            if candidates.len() >= READ_CACHE_EVICTION_SAMPLE_SIZE {
                break;
            }
            if entry.key().as_str() == target_world {
                continue;
            }
            let slot = entry.value().clone();
            candidates.push((
                entry.key().clone(),
                slot.last_access.load(Ordering::Relaxed),
                slot,
            ));
        }
        if candidates.len() < READ_CACHE_EVICTION_SAMPLE_SIZE && start > 0 {
            for entry in self.read_conns.iter().take(start) {
                if candidates.len() >= READ_CACHE_EVICTION_SAMPLE_SIZE {
                    break;
                }
                if entry.key().as_str() == target_world {
                    continue;
                }
                let slot = entry.value().clone();
                candidates.push((
                    entry.key().clone(),
                    slot.last_access.load(Ordering::Relaxed),
                    slot,
                ));
            }
        }
        candidates.sort_by_key(|(_world, last_access, _slot)| *last_access);

        for (world, _last_access, slot) in candidates {
            if self.try_evict_ready_slot(&world, &slot) {
                self.metrics
                    .read_cache_evictions
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Best-effort trim for temporary overshoot caused by concurrent misses.
    ///
    /// The pre-insert cap check prevents ordinary growth, but multiple readers
    /// can all observe room and publish slots concurrently. Trimming after a
    /// successful read keeps the cache close to its cap without blocking the
    /// read on a global reservation lock.
    fn best_effort_trim_over_cap(&self, target_world: &str) {
        for _ in 0..READ_CACHE_RETRY_BUDGET {
            if self.read_conns.len() <= self.max_entries {
                return;
            }
            if !self.try_evict_oldest_sample(target_world) {
                return;
            }
        }
    }

    /// Read body + meta + latest hmac via the cached read path.
    /// Thin wrapper over the generic `with_tracked_conn` machinery.
    pub(crate) fn cached_read_with_hmac(
        &self,
        data: &std::path::Path,
        world: &str,
    ) -> rusqlite::Result<Option<(world::Stage, Option<String>)>> {
        self.with_tracked_conn(data, world, world::read_with_hmac_via_conn)
    }

    /// O(1) chain-head read through the cached read path. Same
    /// SlotState protocol as `cached_verify_chain` -- delete drains
    /// in-flight head reads via the slot's write guard. Outer `None`
    /// means the world's DB is missing; inner `None` means the chain
    /// is empty (bootstrap shape).
    pub(crate) fn cached_chain_head(
        &self,
        data: &std::path::Path,
        world: &str,
    ) -> rusqlite::Result<Option<Option<(i64, String)>>> {
        self.with_tracked_conn(data, world, crate::audit::chain_head_via_conn)
    }

    /// Verify the audit chain through the cached read path (Bug 58).
    /// Same SlotState protocol as `cached_read_with_hmac` -- delete
    /// drains in-flight verifies via the slot's write guard. Closes
    /// the v10 type-gate gap on the admin
    /// `/proc/audit/{world}/verify` endpoint.
    pub(crate) fn cached_verify_chain(
        &self,
        data: &std::path::Path,
        world: &str,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<crate::audit::VerifyReport>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            crate::audit::verify_chain_via_conn(conn, world, &key)
        })
    }

    /// Historical body read through the cached read path. Same SlotState
    /// protocol as ordinary cached reads: delete drains in-flight timeline
    /// reads before unlinking the world database, and a tombstone produces
    /// `Ok(None)` rather than opening a new fd.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cached_read_timeline_body(
        &self,
        data: &std::path::Path,
        address: &crate::timeline::TimelineAddress,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<TimelineReadResult>> {
        let world = address.world().as_str();
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::read_timeline_body_via_conn(
                conn, address, &key,
            ))
        })
    }

    /// Run a closure with a `&mut TrackedReadConnection` obtained
    /// through the SlotState protocol. Three-phase split:
    ///   1. Cache hit (any state, regardless of cap)
    ///   2. Cache miss + cap reached -> approximate eviction, or transient
    ///   3. Cache miss + room -> slot-before-open lazy-init
    ///
    /// `Ok(None)` means the world's DB is missing (404). `Err(_)`
    /// is propagated for real storage errors. The closure runs at
    /// most once and returns its own `rusqlite::Result<R>`.
    fn with_tracked_conn<F, R>(
        &self,
        data: &std::path::Path,
        world: &str,
        f: F,
    ) -> rusqlite::Result<Option<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        let path = world::world_db(data, world);
        let mut f = Some(f);
        let mut counted_miss = false;
        let mut counted_capped = false;

        for _ in 0..READ_CACHE_RETRY_BUDGET {
            // PHASE 1 -- Cache hit (any state).
            if let Some(arc) = self.read_conns.get(world).map(|e| e.value().clone()) {
                self.touch_slot(&arc);
                match self.invoke_via_slot(arc.clone(), &mut f)? {
                    SlotRead::Done(value) => {
                        self.best_effort_trim_over_cap(world);
                        self.metrics.read_cache_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(value);
                    }
                    SlotRead::Opening => continue,
                    SlotRead::Evicted => {
                        self.remove_evicted_entry(world, &arc);
                        continue;
                    }
                }
            }

            if !counted_miss {
                self.metrics
                    .read_cache_misses
                    .fetch_add(1, Ordering::Relaxed);
                counted_miss = true;
            }

            // PHASE 2 -- Cache miss + cap reached: approximate eviction, or
            // transient tracked slot fallback.
            if self.read_conns.len() >= self.max_entries {
                if !counted_capped {
                    self.metrics
                        .read_cache_capped
                        .fetch_add(1, Ordering::Relaxed);
                    counted_capped = true;
                }
                if self.try_evict_oldest_sample(world) {
                    continue;
                }
                return self.invoke_transient(&path, world, f.take().expect("read closure"));
            }

            // PHASE 3 -- Cache miss + room: slot-before-open lazy-init.
            match path.try_exists() {
                Ok(false) => return Ok(None),
                Ok(true) => {}
                Err(_) => {
                    // Defer to the open: if metadata is unreadable, the
                    // open itself will surface the actual error.
                }
            }

            let new_slot = self.new_slot(SlotState::Opening);
            // Cache the pointer up front so we can compare after the
            // `or_insert_with` closure moves `insert_slot` into DashMap.
            // Equivalent to `Arc::ptr_eq(&arc, &new_slot)`.
            let new_slot_ptr = Arc::as_ptr(&new_slot);
            let insert_slot = new_slot.clone();
            // Take the write guard before publishing the Opening slot. Any
            // racing reader that sees our slot will block until it is Ready,
            // Tombstone, or Evicted instead of observing Opening as absence.
            let new_guard = new_slot.inner.write().unwrap_or_else(|p| p.into_inner());
            let arc = self
                .read_conns
                .entry(world.to_string())
                .or_insert_with(move || insert_slot)
                .value()
                .clone();
            let we_own_slot = Arc::as_ptr(&arc) == new_slot_ptr;

            if we_own_slot {
                let mut g = new_guard;
                if matches!(&*g, SlotState::Opening) {
                    let transition = OpeningTransition::new(&mut g);
                    let init = open_verified_read_conn(&path);
                    match init {
                        Ok(c) => transition.promote(c),
                        Err(e) => {
                            transition.fail();
                            drop(g);
                            self.read_conns
                                .remove_if(world, |_k, v| Arc::ptr_eq(v, &arc));
                            self.metrics
                                .read_cache_open_fails
                                .fetch_add(1, Ordering::Relaxed);
                            if matches!(e.sqlite_error_code(), Some(ErrorCode::CannotOpen))
                                && matches!(path.try_exists(), Ok(false))
                            {
                                return Ok(None);
                            }
                            return Err(e);
                        }
                    }
                }
            } else {
                drop(new_guard);
            }

            self.touch_slot(&arc);
            match self.invoke_via_slot(arc.clone(), &mut f)? {
                SlotRead::Done(value) => {
                    self.best_effort_trim_over_cap(world);
                    return Ok(value);
                }
                SlotRead::Opening => {}
                SlotRead::Evicted => {
                    self.remove_evicted_entry(world, &arc);
                }
            }
        }

        log_read_cache_retry_budget_exhausted(world, "tracked");
        self.invoke_transient(
            &path,
            world,
            f.take().expect(
                "read cache retry budget exhausted with no closure; \
                 SlotRead::Done should have returned before budget fallback",
            ),
        )
    }

    fn invoke_transient<F, R>(
        &self,
        path: &std::path::Path,
        world: &str,
        f: F,
    ) -> rusqlite::Result<Option<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        let mut f = Some(f);
        for _ in 0..READ_CACHE_RETRY_BUDGET {
            // Fast-path: slot already exists (concurrent reader installed
            // one, delete installed a tombstone, or eviction has not removed
            // the map entry yet).
            if let Some(arc) = self.read_conns.get(world).map(|e| e.value().clone()) {
                self.touch_slot(&arc);
                match self.invoke_via_slot(arc.clone(), &mut f)? {
                    SlotRead::Done(value) => {
                        self.best_effort_trim_over_cap(world);
                        return Ok(value);
                    }
                    SlotRead::Opening => continue,
                    SlotRead::Evicted => {
                        self.remove_evicted_entry(world, &arc);
                        continue;
                    }
                }
            }

            let transient_slot = self.new_slot(SlotState::Opening);
            // Cache the pointer up front so we can compare after the
            // `or_insert_with` closure moves `insert_slot` into DashMap.
            // Equivalent to `Arc::ptr_eq(&arc, &transient_slot)`.
            let transient_slot_ptr = Arc::as_ptr(&transient_slot);
            let insert_slot = transient_slot.clone();
            // Publish Opening only after its write guard is held; otherwise a
            // racing reader can see Opening and mistake "not ready yet" for
            // absence.
            let new_guard = transient_slot
                .inner
                .write()
                .unwrap_or_else(|p| p.into_inner());
            let arc = self
                .read_conns
                .entry(world.to_string())
                .or_insert_with(move || insert_slot)
                .value()
                .clone();
            let we_own_slot = Arc::as_ptr(&arc) == transient_slot_ptr;

            if we_own_slot {
                let mut g = new_guard;
                if matches!(&*g, SlotState::Opening) {
                    let transition = OpeningTransition::new(&mut g);
                    let init = open_verified_read_conn(path);
                    match init {
                        Ok(c) => transition.promote(c),
                        Err(e) => {
                            transition.fail();
                            drop(g);
                            self.read_conns
                                .remove_if(world, |_k, v| Arc::ptr_eq(v, &arc));
                            self.metrics
                                .read_cache_open_fails
                                .fetch_add(1, Ordering::Relaxed);
                            if matches!(e.sqlite_error_code(), Some(ErrorCode::CannotOpen))
                                && matches!(path.try_exists(), Ok(false))
                            {
                                return Ok(None);
                            }
                            return Err(e);
                        }
                    }
                }
            } else {
                drop(new_guard);
            }

            self.touch_slot(&arc);
            let result = match self.invoke_via_slot(arc.clone(), &mut f)? {
                SlotRead::Done(value) => Ok(value),
                SlotRead::Opening => continue,
                SlotRead::Evicted => {
                    self.remove_evicted_entry(world, &arc);
                    continue;
                }
            };

            // Drain-before-remove (Bug 54, tightened by #138): write guard,
            // mem::replace Evicted (drops Connection inside guard window --
            // fd close happens here), drop guard, then remove_if. Evicted is
            // deliberately not Tombstone: concurrent readers must retry and
            // reopen an existing world rather than returning a spurious 404.
            if we_own_slot {
                {
                    let mut g = arc.inner.write().unwrap_or_else(|p| p.into_inner());
                    let old = std::mem::replace(&mut *g, SlotState::Evicted);
                    drop(old);
                    drop(g);
                }
                self.read_conns
                    .remove_if(world, |_k, v| Arc::ptr_eq(v, &arc));
            }
            self.best_effort_trim_over_cap(world);
            return result;
        }

        log_read_cache_retry_budget_exhausted(world, "transient");
        Err(read_cache_retry_budget_error(world, "transient"))
    }

    fn invoke_via_slot<F, R>(
        &self,
        arc: Arc<ReadSlot>,
        f: &mut Option<F>,
    ) -> rusqlite::Result<SlotRead<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        let read_guard = arc.inner.read().unwrap_or_else(|p| p.into_inner());
        match &*read_guard {
            SlotState::Ready(tracked_mutex) => {
                let mut tracked = tracked_mutex.lock().unwrap_or_else(|p| p.into_inner());
                tracked.verify_schema()?;
                let f = f.take().expect(
                    "invoke_via_slot closure slot is empty; SlotRead::Opening \
                     and SlotRead::Evicted may re-enter with the closure intact, \
                     and SlotRead::Done must return immediately",
                );
                f(&mut tracked).map(|value| SlotRead::Done(Some(value)))
            }
            SlotState::Tombstone => Ok(SlotRead::Done(None)),
            SlotState::Opening => Ok(SlotRead::Opening),
            SlotState::Evicted => Ok(SlotRead::Evicted),
        }
    }

    /// Sync version. delete callers wrap this in `spawn_blocking` so
    /// the drain wait doesn't stall a Tokio worker.
    pub(crate) fn install_tombstone_blocking(&self, world: &str) {
        let new_tombstone = self.new_slot(SlotState::Tombstone);
        let prev = self.read_conns.insert(world.to_string(), new_tombstone);
        if let Some(prev_slot) = prev {
            let mut g = prev_slot.inner.write().unwrap_or_else(|p| p.into_inner());
            let old = std::mem::replace(&mut *g, SlotState::Tombstone);
            drop(old);
            drop(g);
        }
    }

    /// Remove the tombstone after `delete_world_blocking` returns.
    /// Called on BOTH success and failure (Bug 20): on failure, the
    /// world is still on disk; the next read should lazy-init a
    /// fresh slot rather than seeing a phantom 404.
    pub(crate) fn clear_tombstone(&self, world: &str) {
        self.read_conns.remove(world);
    }

    /// Snapshot accessor for `/proc/pool`; exposes count only, never slots.
    pub(crate) fn snapshot_entries(&self) -> usize {
        self.read_conns.len()
    }

    /// Snapshot accessor for pool introspection; tombstones are delete state, not
    /// eviction candidates.
    pub(crate) fn snapshot_tombstones(&self) -> usize {
        self.read_conns
            .iter()
            .filter(|e| {
                e.value()
                    .inner
                    .try_read()
                    .map(|g| matches!(*g, SlotState::Tombstone))
                    .unwrap_or(false)
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_key() -> crate::engine_types::AuditHmacKey {
        crate::engine_types::AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY)
            .unwrap()
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!(
            "elastik-readcache-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn cache_hit_on_second_read() {
        let dir = scratch_dir("hit");
        let world = "home/cache-hit";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"hello", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);

        let r1 = cache.cached_read_with_hmac(&dir, world).unwrap();
        assert!(r1.is_some());
        assert_eq!(cache.metrics.read_cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(cache.metrics.read_cache_misses.load(Ordering::Relaxed), 1);

        let r2 = cache.cached_read_with_hmac(&dir, world).unwrap();
        assert!(r2.is_some());
        assert_eq!(cache.metrics.read_cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.metrics.read_cache_misses.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn create_legacy_world_without_generation(data_root: &std::path::Path, world: &str) {
        std::fs::create_dir_all(world::world_dir(data_root, world)).unwrap();
        let c = Connection::open(world::world_db(data_root, world)).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, body) VALUES(1, x'');
            CREATE TABLE meta_headers(
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY(name)
            );
            CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT DEFAULT '',
                body_sha256 TEXT DEFAULT '',
                size INTEGER DEFAULT 0,
                content_type TEXT DEFAULT '',
                meta_sha256 TEXT DEFAULT '',
                hmac TEXT NOT NULL,
                prev_hmac TEXT DEFAULT ''
            );
            CREATE TABLE event_headers(
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
    }

    fn drop_generation_column_from_cached_world(data_root: &std::path::Path, world: &str) {
        let c = Connection::open(world::world_db(data_root, world)).unwrap();
        c.execute_batch(
            r#"
            ALTER TABLE stage_meta RENAME TO stage_meta_with_generation;
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, body, content_type)
                SELECT id, body, content_type FROM stage_meta_with_generation;
            DROP TABLE stage_meta_with_generation;
            "#,
        )
        .unwrap();
    }

    #[test]
    fn cache_open_rejects_legacy_stage_meta_without_generation() {
        let dir = scratch_dir("legacy-generation-read-cache");
        create_legacy_world_without_generation(&dir, "home/legacy");
        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);

        let err = match cache.cached_read_with_hmac(&dir, "home/legacy") {
            Ok(_) => panic!("legacy schema must fail before read-cache promotion"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("stage_meta.generation"));
        assert!(cache.read_conns.get("home/legacy").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_revalidates_generation_before_read() {
        let dir = scratch_dir("generation-regression-cache-hit");
        let world = "home/cached";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"hello", "text/plain", &[]).unwrap();
        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);

        assert!(cache.cached_read_with_hmac(&dir, world).unwrap().is_some());
        drop_generation_column_from_cached_world(&dir, world);

        let err = match cache.cached_read_with_hmac(&dir, world) {
            Ok(_) => panic!("cached read must revalidate stage_meta.generation"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("stage_meta.generation"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_updates_last_access_tick() {
        let dir = scratch_dir("last-access");
        for w in ["home/a", "home/b"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"hello", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let a_first = cache
            .read_conns
            .get("home/a")
            .unwrap()
            .last_access
            .load(Ordering::Relaxed);

        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        let b_first = cache
            .read_conns
            .get("home/b")
            .unwrap()
            .last_access
            .load(Ordering::Relaxed);
        assert!(
            b_first > a_first,
            "later insert should receive a newer access tick"
        );

        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let a_second = cache
            .read_conns
            .get("home/a")
            .unwrap()
            .last_access
            .load(Ordering::Relaxed);
        assert!(
            a_second > b_first,
            "cache hit should refresh approximate-LRU recency"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_world_returns_none_via_phase3() {
        let dir = scratch_dir("missing");
        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let r = cache.cached_read_with_hmac(&dir, "home/none").unwrap();
        assert!(r.is_none());
        assert!(cache.read_conns.get("home/none").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_tombstone_short_circuits_read_to_404() {
        let dir = scratch_dir("tombstone");
        let world = "home/tomb";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"x", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let _ = cache.cached_read_with_hmac(&dir, world).unwrap();
        cache.install_tombstone_blocking(world);
        let r = cache.cached_read_with_hmac(&dir, world).unwrap();
        assert!(r.is_none());

        cache.clear_tombstone(world);
        let r2 = cache.cached_read_with_hmac(&dir, world).unwrap();
        assert!(r2.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_full_miss_evicts_cold_slot_and_caches_new_world() {
        let dir = scratch_dir("cap-evict");
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        assert_eq!(cache.read_conns.len(), 2);
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 0);

        let r = cache.cached_read_with_hmac(&dir, "home/c").unwrap();
        assert!(r.is_some());
        assert!(
            cache.read_conns.get("home/a").is_none(),
            "oldest sampled slot should be evicted"
        );
        assert!(cache.read_conns.get("home/b").is_some());
        assert!(cache.read_conns.get("home/c").is_some());
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache.metrics.read_cache_misses.load(Ordering::Relaxed),
            3,
            "A, B, and C are three external cache misses; eviction retry must not double-count C"
        );
        assert_eq!(
            cache.metrics.read_cache_evictions.load(Ordering::Relaxed),
            1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_full_miss_falls_back_to_transient_when_candidates_are_busy() {
        let dir = scratch_dir("cap-transient-busy");
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();

        let a_arc = cache.read_conns.get("home/a").unwrap().value().clone();
        let b_arc = cache.read_conns.get("home/b").unwrap().value().clone();
        let a_guard = a_arc.inner.read().unwrap();
        let b_guard = b_arc.inner.read().unwrap();

        let r = cache.cached_read_with_hmac(&dir, "home/c").unwrap();
        assert!(r.is_some());
        assert!(cache.read_conns.get("home/c").is_none());
        assert!(cache.read_conns.get("home/a").is_some());
        assert!(cache.read_conns.get("home/b").is_some());
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache.metrics.read_cache_misses.load(Ordering::Relaxed),
            3,
            "transient fallback is one miss for C, not one miss per internal retry"
        );
        assert_eq!(
            cache.metrics.read_cache_evictions.load(Ordering::Relaxed),
            0
        );
        drop(a_guard);
        drop(b_guard);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_size_one_evicts_on_every_new_world() {
        let dir = scratch_dir("cap-one-serial");
        let worlds = ["home/a", "home/b", "home/c", "home/d", "home/e"];
        for (idx, w) in worlds.iter().enumerate() {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, &[b'a' + idx as u8], "text/plain", &[])
                .unwrap();
        }

        let cache = ReadCache::new(1);
        for (idx, w) in worlds.iter().enumerate() {
            let read = cache.cached_read_with_hmac(&dir, w).unwrap();
            let (stage, _hmac) = read.expect("existing world must not look missing at cap=1");
            assert_eq!(stage.body, vec![b'a' + idx as u8]);
            assert!(
                cache.read_conns.get(*w).is_some(),
                "the latest world should occupy the single cache slot"
            );
            assert!(
                cache.read_conns.len() <= 1,
                "cache size 1 must never retain multiple slots"
            );
        }

        assert_eq!(cache.metrics.read_cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(cache.metrics.read_cache_misses.load(Ordering::Relaxed), 5);
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 4);
        assert_eq!(
            cache.metrics.read_cache_evictions.load(Ordering::Relaxed),
            4,
            "after the first install, each new world must evict the previous slot"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_size_one_concurrent_readers_never_report_false_404() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dir = StdArc::new(scratch_dir("cap-one-concurrent"));
        let worlds = ["home/a", "home/b", "home/c", "home/d"];
        for (idx, w) in worlds.iter().enumerate() {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, &[b'a' + idx as u8], "text/plain", &[])
                .unwrap();
        }

        let cache = StdArc::new(ReadCache::new(1));
        let mut handles = Vec::new();
        for (idx, world) in worlds.into_iter().enumerate() {
            let dir = dir.clone();
            let cache = cache.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..8 {
                    let read = cache
                        .cached_read_with_hmac(&dir, world)
                        .expect("cache-size-one concurrent read");
                    let (stage, _hmac) =
                        read.expect("existing world must not look missing at cache size 1");
                    assert_eq!(stage.body, vec![b'a' + idx as u8]);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("reader thread");
        }
        assert!(
            cache.read_conns.len() <= 1,
            "cache size 1 must remain capped under concurrent churn"
        );

        let _ = std::fs::remove_dir_all(&*dir);
    }

    #[test]
    fn cache_hit_serves_from_cache_even_at_cap() {
        let dir = scratch_dir("cap-hit");
        for w in ["home/a", "home/b"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        let hits_before = cache.metrics.read_cache_hits.load(Ordering::Relaxed);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let hits_after = cache.metrics.read_cache_hits.load(Ordering::Relaxed);
        assert_eq!(hits_after, hits_before + 1);
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn opening_transition_drop_sets_tombstone_on_panic_path() {
        let slot = Arc::new(ReadSlot {
            inner: StdRwLock::new(SlotState::Opening),
            last_access: AtomicU64::new(0),
        });
        {
            let mut g = slot.inner.write().unwrap();
            let _t = OpeningTransition::new(&mut g);
            // Drop _t without finalize.
        }
        let g = slot.inner.read().unwrap();
        assert!(matches!(*g, SlotState::Tombstone));
    }

    #[test]
    fn evicted_slot_reopens_existing_world_instead_of_404() {
        let dir = scratch_dir("evicted-retry");
        let world = "home/evicted";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"still here", "text/plain", &[])
            .unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        cache
            .read_conns
            .insert(world.to_string(), cache.new_slot(SlotState::Evicted));

        let read = cache.cached_read_with_hmac(&dir, world).unwrap();
        let (stage, _hmac) = read.expect("evicted cache slot must reopen existing world");
        assert_eq!(stage.body, b"still here");
        assert_eq!(
            cache.metrics.read_cache_hits.load(Ordering::Relaxed),
            0,
            "evicted slots are retry signals, not successful cache hits"
        );
        assert_eq!(
            cache.metrics.read_cache_misses.load(Ordering::Relaxed),
            1,
            "evicted slot retry should count as one external miss"
        );
        assert!(
            cache.read_conns.get(world).is_some(),
            "retry path should install a fresh tracked slot"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn eviction_refuses_slots_with_active_read_guards() {
        let dir = scratch_dir("evict-busy");
        let world = "home/busy";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"busy", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let _ = cache.cached_read_with_hmac(&dir, world).unwrap();
        let arc = cache.read_conns.get(world).unwrap().value().clone();
        let read_guard = arc.inner.read().unwrap();

        assert!(
            !cache.try_evict_ready_slot(world, &arc),
            "eviction must not drain a slot while a reader holds the read guard"
        );
        drop(read_guard);
        assert!(
            cache.read_conns.get(world).is_some(),
            "busy eviction refusal must leave the cached slot installed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_evict_ready_slot_removes_idle_ready_entry() {
        let dir = scratch_dir("evict-ready-success");
        let world = "home/idle";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"idle", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let _ = cache.cached_read_with_hmac(&dir, world).unwrap();
        let arc = cache.read_conns.get(world).unwrap().value().clone();

        assert!(
            cache.try_evict_ready_slot(world, &arc),
            "idle Ready slot should be evictable"
        );
        assert!(
            cache.read_conns.get(world).is_none(),
            "successful eviction must remove the map entry"
        );
        let guard = arc.inner.read().unwrap();
        assert!(matches!(&*guard, SlotState::Evicted));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_evict_ready_slot_reports_false_when_map_entry_changed() {
        let dir = scratch_dir("evict-stale-arc");
        let world = "home/stale";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"stale", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let _ = cache.cached_read_with_hmac(&dir, world).unwrap();
        let stale_arc = cache.read_conns.get(world).unwrap().value().clone();
        cache
            .read_conns
            .insert(world.to_string(), cache.new_slot(SlotState::Tombstone));

        assert!(
            !cache.try_evict_ready_slot(world, &stale_arc),
            "evicting a stale Arc must not count as a successful map eviction"
        );
        assert!(
            cache.read_conns.get(world).is_some(),
            "replacement entry must not be removed by stale Arc eviction"
        );
        assert_eq!(
            cache.metrics.read_cache_evictions.load(Ordering::Relaxed),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tombstone_done_none_counts_as_hit_but_opening_is_retry() {
        let dir = scratch_dir("done-none-and-opening");
        let world = "home/done-none";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"x", "text/plain", &[]).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        cache.install_tombstone_blocking(world);
        let tombstone = cache.cached_read_with_hmac(&dir, world).unwrap();
        assert!(tombstone.is_none());
        assert_eq!(
            cache.metrics.read_cache_hits.load(Ordering::Relaxed),
            1,
            "Tombstone is a definitive cached absence answer"
        );
        assert_eq!(cache.metrics.read_cache_misses.load(Ordering::Relaxed), 0);

        let opening_world = "home/opening";
        let opening_slot = cache.new_slot(SlotState::Opening);
        cache
            .read_conns
            .insert(opening_world.to_string(), opening_slot.clone());
        let mut f = Some(|_: &mut TrackedReadConnection| -> rusqlite::Result<()> {
            panic!("Opening must be a retry signal, not a readable slot")
        });
        let opening = cache.invoke_via_slot(opening_slot, &mut f).unwrap();
        assert!(
            matches!(opening, SlotRead::Opening),
            "Opening is not a definitive absence answer"
        );
        assert!(f.is_some(), "Opening retry must leave FnOnce intact");
        assert_eq!(
            cache.metrics.read_cache_hits.load(Ordering::Relaxed),
            1,
            "Opening must not be counted as a hit"
        );
        assert_eq!(cache.metrics.read_cache_misses.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stuck_opening_returns_busy_after_retry_budget() {
        let dir = scratch_dir("stuck-opening-budget");
        let world = "home/stuck-opening";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"still here", "text/plain", &[])
            .unwrap();

        let cache = ReadCache::new(1);
        cache
            .read_conns
            .insert(world.to_string(), cache.new_slot(SlotState::Opening));

        let err = match cache.cached_read_with_hmac(&dir, world) {
            Ok(Some(_)) => panic!("stuck Opening must not resolve as a body"),
            Ok(None) => panic!("stuck Opening must not report a false 404"),
            Err(err) => err,
        };
        assert_eq!(
            err.sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy),
            "retry-budget exhaustion should surface as transient SQLite busy"
        );
        assert_eq!(
            cache.metrics.read_cache_hits.load(Ordering::Relaxed),
            0,
            "Opening retries must not count as hits"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lru_eviction_skips_tombstone_and_evicts_ready_slot() {
        let dir = scratch_dir("evict-skip-tombstone");
        for w in ["home/ready", "home/tomb"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/ready").unwrap();
        cache.install_tombstone_blocking("home/tomb");

        assert!(
            cache.try_evict_oldest_sample("home/new"),
            "sample should skip Tombstone and evict the idle Ready candidate"
        );
        assert!(cache.read_conns.get("home/ready").is_none());
        assert!(
            cache.read_conns.get("home/tomb").is_some(),
            "Tombstone is delete state, not an LRU eviction candidate"
        );
        let tombstone_read = cache.cached_read_with_hmac(&dir, "home/tomb").unwrap();
        assert!(tombstone_read.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn eviction_sample_excludes_requested_world() {
        let dir = scratch_dir("evict-exclude-target");
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(3);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/c").unwrap();

        let a_arc = cache.read_conns.get("home/a").unwrap().value().clone();
        let b_arc = cache.read_conns.get("home/b").unwrap().value().clone();
        let a_guard = a_arc.inner.read().unwrap();
        let b_guard = b_arc.inner.read().unwrap();

        assert!(
            !cache.try_evict_oldest_sample("home/c"),
            "the target world must not be evicted just because older candidates are busy"
        );
        assert!(cache.read_conns.get("home/c").is_some());
        assert_eq!(
            cache.metrics.read_cache_evictions.load(Ordering::Relaxed),
            0
        );
        drop(a_guard);
        drop(b_guard);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Bug 58 (audit verify routes through SlotState) -------------
    //
    // Verifies that `cached_verify_chain` uses the same slot-before-
    // open dance as `cached_read_with_hmac`: a verify after a write
    // populates the cache, a tombstone short-circuits to None, and
    // a fresh verify after clear_tombstone re-opens. If
    // `proc_audit_verify` were still calling the bare
    // `audit::verify_chain` path, this test would still pass for
    // happy cases but the SlotState protocol's drain guarantee
    // would not hold for the admin endpoint -- the test pins the
    // routing, not just the SQL semantics.
    #[test]
    fn cached_verify_chain_uses_slot_protocol() {
        let dir = scratch_dir("verify-slot");
        let world = "home/audited";
        // Seed an audit chain: a single write_with_audit_checked
        // produces a `put` event whose hmac chains to a synthetic
        // genesis (prev = ""). `WriteAuditError` doesn't derive
        // Debug, so don't .unwrap() on it -- match instead.
        let audited_world = crate::engine_types::ValidatedWorldPath::new(world).unwrap();
        match world::write_with_audit_checked(
            &dir,
            &audited_world,
            b"hello",
            "text/plain",
            &[],
            &test_key(),
        ) {
            Ok(_) => {}
            Err(_) => panic!("seed write_with_audit_checked failed"),
        }

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);

        // Phase 3 lazy-init: first verify warms the cache.
        let key = test_key();
        let r1 = cache.cached_verify_chain(&dir, world, &key).unwrap();
        assert!(matches!(r1, Some(crate::audit::VerifyReport::Valid(_))));
        assert!(
            cache.read_conns.get(world).is_some(),
            "expected the verify to populate the SlotState cache; \
             a regression to the bare audit::verify_chain path would \
             leave the map empty"
        );

        // Phase 1 cache hit: second verify reuses the cached slot.
        let r2 = cache.cached_verify_chain(&dir, world, &key).unwrap();
        assert!(matches!(r2, Some(crate::audit::VerifyReport::Valid(_))));

        // Tombstone short-circuits verify (delete intent).
        cache.install_tombstone_blocking(world);
        let r3 = cache.cached_verify_chain(&dir, world, &key).unwrap();
        assert!(r3.is_none());

        // After clear_tombstone the next verify re-opens through
        // Phase 3 lazy-init.
        cache.clear_tombstone(world);
        let r4 = cache.cached_verify_chain(&dir, world, &key).unwrap();
        assert!(matches!(r4, Some(crate::audit::VerifyReport::Valid(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Bug 54 (drain-before-remove for transient slots) ----------
    //
    // Single-threaded `cap_uses_transient_slot_then_drains_and_removes`
    // above covers the install + cleanup ordering on one thread. It
    // does NOT cover the actual race #138 fixed: a Phase 1 cache hit
    // lands on the same transient Arc while the owner is mid-cleanup.
    // The owner's `mem::replace(Evicted)` must drop the Connection inside
    // the write-guard window, so any clone the hitter still holds either
    // finishes before drain (sees Ready, succeeds) or arrives after drain
    // (sees Evicted, retries through the miss/open path). Neither case
    // leaves an fd alive past cleanup, and neither case reports a spurious
    // 404 for an existing world.
    #[test]
    fn cap_transient_slot_concurrent_readers_safe_under_cleanup() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dir = StdArc::new(scratch_dir("cap-transient-concurrent"));
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::test_only_write_without_audit(&dir, w, b"hello world", "text/plain", &[])
                .unwrap();
        }

        // cap=2 -> A and B fill it; C must go through transient.
        let cache = StdArc::new(ReadCache::new(2));
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        let a_arc = cache.read_conns.get("home/a").unwrap().value().clone();
        let b_arc = cache.read_conns.get("home/b").unwrap().value().clone();
        let a_guard = a_arc.inner.read().unwrap();
        let b_guard = b_arc.inner.read().unwrap();

        // Spawn 4 concurrent readers all targeting world C. Whoever
        // wins the Entry race owns the transient slot and runs the
        // drain-before-remove cleanup. Other readers can land on
        // any of three branches:
        //   - Phase 1 cache hit BEFORE the owner's drain begins:
        //     gets `Ok(Some(body))` from the still-Ready slot.
        //   - Phase 1 cache hit AFTER the owner's `mem::replace
        //     Evicted` but BEFORE the owner's `remove_if`: read
        //     guard sees Evicted -> retries through the miss/open
        //     path rather than returning `Ok(None)`.
        //   - Cache miss after the slot is removed: installs a
        //     fresh transient and reads through it.
        //
        // Test contract: every reader returns a correct body (never
        // a spurious Ok(None), never a torn body, never an Err, never
        // a panic). The transient owner is guaranteed to succeed
        // (it took the read guard before its own drain).
        // After all readers complete, the slot is removed (cap
        // honored) and the persistent A / B slots are preserved.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cache = cache.clone();
            let dir = dir.clone();
            handles.push(thread::spawn(move || {
                cache.cached_read_with_hmac(&dir, "home/c").expect("read")
            }));
        }
        for h in handles {
            let (stage, _hmac) = h
                .join()
                .expect("thread")
                .expect("existing world must not look missing during transient cleanup");
            assert_eq!(stage.body, b"hello world", "body must not be torn");
            assert_eq!(stage.content_type, "text/plain");
        }

        // After all readers complete, the transient slot should be
        // gone (cleanup ran). A and B remain (persistent slots).
        assert!(cache.read_conns.get("home/c").is_none());
        assert!(cache.read_conns.get("home/a").is_some());
        assert!(cache.read_conns.get("home/b").is_some());
        drop(a_guard);
        drop(b_guard);

        let _ = std::fs::remove_dir_all(&*dir);
    }

    // -- Bug 43 CANTOPEN classification ----------------------------
    //
    // `path.try_exists()` returning `Ok(false)` -> 404 (file is
    // genuinely gone). Other variants (`Ok(true)` for unreadable
    // file, `Err(_)` for metadata failure) -> propagate the SQLite
    // error so the verb maps to 500/507 via the storage failure
    // classifier. v6 collapsed all CANTOPEN
    // into 404; v7 introduced the recheck; v9 (Bug 49) tightened
    // `path.exists()` -> `path.try_exists()` so metadata errors stop
    // collapsing into a spurious 404.
    //
    // The missing-file -> 404 case is exercised by
    // `missing_world_returns_none_via_phase3` above. The
    // existing-but-unreadable case requires Unix file mode flips
    // and is therefore `cfg(unix)`-gated.
    #[cfg(unix)]
    #[test]
    fn cantopen_with_existing_unreadable_file_propagates_500_not_404() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("cantopen-existing");
        let world = "home/locked";
        let _c = world::open(&dir, world).unwrap();
        world::test_only_write_without_audit(&dir, world, b"hello", "text/plain", &[]).unwrap();

        // chmod 000 the universe.db so SQLite returns CANTOPEN even
        // though the file is genuinely on disk.
        let db_path = world::world_db(&dir, world);
        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&db_path, perms).unwrap();

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);
        let result = cache.cached_read_with_hmac(&dir, world);

        // path.try_exists() returns Ok(true) for the still-on-disk
        // (but unreadable) file. The CANTOPEN error must propagate
        // as Err, not collapse into Ok(None). Don't format `result`
        // with {:?} -- `world::Stage` does not derive Debug, so a
        // Linux test compile would fail; map to a small status
        // string instead.
        let outcome = match &result {
            Ok(Some(_)) => "Ok(Some(_)) <- spurious read",
            Ok(None) => "Ok(None) <- spurious 404",
            Err(_) => "Err(_)",
        };
        assert!(
            result.is_err(),
            "CANTOPEN on existing-but-unreadable file must propagate as Err(_); \
             got {outcome} (a future regression to bare path.exists() would land here)"
        );

        // Restore perms so cleanup works.
        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&db_path, perms).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
