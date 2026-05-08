//! Per-world read connection cache.
//!
//! Caches one open SQLite connection per recently-read world so that
//! GET / HEAD don't re-pay the ~456-700us `Connection::open_with_flags`
//! cost on every request. The naive approach -- `DashMap<String,
//! Mutex<Connection>>` -- has a race: DELETE removes the map entry,
//! but in-flight readers holding cloned Arcs continue using their
//! cached fd. Linux gets an orphan inode (harmless); Windows fails
//! the unlink with sharing-violation (DELETE 500).
//!
//! This module is the v7.1 design distilled from ten review rounds
//! (see `docs/architecture/sqlite-connection-pool.md`). The
//! invariants encoded here:
//!
//! 1. **Slot-before-open** -- a reader reserves a slot in
//!    `SlotState::Opening` via the DashMap Entry API BEFORE calling
//!    `Connection::open_with_flags`, and holds the slot's
//!    `inner.write()` guard for the duration of the open. DELETE's
//!    drain blocks behind that guard. fd lifetime is tracked by the
//!    synchronization primitive, not by chance.
//! 2. **Tombstone protocol** -- DELETE replaces the slot's state with
//!    `Tombstone` inside the write guard window, so the previous
//!    `Ready(Mutex<Connection>)`'s Connection drops INSIDE the guard.
//!    No fd is alive when `delete_world_blocking` runs.
//! 3. **Drain before remove** -- at-cap "transient" slots (cap reached,
//!    we install a slot for one read and then remove it) drain the
//!    slot before removing -- `arc.inner.write()` waits for any
//!    Phase-1-cache-hit clones to release their read guards, then
//!    `mem::replace` Tombstone closes the fd. The map entry is then
//!    safe to remove. See AGENTS.md section "Drain before remove."
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
//! Tokio worker (the same pattern DELETE already uses for
//! `delete_world_blocking`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use dashmap::DashMap;
use rusqlite::{ffi::ErrorCode, Connection, OpenFlags};

use crate::world;

/// Default ceiling on the number of cached read slots. Per-conn
/// memory is bounded to ~250KB (PRAGMA cache_size=-200), so 5000
/// caps resident at ~1.25 GB. Operators with larger working sets
/// raise via `ELASTIK_READ_CACHE_MAX_ENTRIES` (wired in PR 3).
pub(crate) const DEFAULT_READ_CACHE_MAX_ENTRIES: usize = 5000;

/// SQLite busy_timeout for cached read connections. Tighter than
/// the 5000ms `world::open` default because queued readers under
/// writer contention compound the deadline; a per-conn 1000ms keeps
/// the Mutex-queue tail bounded.
const READ_CONN_BUSY_TIMEOUT_MS: u64 = 1000;

/// Newtype around `rusqlite::Connection` that gates read access at
/// the type level. The only constructor (`from_raw`) is reachable
/// solely from `OpeningTransition::promote` below -- no other code
/// in the crate can mint one. `world::read_with_hmac_via_conn`
/// consumes `&mut TrackedReadConnection`, which means the bypass
/// "open a Connection and run the SQL on it" doesn't compile.
///
/// See AGENTS.md section "Physics, not policy."
pub(crate) struct TrackedReadConnection(Connection);

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
    Tombstone,
}

/// Same module-private treatment -- `Arc<ReadSlot>` is held inside
/// `ReadCache.read_conns` (a private field), and there is no public
/// API that exposes the inner `RwLock<SlotState>` to callers.
struct ReadSlot {
    inner: StdRwLock<SlotState>,
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
    pub(crate) max_entries: usize,
    pub(crate) metrics: ReadCacheMetrics,
}

impl ReadCache {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            read_conns: DashMap::new(),
            max_entries,
            metrics: ReadCacheMetrics::default(),
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

    /// Verify the audit chain through the cached read path (Bug 58).
    /// Same SlotState protocol as `cached_read_with_hmac` -- DELETE
    /// drains in-flight verifies via the slot's write guard. Closes
    /// the v10 type-gate gap on the admin
    /// `/proc/audit/{world}/verify` endpoint.
    pub(crate) fn cached_verify_chain(
        &self,
        data: &std::path::Path,
        world: &str,
        key: &[u8],
    ) -> rusqlite::Result<Option<crate::audit::VerifyReport>> {
        let key = key.to_vec();
        self.with_tracked_conn(data, world, move |conn| {
            crate::audit::verify_chain_via_conn(conn, &key)
        })
    }

    /// Run a closure with a `&mut TrackedReadConnection` obtained
    /// through the SlotState protocol. Three-phase split:
    ///   1. Cache hit (any state, regardless of cap)
    ///   2. Cache miss + cap reached -> transient tracked slot
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

        // PHASE 1 -- Cache hit (any state).
        if let Some(arc) = self.read_conns.get(world).map(|e| e.value().clone()) {
            self.metrics.read_cache_hits.fetch_add(1, Ordering::Relaxed);
            return self.invoke_via_slot(arc, f);
        }
        self.metrics
            .read_cache_misses
            .fetch_add(1, Ordering::Relaxed);

        // PHASE 2 -- Cache miss + cap reached: transient tracked slot.
        if self.read_conns.len() >= self.max_entries {
            self.metrics
                .read_cache_capped
                .fetch_add(1, Ordering::Relaxed);
            return self.invoke_transient(&path, world, f);
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

        let new_slot = Arc::new(ReadSlot {
            inner: StdRwLock::new(SlotState::Opening),
        });
        let arc = self
            .read_conns
            .entry(world.to_string())
            .or_insert_with(|| new_slot.clone())
            .value()
            .clone();
        let we_own_slot = Arc::ptr_eq(&arc, &new_slot);

        if we_own_slot {
            let mut g = arc.inner.write().unwrap_or_else(|p| p.into_inner());
            if matches!(&*g, SlotState::Opening) {
                let transition = OpeningTransition::new(&mut g);
                let init: rusqlite::Result<Connection> = (|| {
                    let c = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                    c.busy_timeout(Duration::from_millis(READ_CONN_BUSY_TIMEOUT_MS))?;
                    c.pragma_update(None, "cache_size", -200)?;
                    Ok(c)
                })();
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
        }

        self.invoke_via_slot(arc, f)
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
        // Fast-path: slot already exists (concurrent reader installed
        // one, or DELETE installed a tombstone).
        if let Some(arc) = self.read_conns.get(world).map(|e| e.value().clone()) {
            return self.invoke_via_slot(arc, f);
        }

        let transient_slot = Arc::new(ReadSlot {
            inner: StdRwLock::new(SlotState::Opening),
        });
        let arc = self
            .read_conns
            .entry(world.to_string())
            .or_insert_with(|| transient_slot.clone())
            .value()
            .clone();
        let we_own_slot = Arc::ptr_eq(&arc, &transient_slot);

        if we_own_slot {
            let mut g = arc.inner.write().unwrap_or_else(|p| p.into_inner());
            if matches!(&*g, SlotState::Opening) {
                let transition = OpeningTransition::new(&mut g);
                let init: rusqlite::Result<Connection> = (|| {
                    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                    c.busy_timeout(Duration::from_millis(READ_CONN_BUSY_TIMEOUT_MS))?;
                    c.pragma_update(None, "cache_size", -200)?;
                    Ok(c)
                })();
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
        }

        let result = self.invoke_via_slot(arc.clone(), f);

        // Drain-before-remove (Bug 54): write guard, mem::replace
        // Tombstone (drops Connection inside guard window -- fd
        // close happens here), drop guard, then remove_if.
        if we_own_slot {
            {
                let mut g = arc.inner.write().unwrap_or_else(|p| p.into_inner());
                let old = std::mem::replace(&mut *g, SlotState::Tombstone);
                drop(old);
                drop(g);
            }
            self.read_conns
                .remove_if(world, |_k, v| Arc::ptr_eq(v, &arc));
        }
        result
    }

    fn invoke_via_slot<F, R>(&self, arc: Arc<ReadSlot>, f: F) -> rusqlite::Result<Option<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        let read_guard = arc.inner.read().unwrap_or_else(|p| p.into_inner());
        match &*read_guard {
            SlotState::Ready(tracked_mutex) => {
                let mut tracked = tracked_mutex.lock().unwrap_or_else(|p| p.into_inner());
                f(&mut tracked).map(Some)
            }
            SlotState::Tombstone => Ok(None),
            SlotState::Opening => Ok(None),
        }
    }

    /// Sync version. DELETE callers wrap this in `spawn_blocking` so
    /// the drain wait doesn't stall a Tokio worker.
    pub(crate) fn install_tombstone_blocking(&self, world: &str) {
        let new_tombstone = Arc::new(ReadSlot {
            inner: StdRwLock::new(SlotState::Tombstone),
        });
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

    /// Snapshot accessors for /proc/pool. Marked `dead_code`-allow
    /// because the `/proc/pool` endpoint that consumes them lands
    /// in the next PR (PR 3, observability).
    #[allow(dead_code)]
    pub(crate) fn snapshot_entries(&self) -> usize {
        self.read_conns.len()
    }

    #[allow(dead_code)]
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
        world::write(&dir, world, b"hello", "text/plain", &[]).unwrap();

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
        world::write(&dir, world, b"x", "text/plain", &[]).unwrap();

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
    fn cap_uses_transient_slot_then_drains_and_removes() {
        let dir = scratch_dir("cap-transient");
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::write(&dir, w, b"x", "text/plain", &[]).unwrap();
        }

        let cache = ReadCache::new(2);
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();
        assert_eq!(cache.read_conns.len(), 2);
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 0);

        let r = cache.cached_read_with_hmac(&dir, "home/c").unwrap();
        assert!(r.is_some());
        assert!(cache.read_conns.get("home/c").is_none());
        assert!(cache.read_conns.get("home/a").is_some());
        assert!(cache.read_conns.get("home/b").is_some());
        assert_eq!(cache.metrics.read_cache_capped.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_serves_from_cache_even_at_cap() {
        let dir = scratch_dir("cap-hit");
        for w in ["home/a", "home/b"] {
            let _c = world::open(&dir, w).unwrap();
            world::write(&dir, w, b"x", "text/plain", &[]).unwrap();
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
        });
        {
            let mut g = slot.inner.write().unwrap();
            let _t = OpeningTransition::new(&mut g);
            // Drop _t without finalize.
        }
        let g = slot.inner.read().unwrap();
        assert!(matches!(*g, SlotState::Tombstone));
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
        match world::write_with_audit_checked(
            &dir,
            world,
            b"hello",
            "text/plain",
            &[],
            b"key",
            None,
        ) {
            Ok(_) => {}
            Err(_) => panic!("seed write_with_audit_checked failed"),
        }

        let cache = ReadCache::new(DEFAULT_READ_CACHE_MAX_ENTRIES);

        // Phase 3 lazy-init: first verify warms the cache.
        let r1 = cache.cached_verify_chain(&dir, world, b"key").unwrap();
        assert!(matches!(r1, Some(crate::audit::VerifyReport::Valid(_))));
        assert!(
            cache.read_conns.get(world).is_some(),
            "expected the verify to populate the SlotState cache; \
             a regression to the bare audit::verify_chain path would \
             leave the map empty"
        );

        // Phase 1 cache hit: second verify reuses the cached slot.
        let r2 = cache.cached_verify_chain(&dir, world, b"key").unwrap();
        assert!(matches!(r2, Some(crate::audit::VerifyReport::Valid(_))));

        // Tombstone short-circuits verify (DELETE intent).
        cache.install_tombstone_blocking(world);
        let r3 = cache.cached_verify_chain(&dir, world, b"key").unwrap();
        assert!(r3.is_none());

        // After clear_tombstone the next verify re-opens through
        // Phase 3 lazy-init.
        cache.clear_tombstone(world);
        let r4 = cache.cached_verify_chain(&dir, world, b"key").unwrap();
        assert!(matches!(r4, Some(crate::audit::VerifyReport::Valid(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Bug 54 (drain-before-remove for transient slots) ----------
    //
    // Single-threaded `cap_uses_transient_slot_then_drains_and_removes`
    // above covers the install + cleanup ordering on one thread. It
    // does NOT cover the actual race the v9 round closed: a Phase 1
    // cache hit lands on the same transient Arc while the owner is
    // mid-cleanup. The owner's `mem::replace(Tombstone)` must drop the
    // Connection inside the write-guard window, so any clone the
    // hitter still holds either finishes before drain (sees Ready,
    // succeeds) or arrives after drain (sees Tombstone, returns
    // `Ok(None)`). Neither case leaves an fd alive past the cleanup.
    #[test]
    fn cap_transient_slot_concurrent_readers_safe_under_cleanup() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dir = StdArc::new(scratch_dir("cap-transient-concurrent"));
        for w in ["home/a", "home/b", "home/c"] {
            let _c = world::open(&dir, w).unwrap();
            world::write(&dir, w, b"hello world", "text/plain", &[]).unwrap();
        }

        // cap=2 -> A and B fill it; C must go through transient.
        let cache = StdArc::new(ReadCache::new(2));
        let _ = cache.cached_read_with_hmac(&dir, "home/a").unwrap();
        let _ = cache.cached_read_with_hmac(&dir, "home/b").unwrap();

        // Spawn 4 concurrent readers all targeting world C. Whoever
        // wins the Entry race owns the transient slot and runs the
        // drain-before-remove cleanup. Other readers can land on
        // any of three branches:
        //   - Phase 1 cache hit BEFORE the owner's drain begins:
        //     gets `Ok(Some(body))` from the still-Ready slot.
        //   - Phase 1 cache hit AFTER the owner's `mem::replace
        //     Tombstone` but BEFORE the owner's `remove_if`: read
        //     guard sees Tombstone -> returns `Ok(None)`. This is
        //     the documented v9 "spurious-404 micro-window" trade
        //     -- accepted because the alternative is an fd-vs-DELETE
        //     race that's strictly worse than a transient 404.
        //     `std::sync::RwLock` is reader-preferring on Linux,
        //     so the window is wide enough to hit reliably under
        //     concurrent load (Windows happens to be writer-fair,
        //     which is why this test passed locally before CI on
        //     Linux surfaced it).
        //   - Cache miss after the slot is removed: installs a
        //     fresh transient and reads through it.
        //
        // Test contract: every reader returns either a correct body
        // or a clean `Ok(None)` (never a torn body, never an Err,
        // never a panic). The transient owner is guaranteed to
        // succeed (it took the read guard before its own drain).
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
        let mut bodies = 0usize;
        let mut spurious_404s = 0usize;
        for h in handles {
            match h.join().expect("thread") {
                Some((stage, _hmac)) => {
                    assert_eq!(stage.body, b"hello world", "body must not be torn");
                    assert_eq!(stage.content_type, "text/plain");
                    bodies += 1;
                }
                None => spurious_404s += 1,
            }
        }
        // The transient owner is guaranteed to read its own slot
        // before initiating drain, so at least one body is required.
        assert!(
            bodies >= 1,
            "transient slot owner must read body before drain; \
             got {bodies} body / {spurious_404s} Ok(None)"
        );

        // After all readers complete, the transient slot should be
        // gone (cleanup ran). A and B remain (persistent slots).
        assert!(cache.read_conns.get("home/c").is_none());
        assert!(cache.read_conns.get("home/a").is_some());
        assert!(cache.read_conns.get("home/b").is_some());

        let _ = std::fs::remove_dir_all(&*dir);
    }

    // -- Bug 43 CANTOPEN classification ----------------------------
    //
    // `path.try_exists()` returning `Ok(false)` -> 404 (file is
    // genuinely gone). Other variants (`Ok(true)` for unreadable
    // file, `Err(_)` for metadata failure) -> propagate the SQLite
    // error so the verb maps to 500/507 via
    // `is_insufficient_storage_error`. v6 collapsed all CANTOPEN
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
        world::write(&dir, world, b"hello", "text/plain", &[]).unwrap();

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
