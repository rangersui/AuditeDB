use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use rusqlite::{ffi::ErrorCode, Connection, OpenFlags};

use crate::{engine_types::ValidatedWorldPath, world, world_schema};

use super::{
    log_read_cache_retry_budget_exhausted, read_cache_retry_budget_error, ReadCache, ReadSlot,
    SlotRead, SlotState, READ_CACHE_RETRY_BUDGET, READ_CONN_BUSY_TIMEOUT_MS,
};

fn open_verified_read_conn(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    c.busy_timeout(Duration::from_millis(READ_CONN_BUSY_TIMEOUT_MS))?;
    c.pragma_update(None, "cache_size", -200)?;
    world_schema::verify(&c)?;
    Ok(c)
}

/// Newtype around `rusqlite::Connection` that gates read access at
/// the type level. The only production constructor (`from_raw`) is
/// private to this state-machine module and called only from
/// `OpeningTransition::promote`. Code outside the read-cache state
/// machine can name and borrow the type, but cannot mint one.
///
/// See AGENTS.md section "Physics, not policy."
pub(crate) struct TrackedReadConnection(Connection);

impl TrackedReadConnection {
    fn from_raw(conn: Connection) -> Self {
        Self(conn)
    }

    /// Mutable access to the wrapped Connection for the SQL body of
    /// `world::read_with_hmac_via_conn`. `pub(crate)` -- callers must
    /// already hold a `&mut TrackedReadConnection`, and the only
    /// production path to that is through the SlotState protocol.
    pub(crate) fn as_mut_conn(&mut self) -> &mut Connection {
        &mut self.0
    }

    fn verify_schema(&self) -> rusqlite::Result<()> {
        world_schema::verify(&self.0)
    }
}

/// RAII guard for the Opening -> Ready/Evicted transition. Without
/// it, a panic during `Connection::open`, `busy_timeout`, or
/// `pragma_update` would leave the slot stuck in `Opening`.
///
/// Private to this module so the raw connection wrapper cannot be
/// constructed by sibling read-cache helper modules.
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

    fn promote(mut self, conn: Connection) {
        let tracked = TrackedReadConnection::from_raw(conn);
        *self.state = SlotState::Ready(StdMutex::new(tracked));
        self.finalized = true;
    }

    /// Open or schema verification failed. This is a retry signal, not a
    /// delete tombstone: a waiting reader must not turn it into `Ok(None)`.
    fn fail(mut self) {
        *self.state = SlotState::Evicted;
        self.finalized = true;
    }
}

impl<'a> Drop for OpeningTransition<'a> {
    fn drop(&mut self) {
        if !self.finalized {
            *self.state = SlotState::Evicted;
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

impl ReadCache {
    /// Run a closure with a `&mut TrackedReadConnection` obtained
    /// through the SlotState protocol. Three-phase split:
    ///   1. Cache hit (any state, regardless of cap)
    ///   2. Cache miss + cap reached -> approximate eviction, or transient
    ///   3. Cache miss + room -> slot-before-open lazy-init
    ///
    /// `Ok(None)` means the world's DB is missing (404). `Err(_)`
    /// is propagated for real storage errors. The closure runs at
    /// most once and returns its own `rusqlite::Result<R>`.
    pub(super) fn with_tracked_conn<F, R>(
        &self,
        data: &std::path::Path,
        world: &ValidatedWorldPath,
        f: F,
    ) -> rusqlite::Result<Option<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        let path = world::validated_world_db(data, world);
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
                // Invariant: SlotRead::Done returns immediately after taking
                // the FnOnce; retry states leave it present for fallback.
                #[allow(clippy::expect_used)]
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
                .entry(world.clone())
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
        // Invariant: SlotRead::Done returns immediately after taking the
        // FnOnce; retry-budget fallback still owns it.
        #[allow(clippy::expect_used)]
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
        world: &ValidatedWorldPath,
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
                .entry(world.clone())
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

    pub(super) fn invoke_via_slot<F, R>(
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
                // Invariant: Ready is the only branch allowed to consume the
                // FnOnce; Opening/Evicted/Tombstone return without taking it.
                #[allow(clippy::expect_used)]
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, RwLock as StdRwLock};

    #[test]
    fn opening_transition_drop_sets_evicted_on_panic_path() {
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
        assert!(matches!(*g, SlotState::Evicted));
    }

    #[test]
    fn opening_failure_is_retry_signal_not_cached_absence() {
        let cache = ReadCache::new(crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES);
        let slot = cache.new_slot(SlotState::Opening);
        {
            let mut g = slot.inner.write().unwrap();
            OpeningTransition::new(&mut g).fail();
        }

        let mut f = Some(|_: &mut TrackedReadConnection| -> rusqlite::Result<()> {
            panic!("failed Opening must retry, not run the read closure")
        });
        let read = cache.invoke_via_slot(slot, &mut f).unwrap();
        assert!(
            matches!(read, SlotRead::Evicted),
            "open/schema failure must not be represented as Tombstone/Ok(None)"
        );
        assert!(f.is_some(), "retry signal must leave FnOnce intact");
        assert_eq!(
            cache.metrics.read_cache_hits.load(Ordering::Relaxed),
            0,
            "opening failure retries must not count as cache hits"
        );
    }
}
