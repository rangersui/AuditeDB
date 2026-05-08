//! Audit ledger writer cache.
//!
//! `var/log/deletes` is the hottest open() in the codebase: every
//! DELETE used to open it 2-3 times (existence check + intent
//! append + commit append). This module caches one write
//! `Connection` per process and serializes appends through a
//! single `StdMutex`. Lazy-initialized on first append.
//!
//! The counter (`inits`) tracks `None -> Some` transitions of the
//! inner `Mutex<Option<Connection>>`. In steady state the value is
//! 1 (lazy init on first DELETE in the process). Higher values
//! surface re-init events that would otherwise be invisible from
//! outside (e.g., a future code path resetting the writer for
//! recovery). `/proc/pool` emits this as a `counter` metric.
//!
//! The wrapped types live in their own module to keep `Core`'s
//! field surface narrow: `Core::ledger: Arc<LedgerWriter>` is one
//! field instead of two, and the `append` body lives next to the
//! state it touches. `state.rs` stays under the 500-line budget.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;

use rusqlite::Connection;

use crate::audit;
use crate::world;

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

/// Result of an audit append run inside `spawn_blocking`. Shared
/// between the cached path here and the verb handlers
/// (`handler::execute_delete`).
#[derive(Debug)]
pub(crate) enum BlockingSqliteError {
    Sqlite(rusqlite::Error),
    Worker,
}

/// Cached writer + init counter for `var/log/deletes`. The inner
/// `StdMutex` is the SOLE serializer for ledger appends; the
/// per-world write lock at `var/log/deletes` is intentionally
/// gone (Bug 25). Don't re-add it.
pub(crate) struct LedgerWriter {
    /// `None` until the first successful `world::open` in
    /// `append`. Subsequent appends reuse the cached connection.
    /// Never invalidated — the ledger world is never deleted by
    /// user-facing DELETE (`var/log/*` is reserved).
    conn: StdMutex<Option<Connection>>,
    /// Counter; bumped after each `None -> Some` transition.
    pub(crate) inits: AtomicUsize,
}

impl LedgerWriter {
    pub(crate) fn new() -> Self {
        Self {
            conn: StdMutex::new(None),
            inits: AtomicUsize::new(0),
        }
    }

    /// Append one row to `var/log/deletes` using the cached
    /// connection. Lazy-initializes via `world::open` on the first
    /// successful call. Increments `inits` only after `world::open`
    /// succeeds — failed opens leave the slot as `None` and do not
    /// count.
    ///
    /// Caller wraps this in `tokio::task::spawn_blocking` (see
    /// `Core::append_to_ledger`) so the inner `StdMutex` doesn't
    /// stall a Tokio worker when contended.
    pub(crate) fn append(
        &self,
        data: &Path,
        job: AuditAppendJob,
    ) -> Result<String, BlockingSqliteError> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            // Lazy init. `world::open` creates the schema; safe to
            // call whether or not the ledger DB exists on disk.
            let conn = world::open(data, job.ledger_world).map_err(BlockingSqliteError::Sqlite)?;
            *guard = Some(conn);
            self.inits.fetch_add(1, Ordering::Relaxed);
        }
        let conn = guard.as_mut().expect("ledger connection initialized above");
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
        .map_err(BlockingSqliteError::Sqlite)
    }
}
