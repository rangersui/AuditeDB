//! Audit ledger writer cache.
//!
//! `var/log/deletes` is the hottest open() in the codebase: every
//! Delete used to open it 2-3 times (existence check + intent
//! append + commit append). This module caches one write
//! `Connection` per process and serializes appends through a
//! single `StdMutex`. Lazy-initialized on first append.
//!
//! The counter (`inits`) tracks `None -> Some` transitions of the
//! inner `Mutex<Option<Connection>>`. In steady state the value is
//! 1 (lazy init on first delete in the process). Higher values
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
use crate::engine_types::AuditHmacKey;
use crate::event::EventMetadataKind;
use crate::timeline::BodySha256;
use crate::world;

/// One audit append's input. Owns its strings/buffers because the
/// `spawn_blocking` closure that runs the SQL must be `'static`.
pub(crate) struct AuditAppendJob {
    pub(crate) ledger_world: &'static str,
    pub(crate) event_type: EventMetadataKind,
    pub(crate) target: String,
    pub(crate) body_sha256: BodySha256,
    pub(crate) size: i64,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) key: AuditHmacKey,
}

/// Result of an audit append run inside `spawn_blocking`. Shared
/// between the cached path here and the verb handlers
/// (`handler::execute_delete`).
#[derive(Debug)]
pub(crate) enum BlockingSqliteError {
    Audit(audit::AuditError),
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
    /// Never invalidated -- the ledger world is never deleted by
    /// public delete operation (`var/log/*` is reserved).
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
    /// succeeds -- failed opens leave the slot as `None` and do not
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
        let Some(conn) = guard.as_mut() else {
            return Err(BlockingSqliteError::Worker);
        };
        let is_empty = ledger_is_empty(conn).map_err(BlockingSqliteError::Sqlite)?;
        let append = if is_empty {
            audit::append_with_conn_genesis
        } else {
            audit::append_with_conn_existing
        };
        append(
            conn,
            job.event_type,
            &job.target,
            &job.body_sha256,
            job.size,
            &job.content_type,
            &job.headers,
            &job.key,
        )
        .map_err(BlockingSqliteError::Audit)
    }
}

fn ledger_is_empty(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| {
        Ok(r.get::<_, i64>(0)? == 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    #[test]
    fn append_uses_genesis_for_existing_empty_ledger() {
        let dir = std::env::temp_dir().join(format!("elastik-ledger-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        drop(world::open(&dir, "var/log/deletes").unwrap());

        let ledger = LedgerWriter::new();
        let hmac = ledger
            .append(
                &dir,
                AuditAppendJob {
                    ledger_world: "var/log/deletes",
                    event_type: EventMetadataKind::DELETE_INTENT,
                    target: "home/deleted".to_owned(),
                    body_sha256: BodySha256::for_body(b"body"),
                    size: 0,
                    content_type: "application/octet-stream".to_owned(),
                    headers: Vec::new(),
                    key: test_key(),
                },
            )
            .unwrap();

        let c = Connection::open(world::world_db(&dir, "var/log/deletes")).unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let stored_hmac: String = c
            .query_row("SELECT hmac FROM events WHERE id=1", [], |r| r.get(0))
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(stored_hmac, hmac);
        let _ = std::fs::remove_dir_all(dir);
    }
}
