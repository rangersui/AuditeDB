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

use crate::audit::{self, AuditHeaders};
use crate::engine_types::{AuditHmacKey, ValidatedWorldPath};
use crate::event::{AuditEventKind, EventMetadataKind};
use crate::state::FileOpPermit;
use crate::subscription_event_id::SubscriptionEventId;
use crate::timeline::{BodySha256, DeleteSubjectProof};
use crate::world;

/// One audit append's input. Owns its strings/buffers so the delete
/// ledger append can run after async request parsing has finished.
pub(crate) struct AuditAppendJob {
    pub(crate) event_type: EventMetadataKind,
    pub(crate) target: ValidatedWorldPath,
    pub(crate) body_sha256: BodySha256,
    pub(crate) size: i64,
    pub(crate) content_type: String,
    pub(crate) headers: AuditHeaders,
    pub(crate) key: AuditHmacKey,
}

/// Result of an audit append. Shared between the cached path here and
/// delete operation code.
#[derive(Debug)]
pub(crate) enum BlockingSqliteError {
    Audit(audit::AuditError),
    Sqlite(rusqlite::Error),
    Worker,
}

/// One successfully appended row in the delete ledger.
pub(crate) struct AppendedLedgerEvent {
    event_type: AuditEventKind,
    target: ValidatedWorldPath,
    event_id: SubscriptionEventId,
    body_sha256: BodySha256,
    size: i64,
    content_type: String,
    delete_subject: Option<DeleteSubjectProof>,
    hmac: String,
    format_event: Option<audit::AppendedAuditRow>,
}

/// Proof view that a ledger row is the delete intent for a subject delete.
pub(crate) struct AppendedDeleteIntentEvent<'a>(&'a AppendedLedgerEvent);

impl AppendedLedgerEvent {
    pub(crate) fn event_type(&self) -> AuditEventKind {
        self.event_type
    }

    pub(crate) fn event_id(&self) -> &SubscriptionEventId {
        &self.event_id
    }

    pub(crate) fn target(&self) -> &ValidatedWorldPath {
        &self.target
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }

    pub(crate) fn size(&self) -> i64 {
        self.size
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
    }

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject.as_ref()
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }

    pub(crate) fn format_event(&self) -> Option<&audit::AppendedAuditRow> {
        self.format_event.as_ref()
    }

    pub(crate) fn as_delete_intent(&self) -> Option<AppendedDeleteIntentEvent<'_>> {
        if self.event_type == AuditEventKind::DeleteIntent {
            Some(AppendedDeleteIntentEvent(self))
        } else {
            None
        }
    }
}

impl AppendedDeleteIntentEvent<'_> {
    pub(crate) fn event_id(&self) -> &SubscriptionEventId {
        self.0.event_id()
    }

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.0.delete_subject()
    }
}

/// Cached writer + init counter for `var/log/deletes`. The inner
/// `StdMutex` is the SOLE serializer for ledger appends; the
/// per-world write lock at `var/log/deletes` is intentionally
/// gone (Bug 25). Don't re-add it.
pub(crate) struct LedgerWriter {
    /// `None` until the first successful permitted world open in
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

    pub(crate) fn close(&self) {
        let mut guard = self
            .conn
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.take();
    }

    /// Append one row to `var/log/deletes` using the cached
    /// connection. Lazy-initializes via `world::open_validated` under
    /// the caller's `FileOpPermit` on the first successful call.
    /// Increments `inits` only after the open succeeds -- failed opens
    /// leave the slot as `None` and do not count.
    ///
    /// Caller must hold a `FileOpPermit` before appending. Delete
    /// acquires async locks first, then appends synchronously under the
    /// fd-lifetime gate so shutdown can wait for the cached ledger fd.
    pub(crate) fn append(
        &self,
        data: &Path,
        job: AuditAppendJob,
        _file_op: &FileOpPermit,
    ) -> Result<AppendedLedgerEvent, BlockingSqliteError> {
        let ledger_world = delete_ledger_world();
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            // Lazy init. `world::open_validated` creates the schema; safe to
            // call whether or not the ledger DB exists on disk.
            let conn = world::open_validated(data, &ledger_world, _file_op)
                .map_err(BlockingSqliteError::Sqlite)?;
            *guard = Some(conn);
            self.inits.fetch_add(1, Ordering::Relaxed);
        }
        let Some(conn) = guard.as_mut() else {
            return Err(BlockingSqliteError::Worker);
        };
        let is_empty = ledger_is_empty(conn).map_err(BlockingSqliteError::Sqlite)?;
        let requested_event_type = job.event_type;
        let delete_subject = job.headers.delete_subject().cloned();
        let (format_event, row) = if is_empty {
            let (format_event, row) = audit::append_with_conn_genesis_row(
                conn,
                requested_event_type,
                &ledger_world,
                &job.target,
                &job.body_sha256,
                job.size,
                &job.content_type,
                &job.headers,
                &job.key,
            )
            .map_err(BlockingSqliteError::Audit)?;
            (Some(format_event), row)
        } else {
            let row = audit::append_with_conn_existing_row(
                conn,
                requested_event_type,
                &ledger_world,
                &job.target,
                &job.body_sha256,
                job.size,
                &job.content_type,
                &job.headers,
                &job.key,
            )
            .map_err(BlockingSqliteError::Audit)?;
            (None, row)
        };
        Ok(AppendedLedgerEvent {
            event_type: row.event_type(),
            target: row.target().clone(),
            event_id: SubscriptionEventId::from_appended_audit_row(&row),
            body_sha256: row.body_sha256().clone(),
            size: row.size(),
            content_type: row.content_type().to_owned(),
            // This proof is signed into the row's event headers. The append
            // row object does not expose event headers, so the cached proof
            // stays request-derived while row identity fields above are
            // row-derived.
            delete_subject,
            hmac: row.hmac().to_owned(),
            format_event,
        })
    }
}

fn ledger_is_empty(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| {
        Ok(r.get::<_, i64>(0)? == 0)
    })
}

fn delete_ledger_world() -> ValidatedWorldPath {
    match ValidatedWorldPath::new("var/log/deletes") {
        Ok(world) => world,
        // Invariant: var/log/deletes is a constant canonical world path.
        Err(reason) => unreachable!("delete ledger world is a constant canonical path: {reason}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    #[test]
    fn append_uses_genesis_for_existing_empty_ledger() {
        let dir =
            std::env::temp_dir().join(format!("auditedb-ledger-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        drop(world::open(&dir, "var/log/deletes").unwrap());

        let ledger = LedgerWriter::new();
        let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
        let file_op = gate.begin().unwrap();
        let event = ledger
            .append(
                &dir,
                AuditAppendJob {
                    event_type: EventMetadataKind::DELETE_INTENT,
                    target: ValidatedWorldPath::new("home/deleted").unwrap(),
                    body_sha256: BodySha256::for_body(b"body"),
                    size: 0,
                    content_type: "application/octet-stream".to_owned(),
                    headers: AuditHeaders::empty(),
                    key: test_key(),
                },
                &file_op,
            )
            .unwrap();

        let c = Connection::open(world::world_db(&dir, "var/log/deletes")).unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let stored_format: String = c
            .query_row("SELECT event_type FROM events WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let stored_hmac: String = c
            .query_row("SELECT hmac FROM events WHERE id=2", [], |r| r.get(0))
            .unwrap();

        assert_eq!(count, 2);
        assert_eq!(stored_format, "format");
        assert!(event.format_event().is_some());
        assert_eq!(stored_hmac, event.hmac());
        assert_eq!(event.event_id().world().as_str(), "var/log/deletes");
        assert_eq!(event.event_id().seq().get(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
