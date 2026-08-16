//! CAS body retention for one world's SQLite file.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::marker::PhantomData;
use std::path::Path;

use crate::{
    engine_types::ValidatedWorldPath,
    event::AuditEventKind,
    state::FileOpPermit,
    timeline::{BodySha256, TimelineSeq},
};

use super::{
    open_existing_validated, AccountedStorageUsage, StorageUsageSnapshot, WriteAuditError,
};

fn nonnegative_usize(value: i64, column: usize) -> rusqlite::Result<usize> {
    usize::try_from(value.max(0)).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(err),
        )
    })
}

/// Proof that this transaction has retained the full body in CAS storage.
///
/// The lifetimes bind the proof to the transaction that inserted or verified
/// the body, and the private transaction pointer lets the audit append sink
/// reject a proof from a different live transaction with the same lifetime.
pub(crate) struct RetainedCasBody<'tx, 'conn> {
    target: ValidatedWorldPath,
    body_sha256: BodySha256,
    size: i64,
    inserted: bool,
    tx: *const Transaction<'conn>,
    _tx: PhantomData<&'tx Transaction<'conn>>,
}

/// Positive count of body-bearing audit rows whose CAS blobs remain readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedBodyCount {
    count: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PrunedCas {
    bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplaceQuotaSnapshot {
    previous_body_len: usize,
    candidate_cas_len: usize,
    prunable_cas_len: usize,
}

struct EstimatedRetentionFloor(TimelineSeq);

impl<'tx, 'conn> RetainedCasBody<'tx, 'conn> {
    pub(crate) fn target(&self) -> &ValidatedWorldPath {
        &self.target
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }

    pub(crate) fn size(&self) -> i64 {
        self.size
    }

    pub(crate) fn inserted(&self) -> bool {
        self.inserted
    }

    pub(crate) fn was_retained_in(&self, tx: &Transaction<'conn>) -> bool {
        std::ptr::eq(self.tx, tx)
    }
}

impl RetainedBodyCount {
    pub(crate) fn new(value: usize) -> Option<Self> {
        (value > 0
            && value <= crate::defaults::MAX_RETAINED_BODY_COUNT
            && i64::try_from(value).is_ok())
        .then_some(Self { count: value })
    }

    pub(crate) fn get(self) -> usize {
        self.count
    }
}

impl Default for RetainedBodyCount {
    fn default() -> Self {
        Self {
            count: crate::defaults::DEFAULT_RETAINED_BODY_COUNT,
        }
    }
}

impl PrunedCas {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl ReplaceQuotaSnapshot {
    pub(crate) fn previous_body_len(self) -> usize {
        self.previous_body_len
    }

    pub(crate) fn candidate_cas_len(self) -> usize {
        self.candidate_cas_len
    }

    pub(crate) fn prunable_cas_len(self) -> usize {
        self.prunable_cas_len
    }
}

pub(super) fn retain_body_tx<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    target: &ValidatedWorldPath,
    body: &[u8],
) -> Result<RetainedCasBody<'tx, 'conn>, WriteAuditError> {
    let body_sha256 = BodySha256::for_body(body);
    let size = i64::try_from(body.len())
        .map_err(|_| WriteAuditError::StorageInvariant("body length does not fit i64"))?;
    let inserted = tx.execute(
        r#"INSERT INTO cas_bodies(body_sha256, body)
           VALUES(?1, ?2)
           ON CONFLICT(body_sha256) DO NOTHING"#,
        params![body_sha256.as_str(), body],
    )? == 1;
    let stored_len: Option<i64> = tx.query_row(
        "SELECT CASE WHEN typeof(body)='blob' THEN length(body) END
         FROM cas_bodies WHERE body_sha256=?1",
        params![body_sha256.as_str()],
        |r| r.get(0),
    )?;
    if stored_len != Some(size) {
        return Err(WriteAuditError::CasBodyMismatch { body_sha256 });
    }
    Ok(RetainedCasBody {
        target: target.clone(),
        body_sha256,
        size,
        inserted,
        tx,
        _tx: PhantomData,
    })
}

pub(super) fn mark_retention_started_tx(
    tx: &Transaction<'_>,
    event_id: TimelineSeq,
) -> Result<(), WriteAuditError> {
    let floor = tx
        .query_row(
            "SELECT first_retained_seq FROM cas_state WHERE id=1",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .ok_or(WriteAuditError::StorageInvariant(
            "cas_state singleton row missing",
        ))?;
    if let Some(floor) = floor {
        let floor = TimelineSeq::new(floor).map_err(|_| {
            WriteAuditError::StorageInvariant("cas_state first_retained_seq invalid")
        })?;
        if !body_event_exists_tx(tx, floor)? {
            return Err(WriteAuditError::StorageInvariant(
                "cas_state first_retained_seq does not point at a body event",
            ));
        }
        if floor > event_id {
            return Err(WriteAuditError::StorageInvariant(
                "cas_state first_retained_seq is ahead of event row",
            ));
        }
        return Ok(());
    }
    if first_body_event_seq_tx(tx)? != event_id {
        return Err(WriteAuditError::StorageInvariant(
            "cas retention cannot start after existing body events",
        ));
    }
    let changed = tx.execute(
        "UPDATE cas_state SET first_retained_seq=?1 WHERE id=1",
        params![event_id.get()],
    )?;
    if changed != 1 {
        return Err(WriteAuditError::StorageInvariant(
            "cas_state singleton row missing",
        ));
    }
    Ok(())
}

pub(super) fn prune_to_count_tx(
    tx: &Transaction<'_>,
    retained: RetainedBodyCount,
) -> Result<PrunedCas, WriteAuditError> {
    let Some(new_floor) = retained_floor_for_count_tx(tx, retained)? else {
        return Ok(PrunedCas::default());
    };
    let current_floor = tx
        .query_row(
            "SELECT first_retained_seq FROM cas_state WHERE id=1",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .ok_or(WriteAuditError::StorageInvariant(
            "cas_state singleton row missing",
        ))?
        .map(|seq| {
            TimelineSeq::new(seq).map_err(|_| {
                WriteAuditError::StorageInvariant("cas_state first_retained_seq invalid")
            })
        })
        .transpose()?;
    if current_floor.is_some_and(|floor| new_floor <= floor) {
        return Ok(PrunedCas::default());
    }

    tx.execute_batch(
        r#"CREATE TEMP TABLE cas_prune_candidates (
               body_sha256 TEXT PRIMARY KEY
           ) WITHOUT ROWID;"#,
    )?;
    tx.execute(
        r#"INSERT INTO temp.cas_prune_candidates(body_sha256)
           SELECT body_sha256 FROM cas_bodies
           WHERE body_sha256 IN (
               SELECT body_sha256 FROM events
               WHERE event_type IN (?1, ?2) AND id < ?3
           )
           AND body_sha256 NOT IN (
               SELECT body_sha256 FROM events
               WHERE event_type IN (?1, ?2) AND id >= ?3
           )"#,
        params![
            AuditEventKind::Put.as_str(),
            AuditEventKind::Append.as_str(),
            new_floor.get(),
        ],
    )?;
    let pruned_bytes: i64 = tx.query_row(
        r#"SELECT COALESCE(SUM(length(c.body)), 0)
           FROM cas_bodies AS c
           JOIN temp.cas_prune_candidates AS p USING(body_sha256)"#,
        [],
        |r| r.get(0),
    )?;
    tx.execute(
        r#"DELETE FROM cas_bodies
           WHERE body_sha256 IN (
               SELECT body_sha256 FROM temp.cas_prune_candidates
           )"#,
        [],
    )?;
    let remaining_old_bodies: i64 = tx.query_row(
        r#"SELECT COUNT(*)
           FROM cas_bodies AS c
           JOIN temp.cas_prune_candidates AS p USING(body_sha256)"#,
        [],
        |r| r.get(0),
    )?;
    if remaining_old_bodies != 0 {
        return Err(WriteAuditError::StorageInvariant(
            "old CAS bodies remain after retention prune",
        ));
    }
    let changed = tx.execute(
        "UPDATE cas_state SET first_retained_seq=?1 WHERE id=1",
        params![new_floor.get()],
    )?;
    if changed != 1 {
        return Err(WriteAuditError::StorageInvariant(
            "cas_state singleton row missing",
        ));
    }
    tx.execute("DROP TABLE temp.cas_prune_candidates", [])?;
    Ok(PrunedCas {
        bytes: nonnegative_usize(pruned_bytes, 0)?,
    })
}

#[cfg(test)]
pub fn storage_len(
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> rusqlite::Result<Option<usize>> {
    let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
    let file_op = gate.begin().ok_or_else(|| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERNAL),
            Some("test file operation gate unexpectedly closed".to_owned()),
        )
    })?;
    Ok(storage_usage(
        &mut crate::blocking_sqlite::test_only_mint(),
        data_root,
        world,
        &file_op,
    )?
    .map(StorageUsageSnapshot::total_body_bytes))
}

pub fn storage_usage(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<StorageUsageSnapshot>> {
    storage_usage_inner(proof, data_root, world, file_op)
}

pub fn accounted_storage_usage(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<AccountedStorageUsage>> {
    Ok(
        storage_usage_inner(proof, data_root, world, file_op)?.map(|usage| AccountedStorageUsage {
            data_root: data_root.to_path_buf(),
            world: world.clone(),
            usage,
        }),
    )
}

fn storage_usage_inner(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<StorageUsageSnapshot>> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(None);
    };
    let current_len: i64 = c.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let retained_len: i64 = c.query_row(
        r#"SELECT COALESCE(SUM(
               CASE WHEN typeof(body)='blob' THEN length(body) END
           ), 0)
           FROM cas_bodies"#,
        [],
        |r| r.get(0),
    )?;
    let events: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let current_len = nonnegative_usize(current_len, 0)?;
    let retained_len = nonnegative_usize(retained_len, 0)?;
    current_len
        .checked_add(retained_len)
        .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
    Ok(Some(StorageUsageSnapshot::from_durable_parts(
        current_len,
        retained_len,
        nonnegative_usize(events, 0)?,
    )))
}

pub(crate) fn replace_quota_snapshot(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    retained: RetainedBodyCount,
    file_op: &FileOpPermit,
) -> rusqlite::Result<ReplaceQuotaSnapshot> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(ReplaceQuotaSnapshot {
            previous_body_len: 0,
            candidate_cas_len: body.len(),
            prunable_cas_len: 0,
        });
    };
    let previous_body_len = c.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |row| nonnegative_usize(row.get::<_, i64>(0)?, 0),
    )?;
    Ok(ReplaceQuotaSnapshot {
        previous_body_len,
        candidate_cas_len: missing_body_len(&c, body)?,
        prunable_cas_len: prunable_body_len_after_next_body(&c, body, retained)?,
    })
}

pub fn append_body_len_if_missing(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    append_body: &[u8],
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(None);
    };
    let mut body: Vec<u8> =
        c.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))?;
    body.extend_from_slice(append_body);
    Ok(Some(missing_body_len(&c, &body)?))
}

pub fn append_prunable_body_len_after_next_write(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    append_body: &[u8],
    retained: RetainedBodyCount,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(None);
    };
    let mut body: Vec<u8> =
        c.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))?;
    body.extend_from_slice(append_body);
    Ok(Some(prunable_body_len_after_next_body(
        &c, &body, retained,
    )?))
}

fn retained_floor_for_count_tx(
    tx: &Transaction<'_>,
    retained: RetainedBodyCount,
) -> Result<Option<TimelineSeq>, WriteAuditError> {
    let limit = i64::try_from(retained.get())
        .map_err(|_| WriteAuditError::StorageInvariant("retained body count exceeds i64"))?;
    let row = tx
        .query_row(
            r#"SELECT id FROM (
                   SELECT id FROM events
                   WHERE event_type IN (?1, ?2)
                   ORDER BY id DESC
                   LIMIT ?3
               )
               ORDER BY id ASC
               LIMIT 1"#,
            params![
                AuditEventKind::Put.as_str(),
                AuditEventKind::Append.as_str(),
                limit,
            ],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    row.map(|seq| {
        TimelineSeq::new(seq)
            .map_err(|_| WriteAuditError::StorageInvariant("body event id invalid"))
    })
    .transpose()
}

fn first_body_event_seq_tx(tx: &Transaction<'_>) -> Result<TimelineSeq, WriteAuditError> {
    let seq: i64 = tx.query_row(
        "SELECT id FROM events WHERE event_type IN (?1, ?2) ORDER BY id ASC LIMIT 1",
        params![
            AuditEventKind::Put.as_str(),
            AuditEventKind::Append.as_str()
        ],
        |r| r.get(0),
    )?;
    TimelineSeq::new(seq).map_err(|_| WriteAuditError::StorageInvariant("body event id invalid"))
}

fn body_event_exists_tx(tx: &Transaction<'_>, seq: TimelineSeq) -> Result<bool, WriteAuditError> {
    let exists = tx
        .query_row(
            "SELECT 1 FROM events WHERE id=?1 AND event_type IN (?2, ?3)",
            params![
                seq.get(),
                AuditEventKind::Put.as_str(),
                AuditEventKind::Append.as_str(),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn missing_body_len(c: &Connection, body: &[u8]) -> rusqlite::Result<usize> {
    let body_sha256 = BodySha256::for_body(body);
    let exists = c
        .query_row(
            "SELECT 1 FROM cas_bodies WHERE body_sha256=?1",
            params![body_sha256.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(if exists { 0 } else { body.len() })
}

fn prunable_body_len_after_next_body(
    c: &Connection,
    body: &[u8],
    retained: RetainedBodyCount,
) -> rusqlite::Result<usize> {
    let Some(new_floor) = retained_floor_after_next_body(c, retained)? else {
        return Ok(0);
    };
    let current_floor = c
        .query_row(
            "SELECT first_retained_seq FROM cas_state WHERE id=1",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten()
        .map(TimelineSeq::new)
        .transpose()
        .map_err(|_| corrupt("cas_state first_retained_seq invalid"))?;
    if current_floor.is_some_and(|floor| new_floor.seq() <= floor) {
        return Ok(0);
    }

    let candidate = BodySha256::for_body(body);
    let pruned_bytes: i64 = c.query_row(
        r#"SELECT COALESCE(SUM(length(body)), 0)
           FROM cas_bodies
           WHERE body_sha256 IN (
               SELECT body_sha256 FROM events
               WHERE event_type IN (?1, ?2) AND id < ?3
           )
           AND body_sha256 <> ?4
           AND body_sha256 NOT IN (
               SELECT body_sha256 FROM events
               WHERE event_type IN (?1, ?2) AND id >= ?3
           )"#,
        params![
            AuditEventKind::Put.as_str(),
            AuditEventKind::Append.as_str(),
            new_floor.seq().get(),
            candidate.as_str(),
        ],
        |r| r.get(0),
    )?;
    nonnegative_usize(pruned_bytes, 0)
}

fn retained_floor_after_next_body(
    c: &Connection,
    retained: RetainedBodyCount,
) -> rusqlite::Result<Option<EstimatedRetentionFloor>> {
    let Ok(retained_limit) = i64::try_from(retained.get()) else {
        return Ok(None);
    };
    let existing_body_rows: i64 = c.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type IN (?1, ?2)",
        params![
            AuditEventKind::Put.as_str(),
            AuditEventKind::Append.as_str()
        ],
        |r| r.get(0),
    )?;
    if existing_body_rows.saturating_add(1) < retained_limit {
        return Ok(None);
    }
    if retained_limit == 1 {
        let next_event_id: i64 =
            c.query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM events", [], |r| {
                r.get(0)
            })?;
        return EstimatedRetentionFloor::new(next_event_id).map(Some);
    }
    let existing_to_keep = retained_limit - 1;
    let floor = c
        .query_row(
            r#"SELECT id FROM (
               SELECT id FROM events
               WHERE event_type IN (?1, ?2)
               ORDER BY id DESC
               LIMIT ?3
           )
           ORDER BY id ASC
           LIMIT 1"#,
            params![
                AuditEventKind::Put.as_str(),
                AuditEventKind::Append.as_str(),
                existing_to_keep,
            ],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    floor.map(EstimatedRetentionFloor::new).transpose()
}

impl EstimatedRetentionFloor {
    fn new(seq: i64) -> rusqlite::Result<Self> {
        TimelineSeq::new(seq)
            .map(Self)
            .map_err(|_| corrupt("estimated retention floor is not a positive event id"))
    }

    fn seq(&self) -> TimelineSeq {
        self.0
    }
}

fn corrupt(message: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
        Some(message.to_owned()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn prune_temp_table_fails_loud_and_rolls_back_cleanly() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"CREATE TABLE cas_state (
                   id INTEGER PRIMARY KEY,
                   first_retained_seq INTEGER
               );
               INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
               CREATE TABLE events (
                   id INTEGER PRIMARY KEY,
                   event_type TEXT NOT NULL,
                   body_sha256 TEXT NOT NULL
               );
               INSERT INTO events(id, event_type, body_sha256)
               VALUES(1, 'put', 'old'), (2, 'put', 'new');
               CREATE TABLE cas_bodies (
                   body_sha256 TEXT PRIMARY KEY,
                   body BLOB NOT NULL
               );
               INSERT INTO cas_bodies(body_sha256, body)
               VALUES('old', x'6f6c64'), ('new', x'6e6577');
               CREATE TEMP TABLE cas_prune_candidates(wrong_shape INTEGER);"#,
        )
        .unwrap();

        let retained = RetainedBodyCount::new(1).unwrap();
        let tx = conn.transaction().unwrap();
        assert!(matches!(
            prune_to_count_tx(&tx, retained),
            Err(WriteAuditError::Sqlite(_))
        ));
        drop(tx);
        conn.execute_batch(
            r#"DROP TABLE temp.cas_prune_candidates;
               CREATE TRIGGER fail_floor_update
               BEFORE UPDATE OF first_retained_seq ON cas_state
               BEGIN
                   SELECT RAISE(ABORT, 'injected floor update failure');
               END;"#,
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        assert!(matches!(
            prune_to_count_tx(&tx, retained),
            Err(WriteAuditError::Sqlite(_))
        ));
        drop(tx);
        conn.execute_batch("DROP TRIGGER fail_floor_update")
            .unwrap();

        let tx = conn.transaction().unwrap();
        let pruned = prune_to_count_tx(&tx, retained).unwrap();
        assert_eq!(pruned.bytes(), 3);
        tx.commit().unwrap();

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM cas_bodies", [], |row| row.get(0))
            .unwrap();
        let temp_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM temp.sqlite_schema WHERE name='cas_prune_candidates'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(temp_tables, 0);
    }
}
