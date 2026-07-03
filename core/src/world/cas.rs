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
        (value > 0 && i64::try_from(value).is_ok()).then_some(Self { count: value })
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
    let stored: Vec<u8> = tx.query_row(
        "SELECT body FROM cas_bodies WHERE body_sha256=?1",
        params![body_sha256.as_str()],
        |r| r.get(0),
    )?;
    if stored != body {
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

    let pruned_bytes: i64 = tx.query_row(
        r#"SELECT COALESCE(SUM(length(body)), 0)
           FROM cas_bodies
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
        |r| r.get(0),
    )?;
    tx.execute(
        r#"DELETE FROM cas_bodies
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
    let remaining_old_bodies: i64 = tx.query_row(
        r#"SELECT COUNT(*)
           FROM cas_bodies
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
    Ok(PrunedCas {
        bytes: pruned_bytes.max(0) as usize,
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
    Ok(Some(StorageUsageSnapshot::from_durable_parts(
        current_len.max(0) as usize,
        retained_len.max(0) as usize,
        events.max(0) as usize,
    )))
}

pub fn body_len_if_missing(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    file_op: &FileOpPermit,
) -> rusqlite::Result<usize> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(body.len());
    };
    missing_body_len(&c, body)
}

pub fn prunable_body_len_after_next_write(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    retained: RetainedBodyCount,
    file_op: &FileOpPermit,
) -> rusqlite::Result<usize> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(0);
    };
    prunable_body_len_after_next_body(&c, body, retained)
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
    Ok(pruned_bytes.max(0) as usize)
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
