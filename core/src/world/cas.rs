//! CAS body retention for one world's SQLite file.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::marker::PhantomData;
use std::path::Path;

use crate::{
    engine_types::ValidatedWorldPath,
    event::AuditEventKind,
    timeline::{BodySha256, TimelineSeq},
};

use super::{open_existing_validated, WriteAuditError};

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
        if floor != first_body_event_seq_tx(tx)? {
            return Err(WriteAuditError::StorageInvariant(
                "cas_state first_retained_seq does not match first body event",
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

pub fn storage_len(
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing_validated(data_root, world)? else {
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
    Ok(Some(
        (current_len.max(0) as usize).saturating_add(retained_len.max(0) as usize),
    ))
}

pub fn body_len_if_missing(
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
) -> rusqlite::Result<usize> {
    let Some(c) = open_existing_validated(data_root, world)? else {
        return Ok(body.len());
    };
    missing_body_len(&c, body)
}

pub fn append_body_len_if_missing(
    data_root: &Path,
    world: &ValidatedWorldPath,
    append_body: &[u8],
) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing_validated(data_root, world)? else {
        return Ok(None);
    };
    let mut body: Vec<u8> =
        c.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))?;
    body.extend_from_slice(append_body);
    Ok(Some(missing_body_len(&c, &body)?))
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
