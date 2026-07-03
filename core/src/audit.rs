//! HMAC event chain: one row per write, linked by `prev_hmac`.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{OptionalExtension, Statement, Transaction};
use sha2::{Digest, Sha256};

use crate::{
    blocking_sqlite::BlockingSqlite,
    chain_stamp::{ChainSeq, ChainStamp, ChainStampRead},
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::AuditEventKind,
    timeline::{BodySha256, TimelineSeq},
    world,
    world_generation::WorldGeneration,
};
use std::{fmt, path::Path};

mod append;
mod headers;
mod live_body;
mod retention;
#[cfg(test)]
mod test_support;
mod timeline_address;
pub(crate) mod timeline_dereference;
mod timeline_row;
mod verifier;

#[cfg(test)]
use append::test_only_append_tx_inner as append_tx_inner;
pub(crate) use append::{
    append_format_tx_row, append_retained_body_tx_row, append_with_conn_existing_row,
    append_with_conn_genesis_row, AppendedAuditRow, AppendedBodyAuditRow, AppendedBodyEvent,
};
pub(crate) use headers::{AuditHeaders, VerifiedDeleteSubject};
#[cfg(test)]
pub(crate) use headers::{
    DELETE_SUBJECT_BODY_SHA256, DELETE_SUBJECT_GENERATION, DELETE_SUBJECT_HMAC, DELETE_SUBJECT_SEQ,
    DELETE_SUBJECT_WORLD,
};
#[cfg(test)]
use rusqlite::Connection;
#[cfg(test)]
pub use test_support::latest_hmac;
pub(crate) use timeline_address::{
    read_timeline_body_via_conn, verified_latest_body_head_via_conn,
    verified_replay_events_after_via_conn, VerifiedBodyEvent, VerifiedBodyHead,
    VerifiedExpiredTimelineBody, VerifiedReplayAfter, VerifiedReplayBodyEvent, VerifiedReplayEvent,
    VerifiedReplayNonBodyEvent,
};
#[cfg(feature = "unstable-engine")]
pub use timeline_dereference::{
    TimelineDereference, VerifiedBodyHashMismatch, VerifiedExpiredBody, VerifiedGenerationMismatch,
    VerifiedMissingRow, VerifiedNonBodyEvent,
};
pub(crate) use timeline_row::MatchedTimelineRowHmac;
use verifier::{verify_statement_capture, verify_tail_event, VerifyCapturedReport};
pub(crate) use verifier::{
    VerifiedChainHead, VerifiedChainHeadParts, VerifiedChainStampMissingParts,
    VerifiedChainStampParts,
};

const AUDIT_SELECT: &str = r#"SELECT e.id, e.timestamp, e.event_type, e.target, e.body_sha256, e.size,
                  e.content_type, e.meta_sha256, e.hmac, e.prev_hmac,
                  h.name, h.value
           FROM events e
           LEFT JOIN event_headers h ON h.event_id=e.id
           ORDER BY e.id ASC, h.name ASC, h.value ASC"#;
const AUDIT_TAIL_SELECT: &str = r#"SELECT e.id, e.timestamp, e.event_type, e.target, e.body_sha256, e.size,
                  e.content_type, e.meta_sha256, e.hmac, e.prev_hmac,
                  h.name, h.value
           FROM events e
           LEFT JOIN event_headers h ON h.event_id=e.id
           WHERE e.id=(SELECT id FROM events ORDER BY id DESC LIMIT 1)
           ORDER BY h.name ASC, h.value ASC"#;
pub(crate) const AUDIT_CHAIN_BROKEN_PREFIX: &str = "audit chain broken at event ";
const WORLD_FORMAT_VERSION_HEADER: &str = "auditedb-world-format-version";

pub struct VerifiedAuditTx<'tx, 'conn, 'key> {
    tx: &'tx Transaction<'conn>,
    key: &'key AuditHmacKey,
    world: ValidatedWorldPath,
    generation: WorldGeneration,
}

pub type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug)]
pub enum AuditError {
    ChainBroken(VerifyBreak),
    Storage(rusqlite::Error),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainBroken(break_report) => write!(
                f,
                "{AUDIT_CHAIN_BROKEN_PREFIX}{}: expected {}, actual {}",
                break_report.break_at, break_report.expected, break_report.actual
            ),
            Self::Storage(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<rusqlite::Error> for AuditError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

#[derive(Clone, Copy)]
enum EmptyChain {
    Allow,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOk {
    pub events: usize,
    pub genesis: String,
    pub latest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyBreak {
    pub break_at: usize,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyReport {
    Valid(VerifyOk),
    Broken(VerifyBreak),
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_all_worlds(data_root: &Path, key: &AuditHmacKey) -> AuditResult<()> {
    let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
    let file_op = gate
        .begin()
        .ok_or_else(|| AuditError::Storage(file_op_gate_closed_error()))?;
    for world in
        crate::blocking_sqlite::run_scoped(|proof| world::list(proof, data_root, &file_op))?
    {
        crate::blocking_sqlite::run_scoped(|proof| {
            verify_world_with_file_op(proof, data_root, &world, key, &file_op)
        })?;
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_world(
    data_root: &Path,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> AuditResult<()> {
    let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
    let file_op = gate
        .begin()
        .ok_or_else(|| AuditError::Storage(file_op_gate_closed_error()))?;
    crate::blocking_sqlite::run_scoped(|proof| {
        verify_world_with_file_op(proof, data_root, world, key, &file_op)
    })
}

pub(crate) fn verify_world_with_file_op(
    proof: &mut crate::blocking_sqlite::BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
    file_op: &crate::state::FileOpPermit,
) -> AuditResult<()> {
    let Some(mut c) = world::open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(());
    };
    let tx = c.transaction()?;
    require_intact(verify_world_tx(proof, &tx, world, key)?)?;
    if let Some(break_report) = live_body::verify_tx(&tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(())
}

fn file_op_gate_closed_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERNAL),
        Some("file operation gate unexpectedly closed".to_owned()),
    )
}

pub(crate) fn require_world_intact_tx(
    proof: &mut BlockingSqlite,
    tx: &Transaction<'_>,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> AuditResult<()> {
    require_intact(verify_world_tx(proof, tx, world, key)?)?;
    if let Some(break_report) = live_body::verify_tx(tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(())
}

pub(crate) fn require_current_world_intact_tx(
    proof: &mut BlockingSqlite,
    tx: &Transaction<'_>,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> AuditResult<()> {
    require_current_tail_intact_tx(proof, tx, world, key)
}

pub(crate) fn verify_appendable_tx_existing_checked<'tx, 'conn, 'key>(
    proof: &mut BlockingSqlite,
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx_full(proof, tx, world_name, key, EmptyChain::Reject)
}

pub(crate) fn verify_appendable_tx_genesis_checked<'tx, 'conn, 'key>(
    proof: &mut BlockingSqlite,
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx(proof, tx, world_name, key, EmptyChain::Allow)
}

fn verify_appendable_tx<'tx, 'conn, 'key>(
    proof: &mut BlockingSqlite,
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx_full(proof, tx, world_name, key, empty_chain)
}

fn verify_appendable_tx_full<'tx, 'conn, 'key>(
    proof: &mut BlockingSqlite,
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    let generation = crate::world_schema::generation(proof, tx)?;
    let retention = retention::load_for_append(tx)?;
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    let allow_empty = matches!(empty_chain, EmptyChain::Allow);
    require_intact(verify_statement(
        &mut stmt,
        key,
        allow_empty,
        &retention,
        world_name,
        &generation,
    )?)?;
    if let Some(break_report) = verify_current_tail_body_tx(tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    if let Some(break_report) = live_body::verify_tx(tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(VerifiedAuditTx {
        tx,
        key,
        world: world_name.clone(),
        generation,
    })
}

/// O(1) current-state gate for ordinary reads.
///
/// Full-chain verification remains the explicit security primitive for engine
/// startup, explicit verify endpoints, chain-head reads, and durable write
/// authority. Ordinary current reads prove only the live tail they return:
/// current generation, latest row HMAC, latest `prev_hmac` link, CAS body for
/// the retained tail when applicable, and the live body pointer. This function
/// intentionally does not mint `VerifiedAuditTx`.
fn require_current_tail_intact_tx(
    proof: &mut BlockingSqlite,
    tx: &Transaction<'_>,
    world_name: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> AuditResult<()> {
    let generation = crate::world_schema::generation(proof, tx)?;
    let event_count = event_count_tx(tx)?;
    let Some((tail, headers)) = latest_event_with_headers_tx(tx)? else {
        return Err(AuditError::ChainBroken(VerifyBreak {
            break_at: 0,
            expected: "at-least-one-event".to_owned(),
            actual: "no-events".to_owned(),
        }));
    };
    let prev = previous_hmac_tx(tx, tail.id)?;
    if let Some(break_report) = verify_tail_event(
        &tail,
        &headers,
        key,
        world_name,
        &generation,
        prev,
        event_count,
    ) {
        return Err(AuditError::ChainBroken(break_report));
    }
    if let Some(break_report) =
        retention::verify_tail_body_tx(tx, &tail, event_count.saturating_sub(1))?
    {
        return Err(AuditError::ChainBroken(break_report));
    }
    if let Some(break_report) = live_body::verify_tx(tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(())
}

fn event_count_tx(tx: &Transaction<'_>) -> rusqlite::Result<usize> {
    let count = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))?;
    usize::try_from(count)
        .map_err(|_| rusqlite::Error::InvalidParameterName("negative audit event count".to_owned()))
}

fn latest_event_with_headers_tx(
    tx: &Transaction<'_>,
) -> rusqlite::Result<Option<EventWithHeaders>> {
    let mut stmt = tx.prepare(AUDIT_TAIL_SELECT)?;
    let mut rows = stmt.query([])?;
    let mut event: Option<EventRow> = None;
    let mut headers = Vec::new();

    while let Some(r) = rows.next()? {
        let row = EventRow {
            id: r.get(0)?,
            timestamp: r.get(1)?,
            event_type: r.get(2)?,
            target: r.get(3)?,
            body_sha256: r.get(4)?,
            size: r.get(5)?,
            content_type: r.get(6)?,
            meta_sha256: r.get(7)?,
            hmac: r.get(8)?,
            prev_hmac: r.get(9)?,
        };
        if let Some(existing) = &event {
            if existing.id != row.id {
                return Err(rusqlite::Error::InvalidQuery);
            }
        } else {
            event = Some(row);
        }
        let header_name: Option<String> = r.get(10)?;
        let header_value: Option<String> = r.get(11)?;
        if let (Some(name), Some(value)) = (header_name, header_value) {
            headers.push((name, value));
        }
    }

    Ok(event.map(|row| (row, headers)))
}

fn verify_current_tail_body_tx(tx: &Transaction<'_>) -> rusqlite::Result<Option<VerifyBreak>> {
    let event_count = event_count_tx(tx)?;
    let Some((tail, _headers)) = latest_event_with_headers_tx(tx)? else {
        return Ok(None);
    };
    retention::verify_tail_body_tx(tx, &tail, event_count.saturating_sub(1))
}

fn previous_hmac_tx(tx: &Transaction<'_>, tail_id: i64) -> rusqlite::Result<String> {
    tx.query_row(
        "SELECT hmac FROM events WHERE id < ?1 ORDER BY id DESC LIMIT 1",
        [tail_id],
        |r| r.get(0),
    )
    .optional()
    .map(|prev| prev.unwrap_or_default())
}

impl VerifiedAuditTx<'_, '_, '_> {
    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    pub(crate) fn generation(&self) -> &WorldGeneration {
        &self.generation
    }
}

struct EventRow {
    id: i64,
    timestamp: String,
    event_type: String,
    target: String,
    body_sha256: String,
    size: i64,
    content_type: String,
    meta_sha256: String,
    hmac: String,
    prev_hmac: String,
}

type EventWithHeaders = (EventRow, Vec<(String, String)>);

struct EventHmacInput<'a> {
    prev: &'a str,
    world: &'a ValidatedWorldPath,
    timestamp: &'a AuditTimestamp,
    event_type: &'a str,
    target: &'a str,
    generation: &'a WorldGeneration,
    body_sha256: &'a str,
    size: i64,
    content_type: &'a str,
    meta_sha256: &'a str,
}

struct AuditTimestamp(String);

impl AuditTimestamp {
    fn now_tx(tx: &Transaction<'_>) -> rusqlite::Result<Self> {
        let raw: String =
            tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })?;
        Self::from_storage(raw).map_err(timestamp_error)
    }

    fn from_storage(raw: String) -> Result<Self, String> {
        if is_canonical_sqlite_utc_timestamp(&raw) {
            Ok(Self(raw))
        } else {
            Err(raw)
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Verified chain-head read through the SlotState-tracked read path: the
/// world's generation plus the verified event count and latest event HMAC.
///
/// This is the unit of external anchoring: a host that remembers the returned
/// stamp can later prove tail truncation or rollback whenever the observed
/// head is behind the anchored seq -- which in-file verification structurally
/// cannot. A rolled-back or replaced chain re-grown past the anchor needs the
/// at-seq divergence check, a later PR. Returns `Ok(None)` for an empty
/// bootstrap-shape DB because there is no head to anchor yet.
///
/// Same type gate as `verify_chain_via_conn`: no bare-connection path, so a
/// delete on the same world drains in-flight head reads via the usual SlotState
/// write guard. The returned `VerifiedChainHead` is minted only after the audit
/// chain verifies in the same SQLite transaction; a malformed or broken latest
/// HMAC never becomes a proof-bearing head stamp.
pub fn chain_head_via_conn(
    proof: &mut BlockingSqlite,
    tracked: &mut crate::read_cache::TrackedReadConnection,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> AuditResult<Option<VerifiedChainHead>> {
    let conn = tracked.as_mut_conn(proof);
    let tx = conn.transaction()?;
    let generation = crate::world_schema::generation(proof, &tx)?;
    let retention = retention::load(&tx)?;
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    let report =
        verify_statement_capture(&mut stmt, key, true, &retention, world, &generation, None)?;
    drop(stmt);
    let head = match report {
        VerifyCapturedReport::Valid { head, .. } => head,
        VerifyCapturedReport::Broken(break_report) => {
            return Err(AuditError::ChainBroken(break_report))
        }
    };
    tx.commit()?;
    Ok(head)
}

/// Verified chain-stamp lookup through the SlotState-tracked read path.
///
/// The requested ordinal is resolved by the verifier walk itself; this function
/// never looks up a stamp with `WHERE id = ?`.
pub fn chain_stamp_via_conn(
    proof: &mut BlockingSqlite,
    tracked: &mut crate::read_cache::TrackedReadConnection,
    world: &ValidatedWorldPath,
    seq: ChainSeq,
    key: &AuditHmacKey,
) -> AuditResult<ChainStampRead> {
    let conn = tracked.as_mut_conn(proof);
    let tx = conn.transaction()?;
    let generation = crate::world_schema::generation(proof, &tx)?;
    let retention = retention::load(&tx)?;
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    let report = verify_statement_capture(
        &mut stmt,
        key,
        true,
        &retention,
        world,
        &generation,
        Some(seq),
    )?;
    drop(stmt);
    let stamp = match report {
        VerifyCapturedReport::Valid {
            stamp: Some(stamp), ..
        } => stamp,
        VerifyCapturedReport::Valid { stamp: None, .. } => {
            return Err(AuditError::Storage(rusqlite::Error::InvalidParameterName(
                "audit stamp verifier did not return a stamp result".to_owned(),
            )));
        }
        VerifyCapturedReport::Broken(break_report) => {
            return Err(AuditError::ChainBroken(break_report));
        }
    };
    tx.commit()?;
    Ok(stamp)
}

/// Verify through the SlotState-tracked read path. There is no bare
/// per-operation verify path, so delete drains in-flight verifies through the
/// same guard as ordinary cached reads.
pub fn verify_chain_via_conn(
    proof: &mut BlockingSqlite,
    tracked: &mut crate::read_cache::TrackedReadConnection,
    world_path: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    let conn = tracked.as_mut_conn(proof);
    let tx = conn.transaction()?;
    let report = verify_world_tx(proof, &tx, world_path, key)?;
    if matches!(report, VerifyReport::Broken(_)) {
        return Ok(report);
    }
    if let Some(break_report) = live_body::verify_tx(&tx)? {
        return Ok(VerifyReport::Broken(break_report));
    }
    Ok(report)
}

#[cfg(test)]
fn verify_connection(c: &Connection, key: &AuditHmacKey) -> rusqlite::Result<VerifyReport> {
    verify_connection_for(c, &validated_for_test("home/a"), key)
}

#[cfg(test)]
fn validated_for_test(world: &str) -> ValidatedWorldPath {
    match ValidatedWorldPath::new(world) {
        Ok(world) => world,
        Err(reason) => unreachable!("test world path is canonical: {reason}"),
    }
}

#[cfg(test)]
fn verify_connection_for(
    c: &Connection,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    let generation = crate::world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), c)?;
    let retention = retention::load(c)?;
    let mut stmt = c.prepare(AUDIT_SELECT)?;
    verify_statement(&mut stmt, key, false, &retention, world, &generation)
}

fn verify_world_tx(
    proof: &mut BlockingSqlite,
    tx: &Transaction<'_>,
    world_name: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    let generation = crate::world_schema::generation(proof, tx)?;
    let retention = retention::load(tx)?;
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    verify_statement(&mut stmt, key, false, &retention, world_name, &generation)
}

fn verify_statement(
    stmt: &mut Statement<'_>,
    key: &AuditHmacKey,
    allow_empty: bool,
    retention: &retention::CasRetentionState,
    chain_world: &ValidatedWorldPath,
    generation: &WorldGeneration,
) -> rusqlite::Result<VerifyReport> {
    match verify_statement_capture(
        stmt,
        key,
        allow_empty,
        retention,
        chain_world,
        generation,
        None,
    )? {
        VerifyCapturedReport::Valid { ok, .. } => Ok(VerifyReport::Valid(ok)),
        VerifyCapturedReport::Broken(break_report) => Ok(VerifyReport::Broken(break_report)),
    }
}

fn require_intact(report: VerifyReport) -> AuditResult<()> {
    match report {
        VerifyReport::Valid(_) => Ok(()),
        VerifyReport::Broken(break_report) => Err(AuditError::ChainBroken(break_report)),
    }
}

fn verify_delete_subject_proof(
    row: &EventRow,
    event_headers: &[(String, String)],
    event_type: AuditEventKind,
    idx: usize,
) -> Option<VerifyBreak> {
    if !matches!(
        event_type,
        AuditEventKind::DeleteIntent
            | AuditEventKind::DeleteCommit
            | AuditEventKind::DeleteCommitFailed
    ) {
        return None;
    }
    let target = match ValidatedWorldPath::from_canonical(row.target.clone()) {
        Ok(target) => target,
        Err(_) => {
            return Some(VerifyBreak {
                break_at: idx,
                expected: "delete-target-canonical-world".to_owned(),
                actual: format!("target-{}", row.target),
            });
        }
    };
    let body_sha256 = match BodySha256::new(row.body_sha256.clone()) {
        Ok(body_sha256) => body_sha256,
        Err(_) => {
            return Some(VerifyBreak {
                break_at: idx,
                expected: "delete-row-body-sha256".to_owned(),
                actual: "invalid-delete-row-body-sha256".to_owned(),
            });
        }
    };
    match headers::delete_subject_proof_from_headers(&target, &body_sha256, event_headers) {
        Ok(_) => None,
        Err(err) => Some(delete_subject_proof_break(idx, err)),
    }
}

fn delete_subject_proof_break(idx: usize, err: headers::DeleteSubjectProofError) -> VerifyBreak {
    match err {
        headers::DeleteSubjectProofError::Missing(name) => VerifyBreak {
            break_at: idx,
            expected: format!("delete-subject-{name}"),
            actual: format!("missing-delete-subject-{name}"),
        },
        headers::DeleteSubjectProofError::Duplicated(name) => VerifyBreak {
            break_at: idx,
            expected: format!("one-delete-subject-{name}"),
            actual: format!("duplicated-delete-subject-{name}"),
        },
        headers::DeleteSubjectProofError::Invalid(name) => VerifyBreak {
            break_at: idx,
            expected: format!("valid-delete-subject-{name}"),
            actual: format!("invalid-delete-subject-{name}"),
        },
        headers::DeleteSubjectProofError::WorldMismatch => VerifyBreak {
            break_at: idx,
            expected: "delete-subject-world-matches-target".to_owned(),
            actual: "delete-subject-world-mismatch".to_owned(),
        },
        headers::DeleteSubjectProofError::BodyHashMismatch => VerifyBreak {
            break_at: idx,
            expected: "delete-subject-body-sha256-matches-row".to_owned(),
            actual: "delete-subject-body-sha256-mismatch".to_owned(),
        },
    }
}

fn meta_sha256_canonical(content_type: &str, headers: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    sha256_field(&mut h, b"content-type", content_type);
    for (name, value) in headers {
        sha256_field(&mut h, b"header-name", name);
        sha256_field(&mut h, b"header-value", value);
    }
    hex::encode(h.finalize())
}

fn sha256_field(h: &mut Sha256, label: &[u8], value: &str) {
    h.update(label);
    h.update(b"\0");
    h.update(value.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(value.as_bytes());
    h.update(b"\0");
}

fn hmac_field(mac: &mut Hmac<Sha256>, label: &[u8], value: &str) {
    mac.update(label);
    mac.update(b"\0");
    mac.update(value.len().to_string().as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.update(b"\0");
}

fn is_canonical_sqlite_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 24
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && bytes.iter().enumerate().all(|(idx, byte)| {
            matches!(idx, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        })
}

fn timestamp_error(actual: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(format!("invalid audit timestamp: {actual}"))
}

fn event_hmac(key: &AuditHmacKey, input: EventHmacInput<'_>) -> String {
    // Invariant: HMAC accepts any key length; AuditHmacKey enforces AuditeDB's
    // key policy before this sink.
    let mut mac = match Hmac::<Sha256>::new_from_slice(key.as_slice()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC accepts any key length"),
    };
    hmac_field(&mut mac, b"prev", input.prev);
    hmac_field(&mut mac, b"world", input.world.as_str());
    hmac_field(&mut mac, b"timestamp", input.timestamp.as_str());
    hmac_field(&mut mac, b"type", input.event_type);
    hmac_field(&mut mac, b"target", input.target);
    hmac_field(&mut mac, b"gen", input.generation.as_str());
    hmac_field(&mut mac, b"body-sha256", input.body_sha256);
    hmac_field(&mut mac, b"size", &input.size.to_string());
    hmac_field(&mut mac, b"content-type", input.content_type);
    hmac_field(&mut mac, b"meta-sha256", input.meta_sha256);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_label(raw: &str) -> String {
    if raw.is_empty() {
        "hmac-".to_owned()
    } else if raw.starts_with("hmac-") {
        raw.to_owned()
    } else {
        format!("hmac-{raw}")
    }
}

fn canonical_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::engine_types::ValidatedWorldPath;
    use crate::timeline::BodySha256;
    use crate::{event::AuditEventKind, test_support::test_core, world};
    use rusqlite::Connection;

    fn test_only_proof() -> BlockingSqlite {
        crate::blocking_sqlite::test_only_mint()
    }

    fn verify_appendable_tx_existing_checked<'tx, 'conn, 'key>(
        tx: &'tx Transaction<'conn>,
        world_name: &ValidatedWorldPath,
        key: &'key AuditHmacKey,
    ) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
        super::verify_appendable_tx_existing_checked(&mut test_only_proof(), tx, world_name, key)
    }

    fn verify_appendable_tx_genesis_checked<'tx, 'conn, 'key>(
        tx: &'tx Transaction<'conn>,
        world_name: &ValidatedWorldPath,
        key: &'key AuditHmacKey,
    ) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
        super::verify_appendable_tx_genesis_checked(&mut test_only_proof(), tx, world_name, key)
    }

    fn verify_world_tx(
        tx: &Transaction<'_>,
        world_name: &ValidatedWorldPath,
        key: &AuditHmacKey,
    ) -> rusqlite::Result<VerifyReport> {
        super::verify_world_tx(&mut test_only_proof(), tx, world_name, key)
    }

    fn test_connection() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                generation TEXT NOT NULL,
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, generation, body)
                VALUES(1, '0123456789abcdef0123456789abcdef', x'');
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
            CREATE TABLE world_format(
                id INTEGER PRIMARY KEY CHECK(id=1),
                version INTEGER NOT NULL
                    CHECK(typeof(version)='integer')
                    CHECK(version=2)
            );
            INSERT INTO world_format(id, version) VALUES(1, 2);
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text')
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
                body BLOB NOT NULL
                    CHECK(typeof(body)='blob')
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
                    CHECK(
                        first_retained_seq IS NULL OR
                        (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
                    )
            );
            INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
            "#,
        )
        .unwrap();
        c
    }

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn delete_subject_headers(target: &str, body: &[u8]) -> Vec<(String, String)> {
        vec![
            (DELETE_SUBJECT_WORLD.to_owned(), target.to_owned()),
            (
                DELETE_SUBJECT_GENERATION.to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
            ),
            (DELETE_SUBJECT_SEQ.to_owned(), "1".to_owned()),
            (
                DELETE_SUBJECT_BODY_SHA256.to_owned(),
                BodySha256::for_body(body).as_str().to_owned(),
            ),
            (
                DELETE_SUBJECT_HMAC.to_owned(),
                format!("hmac-{}", "a".repeat(64)),
            ),
        ]
    }

    fn validated(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn retain_test_body(tx: &Transaction<'_>, body: &[u8]) {
        let body_sha256 = BodySha256::for_body(body);
        tx.execute(
            "INSERT OR IGNORE INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![body_sha256.as_str(), body],
        )
        .unwrap();
    }

    fn set_test_retention_floor(tx: &Transaction<'_>, seq: i64) {
        tx.execute(
            "UPDATE cas_state SET first_retained_seq=?1 WHERE id=1",
            rusqlite::params![seq],
        )
        .unwrap();
    }

    fn hmac_for_fields(event_type: &str, target: &str) -> String {
        let key = test_key();
        let world = validated("home/a");
        let generation = WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap();
        let timestamp =
            AuditTimestamp::from_storage("2026-01-02T03:04:05.678Z".to_owned()).unwrap();
        event_hmac(
            &key,
            EventHmacInput {
                prev: "",
                world: &world,
                timestamp: &timestamp,
                event_type,
                target,
                generation: &generation,
                body_sha256: "abc",
                size: 3,
                content_type: "text/plain",
                meta_sha256: &meta_sha256_canonical("text/plain", &[]),
            },
        )
    }

    #[test]
    fn hmac_sha256_known_vector_matches_rfc4231() {
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_chain_domain_separates_adjacent_fields() {
        assert_ne!(
            hmac_for_fields("replace/home/", "x"),
            hmac_for_fields("replace", "/home/x")
        );
    }

    #[test]
    fn meta_sha256_domain_separates_header_delimiters() {
        let left = vec![("a".to_owned(), "b\0c".to_owned())];
        let right = vec![("a\0b".to_owned(), "c".to_owned())];

        assert_ne!(
            meta_sha256_canonical("text/plain", &left),
            meta_sha256_canonical("text/plain", &right)
        );
    }

    #[test]
    fn meta_sha256_domain_separates_content_type_from_headers() {
        let left = vec![("c".to_owned(), "d".to_owned())];
        let right = vec![("b".to_owned(), "c\0d".to_owned())];

        assert_ne!(
            meta_sha256_canonical("a\0b", &left),
            meta_sha256_canonical("a", &right)
        );
    }

    #[test]
    fn audit_keeps_historical_metadata_without_json_payload() {
        let (core, dir) = test_core("audit-meta");
        let headers = vec![("x-meta-author".to_string(), "ranger".to_string())];
        let h = world::write_with_audit(
            &core.data,
            &validated("home/audit-meta"),
            b"hello",
            "text/plain; charset=utf-8",
            &headers,
            &core.hmac_key,
        )
        .unwrap();

        let c = Connection::open(world::world_db(&core.data, "home/audit-meta")).unwrap();
        let (content_type, meta_sha256): (String, String) = c
            .query_row(
                "SELECT content_type, meta_sha256 FROM events WHERE hmac=?",
                [h],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert_eq!(
            meta_sha256,
            meta_sha256_canonical("text/plain; charset=utf-8", &headers)
        );

        let author: String = c
            .query_row(
                "SELECT value FROM event_headers WHERE name='x-meta-author'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(author, "ranger");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_world_rejects_tampered_live_body() {
        let (core, dir) = test_core("audit-live-body-tamper");
        world::write_with_audit(
            &core.data,
            &validated("home/live-body"),
            b"good",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/live-body")).unwrap();
        c.execute(
            "UPDATE stage_meta SET body=?1 WHERE id=1",
            [b"bad".as_slice()],
        )
        .unwrap();
        drop(c);

        let err =
            verify_world(&core.data, &validated("home/live-body"), &core.hmac_key).unwrap_err();

        assert!(matches!(
            err,
            AuditError::ChainBroken(VerifyBreak { actual, .. })
                if actual.starts_with("live-body-sha256-")
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_missing_retained_cas_body() {
        let (core, dir) = test_core("audit-missing-cas-body");
        world::write_with_audit(
            &core.data,
            &validated("home/missing-cas"),
            b"retained",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/missing-cas")).unwrap();
        c.execute("DELETE FROM cas_bodies", []).unwrap();

        let report =
            verify_connection_for(&c, &validated("home/missing-cas"), &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "missing-cas-body"
        ));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_corrupt_retained_cas_body() {
        let (core, dir) = test_core("audit-corrupt-cas-body");
        world::write_with_audit(
            &core.data,
            &validated("home/corrupt-cas"),
            b"retained",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/corrupt-cas")).unwrap();
        c.execute("UPDATE cas_bodies SET body=?1", [b"tampered".as_slice()])
            .unwrap();

        let err =
            verify_connection_for(&c, &validated("home/corrupt-cas"), &core.hmac_key).unwrap_err();

        assert!(err.to_string().contains("does not match body_sha256"));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_unreferenced_cas_body() {
        let (core, dir) = test_core("audit-unreferenced-cas-body");
        world::write_with_audit(
            &core.data,
            &validated("home/unreferenced-cas"),
            b"retained",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/unreferenced-cas")).unwrap();
        let extra_hash = BodySha256::for_body(b"extra");
        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![extra_hash.as_str(), b"extra".as_slice()],
        )
        .unwrap();

        let report =
            verify_connection_for(&c, &validated("home/unreferenced-cas"), &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "unreferenced-cas-body"
        ));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_retained_cas_body_size_mismatch() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx =
            verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::Put,
            &validated("home/a"),
            &BodySha256::for_body(b"abc"),
            4,
            "text/plain",
            &[],
        )
        .unwrap();
        retain_test_body(&tx, b"abc");
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();

        let report = verify_connection(&c, &key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "cas-body-size-3"
        ));
    }

    #[test]
    fn verify_connection_rejects_advanced_floor_with_unpruned_old_cas_body() {
        let (core, dir) = test_core("audit-floor-skips-body");
        world::write_with_audit(
            &core.data,
            &validated("home/floor-skip"),
            b"one",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit(
            &core.data,
            &validated("home/floor-skip"),
            b"two",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/floor-skip")).unwrap();
        c.execute("UPDATE cas_state SET first_retained_seq=3 WHERE id=1", [])
            .unwrap();

        let report =
            verify_connection_for(&c, &validated("home/floor-skip"), &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "unreferenced-cas-body"
        ));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_retention_floor_pointing_at_metadata_event() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx =
            verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::DeleteIntent,
            &validated("home/a"),
            &BodySha256::for_body(b""),
            0,
            "",
            &delete_subject_headers("home/a", b""),
        )
        .unwrap();
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();

        let report = verify_connection(&c, &key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "delete_intent"
        ));
    }

    #[test]
    fn verify_connection_accepts_floor_raise_after_old_cas_body_deleted() {
        let (core, dir) = test_core("audit-floor-raise-delete-cas");
        world::write_with_audit(
            &core.data,
            &validated("home/floor-raise-delete"),
            b"one",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit(
            &core.data,
            &validated("home/floor-raise-delete"),
            b"two",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/floor-raise-delete")).unwrap();
        let first_hash: String = c
            .query_row("SELECT body_sha256 FROM events WHERE id=2", [], |r| {
                r.get(0)
            })
            .unwrap();
        c.execute(
            "DELETE FROM cas_bodies WHERE body_sha256=?1",
            [first_hash.as_str()],
        )
        .unwrap();
        c.execute("UPDATE cas_state SET first_retained_seq=3 WHERE id=1", [])
            .unwrap();

        let report =
            verify_connection_for(&c, &validated("home/floor-raise-delete"), &core.hmac_key)
                .unwrap();

        assert!(matches!(
            report,
            VerifyReport::Valid(VerifyOk { events: 3, .. })
        ));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_null_floor_plus_deleted_cas_bodies() {
        let (core, dir) = test_core("audit-null-floor-delete-cas");
        world::write_with_audit(
            &core.data,
            &validated("home/null-floor-delete"),
            b"one",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, "home/null-floor-delete")).unwrap();
        c.execute("DELETE FROM cas_bodies", []).unwrap();
        c.execute(
            "UPDATE cas_state SET first_retained_seq=NULL WHERE id=1",
            [],
        )
        .unwrap();

        let err = verify_connection_for(&c, &validated("home/null-floor-delete"), &core.hmac_key)
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("body-bearing events exist before first_retained_seq is set"));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_accepts_intact_chain() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx =
            verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
        let row1 = append_tx_inner(
            &audit_tx,
            AuditEventKind::Put,
            &validated("home/a"),
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
        )
        .unwrap();
        let row2 = append_tx_inner(
            &audit_tx,
            AuditEventKind::Append,
            &validated("home/a"),
            &BodySha256::for_body(b"abcdef"),
            6,
            "text/plain",
            &[],
        )
        .unwrap();
        assert_eq!(row1.id().get(), 1);
        assert_eq!(row2.id().get(), 2);
        let h1 = row1.hmac().to_owned();
        let h2 = row2.hmac().to_owned();
        retain_test_body(&tx, b"abc");
        retain_test_body(&tx, b"abcdef");
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();

        let report = verify_connection(&c, &key).unwrap();
        assert_eq!(
            report,
            VerifyReport::Valid(VerifyOk {
                events: 2,
                genesis: format!("hmac-{h1}"),
                latest: format!("hmac-{h2}"),
            })
        );
    }

    #[test]
    fn verify_chain_reports_real_format_boundary_as_genesis() {
        let (core, dir) = test_core("audit-real-format-boundary");
        let world_path = validated("home/real-format-boundary");
        world::write_with_audit_checked(
            &core.data,
            &world_path,
            b"body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let conn = Connection::open(world::world_db(&core.data, world_path.as_str())).unwrap();
        let (format_hmac, body_hmac): (String, String) = conn
            .query_row(
                "SELECT
                    (SELECT hmac FROM events WHERE id=1),
                    (SELECT hmac FROM events WHERE id=2)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let report = verify_chain_via_conn(
            &mut crate::blocking_sqlite::test_only_mint(),
            &mut tracked,
            &world_path,
            &core.hmac_key,
        )
        .unwrap();

        assert_eq!(
            report,
            VerifyReport::Valid(VerifyOk {
                events: 2,
                genesis: format!("hmac-{format_hmac}"),
                latest: format!("hmac-{body_hmac}"),
            })
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_world_rejects_format_event_without_signed_version() {
        let (core, dir) = test_core("audit-format-version-header");
        let world_path = validated("home/format-version-header");
        world::write_with_audit_checked(
            &core.data,
            &world_path,
            b"body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let conn = Connection::open(world::world_db(&core.data, world_path.as_str())).unwrap();
        conn.execute(
            "DELETE FROM event_headers WHERE event_id=1 AND name=?1",
            [WORLD_FORMAT_VERSION_HEADER],
        )
        .unwrap();
        drop(conn);

        let err = verify_world(&core.data, &world_path, &core.hmac_key).unwrap_err();

        assert!(matches!(
            err,
            AuditError::ChainBroken(VerifyBreak {
                break_at: 0,
                expected,
                actual,
            }) if expected == "auditedb-world-format-version-2"
                && actual == "missing-world-format-version"
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_unknown_event_type_even_when_hmac_matches() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let world = validated("home/future-event");
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &world, &key).unwrap();
        let body_sha256 = BodySha256::for_body(b"abc");
        append_tx_inner(
            &audit_tx,
            AuditEventKind::Put,
            &world,
            &body_sha256,
            3,
            "text/plain",
            &[],
        )
        .unwrap();
        retain_test_body(&tx, b"abc");
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();

        assert!(matches!(
            verify_connection_for(&c, &world, &key).unwrap(),
            VerifyReport::Valid(_)
        ));

        let generation = WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap();
        let stored_timestamp: String = c
            .query_row("SELECT timestamp FROM events WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let timestamp = AuditTimestamp::from_storage(stored_timestamp).unwrap();
        let unknown_hmac = event_hmac(
            &key,
            EventHmacInput {
                prev: "",
                world: &world,
                timestamp: &timestamp,
                event_type: "future_event",
                target: world.as_str(),
                generation: &generation,
                body_sha256: body_sha256.as_str(),
                size: 3,
                content_type: "text/plain",
                meta_sha256: &meta_sha256_canonical("text/plain", &[]),
            },
        );
        let tx = c.transaction().unwrap();
        tx.execute(
            "UPDATE events SET event_type='future_event', hmac=?1 WHERE id=1",
            rusqlite::params![unknown_hmac],
        )
        .unwrap();
        tx.commit().unwrap();

        let report = verify_connection_for(&c, &world, &key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "known-event-type".to_owned(),
                actual: "event-type-future_event".to_owned(),
            })
        );
    }

    #[test]
    fn verify_world_rejects_format_event_for_wrong_world() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let world = validated("home/format-owner");
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &world, &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::Format,
            &validated("home/other-world"),
            &BodySha256::for_body(b""),
            0,
            "",
            &[],
        )
        .unwrap();

        let report = verify_world_tx(&tx, &world, &key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "target-home/format-owner".to_owned(),
                actual: "target-home/other-world".to_owned(),
            })
        );
    }

    #[test]
    fn append_tx_propagates_prev_hmac_read_errors() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                generation TEXT NOT NULL,
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, generation, body)
                VALUES(1, '0123456789abcdef0123456789abcdef', x'');
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
            CREATE TABLE world_format(
                id INTEGER PRIMARY KEY CHECK(id=1),
                version INTEGER NOT NULL
                    CHECK(typeof(version)='integer')
                    CHECK(version=2)
            );
            INSERT INTO world_format(id, version) VALUES(1, 2);
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text')
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
                body BLOB NOT NULL
                    CHECK(typeof(body)='blob')
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
                    CHECK(
                        first_retained_seq IS NULL OR
                        (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
                    )
            );
            INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
            "#,
        )
        .unwrap();
        let body_sha256 = BodySha256::for_body(b"abc");
        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![body_sha256.as_str(), b"abc".as_slice()],
        )
        .unwrap();
        c.execute("UPDATE cas_state SET first_retained_seq=1 WHERE id=1", [])
            .unwrap();
        c.execute(
            r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                                  content_type, meta_sha256, hmac, prev_hmac)
               VALUES(datetime('now'), 'put', 'home/a', ?1, 3,
                      'text/plain', 'meta', x'ff', '')"#,
            rusqlite::params![body_sha256.as_str()],
        )
        .unwrap();

        let tx = c.transaction().unwrap();
        let key = test_key();
        let err = match verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key) {
            Ok(_) => panic!("corrupt latest hmac must not be treated as an empty chain"),
            Err(e) => e,
        };

        assert!(matches!(
            err,
            AuditError::Storage(rusqlite::Error::InvalidColumnType(..))
        ));
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_appendable_existing_reports_chain_broken_error() {
        let mut c = test_connection();
        {
            let tx = c.transaction().unwrap();
            let key = test_key();
            let audit_tx =
                verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
            append_tx_inner(
                &audit_tx,
                AuditEventKind::Put,
                &validated("home/a"),
                &BodySha256::for_body(b"abc"),
                3,
                "text/plain",
                &[],
            )
            .unwrap();
            retain_test_body(&tx, b"abc");
            set_test_retention_floor(&tx, 1);
            tx.commit().unwrap();
        }
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let tx = c.transaction().unwrap();
        let key = test_key();
        let err = match verify_appendable_tx_existing_checked(&tx, &validated("home/a"), &key) {
            Ok(_) => panic!("tampered audit chain must not be appendable"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            AuditError::ChainBroken(VerifyBreak {
                break_at: 0,
                actual,
                ..
            }) if actual == "hmac-bad"
        ));
    }

    #[test]
    fn verify_connection_rejects_tampered_event_hmac() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx =
            verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::Put,
            &validated("home/a"),
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[],
        )
        .unwrap();
        retain_test_body(&tx, b"abc");
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let report = verify_connection(&c, &key).unwrap();
        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                actual,
                ..
            }) if actual == "hmac-bad"
        ));
    }

    #[test]
    fn verify_connection_rejects_tampered_event_timestamp() {
        let (core, dir) = test_core("audit-timestamp-tamper");
        let world_path = validated("home/timestamp-tamper");
        world::write_with_audit(
            &core.data,
            &world_path,
            b"body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, world_path.as_str())).unwrap();
        c.execute(
            "UPDATE events SET timestamp='2026-01-02T03:04:05.678Z' WHERE id=2",
            [],
        )
        .unwrap();

        let report = verify_connection_for(&c, &world_path, &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 1,
                expected,
                actual,
            }) if expected.starts_with("hmac-") && actual.starts_with("hmac-")
        ));
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_noncanonical_event_timestamp() {
        let (core, dir) = test_core("audit-bad-timestamp");
        let world_path = validated("home/bad-timestamp");
        world::write_with_audit(
            &core.data,
            &world_path,
            b"body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let c = Connection::open(world::world_db(&core.data, world_path.as_str())).unwrap();
        c.execute("UPDATE events SET timestamp='not-time' WHERE id=2", [])
            .unwrap();

        let report = verify_connection_for(&c, &world_path, &core.hmac_key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 1,
                expected: "timestamp-sqlite-utc-ms".to_owned(),
                actual: "timestamp-not-time".to_owned(),
            })
        );
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_connection_rejects_non_body_event_moved_to_other_world() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let ledger_world = validated("var/log/deletes");
        let other_ledger_world = validated("var/log/other");
        let target = validated("home/deleted");
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &ledger_world, &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::DeleteIntent,
            &target,
            &BodySha256::for_body(b""),
            0,
            "",
            &delete_subject_headers("home/deleted", b""),
        )
        .unwrap();
        tx.commit().unwrap();

        assert!(matches!(
            verify_connection_for(&c, &ledger_world, &key).unwrap(),
            VerifyReport::Valid(_)
        ));

        let report = verify_connection_for(&c, &other_ledger_world, &key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected,
                actual,
            }) if expected.starts_with("hmac-") && actual.starts_with("hmac-")
        ));
    }

    #[test]
    fn verify_connection_rejects_missing_delete_subject_generation() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let ledger_world = validated("var/log/deletes");
        let target = validated("home/deleted");
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &ledger_world, &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::DeleteIntent,
            &target,
            &BodySha256::for_body(b""),
            0,
            "",
            &[],
        )
        .unwrap();
        tx.commit().unwrap();

        let report = verify_connection_for(&c, &ledger_world, &key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "delete-subject-auditedb-delete-subject-world".to_owned(),
                actual: "missing-delete-subject-auditedb-delete-subject-world".to_owned(),
            })
        );
    }

    #[test]
    fn verify_connection_rejects_duplicated_delete_subject_generation() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let ledger_world = validated("var/log/deletes");
        let target = validated("home/deleted");
        let headers = delete_subject_headers("home/deleted", b"");
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &ledger_world, &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::DeleteIntent,
            &target,
            &BodySha256::for_body(b""),
            0,
            "",
            &headers,
        )
        .unwrap();
        tx.commit().unwrap();
        c.execute(
            "INSERT INTO event_headers(event_id, name, value) VALUES(1, ?1, ?2)",
            rusqlite::params![
                DELETE_SUBJECT_GENERATION,
                "fedcba9876543210fedcba9876543210"
            ],
        )
        .unwrap();

        let report = verify_connection_for(&c, &ledger_world, &key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "one-delete-subject-auditedb-delete-subject-generation".to_owned(),
                actual: "duplicated-delete-subject-auditedb-delete-subject-generation".to_owned(),
            })
        );
    }

    #[test]
    fn verify_connection_rejects_noncanonical_delete_subject_seq() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let ledger_world = validated("var/log/deletes");
        let target = validated("home/deleted");
        let mut headers = delete_subject_headers("home/deleted", b"");
        for (name, value) in &mut headers {
            if name == DELETE_SUBJECT_SEQ {
                *value = "01".to_owned();
            }
        }
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &ledger_world, &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::DeleteIntent,
            &target,
            &BodySha256::for_body(b""),
            0,
            "",
            &headers,
        )
        .unwrap();
        tx.commit().unwrap();

        let report = verify_connection_for(&c, &ledger_world, &key).unwrap();

        assert_eq!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "valid-delete-subject-auditedb-delete-subject-seq".to_owned(),
                actual: "invalid-delete-subject-auditedb-delete-subject-seq".to_owned(),
            })
        );
    }

    #[test]
    fn startup_verification_rejects_tampered_world() {
        let root =
            std::env::temp_dir().join(format!("auditedb-audit-startup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        world::write_with_audit(&root, &validated("home/a"), b"abc", "text/plain", &[], &key)
            .unwrap();
        {
            let c = Connection::open(world::world_db(&root, "home/a")).unwrap();
            c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
                .unwrap();
        }

        assert!(verify_all_worlds(&root, &key).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_connection_rejects_tampered_event_headers() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx =
            verify_appendable_tx_genesis_checked(&tx, &validated("home/a"), &key).unwrap();
        append_tx_inner(
            &audit_tx,
            AuditEventKind::Put,
            &validated("home/a"),
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
        )
        .unwrap();
        retain_test_body(&tx, b"abc");
        set_test_retention_floor(&tx, 1);
        tx.commit().unwrap();
        c.execute(
            "UPDATE event_headers SET value='intruder' WHERE name='x-meta-author'",
            [],
        )
        .unwrap();

        let report = verify_connection(&c, &key).unwrap();
        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak {
                break_at: 0,
                expected,
                actual,
            }) if expected.starts_with("meta-sha256-") && actual.starts_with("meta-sha256-")
        ));
    }
}
