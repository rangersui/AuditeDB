//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. The chain is a
//! core storage invariant, independent of which SDK or bridge produced
//! the write.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, Statement, Transaction};
use sha2::{Digest, Sha256};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    timeline::TimelineSeq,
    world,
    world_generation::WorldGeneration,
};
use std::{collections::HashSet, fmt, path::Path};

mod append;
mod headers;
mod live_body;
mod retention;
#[cfg(test)]
mod test_support;
mod timeline_address;
mod timeline_dereference;

#[cfg(test)]
use append::test_only_append_tx_inner as append_tx_inner;
pub(crate) use append::{
    append_retained_body_tx_row, append_with_conn_existing, append_with_conn_genesis,
    AppendedBodyEvent,
};
pub(crate) use headers::{AuditHeaders, VerifiedDeleteSubject};
#[cfg(test)]
pub(crate) use headers::{
    DELETE_SUBJECT_BODY_SHA256, DELETE_SUBJECT_GENERATION, DELETE_SUBJECT_HMAC, DELETE_SUBJECT_SEQ,
    DELETE_SUBJECT_WORLD,
};
#[cfg(test)]
pub use test_support::latest_hmac;
pub(crate) use timeline_address::read_timeline_body_via_conn;
pub(crate) use timeline_address::{
    verified_latest_body_head_via_conn, VerifiedBodyEvent, VerifiedBodyHead,
};
#[cfg(feature = "unstable-engine")]
pub use timeline_dereference::{
    TimelineDereference, VerifiedBodyHashMismatch, VerifiedGenerationMismatch, VerifiedMissingRow,
    VerifiedNonBodyEvent,
};

const AUDIT_SELECT: &str = r#"SELECT e.id, e.event_type, e.target, e.body_sha256, e.size,
                  e.content_type, e.meta_sha256, e.hmac, e.prev_hmac,
                  h.name, h.value
           FROM events e
           LEFT JOIN event_headers h ON h.event_id=e.id
           ORDER BY e.id ASC, h.name ASC, h.value ASC"#;
pub(crate) const AUDIT_CHAIN_BROKEN_PREFIX: &str = "audit chain broken at event ";

pub struct VerifiedAuditTx<'tx, 'conn, 'key> {
    tx: &'tx Transaction<'conn>,
    key: &'key AuditHmacKey,
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
    for world_name in world::list(data_root)? {
        verify_world(data_root, &world_name, key)?;
    }
    Ok(())
}

pub fn verify_world(data_root: &Path, world_name: &str, key: &AuditHmacKey) -> AuditResult<()> {
    let world_path = ValidatedWorldPath::new(world_name.to_owned())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let Some(c) = world::open_existing(data_root, world_name)? else {
        return Ok(());
    };
    require_intact(verify_world_connection(&c, &world_path, key)?)?;
    if let Some(break_report) = live_body::verify_conn(&c)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(())
}

pub(crate) fn verify_appendable_tx_existing_checked<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx(tx, world_name, key, EmptyChain::Reject)
}

pub(crate) fn verify_appendable_tx_genesis_checked<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx(tx, world_name, key, EmptyChain::Allow)
}

fn verify_appendable_tx<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    world_name: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    let generation = crate::world_schema::generation(tx)?;
    let retention = retention::load(tx)?;
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    let allow_empty = matches!(empty_chain, EmptyChain::Allow);
    require_intact(verify_statement(
        &mut stmt,
        key,
        allow_empty,
        &retention,
        Some(world_name.as_str()),
        &generation,
    )?)?;
    if let Some(break_report) = live_body::verify_tx(tx)? {
        return Err(AuditError::ChainBroken(break_report));
    }
    Ok(VerifiedAuditTx { tx, key })
}

struct EventRow {
    id: i64,
    event_type: String,
    target: String,
    body_sha256: String,
    size: i64,
    content_type: String,
    meta_sha256: String,
    hmac: String,
    prev_hmac: String,
}

struct VerifyAccumulator {
    prev: String,
    genesis: String,
    events: usize,
    first_body_event: Option<TimelineSeq>,
    saw_retention_floor: bool,
    referenced_retained_bodies: HashSet<String>,
}

struct EventHmacInput<'a> {
    prev: &'a str,
    event_type: &'a str,
    target: &'a str,
    generation: &'a WorldGeneration,
    body_sha256: &'a str,
    size: i64,
    content_type: &'a str,
    meta_sha256: &'a str,
}

/// O(1) chain-head read through the SlotState-tracked read path: newest
/// `(id, hmac)` without re-walking the chain. `Ok(None)` means an empty
/// bootstrap-shape DB. Same type gate as `verify_chain_via_conn`, so delete
/// drains in-flight head reads through SlotState.
pub fn chain_head_via_conn(
    tracked: &mut crate::read_cache::TrackedReadConnection,
) -> rusqlite::Result<Option<(i64, String)>> {
    tracked
        .as_mut_conn()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM events), hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            // Same `hmac-` rendering as VerifyOk.
            |r| Ok((r.get::<_, i64>(0)?, hmac_label(&r.get::<_, String>(1)?))),
        )
        .optional()
}

/// Verify through the SlotState-tracked read path. There is no bare
/// per-operation verify path, so delete drains in-flight verifies through the
/// same guard as ordinary cached reads.
pub fn verify_chain_via_conn(
    tracked: &mut crate::read_cache::TrackedReadConnection,
    world_path: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    let conn = tracked.as_mut_conn();
    let report = verify_world_connection(conn, world_path, key)?;
    if matches!(report, VerifyReport::Broken(_)) {
        return Ok(report);
    }
    if let Some(break_report) = live_body::verify_conn(conn)? {
        return Ok(VerifyReport::Broken(break_report));
    }
    Ok(report)
}

#[cfg(test)]
fn verify_connection(c: &Connection, key: &AuditHmacKey) -> rusqlite::Result<VerifyReport> {
    let generation = crate::world_schema::generation(c)?;
    let retention = retention::load(c)?;
    let mut stmt = c.prepare(AUDIT_SELECT)?;
    verify_statement(&mut stmt, key, false, &retention, None, &generation)
}

fn verify_world_connection(
    c: &Connection,
    world_name: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    let generation = crate::world_schema::generation(c)?;
    let retention = retention::load(c)?;
    let mut stmt = c.prepare(AUDIT_SELECT)?;
    verify_statement(
        &mut stmt,
        key,
        false,
        &retention,
        Some(world_name.as_str()),
        &generation,
    )
}

fn verify_statement(
    stmt: &mut Statement<'_>,
    key: &AuditHmacKey,
    allow_empty: bool,
    retention: &retention::CasRetentionState,
    expected_target: Option<&str>,
    generation: &WorldGeneration,
) -> rusqlite::Result<VerifyReport> {
    let mut state = VerifyAccumulator {
        prev: String::new(),
        genesis: String::new(),
        events: 0,
        first_body_event: None,
        saw_retention_floor: retention.floor_is_unset(),
        referenced_retained_bodies: HashSet::new(),
    };
    let mut rows = stmt.query([])?;
    let mut current: Option<EventRow> = None;
    let mut headers = Vec::new();

    while let Some(r) = rows.next()? {
        let row = EventRow {
            id: r.get(0)?,
            event_type: r.get(1)?,
            target: r.get(2)?,
            body_sha256: r.get(3)?,
            size: r.get(4)?,
            content_type: r.get(5)?,
            meta_sha256: r.get(6)?,
            hmac: r.get(7)?,
            prev_hmac: r.get(8)?,
        };
        if current.as_ref().is_some_and(|event| event.id != row.id) {
            let event = current.take().expect("current event");
            if let Some(break_report) = verify_event(
                &event,
                &headers,
                key,
                retention,
                &mut state,
                expected_target,
                generation,
            ) {
                return Ok(VerifyReport::Broken(break_report));
            }
            headers.clear();
        }
        if current.is_none() {
            current = Some(row);
        }
        let header_name: Option<String> = r.get(9)?;
        let header_value: Option<String> = r.get(10)?;
        if let (Some(name), Some(value)) = (header_name, header_value) {
            headers.push((name, value));
        }
    }

    if let Some(event) = current {
        if let Some(break_report) = verify_event(
            &event,
            &headers,
            key,
            retention,
            &mut state,
            expected_target,
            generation,
        ) {
            return Ok(VerifyReport::Broken(break_report));
        }
    }

    if let Some(break_report) = retention::verify_completion(&state, retention) {
        return Ok(VerifyReport::Broken(break_report));
    }

    if state.events == 0 {
        if allow_empty {
            return Ok(VerifyReport::Valid(VerifyOk {
                events: 0,
                genesis: hmac_label(""),
                latest: hmac_label(""),
            }));
        }
        return Ok(VerifyReport::Broken(VerifyBreak {
            break_at: 0,
            expected: "at-least-one-event".to_owned(),
            actual: "no-events".to_owned(),
        }));
    }

    Ok(VerifyReport::Valid(VerifyOk {
        events: state.events,
        genesis: hmac_label(&state.genesis),
        latest: hmac_label(&state.prev),
    }))
}

fn require_intact(report: VerifyReport) -> AuditResult<()> {
    match report {
        VerifyReport::Valid(_) => Ok(()),
        VerifyReport::Broken(break_report) => Err(AuditError::ChainBroken(break_report)),
    }
}

fn verify_event(
    row: &EventRow,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retention: &retention::CasRetentionState,
    state: &mut VerifyAccumulator,
    expected_target: Option<&str>,
    generation: &WorldGeneration,
) -> Option<VerifyBreak> {
    let idx = state.events;
    if matches!(row.event_type.as_str(), "put" | "append")
        && expected_target.is_some_and(|target| target != row.target)
    {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("target-{}", expected_target.unwrap_or_default()),
            actual: format!("target-{}", row.target),
        });
    }
    if !crate::auth::ct_eq(row.prev_hmac.as_bytes(), state.prev.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: hmac_label(&state.prev),
            actual: hmac_label(&row.prev_hmac),
        });
    }
    let expected_meta = meta_sha256_canonical(&row.content_type, headers);
    if !crate::auth::ct_eq(expected_meta.as_bytes(), row.meta_sha256.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("meta-sha256-{expected_meta}"),
            actual: format!("meta-sha256-{}", row.meta_sha256),
        });
    }
    let expected_hmac = event_hmac(
        key,
        EventHmacInput {
            prev: &state.prev,
            event_type: &row.event_type,
            target: &row.target,
            generation,
            body_sha256: &row.body_sha256,
            size: row.size,
            content_type: &row.content_type,
            meta_sha256: &row.meta_sha256,
        },
    );
    if !crate::auth::ct_eq(expected_hmac.as_bytes(), row.hmac.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: hmac_label(&expected_hmac),
            actual: hmac_label(&row.hmac),
        });
    }
    if let Some(break_report) = retention::verify_retained_body(row, idx, retention, state) {
        return Some(break_report);
    }
    if idx == 0 {
        state.genesis = row.hmac.clone();
    }
    state.prev = row.hmac.clone();
    state.events += 1;
    None
}

fn meta_sha256_canonical(content_type: &str, headers: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    h.update(b"content-type\0");
    h.update(content_type.as_bytes());
    h.update(b"\0");
    for (name, value) in headers {
        h.update(name.as_bytes());
        h.update(b"\0");
        h.update(value.as_bytes());
        h.update(b"\0");
    }
    hex::encode(h.finalize())
}

fn hmac_field(mac: &mut Hmac<Sha256>, label: &[u8], value: &str) {
    mac.update(label);
    mac.update(b"\0");
    mac.update(value.len().to_string().as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.update(b"\0");
}

fn event_hmac(key: &AuditHmacKey, input: EventHmacInput<'_>) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice()).expect("hmac key");
    hmac_field(&mut mac, b"prev", input.prev);
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
mod tests {
    use super::*;
    use crate::engine_types::ValidatedWorldPath;
    use crate::timeline::BodySha256;
    use crate::{event::AuditEventKind, test_support::test_core, world};
    use rusqlite::Connection;

    fn test_connection() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                meta_sha256 TEXT NOT NULL,
                hmac TEXT NOT NULL,
                prev_hmac TEXT NOT NULL
            );
            CREATE TABLE event_headers(
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE VIEW stage_meta AS
            SELECT 1 AS id, '0123456789abcdef0123456789abcdef' AS generation;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY,
                body BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
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
        let generation = WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap();
        event_hmac(
            &key,
            EventHmacInput {
                prev: "",
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

        let err = verify_world(&core.data, "home/live-body", &core.hmac_key).unwrap_err();

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

        let report = verify_connection(&c, &core.hmac_key).unwrap();

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

        let err = verify_connection(&c, &core.hmac_key).unwrap_err();

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

        let report = verify_connection(&c, &core.hmac_key).unwrap();

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
            "home/a",
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
    fn verify_connection_rejects_retention_floor_that_skips_body() {
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
        c.execute("UPDATE cas_state SET first_retained_seq=2 WHERE id=1", [])
            .unwrap();

        let report = verify_connection(&c, &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "first_retained_seq-2"
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
            "home/a",
            &BodySha256::for_body(b""),
            0,
            "",
            &[],
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
    fn verify_connection_rejects_floor_raise_plus_deleted_old_cas_body() {
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
            .query_row("SELECT body_sha256 FROM events WHERE id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        c.execute(
            "DELETE FROM cas_bodies WHERE body_sha256=?1",
            [first_hash.as_str()],
        )
        .unwrap();
        c.execute("UPDATE cas_state SET first_retained_seq=2 WHERE id=1", [])
            .unwrap();

        let report = verify_connection(&c, &core.hmac_key).unwrap();

        assert!(matches!(
            report,
            VerifyReport::Broken(VerifyBreak { actual, .. }) if actual == "first_retained_seq-2"
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

        let err = verify_connection(&c, &core.hmac_key).unwrap_err();

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
            "home/a",
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
        )
        .unwrap();
        let row2 = append_tx_inner(
            &audit_tx,
            AuditEventKind::Append,
            "home/a",
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
    fn append_tx_propagates_prev_hmac_read_errors() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                meta_sha256 TEXT NOT NULL,
                hmac BLOB NOT NULL,
                prev_hmac TEXT NOT NULL
            );
            CREATE TABLE event_headers(
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE VIEW stage_meta AS
            SELECT 1 AS id, '0123456789abcdef0123456789abcdef' AS generation;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY,
                body BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
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
                "home/a",
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
            "home/a",
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
    fn startup_verification_rejects_tampered_world() {
        let root =
            std::env::temp_dir().join(format!("elastik-audit-startup-{}", std::process::id()));
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
            "home/a",
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
