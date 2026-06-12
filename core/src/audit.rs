//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. The chain is a
//! core storage invariant, independent of which SDK or bridge produced
//! the write.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, Statement, Transaction};
use sha2::{Digest, Sha256};

use crate::{engine_types::AuditHmacKey, world};
use std::{fmt, path::Path};

mod append;

pub(crate) use append::{append_body_tx_row, append_with_conn_existing, append_with_conn_genesis};

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
    let Some(c) = world::open_existing(data_root, world_name)? else {
        return Ok(());
    };
    require_intact(verify_connection(&c, key)?)
}

pub(crate) fn verify_appendable_tx_existing_checked<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx(tx, key, EmptyChain::Reject)
}

pub(crate) fn verify_appendable_tx_genesis_checked<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    key: &'key AuditHmacKey,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    verify_appendable_tx(tx, key, EmptyChain::Allow)
}

fn verify_appendable_tx<'tx, 'conn, 'key>(
    tx: &'tx Transaction<'conn>,
    key: &'key AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<VerifiedAuditTx<'tx, 'conn, 'key>> {
    let mut stmt = tx.prepare(AUDIT_SELECT)?;
    let allow_empty = matches!(empty_chain, EmptyChain::Allow);
    require_intact(verify_statement(&mut stmt, key.as_slice(), allow_empty)?)?;
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

struct EventHmacInput<'a> {
    prev: &'a str,
    event_type: &'a str,
    target: &'a str,
    body_sha256: &'a str,
    size: i64,
    content_type: &'a str,
    meta_sha256: &'a str,
}

/// O(1) chain-head read through the SlotState-tracked read path: the
/// newest event's `(id, hmac)` without re-walking the chain.
///
/// This is the unit of external anchoring (the O(1) subset of what
/// `verify_chain_via_conn` reports as `latest`): a host that remembers the
/// returned stamp can later prove tail truncation or rollback whenever the
/// observed head is behind the anchored seq — which in-file verification
/// structurally cannot. (A rolled-back or replaced chain re-grown past the
/// anchor needs the at-seq divergence check, a later PR.) Returns
/// `Ok(None)` for an empty chain (bootstrap-shape DB) — nothing to anchor
/// yet.
///
/// Same type gate as `verify_chain_via_conn`: no bare-connection path, so
/// a delete on the same world drains in-flight head reads via the usual
/// SlotState write guard.
pub fn chain_head_via_conn(
    tracked: &mut crate::read_cache::TrackedReadConnection,
) -> rusqlite::Result<Option<(i64, String)>> {
    tracked
        .as_mut_conn()
        .query_row(
            "SELECT id, hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            // hmac_label: same `hmac-` rendering as VerifyOk's
            // genesis/latest, so a stamp compares byte-for-byte with
            // what verify reports and what subscribers witness.
            |r| Ok((r.get::<_, i64>(0)?, hmac_label(&r.get::<_, String>(1)?))),
        )
        .optional()
}

/// Verify the audit chain through a `TrackedReadConnection` (the
/// SlotState-tracked read path). Mirrors `world::read_with_hmac_via_conn`
/// -- the cache layer drives the slot-before-open dance and hands us
/// the connection through the type gate. The bare per-operation
/// `verify_chain(data, world, key)` path is gone (Bug 58); admin
/// audit-verify surfaces now go through `Core::cached_verify_chain`,
/// so a delete on the same world drains in-flight verifies via the
/// usual SlotState write guard.
pub fn verify_chain_via_conn(
    tracked: &mut crate::read_cache::TrackedReadConnection,
    key: &AuditHmacKey,
) -> rusqlite::Result<VerifyReport> {
    verify_connection(tracked.as_mut_conn(), key)
}

fn verify_connection(c: &Connection, key: &AuditHmacKey) -> rusqlite::Result<VerifyReport> {
    let mut stmt = c.prepare(AUDIT_SELECT)?;
    verify_statement(&mut stmt, key.as_slice(), false)
}

fn verify_statement(
    stmt: &mut Statement<'_>,
    key: &[u8],
    allow_empty: bool,
) -> rusqlite::Result<VerifyReport> {
    let mut prev = String::new();
    let mut genesis = String::new();
    let mut events = 0usize;
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
            if let Some(break_report) =
                verify_event(&event, &headers, key, &mut prev, &mut genesis, &mut events)
            {
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
        if let Some(break_report) =
            verify_event(&event, &headers, key, &mut prev, &mut genesis, &mut events)
        {
            return Ok(VerifyReport::Broken(break_report));
        }
    }

    if events == 0 {
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
        events,
        genesis: hmac_label(&genesis),
        latest: hmac_label(&prev),
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
    key: &[u8],
    prev: &mut String,
    genesis: &mut String,
    events: &mut usize,
) -> Option<VerifyBreak> {
    let idx = *events;
    if !crate::auth::ct_eq(row.prev_hmac.as_bytes(), prev.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: hmac_label(prev),
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
            prev,
            event_type: &row.event_type,
            target: &row.target,
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
    if idx == 0 {
        *genesis = row.hmac.clone();
    }
    *prev = row.hmac.clone();
    *events += 1;
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

fn event_hmac(key: &[u8], input: EventHmacInput<'_>) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    hmac_field(&mut mac, b"prev", input.prev);
    hmac_field(&mut mac, b"type", input.event_type);
    hmac_field(&mut mac, b"target", input.target);
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
pub fn latest_hmac(data_root: &Path, world_name: &str) -> Option<String> {
    let path = world::world_db(data_root, world_name);
    if !path.exists() {
        return None;
    }
    let c = rusqlite::Connection::open(path).ok()?;
    c.query_row(
        "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event::BodyEventKind, test_support::test_core, timeline::BodySha256, world};
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
            "#,
        )
        .unwrap();
        c
    }

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn hmac_for_fields(event_type: &str, target: &str) -> String {
        let key = test_key();
        event_hmac(
            key.as_slice(),
            EventHmacInput {
                prev: "",
                event_type,
                target,
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
            "home/audit-meta",
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
    fn verify_connection_accepts_intact_chain() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let key = test_key();
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &key).unwrap();
        let h1 = append_body_tx_row(
            &audit_tx,
            BodyEventKind::PUT,
            "home/a",
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
        )
        .unwrap();
        let h2 = append_body_tx_row(
            &audit_tx,
            BodyEventKind::APPEND,
            "home/a",
            &BodySha256::for_body(b"abcdef"),
            6,
            "text/plain",
            &[],
        )
        .unwrap();
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
            INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                               content_type, meta_sha256, hmac, prev_hmac)
            VALUES(datetime('now'), 'put', 'home/a', 'abc', 3,
                   'text/plain', 'meta', x'ff', '');
            "#,
        )
        .unwrap();

        let tx = c.transaction().unwrap();
        let key = test_key();
        let err = match verify_appendable_tx_genesis_checked(&tx, &key) {
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
            let audit_tx = verify_appendable_tx_genesis_checked(&tx, &key).unwrap();
            append_body_tx_row(
                &audit_tx,
                BodyEventKind::PUT,
                "home/a",
                &BodySha256::for_body(b"abc"),
                3,
                "text/plain",
                &[],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let tx = c.transaction().unwrap();
        let key = test_key();
        let err = match verify_appendable_tx_existing_checked(&tx, &key) {
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
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &key).unwrap();
        append_body_tx_row(
            &audit_tx,
            BodyEventKind::PUT,
            "home/a",
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[],
        )
        .unwrap();
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
        world::write_with_audit(&root, "home/a", b"abc", "text/plain", &[], &key).unwrap();
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
        let audit_tx = verify_appendable_tx_genesis_checked(&tx, &key).unwrap();
        append_body_tx_row(
            &audit_tx,
            BodyEventKind::PUT,
            "home/a",
            &BodySha256::for_body(b"abc"),
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
        )
        .unwrap();
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
