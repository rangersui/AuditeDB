//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. The chain is a
//! core storage invariant, independent of which SDK or bridge produced
//! the HTTP write.

use hmac::{Hmac, Mac};
use rusqlite::{Connection, Statement, Transaction};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::world;

#[allow(clippy::too_many_arguments)]
pub fn append(
    data_root: &Path,
    world_name: &str,
    event_type: &str,
    target: &str,
    body_sha256: &str,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
) -> rusqlite::Result<String> {
    let mut c = world::open(data_root, world_name)?;
    let tx = c.transaction()?;
    let h = append_tx(
        &tx,
        event_type,
        target,
        body_sha256,
        size,
        content_type,
        headers,
        key,
    )?;
    tx.commit()?;
    Ok(h)
}

#[allow(clippy::too_many_arguments)]
pub fn append_tx(
    tx: &Transaction<'_>,
    event_type: &str,
    target: &str,
    body_sha256: &str,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
) -> rusqlite::Result<String> {
    let canonical = canonical_headers(headers);
    let meta_sha256 = meta_sha256_canonical(content_type, &canonical);
    let prev: String = tx
        .query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    let h = event_hmac(
        key,
        EventHmacInput {
            prev: &prev,
            event_type,
            target,
            body_sha256,
            size,
            content_type,
            meta_sha256: &meta_sha256,
        },
    );
    tx.execute(
        r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                              content_type, meta_sha256, hmac, prev_hmac)
           VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)"#,
        rusqlite::params![
            event_type,
            target,
            body_sha256,
            size,
            content_type,
            meta_sha256,
            h,
            prev
        ],
    )?;
    let event_id = tx.last_insert_rowid();
    let mut stmt =
        tx.prepare("INSERT INTO event_headers(event_id, name, value) VALUES(?, ?, ?)")?;
    for (name, value) in canonical {
        stmt.execute(rusqlite::params![event_id, name, value])?;
    }
    Ok(h)
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

pub fn verify_chain(
    data_root: &Path,
    world_name: &str,
    key: &[u8],
) -> rusqlite::Result<Option<VerifyReport>> {
    let path = world::world_db(data_root, world_name);
    if !path.exists() {
        return Ok(None);
    }
    let c = world::open(data_root, world_name)?;
    verify_connection(&c, key).map(Some)
}

fn verify_connection(c: &Connection, key: &[u8]) -> rusqlite::Result<VerifyReport> {
    let mut stmt = c.prepare(
        r#"SELECT id, event_type, target, body_sha256, size,
                  content_type, meta_sha256, hmac, prev_hmac
           FROM events
           ORDER BY id ASC"#,
    )?;
    let mut prev = String::new();
    let mut genesis = String::new();
    let mut events = 0usize;
    let mut header_stmt =
        c.prepare("SELECT name, value FROM event_headers WHERE event_id=? ORDER BY name, value")?;
    let rows = stmt.query_map([], |r| {
        Ok(EventRow {
            id: r.get(0)?,
            event_type: r.get(1)?,
            target: r.get(2)?,
            body_sha256: r.get(3)?,
            size: r.get(4)?,
            content_type: r.get(5)?,
            meta_sha256: r.get(6)?,
            hmac: r.get(7)?,
            prev_hmac: r.get(8)?,
        })
    })?;

    for row in rows {
        let row = row?;
        let idx = events;
        if row.prev_hmac != prev {
            return Ok(VerifyReport::Broken(VerifyBreak {
                break_at: idx,
                expected: hmac_label(&prev),
                actual: hmac_label(&row.prev_hmac),
            }));
        }
        let headers = event_headers(&mut header_stmt, row.id)?;
        let expected_meta = meta_sha256_canonical(&row.content_type, &headers);
        if expected_meta != row.meta_sha256 {
            return Ok(VerifyReport::Broken(VerifyBreak {
                break_at: idx,
                expected: format!("meta-sha256-{expected_meta}"),
                actual: format!("meta-sha256-{}", row.meta_sha256),
            }));
        }
        let expected_hmac = event_hmac(
            key,
            EventHmacInput {
                prev: &prev,
                event_type: &row.event_type,
                target: &row.target,
                body_sha256: &row.body_sha256,
                size: row.size,
                content_type: &row.content_type,
                meta_sha256: &row.meta_sha256,
            },
        );
        if expected_hmac != row.hmac {
            return Ok(VerifyReport::Broken(VerifyBreak {
                break_at: idx,
                expected: hmac_label(&expected_hmac),
                actual: hmac_label(&row.hmac),
            }));
        }
        if idx == 0 {
            genesis = row.hmac.clone();
        }
        prev = row.hmac.clone();
        events += 1;
    }

    if events == 0 {
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

fn event_headers(
    stmt: &mut Statement<'_>,
    event_id: i64,
) -> rusqlite::Result<Vec<(String, String)>> {
    let rows = stmt
        .query_map([event_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect();
    rows
}

#[cfg(test)]
pub(crate) fn meta_sha256(content_type: &str, headers: &[(String, String)]) -> String {
    meta_sha256_canonical(content_type, &canonical_headers(headers))
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

    fn hmac_for(event_type: &str, target: &str) -> String {
        let c = test_connection();
        let tx = c.unchecked_transaction().unwrap();
        append_tx(&tx, event_type, target, "abc", 3, "text/plain", &[], b"key").unwrap()
    }

    #[test]
    fn hmac_chain_domain_separates_adjacent_fields() {
        assert_ne!(hmac_for("PUT/home/", "x"), hmac_for("PUT", "/home/x"));
    }

    #[test]
    fn verify_connection_accepts_intact_chain() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        let h1 = append_tx(
            &tx,
            "put",
            "home/a",
            "abc",
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
            b"key",
        )
        .unwrap();
        let h2 = append_tx(&tx, "append", "home/a", "def", 6, "text/plain", &[], b"key").unwrap();
        tx.commit().unwrap();

        let report = verify_connection(&c, b"key").unwrap();
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
    fn verify_connection_rejects_tampered_event_hmac() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        append_tx(&tx, "put", "home/a", "abc", 3, "text/plain", &[], b"key").unwrap();
        tx.commit().unwrap();
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let report = verify_connection(&c, b"key").unwrap();
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
    fn verify_connection_rejects_tampered_event_headers() {
        let mut c = test_connection();
        let tx = c.transaction().unwrap();
        append_tx(
            &tx,
            "put",
            "home/a",
            "abc",
            3,
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
            b"key",
        )
        .unwrap();
        tx.commit().unwrap();
        c.execute(
            "UPDATE event_headers SET value='intruder' WHERE name='x-meta-author'",
            [],
        )
        .unwrap();

        let report = verify_connection(&c, b"key").unwrap();
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
