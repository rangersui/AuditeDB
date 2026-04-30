//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. The chain is a
//! core storage invariant, independent of which SDK or bridge produced
//! the HTTP write.

use hmac::{Hmac, Mac};
use rusqlite::Transaction;
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
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    hmac_field(&mut mac, b"prev", &prev);
    hmac_field(&mut mac, b"type", event_type);
    hmac_field(&mut mac, b"target", target);
    hmac_field(&mut mac, b"body-sha256", body_sha256);
    hmac_field(&mut mac, b"size", &size.to_string());
    hmac_field(&mut mac, b"content-type", content_type);
    hmac_field(&mut mac, b"meta-sha256", &meta_sha256);
    let h = hex::encode(mac.finalize().into_bytes());
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

    fn hmac_for(event_type: &str, target: &str) -> String {
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
        let tx = c.unchecked_transaction().unwrap();
        append_tx(&tx, event_type, target, "abc", 3, "text/plain", &[], b"key").unwrap()
    }

    #[test]
    fn hmac_chain_domain_separates_adjacent_fields() {
        assert_ne!(hmac_for("PUT/home/", "x"), hmac_for("PUT", "/home/x"));
    }
}
