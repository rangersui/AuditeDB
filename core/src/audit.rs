//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. The chain is a
//! core storage invariant, independent of which SDK or bridge produced
//! the HTTP write.

use hmac::{Hmac, Mac};
use rusqlite::Transaction;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::world;

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
    let meta_sha256 = meta_sha256(content_type, headers);
    let prev: String = tx
        .query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(prev.as_bytes());
    mac.update(event_type.as_bytes());
    mac.update(target.as_bytes());
    mac.update(body_sha256.as_bytes());
    mac.update(size.to_string().as_bytes());
    mac.update(content_type.as_bytes());
    mac.update(meta_sha256.as_bytes());
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
    for (name, value) in canonical_headers(headers) {
        stmt.execute(rusqlite::params![event_id, name, value])?;
    }
    Ok(h)
}

pub fn meta_sha256(content_type: &str, headers: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    h.update(b"content-type\0");
    h.update(content_type.as_bytes());
    h.update(b"\0");
    for (name, value) in canonical_headers(headers) {
        h.update(name.as_bytes());
        h.update(b"\0");
        h.update(value.as_bytes());
        h.update(b"\0");
    }
    hex::encode(h.finalize())
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
