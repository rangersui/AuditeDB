//! HMAC event chain. One row per write, hash includes prev_hmac so
//! tampering with any row breaks every row after it. Mirrors
//! server_core.py:591-601's log_event almost exactly.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;

use crate::world;

pub fn append(
    data_root: &Path,
    world_name: &str,
    event_type: &str,
    payload_json: &str,
    key: &[u8],
) -> rusqlite::Result<()> {
    let c = world::open(data_root, world_name)?;
    let prev: String = c
        .query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(prev.as_bytes());
    mac.update(payload_json.as_bytes());
    let h = hex::encode(mac.finalize().into_bytes());
    c.execute(
        r#"INSERT INTO events(timestamp, event_type, payload, hmac, prev_hmac)
           VALUES(datetime('now'), ?, ?, ?, ?)"#,
        rusqlite::params![event_type, payload_json, h, prev],
    )?;
    Ok(())
}
