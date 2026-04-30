//! World storage: one SQLite file per world.
//!
//! v5.0 schema (breaking from pre-v5 cores):
//!
//!     stage_meta(id, body, content_type)
//!     meta_headers(name, value)
//!     events(id, timestamp, event_type, target, body_sha256, size,
//!            content_type, meta_sha256, hmac, prev_hmac)
//!     event_headers(event_id, name, value)
//!
//! Renames vs pre-v5: `stage_html` -> `body`. Drops: `pending_js`,
//! `js_result`, `state`. No migrator. World dirs from older binaries
//! fail SELECT body; wipe `data/` to upgrade.
//!
//! `state` is gone on purpose. The old `pending|active|disabled`
//! triple was a hook for an in-core plugin runtime that no longer
//! exists. `/lib/*` is inert storage in the new architecture, and
//! lifecycle (if any) belongs to whatever SDK / endpoint app loads
//! the source. Keeping the column would falsely suggest core decides
//! when a plugin runs.
//!
//! `meta_headers` is the current X-Meta-* header view. `event_headers`
//! is the historical per-write view. The event chain stores structured
//! audit facts, never JSON blobs.

use crate::audit;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

// Encode chars that confuse Windows / POSIX filesystems. Decoded form
// is the canonical world key; encoded form is the on-disk dir name.
//
// Phoenix data-layout note: this intentionally encodes '%' and '.'.
// Older playground data dirs created before that hardening will not be
// found by the new layout. Wipe data/ when crossing that boundary; no
// migrator is promised for the Phoenix kernel.
const DISK_ENCODE: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'.')
    .add(b'/')
    .add(b'\\')
    .add(b':')
    .add(b'*')
    .add(b'?')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'|')
    .add(b' ');

pub fn disk_name(world: &str) -> String {
    utf8_percent_encode(world, DISK_ENCODE).to_string()
}

pub fn world_dir(data_root: &Path, world: &str) -> PathBuf {
    data_root.join(disk_name(world))
}

pub fn world_db(data_root: &Path, world: &str) -> PathBuf {
    world_dir(data_root, world).join("universe.db")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Open or create the world's universe.db with the v5.0 schema.
pub fn open(data_root: &Path, world: &str) -> rusqlite::Result<Connection> {
    let dir = world_dir(data_root, world);
    std::fs::create_dir_all(&dir).expect("create world dir");
    let c = Connection::open(world_db(data_root, world))?;
    c.busy_timeout(Duration::from_millis(5000))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS stage_meta(
            id INTEGER PRIMARY KEY CHECK(id=1),
            body BLOB DEFAULT '',
            content_type TEXT DEFAULT 'application/octet-stream'
        );
        INSERT OR IGNORE INTO stage_meta(id) VALUES(1);
        CREATE TABLE IF NOT EXISTS meta_headers(
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(name)
        );
        CREATE TABLE IF NOT EXISTS events(
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
        CREATE TABLE IF NOT EXISTS event_headers(
            event_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL
        );
        "#,
    )?;
    Ok(c)
}

pub struct Stage {
    pub body: Vec<u8>,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}

pub struct AppendResult {
    pub body_sha256_after: String,
}

/// Read body/meta and latest audit hmac through one SQLite connection.
/// This keeps GET/HEAD from pairing an old body with a newer ETag when
/// a write lands between two independent reads.
pub fn read_with_hmac(data_root: &Path, world: &str) -> Option<(Stage, Option<String>)> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return None;
    }
    let mut c = Connection::open(&path).ok()?;
    let _ = c.busy_timeout(Duration::from_millis(5000));
    let tx = c.transaction().ok()?;
    let (body, content_type) = {
        let mut stmt = tx
            .prepare("SELECT body, content_type FROM stage_meta WHERE id=1")
            .ok()?;
        stmt.query_row([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0).unwrap_or_default(),
                r.get::<_, String>(1)
                    .unwrap_or_else(|_| "application/octet-stream".into()),
            ))
        })
        .ok()?
    };
    let mut headers = Vec::new();
    if let Ok(mut hs) = tx.prepare("SELECT name, value FROM meta_headers ORDER BY name") {
        if let Ok(rows) = hs.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        {
            for pair in rows.flatten() {
                headers.push(pair);
            }
        }
    }
    let latest_hmac = {
        let result = tx.query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        );
        result.ok()
    };
    tx.commit().ok()?;
    Some((
        Stage {
            body,
            content_type,
            headers,
        },
        latest_hmac,
    ))
}

pub fn write(
    data_root: &Path,
    world: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<()> {
    let mut c = open(data_root, world)?;
    let tx = c.transaction()?;
    tx.execute(
        r#"UPDATE stage_meta
           SET body=?,
               content_type=?
           WHERE id=1"#,
        params![body, content_type],
    )?;
    tx.execute("DELETE FROM meta_headers", [])?;
    {
        let mut stmt = tx.prepare("INSERT INTO meta_headers(name, value) VALUES(?, ?)")?;
        for (name, value) in headers {
            stmt.execute(params![name, value])?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn write_with_audit(
    data_root: &Path,
    world: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
) -> rusqlite::Result<String> {
    let mut c = open(data_root, world)?;
    let tx = c.transaction()?;
    tx.execute(
        r#"UPDATE stage_meta
           SET body=?,
               content_type=?
           WHERE id=1"#,
        params![body, content_type],
    )?;
    tx.execute("DELETE FROM meta_headers", [])?;
    {
        let mut stmt = tx.prepare("INSERT INTO meta_headers(name, value) VALUES(?, ?)")?;
        for (name, value) in headers {
            stmt.execute(params![name, value])?;
        }
    }
    let h = audit::append_tx(
        &tx,
        "put",
        world,
        &sha256_hex(body),
        body.len() as i64,
        content_type,
        headers,
        key,
    )?;
    tx.commit()?;
    Ok(h)
}

/// Append bytes to an existing world's body. Returns Ok(None) if the
/// world does not exist; caller responds 404. Does not touch headers
/// (POST append never updates metadata; PUT owns metadata).
pub fn append(
    data_root: &Path,
    world: &str,
    body: &[u8],
) -> rusqlite::Result<Option<AppendResult>> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let c = open(data_root, world)?;
    let current: Vec<u8> = c
        .query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))
        .unwrap_or_default();
    let mut new_body = current;
    new_body.extend_from_slice(body);
    let after = sha256_hex(&new_body);
    c.execute(
        r#"UPDATE stage_meta
           SET body=?
           WHERE id=1"#,
        params![new_body],
    )?;
    Ok(Some(AppendResult {
        body_sha256_after: after,
    }))
}

pub fn append_with_audit(
    data_root: &Path,
    world: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
) -> rusqlite::Result<Option<(AppendResult, String)>> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let mut c = open(data_root, world)?;
    let tx = c.transaction()?;
    let current: Vec<u8> = tx
        .query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))
        .unwrap_or_default();
    let mut new_body = current;
    new_body.extend_from_slice(body);
    let after = sha256_hex(&new_body);
    let size_after = new_body.len();
    tx.execute(
        r#"UPDATE stage_meta
           SET body=?
           WHERE id=1"#,
        params![new_body],
    )?;
    let h = audit::append_tx(
        &tx,
        "append",
        world,
        &after,
        size_after as i64,
        content_type,
        headers,
        key,
    )?;
    tx.commit()?;
    Ok(Some((
        AppendResult {
            body_sha256_after: after,
        },
        h,
    )))
}

pub fn delete(data_root: &Path, world: &str) -> bool {
    let dir = world_dir(data_root, world);
    if !dir.exists() {
        return false;
    }

    // Windows + SQLite WAL: -wal / -shm files stay locked briefly after
    // the connection drops. Naive remove_dir_all may return Ok while
    // leaving stragglers, or fail outright. Flush WAL via checkpoint,
    // then retry the remove.
    release_wal_files(data_root, world);

    let mut delay = std::time::Duration::from_millis(30);
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                if !dir.exists() {
                    return true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => {}
        }
        if attempt == 19 {
            break;
        }
        std::thread::sleep(delay);
        delay = std::cmp::min(delay * 2, std::time::Duration::from_millis(500));
    }
    !dir.exists()
}

fn release_wal_files(data_root: &Path, world: &str) {
    let db = world_db(data_root, world);
    if let Ok(c) = Connection::open(&db) {
        let _ = c.busy_timeout(Duration::from_millis(5000));
        let _ = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        drop(c);
    }
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(
            data_root
                .join(disk_name(world))
                .join(format!("universe.db{suffix}")),
        );
    }
    std::thread::sleep(Duration::from_millis(10));
}

/// List all sqlite-backed world keys by scanning the data dir.
/// Returns canonical (decoded) names.
pub fn list(data_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(data_root) else {
        return out;
    };
    for entry in rd.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().join("universe.db").exists() {
            continue;
        }
        let decoded = percent_encoding::percent_decode_str(&name)
            .decode_utf8_lossy()
            .into_owned();
        out.push(decoded);
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_names_do_not_alias_literal_percent_with_encoded_slash() {
        assert_ne!(disk_name("home/a%2Fb"), disk_name("home/a/b"));
    }

    #[test]
    fn disk_names_encode_dot_segments_even_if_called_directly() {
        assert_ne!(disk_name("."), ".");
        assert_ne!(disk_name(".."), "..");
        assert_eq!(
            percent_encoding::percent_decode_str(&disk_name("home/file.pdf"))
                .decode_utf8()
                .unwrap(),
            "home/file.pdf"
        );
    }

    #[test]
    fn disk_names_roundtrip_unicode_worlds() {
        let world = "home/销售/报告";
        let disk = disk_name(world);
        let decoded = percent_encoding::percent_decode_str(&disk)
            .decode_utf8()
            .unwrap();
        assert_eq!(decoded, world);
    }
}
