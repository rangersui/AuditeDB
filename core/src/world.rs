//! World storage. One SQLite file per world, schema matches server.py
//! exactly so a /home/foo written by Rust core is readable by the Python
//! reference implementation and vice versa. Schema drift is a bug.

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::time::Duration;

// Match server.py's _disk_name encoding: percent-encode everything that
// would confuse a filesystem (path separators, control chars, Windows
// reserved chars). The decoded world name is the canonical key; the
// encoded form is just the on-disk directory.
const DISK_ENCODE: &AsciiSet = &CONTROLS
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

/// Open or create the world's universe.db with the canonical schema.
/// Schema mirrors server_core.py:464-472 verbatim — when the Python
/// reference adds a column, this needs to stay aligned.
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
            stage_html BLOB DEFAULT '',
            pending_js TEXT DEFAULT '',
            js_result TEXT DEFAULT '',
            version INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT '',
            ext TEXT DEFAULT 'plain',
            headers TEXT DEFAULT '[]',
            state TEXT DEFAULT 'pending'
        );
        INSERT OR IGNORE INTO stage_meta(id, updated_at)
            VALUES(1, datetime('now'));
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT DEFAULT '{}',
            hmac TEXT NOT NULL,
            prev_hmac TEXT DEFAULT ''
        );
        "#,
    )?;
    Ok(c)
}

pub struct Stage {
    pub body: Vec<u8>,
    pub ext: String,
    pub version: i64,
    pub updated_at: String,
    pub headers_json: String,
}

pub fn read(data_root: &Path, world: &str) -> Option<Stage> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return None;
    }
    let c = Connection::open(&path).ok()?;
    let _ = c.busy_timeout(Duration::from_millis(5000));
    let mut stmt = c
        .prepare("SELECT stage_html, ext, version, updated_at, headers FROM stage_meta WHERE id=1")
        .ok()?;
    let row = stmt
        .query_row([], |r| {
            Ok(Stage {
                body: r.get::<_, Vec<u8>>(0).unwrap_or_default(),
                ext: r.get::<_, String>(1).unwrap_or_else(|_| "plain".into()),
                version: r.get::<_, i64>(2).unwrap_or(0),
                updated_at: r.get::<_, String>(3).unwrap_or_default(),
                headers_json: r.get::<_, String>(4).unwrap_or_else(|_| "[]".into()),
            })
        })
        .ok()?;
    Some(row)
}

pub fn write(
    data_root: &Path,
    world: &str,
    body: &[u8],
    ext: &str,
    headers_json: &str,
) -> rusqlite::Result<i64> {
    let c = open(data_root, world)?;
    c.execute(
        r#"UPDATE stage_meta
           SET stage_html=?,
               ext=?,
               headers=?,
               version=version+1,
               updated_at=datetime('now')
           WHERE id=1"#,
        params![body, ext, headers_json],
    )?;
    let v: i64 = c.query_row("SELECT version FROM stage_meta WHERE id=1", [], |r| {
        r.get(0)
    })?;
    Ok(v)
}

pub fn delete(data_root: &Path, world: &str) -> bool {
    let dir = world_dir(data_root, world);
    if !dir.exists() {
        return false;
    }

    // Windows + SQLite WAL keeps -wal / -shm files locked briefly after
    // the connection drops. A naive remove_dir_all can return Ok while
    // leaving stragglers, or fail outright. Mirror server_core.py's
    // _rmtree_retry: flush the WAL via checkpoint, then retry the
    // remove with backoff.
    release_wal_files(data_root, world);

    let mut delay = std::time::Duration::from_millis(30);
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                // Confirm: on Windows remove_dir_all can lie about
                // success when files are open elsewhere.
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

    // Mirror server_core.py::_release_world. After TRUNCATE, SQLite should not
    // need sidecars, but Windows can keep WAL/SHM handles alive briefly. Best
    // effort unlink narrows the race before the recursive directory remove.
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(
            data_root
                .join(disk_name(world))
                .join(format!("universe.db{suffix}")),
        );
    }
    std::thread::sleep(Duration::from_millis(10));
}

/// List all world keys by scanning the data dir. Returns canonical
/// (decoded) names. Used by /proc/worlds.
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
        // percent-decode disk name back to canonical world key
        let decoded = percent_encoding::percent_decode_str(&name)
            .decode_utf8_lossy()
            .into_owned();
        out.push(decoded);
    }
    out.sort();
    out
}
