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
use rusqlite::{ffi, params, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
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
    std::fs::create_dir_all(&dir).map_err(create_dir_error)?;
    let c = Connection::open(world_db(data_root, world))?;
    c.busy_timeout(Duration::from_millis(5000))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS stage_meta(
            id INTEGER PRIMARY KEY CHECK(id=1),
            body BLOB DEFAULT x'',
            content_type TEXT DEFAULT 'application/octet-stream'
        );
        INSERT OR IGNORE INTO stage_meta(id, body) VALUES(1, x'');
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

fn create_dir_error(err: std::io::Error) -> rusqlite::Error {
    let code = match err.kind() {
        ErrorKind::StorageFull | ErrorKind::WriteZero => ffi::SQLITE_FULL,
        ErrorKind::PermissionDenied => ffi::SQLITE_PERM,
        _ => ffi::SQLITE_CANTOPEN,
    };
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(code),
        Some(format!("create world dir failed: {err}")),
    )
}

/// Open an existing world's universe.db without creating directories,
/// files, or schema. Audit verification uses this path because probing
/// a missing world must not resurrect it.
pub fn open_existing(data_root: &Path, world: &str) -> rusqlite::Result<Option<Connection>> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let c = match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(e) => {
            if !path.exists() {
                return Ok(None);
            }
            return Err(e);
        }
    };
    c.busy_timeout(Duration::from_millis(5000))?;
    Ok(Some(c))
}

pub struct Stage {
    pub body: Vec<u8>,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}

pub type MetaHeaders = Vec<(String, String)>;
pub type WorldMetadata = (usize, String, MetaHeaders);

pub struct AppendResult {
    pub body_sha256_after: String,
}

pub struct WriteAuditResult {
    pub hmac: String,
    /// Body length before this write. Populated for callers that may want
    /// it (e.g. counter accounting). Currently unused by the production
    /// code path because `Core::reserve_storage` reads `previous_len`
    /// outside the SQLite transaction under the per-world lock.
    #[allow(dead_code)]
    pub previous_len: usize,
    /// Whether the world existed before this write. Same status as
    /// `previous_len` -- kept for potential future callers; the active
    /// path uses `world::body_len` outside the tx.
    #[allow(dead_code)]
    pub existed: bool,
}

pub enum WriteAuditError {
    Sqlite(rusqlite::Error),
    /// Returned only if the caller passes a `quota` argument to
    /// `write_with_audit_checked`. The active path passes `None` and
    /// enforces quota via `Core::reserve_storage` instead, so this variant
    /// is currently unreachable in production. Kept for diagnostic clarity
    /// and possible test fixtures.
    #[allow(dead_code)]
    Quota {
        used: usize,
        quota: usize,
        projected: usize,
    },
}

impl From<rusqlite::Error> for WriteAuditError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub fn metadata(data_root: &Path, world: &str) -> rusqlite::Result<Option<WorldMetadata>> {
    let Some(c) = open_existing(data_root, world)? else {
        return Ok(None);
    };
    let (body_len, content_type) = c.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END, content_type FROM stage_meta WHERE id=1",
        [],
        |r| {
            let body_len = r.get::<_, i64>(0)?.max(0) as usize;
            let content_type = r.get::<_, String>(1)?;
            Ok((body_len, content_type))
        },
    )?;
    let mut stmt = c.prepare("SELECT name, value FROM meta_headers ORDER BY name")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut headers = Vec::new();
    for pair in rows {
        headers.push(pair?);
    }
    Ok(Some((body_len, content_type, headers)))
}

pub fn body_len(data_root: &Path, world: &str) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing(data_root, world)? else {
        return Ok(None);
    };
    c.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |r| Ok(r.get::<_, i64>(0)?.max(0) as usize),
    )
    .map(Some)
}

pub fn sizes(data_root: &Path) -> rusqlite::Result<Vec<(String, usize)>> {
    let mut out = Vec::new();
    for world in list(data_root)? {
        if let Some(size) = body_len(data_root, &world)? {
            out.push((world, size));
        }
    }
    Ok(out)
}

/// Read body/meta and latest audit hmac via a `TrackedReadConnection`
/// owned by the SlotState cache (`Core::read_cache`). Inputs are
/// type-gated: the only way to obtain `&mut TrackedReadConnection` is
/// through the slot-before-open dance in `crate::read_cache`. This is
/// the v10 enforcement -- a future contributor opening a bare
/// `Connection` and trying to read through it gets a type error.
///
/// One SQLite tx covers body, headers, and the latest audit hmac, so
/// GET/HEAD never pair an old body with a newer ETag when a write
/// lands between independent reads.
pub fn read_with_hmac_via_conn(
    tracked: &mut crate::read_cache::TrackedReadConnection,
) -> rusqlite::Result<(Stage, Option<String>)> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    let (body, content_type) = {
        let mut stmt = tx.prepare("SELECT body, content_type FROM stage_meta WHERE id=1")?;
        stmt.query_row([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
        })?
    };
    let mut headers = Vec::new();
    {
        let mut hs = tx.prepare("SELECT name, value FROM meta_headers ORDER BY name")?;
        let rows = hs.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for pair in rows {
            headers.push(pair?);
        }
    }
    let latest_hmac = {
        let result = tx.query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        );
        match result {
            Ok(hmac) => Some(hmac),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e),
        }
    };
    tx.commit()?;
    Ok((
        Stage {
            body,
            content_type,
            headers,
        },
        latest_hmac,
    ))
}

/// Test-only seed primitive: write body + headers without touching the
/// HMAC chain. Production durable writes go through
/// `write_with_audit_checked` (which signs the chain). Kept for the
/// fixtures used by `Core::write_world`.
#[cfg(test)]
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

#[cfg(test)]
pub fn write_with_audit(
    data_root: &Path,
    world: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
) -> rusqlite::Result<String> {
    write_with_audit_checked(data_root, world, body, content_type, headers, key, None)
        .map(|result| result.hmac)
        .map_err(|err| match err {
            WriteAuditError::Sqlite(e) => e,
            WriteAuditError::Quota { .. } => unreachable!("quota is disabled"),
        })
}

pub fn write_with_audit_checked(
    data_root: &Path,
    world: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &[u8],
    quota: Option<(usize, usize)>,
) -> Result<WriteAuditResult, WriteAuditError> {
    let existed = world_db(data_root, world).exists();
    if !existed {
        if let Some((used, quota)) = quota {
            let projected = used.saturating_add(body.len());
            if projected > quota {
                return Err(WriteAuditError::Quota {
                    used,
                    quota,
                    projected,
                });
            }
        }
    }
    let mut c = open(data_root, world)?;
    let tx = c.transaction()?;
    let previous_len = tx.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |r| Ok(r.get::<_, i64>(0)?.max(0) as usize),
    )?;
    if let Some((used, quota)) = quota {
        let projected = used.saturating_sub(previous_len).saturating_add(body.len());
        if projected > quota {
            return Err(WriteAuditError::Quota {
                used,
                quota,
                projected,
            });
        }
    }
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
    Ok(WriteAuditResult {
        hmac: h,
        previous_len,
        existed,
    })
}

/// Append bytes to an existing world's body without entering the HMAC
/// chain. Production POST appends go through `append_with_audit`; this
/// raw form is unused after the lock refactor and is preserved with
/// `#[allow(dead_code)]` against future direct callers (e.g. log
/// rotation tooling). Returns Ok(None) if the world does not exist.
#[allow(dead_code)]
pub fn append(
    data_root: &Path,
    world: &str,
    body: &[u8],
) -> rusqlite::Result<Option<AppendResult>> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let mut c = open(data_root, world)?;
    let tx = c.transaction()?;
    let current = tx.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| {
        r.get::<_, Vec<u8>>(0)
    })?;
    let mut new_body = current;
    new_body.extend_from_slice(body);
    let after = sha256_hex(&new_body);
    tx.execute(
        r#"UPDATE stage_meta
           SET body=?
           WHERE id=1"#,
        params![new_body],
    )?;
    tx.commit()?;
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
    let current = tx.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| {
        r.get::<_, Vec<u8>>(0)
    })?;
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
pub fn list(data_root: &Path) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(data_root).map_err(create_dir_error)?;
    for entry in rd {
        let entry = entry.map_err(create_dir_error)?;
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
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("elastik-world-test-{name}-{}", std::process::id()))
    }

    fn force_text_body(data_root: &Path, world: &str, text: &str) {
        let c = Connection::open(world_db(data_root, world)).unwrap();
        c.execute(
            "UPDATE stage_meta SET body=?1, content_type='text/plain; charset=utf-8' WHERE id=1",
            params![text],
        )
        .unwrap();
    }

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

    #[test]
    fn create_dir_storage_full_maps_to_sqlite_disk_full() {
        let err = create_dir_error(std::io::Error::from(ErrorKind::StorageFull));
        assert_eq!(
            err.sqlite_error_code(),
            Some(rusqlite::ffi::ErrorCode::DiskFull)
        );
    }

    #[test]
    fn text_body_storage_is_schema_corruption_not_legacy() {
        let root = test_root("text-body-corruption");
        let _ = std::fs::remove_dir_all(&root);

        write(
            &root,
            "home/plain",
            b"seed",
            "text/plain; charset=utf-8",
            &[],
        )
        .unwrap();
        force_text_body(&root, "home/plain", "\u{00e9}");

        assert!(body_len(&root, "home/plain").is_err());
        assert!(metadata(&root, "home/plain").is_err());
        assert!(sizes(&root).is_err());
        // Read path goes through ReadCache now. Wrap the bare
        // Connection via the test-only helper exported from
        // `read_cache` and call `read_with_hmac_via_conn` on it.
        // The helper is `#[cfg(test)] pub(crate) fn` -- production
        // code cannot construct a `TrackedReadConnection` outside
        // `OpeningTransition::promote`. v10 type gate intact.
        {
            let conn = open(&root, "home/plain").unwrap();
            let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
            assert!(read_with_hmac_via_conn(&mut tracked).is_err());
        }
        assert!(append(&root, "home/plain", b"!").is_err());

        write(
            &root,
            "home/audited",
            b"seed",
            "text/plain; charset=utf-8",
            &[],
        )
        .unwrap();
        force_text_body(&root, "home/audited", "\u{00e9}");
        assert!(append_with_audit(
            &root,
            "home/audited",
            b"!",
            "text/plain; charset=utf-8",
            &[],
            b"test-key",
        )
        .is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    // ---------------- bench sketch (sqlite-connection-pool.md Appendix A)
    //
    // Run via:
    //   cargo test --release --manifest-path core/Cargo.toml \
    //              sqlite_bench_sketch -- --ignored --nocapture
    //
    // Used to bench-gate the v7.1 read-cache PR. Decision criteria
    // (from section10 / Appendix A of the design doc):
    //   < 50 us warm  -> drop read cache, ship ledger-only fallback
    //   50-200 us     -> ship full plan
    //   > 200 us      -> ship full plan with confidence
    mod sqlite_bench_sketch {
        use super::*;
        use std::time::Instant;

        fn scratch_dir(label: &str) -> PathBuf {
            let mut d = std::env::temp_dir();
            d.push(format!(
                "elastik-bench-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        #[ignore]
        fn bench_open_existing_warm() {
            let dir = scratch_dir("open-existing-warm");
            let world = "home/bench";
            let _c = open(&dir, world).unwrap();
            write(&dir, world, b"hello world", "text/plain", &[]).unwrap();

            let n = 10_000;
            let start = Instant::now();
            for _ in 0..n {
                let conn = open_existing(&dir, world).unwrap().unwrap();
                let _len: usize = conn
                    .query_row("SELECT length(body) FROM stage_meta WHERE id=1", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
            }
            let elapsed = start.elapsed();
            eprintln!(
                "open_existing_warm: {:.1} us/iter ({} iters in {:?})",
                elapsed.as_secs_f64() * 1e6 / n as f64,
                n,
                elapsed
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        #[ignore]
        fn bench_open_full_warm() {
            // Full open() with all PRAGMAs + CREATE TABLE IF NOT EXISTS.
            // Bounds the cost the cache eliminates on cold-path reads
            // (open_existing skips the schema CREATEs but still pays
            // the open + busy_timeout + WAL discovery).
            let dir = scratch_dir("open-full-warm");
            let world = "home/bench";
            let _c = open(&dir, world).unwrap();
            write(&dir, world, b"hello world", "text/plain", &[]).unwrap();

            let n = 10_000;
            let start = Instant::now();
            for _ in 0..n {
                let _conn = open(&dir, world).unwrap();
            }
            let elapsed = start.elapsed();
            eprintln!(
                "open_full_warm: {:.1} us/iter ({} iters in {:?})",
                elapsed.as_secs_f64() * 1e6 / n as f64,
                n,
                elapsed
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
