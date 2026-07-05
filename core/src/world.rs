//! World storage: one SQLite file per world.
//!
//! v5.2 schema (breaking from pre-v5.2 cores):
//!
//! ```text
//!     stage_meta(id, generation, body, content_type)
//!     world_format(id, version)
//!     cas_bodies(body_sha256, body)
//!     cas_state(id, first_retained_seq)
//!     meta_headers(name, value)
//!     events(id, timestamp, event_type, target, body_sha256, size,
//!            content_type, meta_sha256, hmac, prev_hmac)
//!     event_headers(event_id, name, value)
//!     cas_bodies(body_sha256, body)
//!     cas_state(id=1, first_retained_seq)
//! ```
//!
//! Renames vs pre-v5: `stage_html` -> `body`. Drops: `pending_js`,
//! `js_result`, `state`. v5.2 adds CAS tables; stale dirs fail loudly.

use crate::{
    audit,
    blocking_sqlite::BlockingSqlite,
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::BodyEventKind,
    state::FileOpPermit,
    timeline::BodySha256,
    world_generation, world_schema,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rusqlite::{ffi, params, Connection, OpenFlags, Transaction};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod cas;
mod files;

#[cfg(test)]
pub use cas::storage_len;
pub use cas::{
    accounted_storage_usage, append_body_len_if_missing as append_cas_body_len_if_missing,
    append_prunable_body_len_after_next_write as append_prunable_cas_body_len_after_next_write,
    body_len_if_missing as cas_body_len_if_missing,
    prunable_body_len_after_next_write as prunable_cas_body_len_after_next_write, storage_usage,
};
pub(crate) use cas::{PrunedCas, RetainedBodyCount, RetainedCasBody};
#[cfg(test)]
use files::open_checkpoint_conn;
pub use files::{list, list_with_prefix, list_with_prefix_bounded};
pub(crate) use files::{try_for_each, WalkWorldsError};

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

fn disk_name(world: &str) -> String {
    utf8_percent_encode(world, DISK_ENCODE).to_string()
}

fn world_dir_raw(data_root: &Path, world: &str) -> PathBuf {
    data_root.join(disk_name(world))
}

fn world_db_raw(data_root: &Path, world: &str) -> PathBuf {
    world_dir_raw(data_root, world).join("universe.db")
}

#[cfg(test)]
pub fn world_dir(data_root: &Path, world: &str) -> PathBuf {
    world_dir_raw(data_root, world)
}

#[cfg(test)]
pub fn world_db(data_root: &Path, world: &str) -> PathBuf {
    world_db_raw(data_root, world)
}

pub fn validated_world_dir(data_root: &Path, world: &ValidatedWorldPath) -> PathBuf {
    world_dir_raw(data_root, world.as_str())
}

pub fn validated_world_db(data_root: &Path, world: &ValidatedWorldPath) -> PathBuf {
    world_db_raw(data_root, world.as_str())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Open or create the world's universe.db with the v5.2 schema.
#[cfg(test)]
pub fn open(data_root: &Path, world: &str) -> rusqlite::Result<Connection> {
    let mut proof = crate::blocking_sqlite::test_only_mint();
    open_with_generation_minter(
        data_root,
        world,
        || world_generation::WorldGeneration::mint().map_err(mint_generation_error),
        &mut proof,
    )
}

pub fn open_validated(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    _file_op: &FileOpPermit,
) -> rusqlite::Result<Connection> {
    open_validated_with_generation_minter(_proof, data_root, world, || {
        world_generation::WorldGeneration::mint().map_err(mint_generation_error)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenedWorldKind {
    Created,
    Existing,
}

pub(crate) struct OpenedWriteConnection {
    conn: Connection,
    opened: OpenedWorldKind,
}

impl OpenedWriteConnection {
    fn new(conn: Connection, opened: OpenedWorldKind) -> Self {
        Self { conn, opened }
    }

    pub(crate) fn verify_shape(&self, proof: &mut BlockingSqlite) -> rusqlite::Result<()> {
        world_schema::verify_open_shape(proof, &self.conn)
    }

    fn as_mut_conn(&mut self, _proof: &mut BlockingSqlite) -> &mut Connection {
        &mut self.conn
    }

    fn mark_existing(&mut self) {
        self.opened = OpenedWorldKind::Existing;
    }
}

#[cfg(test)]
fn open_with_generation_minter<F>(
    data_root: &Path,
    world: &str,
    mint_generation: F,
    proof: &mut BlockingSqlite,
) -> rusqlite::Result<Connection>
where
    F: FnOnce() -> rusqlite::Result<world_generation::MintedWorldGeneration>,
{
    open_world_paths_with_generation_minter_and_kind(
        world_dir_raw(data_root, world),
        world_db_raw(data_root, world),
        mint_generation,
        proof,
    )
    .map(|(conn, _)| conn)
}

fn open_validated_with_generation_minter<F>(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    mint_generation: F,
) -> rusqlite::Result<Connection>
where
    F: FnOnce() -> rusqlite::Result<world_generation::MintedWorldGeneration>,
{
    open_validated_with_generation_minter_and_kind(proof, data_root, world, mint_generation)
        .map(|(conn, _)| conn)
}

#[cfg(test)]
fn open_validated_for_audit(
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> rusqlite::Result<(Connection, OpenedWorldKind)> {
    let mut proof = crate::blocking_sqlite::test_only_mint();
    open_validated_with_generation_minter_and_kind(&mut proof, data_root, world, || {
        world_generation::WorldGeneration::mint().map_err(mint_generation_error)
    })
}

pub(crate) fn open_cached_writer(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    _file_op: &FileOpPermit,
) -> rusqlite::Result<OpenedWriteConnection> {
    open_world_paths_with_generation_minter_and_kind(
        validated_world_dir(data_root, world),
        validated_world_db(data_root, world),
        || world_generation::WorldGeneration::mint().map_err(mint_generation_error),
        _proof,
    )
    .map(|(conn, opened)| OpenedWriteConnection::new(conn, opened))
}

fn open_validated_with_generation_minter_and_kind<F>(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    mint_generation: F,
) -> rusqlite::Result<(Connection, OpenedWorldKind)>
where
    F: FnOnce() -> rusqlite::Result<world_generation::MintedWorldGeneration>,
{
    open_world_paths_with_generation_minter_and_kind(
        validated_world_dir(data_root, world),
        validated_world_db(data_root, world),
        mint_generation,
        proof,
    )
}

fn open_world_paths_with_generation_minter_and_kind<F>(
    dir: PathBuf,
    db: PathBuf,
    mint_generation: F,
    proof: &mut BlockingSqlite,
) -> rusqlite::Result<(Connection, OpenedWorldKind)>
where
    F: FnOnce() -> rusqlite::Result<world_generation::MintedWorldGeneration>,
{
    let db_existed = db.exists();
    let opened = if db_existed {
        OpenedWorldKind::Existing
    } else {
        OpenedWorldKind::Created
    };
    let generation = if db_existed {
        None
    } else {
        Some(mint_generation()?)
    };

    std::fs::create_dir_all(&dir).map_err(create_dir_error)?;
    let c = Connection::open(db)?;
    c.busy_timeout(Duration::from_millis(5000))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        PRAGMA wal_autocheckpoint=0;
        "#,
    )?;
    if db_existed {
        world_schema::verify_open_shape(proof, &c)?;
    } else {
        let schema = world_schema::new_world(proof, &c)?;
        let generation = generation.ok_or_else(missing_minted_generation_error)?;
        world_schema::create(proof, schema, generation)?;
    }
    Ok((c, opened))
}

fn mint_generation_error(err: world_generation::MintWorldGenerationError) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_IOERR),
        Some(format!("mint world generation failed: {err}")),
    )
}

fn missing_minted_generation_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_INTERNAL),
        Some("new world schema creation reached without minted generation".to_owned()),
    )
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
#[cfg(test)]
pub fn open_existing(data_root: &Path, world: &str) -> rusqlite::Result<Option<Connection>> {
    let path = world_db_raw(data_root, world);
    open_existing_path(&mut crate::blocking_sqlite::test_only_mint(), &path)
}

pub fn open_existing_validated(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    _file_op: &FileOpPermit,
) -> rusqlite::Result<Option<Connection>> {
    let path = validated_world_db(data_root, world);
    open_existing_path(_proof, &path)
}

pub(crate) fn delete(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    _file_op: &FileOpPermit,
) -> bool {
    files::delete(proof, data_root, world)
}

fn open_existing_path(
    proof: &mut BlockingSqlite,
    path: &Path,
) -> rusqlite::Result<Option<Connection>> {
    if !path.exists() {
        return Ok(None);
    }
    let c = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(e) => {
            if !path.exists() {
                return Ok(None);
            }
            return Err(e);
        }
    };
    c.busy_timeout(Duration::from_millis(5000))?;
    world_schema::verify_open_shape(proof, &c)?;
    Ok(Some(c))
}

#[cfg(test)]
fn open_existing_validated_for_write(
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> rusqlite::Result<Option<Connection>> {
    open_existing_writer_path(
        &mut crate::blocking_sqlite::test_only_mint(),
        &validated_world_db(data_root, world),
    )
}

pub(crate) fn open_existing_cached_writer(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    _file_op: &FileOpPermit,
) -> rusqlite::Result<Option<OpenedWriteConnection>> {
    Ok(
        open_existing_writer_path(_proof, &validated_world_db(data_root, world))?
            .map(|conn| OpenedWriteConnection::new(conn, OpenedWorldKind::Existing)),
    )
}

fn open_existing_writer_path(
    proof: &mut BlockingSqlite,
    path: &Path,
) -> rusqlite::Result<Option<Connection>> {
    if !path.exists() {
        return Ok(None);
    }
    let c = match Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            if !path.exists() {
                return Ok(None);
            }
            return Err(e);
        }
    };
    c.busy_timeout(Duration::from_millis(5000))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        PRAGMA wal_autocheckpoint=0;
        "#,
    )?;
    world_schema::verify_open_shape(proof, &c)?;
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StorageUsageSnapshot {
    current_body_bytes: usize,
    retained_cas_body_bytes: usize,
    audit_chain_events: usize,
}

impl StorageUsageSnapshot {
    pub(crate) fn total_body_bytes(self) -> usize {
        self.current_body_bytes
            .saturating_add(self.retained_cas_body_bytes)
    }

    pub(crate) fn from_current_body_bytes(current_body_bytes: usize) -> Self {
        Self {
            current_body_bytes,
            retained_cas_body_bytes: 0,
            audit_chain_events: 0,
        }
    }

    fn from_durable_parts(
        current_body_bytes: usize,
        retained_cas_body_bytes: usize,
        audit_chain_events: usize,
    ) -> Self {
        Self {
            current_body_bytes,
            retained_cas_body_bytes,
            audit_chain_events,
        }
    }

    pub(crate) fn current_body_bytes(self) -> usize {
        self.current_body_bytes
    }

    pub(crate) fn retained_cas_body_bytes(self) -> usize {
        self.retained_cas_body_bytes
    }

    pub(crate) fn audit_chain_events(self) -> usize {
        self.audit_chain_events
    }
}

pub(crate) struct AccountedStorageUsage {
    data_root: PathBuf,
    world: ValidatedWorldPath,
    usage: StorageUsageSnapshot,
}

impl AccountedStorageUsage {
    pub(crate) fn into_snapshot_for(
        self,
        data_root: &Path,
        world: &ValidatedWorldPath,
    ) -> Result<StorageUsageSnapshot, AccountedStorageUsageMismatch> {
        if self.data_root == data_root && self.world == *world {
            Ok(self.usage)
        } else {
            Err(AccountedStorageUsageMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccountedStorageUsageMismatch;

pub struct AppendAuditResult {
    pub(crate) cas_body_inserted: bool,
    pub(crate) pruned_cas: PrunedCas,
    pub(crate) format_event: Option<audit::AppendedAuditRow>,
    pub(crate) body_event: audit::AppendedBodyAuditRow,
}

pub struct WriteAuditResult {
    pub hmac: String,
    pub(crate) cas_body_inserted: bool,
    pub(crate) pruned_cas: PrunedCas,
    pub(crate) format_event: Option<audit::AppendedAuditRow>,
    pub(crate) body_event: audit::AppendedBodyAuditRow,
    /// Body length before this write. Used by no-quota accounting, where
    /// the hot path avoids an extra pre-write metadata connection and
    /// reconciles counters from the committed transaction result.
    pub previous_len: usize,
    /// Whether the world existed before this write. Used by no-quota
    /// accounting to update durable-world counters from committed state.
    pub existed: bool,
}

#[derive(Debug)]
pub enum WriteAuditError {
    Audit(audit::AuditError),
    Sqlite(rusqlite::Error),
    CasBodyMismatch { body_sha256: BodySha256 },
    StorageInvariant(&'static str),
}

impl From<rusqlite::Error> for WriteAuditError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<audit::AuditError> for WriteAuditError {
    fn from(value: audit::AuditError) -> Self {
        Self::Audit(value)
    }
}

pub fn metadata(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<WorldMetadata>> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
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

pub fn body_len(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Option<usize>> {
    let Some(c) = open_existing_validated(proof, data_root, world, file_op)? else {
        return Ok(None);
    };
    c.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |r| Ok(r.get::<_, i64>(0)?.max(0) as usize),
    )
    .map(Some)
}

pub(crate) fn usages(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    file_op: &FileOpPermit,
) -> rusqlite::Result<Vec<(ValidatedWorldPath, StorageUsageSnapshot)>> {
    let mut out = Vec::new();
    for world_path in list(proof, data_root, file_op)? {
        if let Some(usage) = storage_usage(proof, data_root, &world_path, file_op)? {
            out.push((world_path, usage));
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
/// Read operations never pair an old body with a newer ETag when a write
/// lands between independent reads.
pub fn read_with_hmac_via_conn(
    proof: &mut BlockingSqlite,
    tracked: &mut crate::read_cache::TrackedReadConnection,
    world: &crate::engine_types::ValidatedWorldPath,
    key: &crate::engine_types::AuditHmacKey,
) -> crate::audit::AuditResult<(Stage, Option<String>)> {
    let conn = tracked.as_mut_conn(proof);
    let tx = conn.transaction()?;
    crate::audit::require_current_world_intact_tx(proof, &tx, world, key)?;
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
            Err(e) => return Err(crate::audit::AuditError::Storage(e)),
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
pub fn test_only_write_without_audit(
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
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
) -> Result<String, WriteAuditError> {
    write_with_audit_checked_retaining(
        data_root,
        world,
        body,
        content_type,
        headers,
        key,
        RetainedBodyCount::default(),
    )
    .map(|result| result.hmac)
}

#[cfg(test)]
pub fn write_with_audit_checked(
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
) -> Result<WriteAuditResult, WriteAuditError> {
    write_with_audit_checked_retaining(
        data_root,
        world,
        body,
        content_type,
        headers,
        key,
        RetainedBodyCount::default(),
    )
}

#[cfg(test)]
pub(crate) fn write_with_audit_checked_retaining(
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retained_body_count: RetainedBodyCount,
) -> Result<WriteAuditResult, WriteAuditError> {
    let (c, opened) = open_validated_for_audit(data_root, world)?;
    let mut opened_conn = OpenedWriteConnection::new(c, opened);
    let verified_audit_worlds =
        crate::state::AuditVerificationCache::from_verified(std::iter::empty());
    write_with_audit_checked_retaining_on_conn(
        &mut crate::blocking_sqlite::test_only_mint(),
        &mut opened_conn,
        &verified_audit_worlds,
        world,
        body,
        content_type,
        headers,
        key,
        retained_body_count,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_with_audit_checked_retaining_on_conn(
    proof: &mut BlockingSqlite,
    opened_conn: &mut OpenedWriteConnection,
    verified_audit_worlds: &crate::state::AuditVerificationCache,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retained_body_count: RetainedBodyCount,
) -> Result<WriteAuditResult, WriteAuditError> {
    let opened = opened_conn.opened;
    let conn = opened_conn.as_mut_conn(proof);
    let tx = conn.transaction()?;
    let previous_len = tx.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) END FROM stage_meta WHERE id=1",
        [],
        |r| Ok(r.get::<_, i64>(0)?.max(0) as usize),
    )?;
    let (format_event, hmac, cas_body_inserted, pruned_cas, body_event, verified_prefix) = {
        let (audit_tx, is_genesis, verified_prefix) =
            verify_appendable_world_tx(proof, &tx, verified_audit_worlds, world, key, opened)?;
        let format_event = if is_genesis {
            Some(audit::append_format_tx_row(&audit_tx)?)
        } else {
            None
        };
        let retained = cas::retain_body_tx(&tx, world, body)?;
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
        let row = audit::append_retained_body_tx_row(
            &audit_tx,
            BodyEventKind::PUT,
            &retained,
            content_type,
            headers,
        )?;
        cas::mark_retention_started_tx(&tx, row.id())?;
        let pruned = cas::prune_to_count_tx(&tx, retained_body_count)?;
        (
            format_event,
            row.hmac().to_owned(),
            retained.inserted(),
            pruned,
            row,
            verified_prefix,
        )
    };
    tx.commit()?;
    if let Some(prefix) = verified_prefix {
        verified_audit_worlds.mark_verified(prefix);
    }
    opened_conn.mark_existing();
    Ok(WriteAuditResult {
        hmac,
        cas_body_inserted,
        pruned_cas,
        format_event,
        body_event,
        previous_len,
        existed: matches!(opened, OpenedWorldKind::Existing),
    })
}

/// Append bytes to an existing world's body without entering the HMAC
/// chain. Test-only schema-corruption probes use this to make sure raw
/// SQLite body errors are still detected; production durable appends must
/// go through `append_with_audit`.
#[cfg(test)]
#[allow(dead_code)]
fn test_only_append_without_audit(
    data_root: &Path,
    world: &str,
    body: &[u8],
) -> rusqlite::Result<Option<AppendResult>> {
    let path = world_db_raw(data_root, world);
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

#[cfg(test)]
pub fn append_with_audit(
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
) -> Result<Option<(AppendAuditResult, String)>, WriteAuditError> {
    append_with_audit_retaining(
        data_root,
        world,
        body,
        content_type,
        headers,
        key,
        RetainedBodyCount::default(),
    )
}

#[cfg(test)]
pub(crate) fn append_with_audit_retaining(
    data_root: &Path,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retained_body_count: RetainedBodyCount,
) -> Result<Option<(AppendAuditResult, String)>, WriteAuditError> {
    let path = validated_world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let Some(c) = open_existing_validated_for_write(data_root, world)? else {
        return Ok(None);
    };
    let mut opened_conn = OpenedWriteConnection::new(c, OpenedWorldKind::Existing);
    let verified_audit_worlds =
        crate::state::AuditVerificationCache::from_verified(std::iter::empty());
    append_with_audit_retaining_on_conn(
        &mut crate::blocking_sqlite::test_only_mint(),
        &mut opened_conn,
        &verified_audit_worlds,
        world,
        body,
        content_type,
        headers,
        key,
        retained_body_count,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_with_audit_retaining_on_conn(
    proof: &mut BlockingSqlite,
    opened_conn: &mut OpenedWriteConnection,
    verified_audit_worlds: &crate::state::AuditVerificationCache,
    world: &ValidatedWorldPath,
    body: &[u8],
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retained_body_count: RetainedBodyCount,
) -> Result<Option<(AppendAuditResult, String)>, WriteAuditError> {
    let conn = opened_conn.as_mut_conn(proof);
    let tx = conn.transaction()?;
    let (cas_body_inserted, pruned_cas, format_event, body_event, hmac, verified_prefix) = {
        let (audit_tx, is_genesis, verified_prefix) = verify_appendable_world_tx(
            proof,
            &tx,
            verified_audit_worlds,
            world,
            key,
            OpenedWorldKind::Existing,
        )?;
        let format_event = if is_genesis {
            Some(audit::append_format_tx_row(&audit_tx)?)
        } else {
            None
        };
        let current = tx.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        let mut new_body = current;
        new_body.extend_from_slice(body);
        let retained = cas::retain_body_tx(&tx, world, &new_body)?;
        tx.execute(
            r#"UPDATE stage_meta
               SET body=?
               WHERE id=1"#,
            params![new_body],
        )?;
        let row = audit::append_retained_body_tx_row(
            &audit_tx,
            BodyEventKind::APPEND,
            &retained,
            content_type,
            headers,
        )?;
        cas::mark_retention_started_tx(&tx, row.id())?;
        let pruned = cas::prune_to_count_tx(&tx, retained_body_count)?;
        let hmac = row.hmac().to_owned();
        (
            retained.inserted(),
            pruned,
            format_event,
            row,
            hmac,
            verified_prefix,
        )
    };
    tx.commit()?;
    if let Some(prefix) = verified_prefix {
        verified_audit_worlds.mark_verified(prefix);
    }
    Ok(Some((
        AppendAuditResult {
            cas_body_inserted,
            pruned_cas,
            format_event,
            body_event,
        },
        hmac,
    )))
}

fn verify_appendable_world_tx<'tx, 'conn, 'key>(
    proof: &mut BlockingSqlite,
    tx: &'tx Transaction<'conn>,
    verified_audit_worlds: &crate::state::AuditVerificationCache,
    world: &ValidatedWorldPath,
    key: &'key AuditHmacKey,
    opened: OpenedWorldKind,
) -> Result<
    (
        audit::VerifiedAuditTx<'tx, 'conn, 'key>,
        bool,
        Option<audit::VerifiedAuditPrefix>,
    ),
    WriteAuditError,
> {
    match audit_chain_opening(tx, opened)? {
        AuditChainOpening::Genesis(_proof) => {
            verified_audit_worlds.note_full_append_gate();
            let (audit_tx, prefix) =
                audit::verify_appendable_tx_genesis_checked_with_prefix(proof, tx, world, key)?;
            Ok((audit_tx, true, Some(prefix)))
        }
        AuditChainOpening::Existing => {
            if let Some(prefix) = verified_audit_worlds.verified_prefix(world) {
                verified_audit_worlds.note_tail_append_gate();
                Ok((
                    audit::verify_appendable_tx_existing_tail_checked(proof, tx, &prefix, key)?,
                    false,
                    None,
                ))
            } else {
                verified_audit_worlds.note_full_append_gate();
                let (audit_tx, prefix) = audit::verify_appendable_tx_existing_checked_with_prefix(
                    proof, tx, world, key,
                )?;
                Ok((audit_tx, false, Some(prefix)))
            }
        }
    }
}

struct GenesisAuditProof {
    _private: (),
}

enum AuditChainOpening {
    Genesis(GenesisAuditProof),
    Existing,
}

fn audit_chain_opening(
    tx: &Transaction<'_>,
    opened: OpenedWorldKind,
) -> Result<AuditChainOpening, WriteAuditError> {
    match opened {
        OpenedWorldKind::Created => Ok(AuditChainOpening::Genesis(GenesisAuditProof {
            _private: (),
        })),
        OpenedWorldKind::Existing if is_empty_bootstrap_tx(tx)? => {
            Ok(AuditChainOpening::Genesis(GenesisAuditProof {
                _private: (),
            }))
        }
        OpenedWorldKind::Existing => Ok(AuditChainOpening::Existing),
    }
}

fn is_empty_bootstrap_tx(tx: &Transaction<'_>) -> rusqlite::Result<bool> {
    let events: i64 = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let event_headers: i64 =
        tx.query_row("SELECT COUNT(*) FROM event_headers", [], |r| r.get(0))?;
    let meta_headers: i64 = tx.query_row("SELECT COUNT(*) FROM meta_headers", [], |r| r.get(0))?;
    let body_len: i64 = tx.query_row(
        "SELECT CASE WHEN typeof(body) = 'blob' THEN length(body) ELSE -1 END FROM stage_meta WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    Ok(events == 0 && event_headers == 0 && meta_headers == 0 && body_len == 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("auditedb-world-test-{name}-{}", std::process::id()))
    }

    fn validated(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn force_text_body(data_root: &Path, world: &str, text: &str) {
        let c = Connection::open(world_db(data_root, world)).unwrap();
        c.execute(
            "UPDATE stage_meta SET body=?1, content_type='text/plain; charset=utf-8' WHERE id=1",
            params![text],
        )
        .unwrap();
    }

    fn create_legacy_world_without_generation(data_root: &Path, world: &str) {
        std::fs::create_dir_all(world_dir(data_root, world)).unwrap();
        let c = Connection::open(world_db(data_root, world)).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, body) VALUES(1, x'');
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
            "#,
        )
        .unwrap();
    }

    #[test]
    fn retained_cas_body_rejects_different_transaction() {
        let root_a = test_root("retained-cas-tx-identity-a");
        let root_b = test_root("retained-cas-tx-identity-b");
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
        let key = test_key();
        let world = validated("home/cas-tx-identity");

        let mut c1 = open(&root_a, world.as_str()).unwrap();
        let mut c2 = open(&root_b, world.as_str()).unwrap();
        let tx1 = c1.transaction().unwrap();
        let tx2 = c2.transaction().unwrap();
        let retained = cas::retain_body_tx(&tx1, &world, b"retained elsewhere").unwrap();
        let audit_tx = audit::verify_appendable_tx_genesis_checked(
            &mut crate::blocking_sqlite::test_only_mint(),
            &tx2,
            &world,
            &key,
        )
        .unwrap();

        let err = match audit::append_retained_body_tx_row(
            &audit_tx,
            BodyEventKind::PUT,
            &retained,
            "text/plain",
            &[],
        ) {
            Ok(_) => panic!("retained body proof from a different transaction must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, rusqlite::Error::InvalidQuery));
    }

    #[test]
    fn audited_write_retains_cas_body_and_starts_floor() {
        let root = test_root("cas-retain-write");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        let body = b"retained body";
        let body_hash = sha256_hex(body);

        let hmac =
            write_with_audit(&root, &validated("home/cas"), body, "text/plain", &[], &key).unwrap();

        let c = Connection::open(world_db(&root, "home/cas")).unwrap();
        let retained: Vec<u8> = c
            .query_row(
                "SELECT body FROM cas_bodies WHERE body_sha256=?1",
                params![body_hash],
                |r| r.get(0),
            )
            .unwrap();
        let first_retained_seq: i64 = c
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let (format_type, format_target): (String, String) = c
            .query_row(
                "SELECT event_type, target FROM events WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let (event_hmac, event_hash): (String, String) = c
            .query_row("SELECT hmac, body_sha256 FROM events WHERE id=2", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();

        assert_eq!(retained, body);
        assert_eq!(format_type, "format");
        assert_eq!(format_target, "home/cas");
        assert_eq!(first_retained_seq, 2);
        assert_eq!(event_hmac, hmac);
        assert_eq!(event_hash, body_hash);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_append_retains_full_body_without_moving_floor() {
        let root = test_root("cas-retain-append");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();

        write_with_audit(
            &root,
            &validated("home/cas-append"),
            b"one",
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        let (result, _) = append_with_audit(
            &root,
            &validated("home/cas-append"),
            b"two",
            "text/plain",
            &[],
            &key,
        )
        .unwrap()
        .unwrap();

        let full_body = b"onetwo";
        let full_hash = sha256_hex(full_body);
        assert_eq!(
            result.body_event.timeline_address().body_sha256().as_str(),
            full_hash
        );

        let c = Connection::open(world_db(&root, "home/cas-append")).unwrap();
        let retained: Vec<u8> = c
            .query_row(
                "SELECT body FROM cas_bodies WHERE body_sha256=?1",
                params![full_hash],
                |r| r.get(0),
            )
            .unwrap();
        let first_retained_seq: i64 = c
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let cas_rows: i64 = c
            .query_row("SELECT COUNT(*) FROM cas_bodies", [], |r| r.get(0))
            .unwrap();

        assert_eq!(retained, full_body);
        assert_eq!(first_retained_seq, 2);
        assert_eq!(cas_rows, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_reuses_same_cas_body_without_moving_floor() {
        let root = test_root("cas-idempotent");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();

        write_with_audit(
            &root,
            &validated("home/cas-idempotent"),
            b"same",
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        write_with_audit(
            &root,
            &validated("home/cas-idempotent"),
            b"same",
            "application/octet-stream",
            &[],
            &key,
        )
        .unwrap();

        let c = Connection::open(world_db(&root, "home/cas-idempotent")).unwrap();
        let cas_rows: i64 = c
            .query_row("SELECT COUNT(*) FROM cas_bodies", [], |r| r.get(0))
            .unwrap();
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let first_retained_seq: i64 = c
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(cas_rows, 1);
        assert_eq!(events, 3);
        assert_eq!(first_retained_seq, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_rejects_cas_mismatch_before_event_commit() {
        let root = test_root("cas-mismatch");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        let old_body = b"old-value";
        let new_body = b"new-value";
        let new_body_hash = sha256_hex(new_body);

        write_with_audit(
            &root,
            &validated("home/cas-mismatch"),
            old_body,
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        {
            let c = Connection::open(world_db(&root, "home/cas-mismatch")).unwrap();
            c.execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, x'00')",
                params![new_body_hash],
            )
            .unwrap();
        }

        let _err = write_with_audit(
            &root,
            &validated("home/cas-mismatch"),
            new_body,
            "text/plain",
            &[],
            &key,
        )
        .unwrap_err();

        let c = Connection::open(world_db(&root, "home/cas-mismatch")).unwrap();
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let stage_body: Vec<u8> = c
            .query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let first_retained_seq: i64 = c
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(events, 2);
        assert_eq!(stage_body, old_body);
        assert_eq!(first_retained_seq, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_rejects_current_tail_cas_mismatch_before_event_commit() {
        let root = test_root("cas-tail-mismatch");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        let old_body = b"old-value";
        let old_body_hash = sha256_hex(old_body);

        write_with_audit(
            &root,
            &validated("home/cas-tail-mismatch"),
            old_body,
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        {
            let c = Connection::open(world_db(&root, "home/cas-tail-mismatch")).unwrap();
            c.execute(
                "UPDATE cas_bodies SET body=?1 WHERE body_sha256=?2",
                params![b"bad-value".as_slice(), old_body_hash],
            )
            .unwrap();
        }

        let _err = write_with_audit(
            &root,
            &validated("home/cas-tail-mismatch"),
            b"new-value",
            "text/plain",
            &[],
            &key,
        )
        .unwrap_err();

        let c = Connection::open(world_db(&root, "home/cas-tail-mismatch")).unwrap();
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let stage_body: Vec<u8> = c
            .query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))
            .unwrap();

        assert_eq!(events, 2);
        assert_eq!(stage_body, old_body);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_append_rejects_cas_mismatch_before_event_commit() {
        let root = test_root("cas-append-mismatch");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();

        write_with_audit(
            &root,
            &validated("home/cas-append-mismatch"),
            b"one",
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        let next_hash = sha256_hex(b"onetwo");
        {
            let c = Connection::open(world_db(&root, "home/cas-append-mismatch")).unwrap();
            c.execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, x'00')",
                params![next_hash],
            )
            .unwrap();
        }

        let _err = match append_with_audit(
            &root,
            &validated("home/cas-append-mismatch"),
            b"two",
            "text/plain",
            &[],
            &key,
        ) {
            Ok(_) => panic!("corrupt CAS body row must reject append"),
            Err(err) => err,
        };

        let c = Connection::open(world_db(&root, "home/cas-append-mismatch")).unwrap();
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let body: Vec<u8> = c
            .query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| r.get(0))
            .unwrap();

        assert_eq!(events, 2);
        assert_eq!(body, b"one");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_rejects_cas_floor_ahead_of_event() {
        let root = test_root("cas-floor-ahead");
        let _ = std::fs::remove_dir_all(&root);
        drop(open(&root, "home/cas-floor").unwrap());
        {
            let c = Connection::open(world_db(&root, "home/cas-floor")).unwrap();
            c.execute("UPDATE cas_state SET first_retained_seq=999 WHERE id=1", [])
                .unwrap();
        }

        let err = write_with_audit(
            &root,
            &validated("home/cas-floor"),
            b"one",
            "text/plain",
            &[],
            &test_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WriteAuditError::Audit(audit::AuditError::ChainBroken(break_report))
                if break_report.actual == "missing-retention-floor-event"
        ));

        let c = Connection::open(world_db(&root, "home/cas-floor")).unwrap();
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();

        assert_eq!(events, 0);
        let _ = std::fs::remove_dir_all(root);
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
    fn list_rejects_invalid_percent_utf8_world_dirs() {
        let root = test_root("invalid-percent-world-dir");
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("home%2F%FF");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(dir.join("universe.db")).unwrap();

        let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
        let file_op = gate.begin().unwrap();
        let err = list(
            &mut crate::blocking_sqlite::test_only_mint(),
            &root,
            &file_op,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid percent UTF-8"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn list_rejects_noncanonical_percent_world_dirs() {
        let root = test_root("noncanonical-percent-world-dir");
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("home%2flower");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(dir.join("universe.db")).unwrap();

        let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
        let file_op = gate.begin().unwrap();
        let err = list(
            &mut crate::blocking_sqlite::test_only_mint(),
            &root,
            &file_op,
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-canonical disk name"));
        let _ = std::fs::remove_dir_all(root);
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
    fn open_new_world_persists_generation() {
        let root = test_root("world-generation");
        let _ = std::fs::remove_dir_all(&root);
        let stored = {
            let c = open(&root, "home/generated").unwrap();
            let generation =
                crate::world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &c)
                    .unwrap();
            let raw: String = c
                .query_row("SELECT generation FROM stage_meta WHERE id=1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(raw.len(), 32);
            assert!(raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            assert_eq!(
                generation,
                crate::world_generation::WorldGeneration::new(raw.clone()).unwrap()
            );
            raw
        };

        let c = open(&root, "home/generated").unwrap();
        assert_eq!(
            crate::world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &c)
                .unwrap(),
            crate::world_generation::WorldGeneration::new(stored).unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn open_mint_failure_does_not_create_world_artifacts() {
        let root = test_root("world-generation-mint-failure");
        let _ = std::fs::remove_dir_all(&root);

        let err = open_with_generation_minter(
            &root,
            "home/generated",
            || {
                Err(rusqlite::Error::SqliteFailure(
                    ffi::Error::new(ffi::SQLITE_IOERR),
                    Some("forced mint failure".to_owned()),
                ))
            },
            &mut crate::blocking_sqlite::test_only_mint(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("forced mint failure"));
        assert!(!world_dir(&root, "home/generated").exists());
        assert!(!world_db(&root, "home/generated").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn open_existing_rejects_legacy_stage_meta_without_generation() {
        let root = test_root("legacy-world-generation");
        let _ = std::fs::remove_dir_all(&root);
        create_legacy_world_without_generation(&root, "home/legacy");

        let err = open_existing(&root, "home/legacy").unwrap_err();

        assert!(err.to_string().contains("stage_meta.generation"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_open_does_not_create_missing_universe_db() {
        let root = test_root("checkpoint-missing-db");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(world_dir(&root, "home/missing")).unwrap();

        let conn = open_checkpoint_conn(&root, "home/missing").unwrap();

        assert!(conn.is_none());
        assert!(!world_db(&root, "home/missing").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_open_rejects_legacy_stage_meta_without_generation() {
        let root = test_root("checkpoint-legacy-generation");
        let _ = std::fs::remove_dir_all(&root);
        create_legacy_world_without_generation(&root, "home/legacy");

        let err = open_checkpoint_conn(&root, "home/legacy").unwrap_err();

        assert!(err.to_string().contains("stage_meta.generation"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn text_body_storage_is_schema_corruption_not_legacy() {
        let root = test_root("text-body-corruption");
        let _ = std::fs::remove_dir_all(&root);

        test_only_write_without_audit(
            &root,
            "home/plain",
            b"seed",
            "text/plain; charset=utf-8",
            &[],
        )
        .unwrap();
        force_text_body(&root, "home/plain", "\u{00e9}");

        let world = ValidatedWorldPath::new("home/plain").unwrap();
        let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
        let file_op = gate.begin().unwrap();
        assert!(body_len(
            &mut crate::blocking_sqlite::test_only_mint(),
            &root,
            &world,
            &file_op
        )
        .is_err());
        assert!(metadata(
            &mut crate::blocking_sqlite::test_only_mint(),
            &root,
            &world,
            &file_op
        )
        .is_err());
        assert!(usages(
            &mut crate::blocking_sqlite::test_only_mint(),
            &root,
            &file_op
        )
        .is_err());
        // Read path goes through ReadCache now. Wrap the bare
        // Connection via the test-only helper exported from
        // `read_cache` and call `read_with_hmac_via_conn` on it.
        // The helper is `#[cfg(test)] pub(crate) fn` -- production
        // code cannot construct a `TrackedReadConnection` outside
        // `OpeningTransition::promote`. v10 type gate intact.
        {
            let conn = open(&root, "home/plain").unwrap();
            let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
            assert!(read_with_hmac_via_conn(
                &mut crate::blocking_sqlite::test_only_mint(),
                &mut tracked,
                &world,
                &test_key()
            )
            .is_err());
        }
        assert!(test_only_append_without_audit(&root, "home/plain", b"!").is_err());

        test_only_write_without_audit(
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
            &validated("home/audited"),
            b"!",
            "text/plain; charset=utf-8",
            &[],
            &test_key(),
        )
        .is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_rejects_tampered_existing_chain() {
        let root = test_root("tampered-audit-chain");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        write_with_audit(
            &root,
            &validated("home/tamper"),
            b"one",
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        {
            let c = Connection::open(world_db(&root, "home/tamper")).unwrap();
            c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
                .unwrap();
        }

        assert!(write_with_audit(
            &root,
            &validated("home/tamper"),
            b"two",
            "text/plain",
            &[],
            &key,
        )
        .is_err());

        let c = Connection::open(world_db(&root, "home/tamper")).unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_recovers_empty_bootstrap_db() {
        let root = test_root("empty-bootstrap-db");
        let _ = std::fs::remove_dir_all(&root);
        drop(open(&root, "home/retry").unwrap());

        write_with_audit(
            &root,
            &validated("home/retry"),
            b"one",
            "text/plain",
            &[],
            &test_key(),
        )
        .unwrap();

        let c = Connection::open(world_db(&root, "home/retry")).unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_append_recovers_empty_bootstrap_db_with_format_boundary() {
        let root = test_root("empty-bootstrap-append-db");
        let _ = std::fs::remove_dir_all(&root);
        let world = validated("home/append-retry");
        drop(open(&root, world.as_str()).unwrap());

        let (result, hmac) = append_with_audit(
            &root,
            &world,
            b"one",
            "application/octet-stream",
            &[],
            &test_key(),
        )
        .unwrap()
        .unwrap();

        let c = Connection::open(world_db(&root, world.as_str())).unwrap();
        let events: Vec<(i64, String)> = {
            let mut stmt = c
                .prepare("SELECT id, event_type FROM events ORDER BY id")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let body_hmac: String = c
            .query_row("SELECT hmac FROM events WHERE id=2", [], |r| r.get(0))
            .unwrap();

        assert_eq!(
            events,
            vec![(1, "format".to_owned()), (2, "append".to_owned())]
        );
        assert!(result.format_event.is_some());
        assert_eq!(result.body_event.timeline_address().seq().get(), 2);
        assert_eq!(body_hmac, hmac);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audited_write_rejects_empty_chain_with_body() {
        let root = test_root("empty-chain-with-body");
        let _ = std::fs::remove_dir_all(&root);
        {
            let c = open(&root, "home/orphan").unwrap();
            c.execute("UPDATE stage_meta SET body=x'6f727068616e' WHERE id=1", [])
                .unwrap();
        }

        assert!(write_with_audit(
            &root,
            &validated("home/orphan"),
            b"two",
            "text/plain",
            &[],
            &test_key(),
        )
        .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn existing_world_missing_audit_table_is_not_recreated() {
        let root = test_root("missing-audit-table");
        let _ = std::fs::remove_dir_all(&root);
        let key = test_key();
        write_with_audit(
            &root,
            &validated("home/drop-events"),
            b"one",
            "text/plain",
            &[],
            &key,
        )
        .unwrap();
        {
            let c = Connection::open(world_db(&root, "home/drop-events")).unwrap();
            c.execute("DROP TABLE events", []).unwrap();
        }

        assert!(open(&root, "home/drop-events").is_err());
        assert!(write_with_audit(
            &root,
            &validated("home/drop-events"),
            b"two",
            "text/plain",
            &[],
            &key,
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
                "auditedb-bench-{label}-{}-{}",
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
            test_only_write_without_audit(&dir, world, b"hello world", "text/plain", &[]).unwrap();

            let n = 10_000;
            let start = Instant::now();
            for _ in 0..n {
                let conn = open_existing(&dir, world).unwrap().unwrap();
                let _len: i64 = conn
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
            test_only_write_without_audit(&dir, world, b"hello world", "text/plain", &[]).unwrap();

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
