//! Process-local ownership guard for one AuditeDB data directory.
//!
//! This is a SQLite-backed mutex for one host process at a time. It is not a
//! distributed lease and should not be treated as reliable fencing on NFS or
//! other network filesystems with weak locking/cache semantics. Put
//! `AUDITEDB_DATA` on a local filesystem, or use an external coordinator that is
//! designed for distributed ownership.
//!
//! The lock database deliberately uses rollback-journal mode. WAL is useful for
//! durable world databases because readers and writers coexist there; this
//! file only needs a single uncommitted `BEGIN IMMEDIATE` transaction to keep a
//! second writer out.

use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub(crate) enum DataRootWriterLockError {
    Storage(rusqlite::Error),
    Held {
        source: rusqlite::Error,
        holder_pid: Option<String>,
    },
}

impl DataRootWriterLockError {
    pub(crate) fn sqlite_error(&self) -> &rusqlite::Error {
        match self {
            Self::Storage(err) | Self::Held { source: err, .. } => err,
        }
    }

    pub(crate) fn holder_pid(&self) -> Option<&str> {
        match self {
            Self::Held { holder_pid, .. } => holder_pid.as_deref(),
            Self::Storage(_) => None,
        }
    }
}

impl From<rusqlite::Error> for DataRootWriterLockError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

pub(crate) fn acquire_data_root_writer_lock(
    data: &Path,
) -> Result<rusqlite::Connection, DataRootWriterLockError> {
    let c = rusqlite::Connection::open(data.join(".auditedb-writer-lock.sqlite3"))?;
    c.busy_timeout(Duration::from_millis(0))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=DELETE;
        CREATE TABLE IF NOT EXISTS writer_lock(
            id INTEGER PRIMARY KEY CHECK(id=1),
            holder TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO writer_lock(id, holder) VALUES(1, '');
        "#,
    )
    .map_err(|source| lock_attempt_error(&c, source))?;

    // `holder` is diagnostic, not part of SQLite's locking proof. Commit it
    // before the never-committed lock transaction so a rejected second process
    // can report who was most likely already holding the data root. It is a
    // best-effort diagnostic, not proof of the current holder.
    let holder = std::process::id().to_string();
    commit_holder(&c, holder.as_str()).map_err(|source| lock_attempt_error(&c, source))?;
    c.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|source| lock_attempt_error(&c, source))?;
    Ok(c)
}

fn commit_holder(c: &rusqlite::Connection, holder: &str) -> rusqlite::Result<()> {
    c.execute_batch("BEGIN IMMEDIATE;")?;
    let result = c
        .execute("UPDATE writer_lock SET holder=?1 WHERE id=1", [holder])
        .and_then(|_| c.execute_batch("COMMIT;"));
    if result.is_err() {
        let _ = c.execute_batch("ROLLBACK;");
    }
    result
}

fn lock_attempt_error(
    c: &rusqlite::Connection,
    source: rusqlite::Error,
) -> DataRootWriterLockError {
    DataRootWriterLockError::Held {
        holder_pid: query_holder(c).ok().flatten(),
        source,
    }
}

#[cfg(test)]
fn read_data_root_writer_lock_holder(data: &Path) -> rusqlite::Result<Option<String>> {
    let c = rusqlite::Connection::open(data.join(".auditedb-writer-lock.sqlite3"))?;
    c.busy_timeout(Duration::from_millis(0))?;
    query_holder(&c)
}

fn query_holder(c: &rusqlite::Connection) -> rusqlite::Result<Option<String>> {
    let holder = c.query_row("SELECT holder FROM writer_lock WHERE id=1", [], |row| {
        row.get::<_, String>(0)
    })?;
    if holder.is_empty() {
        Ok(None)
    } else {
        Ok(Some(holder))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn data_root_writer_lock_is_exclusive() {
        let dir =
            std::env::temp_dir().join(format!("auditedb-data-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = acquire_data_root_writer_lock(&dir).unwrap();
        assert!(matches!(
            acquire_data_root_writer_lock(&dir),
            Err(DataRootWriterLockError::Held { .. })
        ));
        drop(first);
        let second = acquire_data_root_writer_lock(&dir).unwrap();
        drop(second);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn data_root_writer_lock_uses_rollback_journal() {
        let dir = temp_dir("journal-mode");

        let lock = acquire_data_root_writer_lock(&dir).unwrap();
        let mode: String = lock
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();

        assert_eq!(mode.to_ascii_lowercase(), "delete");

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn data_root_writer_lock_holder_is_visible_while_lock_is_held() {
        let dir = temp_dir("holder");

        let first = acquire_data_root_writer_lock(&dir).unwrap();
        let expected_pid = std::process::id().to_string();
        assert_eq!(
            read_data_root_writer_lock_holder(&dir).unwrap().as_deref(),
            Some(expected_pid.as_str())
        );

        let err = acquire_data_root_writer_lock(&dir).unwrap_err();
        assert_eq!(err.holder_pid(), Some(expected_pid.as_str()));
        assert_eq!(
            read_data_root_writer_lock_holder(&dir).unwrap().as_deref(),
            Some(expected_pid.as_str())
        );

        drop(first);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("auditedb-data-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
