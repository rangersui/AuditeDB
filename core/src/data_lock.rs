use std::path::Path;
use std::time::Duration;

pub(crate) fn acquire_data_root_writer_lock(data: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let c = rusqlite::Connection::open(data.join(".elastik-writer-lock.sqlite3"))?;
    c.busy_timeout(Duration::from_millis(0))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS writer_lock(
            id INTEGER PRIMARY KEY CHECK(id=1),
            holder TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO writer_lock(id, holder) VALUES(1, '');
        BEGIN IMMEDIATE;
        "#,
    )?;
    c.execute(
        "UPDATE writer_lock SET holder=?1 WHERE id=1",
        [std::process::id().to_string()],
    )?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_root_writer_lock_is_exclusive() {
        let dir =
            std::env::temp_dir().join(format!("elastik-data-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = acquire_data_root_writer_lock(&dir).unwrap();
        assert!(acquire_data_root_writer_lock(&dir).is_err());
        drop(first);
        let second = acquire_data_root_writer_lock(&dir).unwrap();
        drop(second);

        let _ = std::fs::remove_dir_all(dir);
    }
}
