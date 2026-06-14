//! SQLite schema helpers for one durable world database.

use rusqlite::{ffi, Connection, OptionalExtension};

pub(crate) fn create(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(
        r#"
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
    )
}

pub(crate) fn verify(c: &Connection) -> rusqlite::Result<()> {
    for table in ["stage_meta", "meta_headers", "events", "event_headers"] {
        let exists = c
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(schema_error(format!("missing required table: {table}")));
        }
    }
    Ok(())
}

fn schema_error(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(ffi::Error::new(ffi::SQLITE_CORRUPT), Some(msg))
}
