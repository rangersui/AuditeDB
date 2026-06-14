//! SQLite schema helpers for one durable world database.

use crate::world_generation::{MintedWorldGeneration, WorldGeneration};
use rusqlite::{ffi, Connection, OptionalExtension};

pub(crate) struct NewWorldSchema<'c> {
    c: &'c Connection,
}

pub(crate) fn new_world(c: &Connection) -> rusqlite::Result<NewWorldSchema<'_>> {
    let existing = c
        .query_row(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' \
             LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    if let Some(table) = existing {
        return Err(schema_error(format!(
            "new world schema already has table: {table}"
        )));
    }

    Ok(NewWorldSchema { c })
}

pub(crate) fn create(
    schema: NewWorldSchema<'_>,
    generation: MintedWorldGeneration,
) -> rusqlite::Result<()> {
    let c = schema.c;
    c.execute_batch(
        r#"
        CREATE TABLE stage_meta(
            id INTEGER PRIMARY KEY CHECK(id=1),
            generation TEXT NOT NULL,
            body BLOB DEFAULT x'',
            content_type TEXT DEFAULT 'application/octet-stream'
        );
        "#,
    )?;
    c.execute(
        "INSERT INTO stage_meta(id, generation, body) VALUES(1, ?1, x'')",
        rusqlite::params![generation],
    )?;
    c.execute_batch(
        r#"
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
    let _ = generation(c)?;
    Ok(())
}

pub(crate) fn generation(c: &Connection) -> rusqlite::Result<WorldGeneration> {
    let mut columns = c.prepare("PRAGMA table_info(stage_meta)")?;
    let rows = columns.query_map([], |r| r.get::<_, String>(1))?;
    let mut has_generation = false;
    for name in rows {
        if name? == "generation" {
            has_generation = true;
            break;
        }
    }
    if !has_generation {
        return Err(schema_error(
            "missing required column: stage_meta.generation".to_owned(),
        ));
    }

    let generation = c
        .query_row(
            "SELECT CASE WHEN typeof(generation) = 'text' THEN generation END \
             FROM stage_meta WHERE id=1",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(|| schema_error("missing required row: stage_meta id=1".to_owned()))?
        .ok_or_else(|| schema_error("stage_meta.generation must be TEXT".to_owned()))?;

    WorldGeneration::new(generation)
        .map_err(|err| schema_error(format!("invalid stage_meta.generation: {err:?}")))
}

fn schema_error(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(ffi::Error::new(ffi::SQLITE_CORRUPT), Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world_generation::MintedWorldGeneration;

    fn minted_generation() -> MintedWorldGeneration {
        MintedWorldGeneration::test_only_from_entropy_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ])
    }

    fn create_legacy_tables(c: &Connection) {
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
    fn create_persists_generation() {
        let c = Connection::open_in_memory().unwrap();

        let schema = new_world(&c).unwrap();
        create(schema, minted_generation()).unwrap();

        let stored = self::generation(&c).unwrap();
        let raw: String = c
            .query_row("SELECT generation FROM stage_meta WHERE id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(raw, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(stored, WorldGeneration::new(raw).unwrap());
        verify(&c).unwrap();
    }

    #[test]
    fn new_world_rejects_existing_schema() {
        let c = Connection::open_in_memory().unwrap();
        create_legacy_tables(&c);

        let err = match new_world(&c) {
            Ok(_) => panic!("existing schema must not mint a new-world proof"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("already has table"));
    }

    #[test]
    fn verify_rejects_legacy_stage_meta_without_generation() {
        let c = Connection::open_in_memory().unwrap();
        create_legacy_tables(&c);

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("stage_meta.generation"));
    }

    #[test]
    fn verify_rejects_invalid_generation_text() {
        let c = Connection::open_in_memory().unwrap();
        let schema = new_world(&c).unwrap();
        create(schema, minted_generation()).unwrap();
        c.execute(
            "UPDATE stage_meta SET generation='000102030405060708090a0b0c0d0e0F'",
            [],
        )
        .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("invalid stage_meta.generation"));
    }
}
