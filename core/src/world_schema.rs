//! SQLite schema helpers for one durable world database.

use crate::{
    blocking_sqlite::BlockingSqlite,
    world_generation::{MintedWorldGeneration, WorldGeneration},
};
use rusqlite::{ffi, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// Current durable world storage format.
///
/// Format v2 is the first timeline/CAS-capable format. Every durable world
/// records this marker so readers fail loudly instead of silently treating an
/// unmarked pre-CAS layout as timeline-addressable storage.
pub(crate) const CURRENT_WORLD_FORMAT_VERSION: i64 = 2;

const WORLD_FORMAT_TABLE_SQL: &str = r#"
CREATE TABLE world_format(
    id INTEGER PRIMARY KEY CHECK(id=1),
    version INTEGER NOT NULL
        CHECK(typeof(version)='integer')
        CHECK(version=2)
)
"#;

const CAS_BODIES_TABLE_SQL: &str = r#"
CREATE TABLE cas_bodies(
    body_sha256 TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(body_sha256)='text')
        CHECK(length(body_sha256)=64)
        CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
    body BLOB NOT NULL
        CHECK(typeof(body)='blob')
) WITHOUT ROWID
"#;

const CAS_STATE_TABLE_SQL: &str = r#"
CREATE TABLE cas_state(
    id INTEGER PRIMARY KEY CHECK(id=1),
    first_retained_seq INTEGER
        CHECK(
            first_retained_seq IS NULL OR
            (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
        )
)
"#;

const EVENT_HEADERS_EVENT_ID_INDEX_NAME: &str = "idx_event_headers_event_id";
const EVENT_HEADERS_EVENT_ID_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_event_headers_event_id ON event_headers(event_id)";
const EVENT_HEADERS_EVENT_ID_INDEX_SHAPE_SQL: &str =
    "CREATE INDEX idx_event_headers_event_id ON event_headers(event_id)";

pub(crate) struct NewWorldSchema<'c> {
    c: &'c Connection,
}

pub(crate) fn new_world<'c>(
    _proof: &mut BlockingSqlite,
    c: &'c Connection,
) -> rusqlite::Result<NewWorldSchema<'c>> {
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
    _proof: &mut BlockingSqlite,
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
    c.execute_batch(WORLD_FORMAT_TABLE_SQL)?;
    c.execute(
        "INSERT INTO world_format(id, version) VALUES(1, ?1)",
        rusqlite::params![CURRENT_WORLD_FORMAT_VERSION],
    )?;
    c.execute_batch(CAS_BODIES_TABLE_SQL)?;
    c.execute_batch(CAS_STATE_TABLE_SQL)?;
    c.execute(
        "INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL)",
        [],
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
    )?;
    ensure_write_indexes(c)
}

pub(crate) fn verify(_proof: &mut BlockingSqlite, c: &Connection) -> rusqlite::Result<()> {
    verify_open_shape(_proof, c)?;
    verify_cas_body_rows(c)?;
    Ok(())
}

pub(crate) fn verify_open_shape(
    proof: &mut BlockingSqlite,
    c: &Connection,
) -> rusqlite::Result<()> {
    for table in ["stage_meta", "meta_headers", "events", "event_headers"] {
        require_table(c, table)?;
    }
    let _ = generation(proof, c)?;
    verify_exact_table(c, "cas_bodies", CAS_BODIES_TABLE_SQL)?;
    verify_exact_table(c, "cas_state", CAS_STATE_TABLE_SQL)?;
    verify_exact_table(c, "world_format", WORLD_FORMAT_TABLE_SQL)?;
    verify_cas_state_row(c)?;
    verify_world_format_row(c)?;
    Ok(())
}

pub(crate) fn ensure_write_indexes(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(EVENT_HEADERS_EVENT_ID_INDEX_SQL)?;
    verify_exact_index(
        c,
        EVENT_HEADERS_EVENT_ID_INDEX_NAME,
        "event_headers",
        EVENT_HEADERS_EVENT_ID_INDEX_SHAPE_SQL,
    )
}

pub(crate) fn generation(
    _proof: &mut BlockingSqlite,
    c: &Connection,
) -> rusqlite::Result<WorldGeneration> {
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

fn require_table(c: &Connection, table: &str) -> rusqlite::Result<()> {
    let exists = c
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(schema_error(format!("missing required table: {table}")))
    }
}

fn verify_exact_table(c: &Connection, table: &str, expected_sql: &str) -> rusqlite::Result<()> {
    let sql = c
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .ok_or_else(|| schema_error(format!("missing required table: {table}")))?;

    if normalized_schema_sql(&sql) == normalized_schema_sql(expected_sql) {
        Ok(())
    } else {
        Err(schema_error(format!(
            "schema mismatch for required table: {table}"
        )))
    }
}

fn verify_exact_index(
    c: &Connection,
    index: &str,
    expected_table: &str,
    expected_sql: &str,
) -> rusqlite::Result<()> {
    let (table, sql) = c
        .query_row(
            "SELECT tbl_name, sql FROM sqlite_schema WHERE type='index' AND name=?1",
            [index],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| schema_error(format!("missing required index: {index}")))?;

    if table == expected_table
        && sql.as_deref().is_some_and(|actual| {
            normalized_schema_sql(actual) == normalized_schema_sql(expected_sql)
        })
    {
        Ok(())
    } else {
        Err(schema_error(format!(
            "schema mismatch for required index: {index}"
        )))
    }
}

fn normalized_schema_sql(sql: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut idx = 0;
    let mut in_string = false;

    while idx < chars.len() {
        let ch = chars[idx];
        if in_string {
            out.push(ch);
            if ch == '\'' {
                if matches!(chars.get(idx + 1), Some('\'')) {
                    idx += 1;
                    out.push(chars[idx]);
                } else {
                    in_string = false;
                }
            }
            idx += 1;
            continue;
        }

        if ch == '\'' {
            in_string = true;
            out.push(ch);
            idx += 1;
        } else if ch.is_ascii_whitespace() {
            while idx < chars.len() && chars[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if let (Some(prev), Some(next)) = (out.chars().last(), chars.get(idx)) {
                if is_sql_word_char(prev) && is_sql_word_char(*next) {
                    out.push(' ');
                }
            }
        } else {
            out.push(ch);
            idx += 1;
        }
    }

    out.trim_end_matches(';').to_owned()
}

fn is_sql_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn verify_cas_body_rows(c: &Connection) -> rusqlite::Result<()> {
    let mut stmt = c.prepare(
        "SELECT body_sha256, typeof(body_sha256), typeof(body), length(body), body FROM cas_bodies",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let hash: String = row.get(0)?;
        let hash_type: String = row.get(1)?;
        let body_type: String = row.get(2)?;
        let body_len: Option<i64> = row.get(3)?;
        if hash_type != "text" || !is_lower_hex_sha256(&hash) {
            return Err(schema_error(
                "cas_bodies.body_sha256 must be 64-byte lower hex TEXT".to_owned(),
            ));
        }
        if body_type != "blob" || body_len.is_none() {
            return Err(schema_error("cas_bodies.body must be BLOB".to_owned()));
        }
        let body: Vec<u8> = row.get(4)?;
        if sha256_hex(&body) != hash {
            return Err(schema_error(
                "cas_bodies.body does not match body_sha256".to_owned(),
            ));
        }
    }

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_cas_state_row(c: &Connection) -> rusqlite::Result<()> {
    let mut stmt =
        c.prepare("SELECT id, typeof(first_retained_seq), first_retained_seq FROM cas_state")?;
    let mut rows = stmt.query([])?;
    let mut count = 0;

    while let Some(row) = rows.next()? {
        count += 1;
        let id: i64 = row.get(0)?;
        if id != 1 {
            return Err(schema_error(
                "invalid row: cas_state.id must be 1".to_owned(),
            ));
        }

        let value_type: String = row.get(1)?;
        if value_type == "null" {
            continue;
        }
        if value_type != "integer" {
            return Err(schema_error(
                "cas_state.first_retained_seq must be INTEGER or NULL".to_owned(),
            ));
        }

        let seq: i64 = row.get(2)?;
        if seq <= 0 {
            return Err(schema_error(
                "cas_state.first_retained_seq must be positive".to_owned(),
            ));
        }
    }

    match count {
        1 => Ok(()),
        0 => Err(schema_error(
            "missing required row: cas_state id=1".to_owned(),
        )),
        _ => Err(schema_error(
            "cas_state must contain exactly one row".to_owned(),
        )),
    }
}

fn verify_world_format_row(c: &Connection) -> rusqlite::Result<()> {
    let mut stmt = c.prepare("SELECT id, typeof(version), version FROM world_format")?;
    let mut rows = stmt.query([])?;
    let mut count = 0;

    while let Some(row) = rows.next()? {
        count += 1;
        let id: i64 = row.get(0)?;
        if id != 1 {
            return Err(schema_error(
                "invalid row: world_format.id must be 1".to_owned(),
            ));
        }

        let value_type: String = row.get(1)?;
        if value_type != "integer" {
            return Err(schema_error(
                "world_format.version must be INTEGER".to_owned(),
            ));
        }

        let version: i64 = row.get(2)?;
        if version != CURRENT_WORLD_FORMAT_VERSION {
            return Err(schema_error(format!(
                "unsupported world format version: {version}"
            )));
        }
    }

    match count {
        1 => Ok(()),
        0 => Err(schema_error(
            "missing required row: world_format id=1".to_owned(),
        )),
        _ => Err(schema_error(
            "world_format must contain exactly one row".to_owned(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::world_generation::MintedWorldGeneration;

    fn test_only_proof() -> BlockingSqlite {
        crate::blocking_sqlite::test_only_mint()
    }

    fn new_world(c: &Connection) -> rusqlite::Result<NewWorldSchema<'_>> {
        super::new_world(&mut test_only_proof(), c)
    }

    fn create(
        schema: NewWorldSchema<'_>,
        generation: MintedWorldGeneration,
    ) -> rusqlite::Result<()> {
        super::create(&mut test_only_proof(), schema, generation)
    }

    fn verify(c: &Connection) -> rusqlite::Result<()> {
        super::verify(&mut test_only_proof(), c)
    }

    fn generation(c: &Connection) -> rusqlite::Result<WorldGeneration> {
        super::generation(&mut test_only_proof(), c)
    }

    fn index_exists(c: &Connection, name: &str) -> bool {
        c.query_row(
            "SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1",
            [name],
            |_| Ok(()),
        )
        .optional()
        .unwrap()
        .is_some()
    }

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

    fn create_pre_cas_tables(c: &Connection) {
        create_legacy_tables(c);
        c.execute("ALTER TABLE stage_meta ADD COLUMN generation TEXT", [])
            .unwrap();
        c.execute(
            "UPDATE stage_meta SET generation='000102030405060708090a0b0c0d0e0f'",
            [],
        )
        .unwrap();
    }

    fn create_valid_schema(c: &Connection) {
        let schema = new_world(c).unwrap();
        create(schema, minted_generation()).unwrap();
    }

    fn assert_schema_mismatch(c: &Connection) {
        assert!(verify(c)
            .unwrap_err()
            .to_string()
            .contains("schema mismatch"));
    }

    #[test]
    fn create_persists_generation() {
        let c = Connection::open_in_memory().unwrap();

        create_valid_schema(&c);

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
    fn create_initializes_empty_cas_schema() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);

        let cas_rows: i64 = c
            .query_row("SELECT count(*) FROM cas_bodies", [], |r| r.get(0))
            .unwrap();
        let state_rows: i64 = c
            .query_row("SELECT count(*) FROM cas_state WHERE id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let format_version: i64 = c
            .query_row("SELECT version FROM world_format WHERE id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let first_retained_type: String = c
            .query_row(
                "SELECT typeof(first_retained_seq) FROM cas_state",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(cas_rows, 0);
        assert_eq!(state_rows, 1);
        assert_eq!(format_version, CURRENT_WORLD_FORMAT_VERSION);
        assert_eq!(first_retained_type, "null");
        assert!(index_exists(&c, "idx_event_headers_event_id"));
        verify(&c).unwrap();
    }

    #[test]
    fn verify_allows_missing_event_headers_index_for_read_only_open() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DROP INDEX idx_event_headers_event_id", [])
            .unwrap();

        assert!(!index_exists(&c, "idx_event_headers_event_id"));
        verify(&c).unwrap();
    }

    #[test]
    fn ensure_write_indexes_backfills_event_headers_index() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DROP INDEX idx_event_headers_event_id", [])
            .unwrap();

        super::ensure_write_indexes(&c).unwrap();

        assert!(index_exists(&c, "idx_event_headers_event_id"));
        verify(&c).unwrap();
    }

    #[test]
    fn ensure_write_indexes_rejects_wrong_event_headers_index_shape() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DROP INDEX idx_event_headers_event_id", [])
            .unwrap();
        c.execute(
            "CREATE INDEX idx_event_headers_event_id ON event_headers(name)",
            [],
        )
        .unwrap();

        let err = super::ensure_write_indexes(&c).unwrap_err();

        assert!(err
            .to_string()
            .contains("schema mismatch for required index"));
    }

    #[test]
    fn cas_bodies_rejects_invalid_rows() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        let hash = "a".repeat(64);

        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![hash, b"body".as_slice()],
        )
        .unwrap();

        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
                rusqlite::params![hash, b"duplicate".as_slice()],
            )
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
                rusqlite::params!["a".repeat(63), b"short-hash".as_slice()],
            )
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
                rusqlite::params!["A".repeat(64), b"upper-hash".as_slice()],
            )
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
                rusqlite::params!["g".repeat(64), b"non-hex-hash".as_slice()],
            )
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(x'aaaaaaaa', ?1)",
                rusqlite::params![b"blob-hash".as_slice()],
            )
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, 'text body')",
                rusqlite::params!["b".repeat(64)],
            )
            .is_err());
    }

    #[test]
    fn cas_state_rejects_invalid_rows() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);

        assert!(c
            .execute(
                "INSERT INTO cas_state(id, first_retained_seq) VALUES(2, NULL)",
                [],
            )
            .is_err());
        assert!(c
            .execute("UPDATE cas_state SET first_retained_seq=0 WHERE id=1", [])
            .is_err());
        assert!(c
            .execute(
                "UPDATE cas_state SET first_retained_seq='text' WHERE id=1",
                [],
            )
            .is_err());
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
    fn verify_rejects_pre_cas_schema_with_generation() {
        let c = Connection::open_in_memory().unwrap();
        create_pre_cas_tables(&c);

        let err = verify(&c).unwrap_err();

        assert!(err
            .to_string()
            .contains("missing required table: cas_bodies"));
    }

    #[test]
    fn verify_rejects_invalid_generation_text() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute(
            "UPDATE stage_meta SET generation='000102030405060708090a0b0c0d0e0F'",
            [],
        )
        .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("invalid stage_meta.generation"));
    }

    #[test]
    fn verify_rejects_missing_cas_state_row() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DELETE FROM cas_state", []).unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("cas_state id=1"));
    }

    #[test]
    fn verify_rejects_non_integer_cas_state_floor() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("PRAGMA ignore_check_constraints=ON", []).unwrap();
        c.execute(
            "UPDATE cas_state SET first_retained_seq='not-an-integer' WHERE id=1",
            [],
        )
        .unwrap();
        c.execute("PRAGMA ignore_check_constraints=OFF", [])
            .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("first_retained_seq"));
    }

    #[test]
    fn verify_rejects_missing_world_format_marker() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DROP TABLE world_format", []).unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("world_format"));
    }

    #[test]
    fn verify_rejects_missing_world_format_row() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("DELETE FROM world_format WHERE id=1", [])
            .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("world_format"));
    }

    #[test]
    fn verify_rejects_unsupported_world_format_version() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("PRAGMA ignore_check_constraints=ON", []).unwrap();
        c.execute("UPDATE world_format SET version=3 WHERE id=1", [])
            .unwrap();
        c.execute("PRAGMA ignore_check_constraints=OFF", [])
            .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("unsupported world format version"));
    }

    #[test]
    fn verify_rejects_corrupt_persisted_cas_body_rows() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("PRAGMA ignore_check_constraints=ON", []).unwrap();
        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, 'text body')",
            rusqlite::params!["g".repeat(64)],
        )
        .unwrap();
        c.execute("PRAGMA ignore_check_constraints=OFF", [])
            .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("cas_bodies.body_sha256"));
    }

    #[test]
    fn verify_rejects_cas_body_hash_mismatch() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![sha256_hex(b"expected"), b"different".as_slice()],
        )
        .unwrap();

        let err = verify(&c).unwrap_err();

        assert!(err.to_string().contains("does not match body_sha256"));
    }

    #[test]
    fn verify_rejects_spoofed_cas_body_check() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute_batch(
            r#"
            DROP TABLE cas_bodies;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text' OR 1)
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
                body BLOB NOT NULL
                    CHECK(typeof(body)='blob')
            ) WITHOUT ROWID;
            "#,
        )
        .unwrap();

        assert_schema_mismatch(&c);
    }

    #[test]
    fn verify_rejects_spoofed_cas_body_literal_whitespace() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute_batch(
            r#"
            DROP TABLE cas_bodies;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text')
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9 a-f]*'),
                body BLOB NOT NULL
                    CHECK(typeof(body)='blob')
            ) WITHOUT ROWID;
            "#,
        )
        .unwrap();

        c.execute(
            "INSERT INTO cas_bodies(body_sha256, body) VALUES(?1, ?2)",
            rusqlite::params![format!("{} ", "a".repeat(63)), b"weak".as_slice()],
        )
        .unwrap();
        assert_schema_mismatch(&c);
    }

    #[test]
    fn verify_rejects_spoofed_cas_state_primary_key_spacing() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute_batch(
            r#"
            DROP TABLE cas_state;
            CREATE TABLE cas_state(
                id INTEGERPRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
                    CHECK(
                        first_retained_seq IS NULL OR
                        (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
                    )
            );
            INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
            "#,
        )
        .unwrap();

        let pk: i64 = c
            .query_row("PRAGMA table_info(cas_state)", [], |r| r.get(5))
            .unwrap();
        assert_eq!(pk, 0);
        assert_schema_mismatch(&c);
    }

    #[test]
    fn verify_rejects_cas_column_shape_changes() {
        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("ALTER TABLE cas_state ADD COLUMN note TEXT", [])
            .unwrap();

        assert_schema_mismatch(&c);

        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute("ALTER TABLE cas_bodies ADD COLUMN content_type TEXT", [])
            .unwrap();

        assert_schema_mismatch(&c);

        let c = Connection::open_in_memory().unwrap();
        create_valid_schema(&c);
        c.execute_batch(
            r#"
            DROP TABLE cas_bodies;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text')
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*')
            ) WITHOUT ROWID;
            "#,
        )
        .unwrap();

        assert_schema_mismatch(&c);
    }
}
