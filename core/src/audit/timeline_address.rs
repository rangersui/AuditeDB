#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::{ffi, params, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::AuditEventKind,
    read_cache::TrackedReadConnection,
    timeline::{BodySha256, TimelineAddress, TimelineAddressLookup, TimelineSeq},
    world_generation::WorldGeneration,
    world_schema,
};

pub(crate) struct VerifiedBodyEvent {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    body_sha256: BodySha256,
}

impl VerifiedBodyEvent {
    fn new(
        world: ValidatedWorldPath,
        gen: WorldGeneration,
        seq: TimelineSeq,
        body_sha256: BodySha256,
    ) -> Self {
        Self {
            world,
            gen,
            seq,
            body_sha256,
        }
    }

    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    pub(crate) fn gen(&self) -> &WorldGeneration {
        &self.gen
    }

    pub(crate) fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }
}

pub(crate) fn verified_timeline_address_via_conn(
    tracked: &mut TrackedReadConnection,
    world: &ValidatedWorldPath,
    seq: TimelineSeq,
    key: &AuditHmacKey,
) -> super::AuditResult<TimelineAddressLookup> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    // Verification and row extraction must share one SQLite snapshot; otherwise
    // a concurrent writer could append a row after verification but before the
    // address lookup.
    super::require_intact(super::verify_world_connection(&tx, world, key)?)?;

    let Some(row) = tx
        .query_row(
            "SELECT event_type, target, body_sha256 FROM events WHERE id=?1",
            params![seq.get()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(TimelineAddressLookup::MissingRow);
    };

    let kind = AuditEventKind::from_storage(&row.0)
        .ok_or_else(|| corrupt("events.event_type is not a known audit event"))?;
    if !kind.class().body_bearing {
        return Ok(TimelineAddressLookup::NoBody);
    }
    if row.1 != world.as_str() {
        return Err(corrupt("events.target does not match requested world").into());
    }
    let body_sha256 = BodySha256::new(row.2)
        .map_err(|err| corrupt(&format!("events.body_sha256 is invalid: {err:?}")))?;
    let gen = world_schema::generation(&tx)?;
    let event = VerifiedBodyEvent::new(world.clone(), gen, seq, body_sha256);
    let lookup = TimelineAddressLookup::Body(TimelineAddress::from_verified_body_event(event));
    tx.commit()?;
    Ok(lookup)
}

fn corrupt(message: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_CORRUPT),
        Some(message.to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        engine::Engine,
        engine_types::{AccessTier, AuditHmacKey, Preconditions, Representation},
    };
    use bytes::Bytes;

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-audit-timeline-address-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn resign_event(
        conn: &rusqlite::Connection,
        id: i64,
        event_type: &str,
        body_sha256: &str,
        key: &AuditHmacKey,
    ) {
        let generation = world_schema::generation(conn).unwrap();
        let (target, size, content_type, meta_sha256, prev_hmac): (
            String,
            i64,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT target, size, content_type, meta_sha256, prev_hmac FROM events WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        let hmac = super::super::event_hmac(
            key,
            super::super::EventHmacInput {
                prev: &prev_hmac,
                event_type,
                target: &target,
                generation: &generation,
                body_sha256,
                size,
                content_type: &content_type,
                meta_sha256: &meta_sha256,
            },
        );
        conn.execute(
            "UPDATE events SET event_type=?1, body_sha256=?2, hmac=?3 WHERE id=?4",
            rusqlite::params![event_type, body_sha256, hmac, id],
        )
        .unwrap();
    }

    fn assert_corrupt_error(result: super::super::AuditResult<TimelineAddressLookup>, text: &str) {
        match result {
            Err(super::super::AuditError::Storage(rusqlite::Error::SqliteFailure(
                err,
                Some(message),
            ))) => {
                assert_eq!(err.extended_code, rusqlite::ffi::SQLITE_CORRUPT);
                assert!(message.contains(text), "{message}");
            }
            other => panic!("expected SQLITE_CORRUPT containing {text:?}, got {other:?}"),
        }
    }

    fn single_event_conn(
        world: &ValidatedWorldPath,
        event_type: &str,
        body_sha256: &str,
        key: &AuditHmacKey,
    ) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                meta_sha256 TEXT NOT NULL,
                hmac TEXT NOT NULL,
                prev_hmac TEXT NOT NULL
            );
            CREATE TABLE event_headers(
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE VIEW stage_meta AS
            SELECT 1 AS id, '0123456789abcdef0123456789abcdef' AS generation;
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY,
                body BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
                first_retained_seq INTEGER
            );
            INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
            "#,
        )
        .unwrap();
        let generation = world_schema::generation(&conn).unwrap();
        let meta_sha256 = super::super::meta_sha256_canonical("application/octet-stream", &[]);
        let hmac = super::super::event_hmac(
            key,
            super::super::EventHmacInput {
                prev: "",
                event_type,
                target: world.as_str(),
                generation: &generation,
                body_sha256,
                size: 0,
                content_type: "application/octet-stream",
                meta_sha256: &meta_sha256,
            },
        );
        conn.execute(
            r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                                  content_type, meta_sha256, hmac, prev_hmac)
               VALUES(datetime('now'), ?1, ?2, ?3, 0, 'application/octet-stream', ?4, ?5, '')"#,
            rusqlite::params![event_type, world.as_str(), body_sha256, meta_sha256, hmac],
        )
        .unwrap();
        conn
    }

    #[tokio::test]
    async fn verified_timeline_address_uses_event_row_not_current_body() {
        let root = temp_root("historical-row");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/history").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"old"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"new"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let lookup = verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(1).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap();

        match lookup {
            TimelineAddressLookup::Body(address) => {
                assert_eq!(address.world(), &world);
                assert_eq!(address.gen(), &gen);
                assert_eq!(address.seq().get(), 1);
                assert_eq!(address.body_sha256(), &BodySha256::for_body(b"old"));
            }
            TimelineAddressLookup::MissingRow | TimelineAddressLookup::NoBody => {
                panic!("expected body timeline address")
            }
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verified_timeline_address_rejects_generation_tampering() {
        let root = temp_root("generation-tamper");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/generation-tamper").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        conn.execute(
            "UPDATE stage_meta SET generation='fedcba9876543210fedcba9876543210' WHERE id=1",
            [],
        )
        .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        assert!(matches!(
            verified_timeline_address_via_conn(
                &mut tracked,
                &world,
                TimelineSeq::new(1).unwrap(),
                &engine.core().hmac_key,
            ),
            Err(super::super::AuditError::ChainBroken(_))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verified_timeline_address_rejects_unknown_event_type_as_corrupt() {
        let key = key();
        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let conn = single_event_conn(&ledger, "custom", "", &key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        assert_corrupt_error(
            verified_timeline_address_via_conn(
                &mut tracked,
                &ledger,
                TimelineSeq::new(1).unwrap(),
                &key,
            ),
            "events.event_type",
        );
    }

    #[tokio::test]
    async fn verified_timeline_address_rejects_invalid_body_hash_before_minting() {
        let root = temp_root("invalid-body-hash");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/invalid-body-hash").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        resign_event(&conn, 1, "put", "not-a-valid-hash", &engine.core().hmac_key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        match verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(1).unwrap(),
            &engine.core().hmac_key,
        ) {
            Err(super::super::AuditError::ChainBroken(report)) => {
                assert_eq!(report.expected, "valid body_sha256");
                assert_eq!(report.actual, "body-sha256-not-a-valid-hash");
            }
            other => panic!("expected invalid body hash to break verification, got {other:?}"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verified_timeline_address_reports_missing_rows() {
        let root = temp_root("missing-row");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/missing-row").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        assert!(matches!(
            verified_timeline_address_via_conn(
                &mut tracked,
                &world,
                TimelineSeq::new(99).unwrap(),
                &engine.core().hmac_key,
            )
            .unwrap(),
            TimelineAddressLookup::MissingRow
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verified_timeline_address_reports_metadata_events_as_no_body() {
        let root = temp_root("no-body");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let subject = ValidatedWorldPath::new("home/deleted").unwrap();
        engine
            .replace(
                &subject,
                Representation::new(Bytes::from_static(b"deleted"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .delete(&subject, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let conn = rusqlite::Connection::open(crate::world::world_db(
            &engine.core().data,
            ledger.as_str(),
        ))
        .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        assert!(matches!(
            verified_timeline_address_via_conn(
                &mut tracked,
                &ledger,
                TimelineSeq::new(1).unwrap(),
                &engine.core().hmac_key,
            )
            .unwrap(),
            TimelineAddressLookup::NoBody
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
