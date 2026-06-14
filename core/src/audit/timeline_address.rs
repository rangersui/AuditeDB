#![cfg_attr(not(test), allow(dead_code))]

use bytes::Bytes;
use rusqlite::{ffi, params, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, Representation, ValidatedWorldPath},
    event::AuditEventKind,
    read_cache::TrackedReadConnection,
    timeline::{
        BodySha256, TimelineAddress, TimelineAddressLookup, TimelineCorruption, TimelineRead,
        TimelineSeq,
    },
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

pub(crate) struct VerifiedBodyHead {
    address: TimelineAddress,
    hmac: String,
}

impl VerifiedBodyHead {
    fn new(address: TimelineAddress, hmac: String) -> Self {
        Self { address, hmac }
    }

    pub(crate) fn address(&self) -> &TimelineAddress {
        &self.address
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }
}

struct TimelineEventSnapshot {
    event_type: String,
    target: String,
    body_sha256: String,
    size: i64,
    content_type: String,
    headers: Vec<(String, String)>,
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
    super::require_intact(super::verify_world_tx(&tx, world, key)?)?;

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

pub(crate) fn verified_latest_body_head_via_conn(
    tracked: &mut TrackedReadConnection,
    world: &ValidatedWorldPath,
    key: &AuditHmacKey,
) -> super::AuditResult<Option<VerifiedBodyHead>> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    // The chain verification and "latest body row" lookup share one SQLite
    // snapshot. Otherwise delete could anchor the ledger to a row that was not
    // part of the verified chain it just observed.
    super::require_intact(super::verify_world_connection(&tx, world, key)?)?;
    if let Some(break_report) = super::live_body::verify_tx(&tx)? {
        return Err(super::AuditError::ChainBroken(break_report));
    }

    let Some((seq, event_type, target, body_sha256, hmac)) = tx
        .query_row(
            "SELECT id, event_type, target, body_sha256, hmac
             FROM events
             WHERE event_type IN ('put', 'append')
             ORDER BY id DESC
             LIMIT 1",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        tx.commit()?;
        return Ok(None);
    };

    let kind = AuditEventKind::from_storage(&event_type)
        .ok_or_else(|| corrupt("events.event_type is not a known audit event"))?;
    if !kind.class().body_bearing {
        return Err(corrupt("latest body query returned a metadata event").into());
    }
    if target != world.as_str() {
        return Err(corrupt("events.target does not match requested world").into());
    }
    let seq = TimelineSeq::new(seq).map_err(|_| corrupt("events.id is not positive"))?;
    let body_sha256 = BodySha256::new(body_sha256)
        .map_err(|err| corrupt(&format!("events.body_sha256 is invalid: {err:?}")))?;
    let gen = world_schema::generation(&tx)?;
    let event = VerifiedBodyEvent::new(world.clone(), gen, seq, body_sha256);
    let address = TimelineAddress::from_verified_body_event(event);
    let head = VerifiedBodyHead::new(address, super::hmac_label(&hmac));
    tx.commit()?;
    Ok(Some(head))
}

pub(crate) fn read_timeline_body_via_conn(
    tracked: &mut TrackedReadConnection,
    address: &TimelineAddress,
    key: &AuditHmacKey,
) -> super::AuditResult<TimelineRead> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    let actual_gen = world_schema::generation(&tx)?;
    super::require_intact(super::verify_world_tx(&tx, address.world(), key)?)?;

    let read = if &actual_gen != address.gen() {
        TimelineRead::GenMismatch {
            requested: address.clone(),
            actual: actual_gen,
        }
    } else {
        match load_event_snapshot(&tx, address.seq())? {
            Some(row) => timeline_read_from_snapshot(&tx, address, row)?,
            None => TimelineRead::MissingRow {
                address: address.clone(),
            },
        }
    };
    tx.commit()?;
    Ok(read)
}

fn load_event_snapshot(
    tx: &rusqlite::Transaction<'_>,
    seq: TimelineSeq,
) -> rusqlite::Result<Option<TimelineEventSnapshot>> {
    let Some((event_type, target, body_sha256, size, content_type)) = tx
        .query_row(
            "SELECT event_type, target, body_sha256, size, content_type FROM events WHERE id=?1",
            params![seq.get()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let mut headers = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT name, value FROM event_headers WHERE event_id=?1 ORDER BY name, value",
        )?;
        let rows = stmt.query_map(params![seq.get()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for pair in rows {
            headers.push(pair?);
        }
    }

    Ok(Some(TimelineEventSnapshot {
        event_type,
        target,
        body_sha256,
        size,
        content_type,
        headers,
    }))
}

fn timeline_read_from_snapshot(
    tx: &rusqlite::Transaction<'_>,
    address: &TimelineAddress,
    row: TimelineEventSnapshot,
) -> rusqlite::Result<TimelineRead> {
    let Some(kind) = AuditEventKind::from_storage(&row.event_type) else {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    };
    if !kind.class().body_bearing {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::MissingBodyForPresentRow,
        ));
    }
    if row.target != address.world().as_str() {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    }
    let Ok(body_sha256) = BodySha256::new(row.body_sha256) else {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    };
    if &body_sha256 != address.body_sha256() {
        return Ok(TimelineRead::AddressMismatch {
            requested: address.clone(),
            actual: body_sha256,
        });
    }

    let Some(body) = tx
        .query_row(
            "SELECT body FROM cas_bodies WHERE body_sha256=?1",
            params![address.body_sha256().as_str()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    else {
        return missing_timeline_body_read(tx, address);
    };
    if i64::try_from(body.len()).ok() != Some(row.size) {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    }

    Ok(TimelineRead::body(
        address.clone(),
        Representation::new(Bytes::from(body), row.content_type, row.headers),
    ))
}

fn timeline_corrupt(address: &TimelineAddress, reason: TimelineCorruption) -> TimelineRead {
    TimelineRead::Corrupt {
        address: address.clone(),
        reason,
    }
}

fn missing_timeline_body_read(
    tx: &rusqlite::Transaction<'_>,
    address: &TimelineAddress,
) -> rusqlite::Result<TimelineRead> {
    let first_retained_seq = first_retained_seq(tx)?;
    if first_retained_seq.is_some_and(|seq| address.seq() >= seq) {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::MissingBodyForPresentRow,
        ));
    }

    Ok(TimelineRead::NeverRetained {
        address: address.clone(),
    })
}

fn first_retained_seq(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<Option<TimelineSeq>> {
    tx.query_row(
        "SELECT first_retained_seq FROM cas_state WHERE id=1",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )?
    .map(|seq| TimelineSeq::new(seq).map_err(|_| corrupt("cas_state.first_retained_seq invalid")))
    .transpose()
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
    async fn read_timeline_body_uses_retained_cas_not_current_body() {
        let root = temp_root("read-historical-body");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/read-history").unwrap();

        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"old"),
                    "text/plain",
                    vec![("x-meta-version".to_owned(), "old".to_owned())],
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"new"),
                    "text/plain",
                    vec![("x-meta-version".to_owned(), "new".to_owned())],
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        let TimelineAddressLookup::Body(address) = verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(1).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap() else {
            panic!("expected body timeline address");
        };

        let read =
            read_timeline_body_via_conn(&mut tracked, &address, &engine.core().hmac_key).unwrap();

        match read {
            TimelineRead::Body(body) => {
                assert_eq!(body.address(), &address);
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
                assert_eq!(body.representation().content_type, "text/plain");
                assert_eq!(
                    body.representation().headers,
                    vec![("x-meta-version".to_owned(), "old".to_owned())]
                );
            }
            _ => panic!("expected retained historical body"),
        }

        assert_eq!(
            engine
                .read(&world, AccessTier::Read)
                .unwrap()
                .unwrap()
                .representation
                .body,
            Bytes::from_static(b"new")
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn timeline_snapshot_reports_address_hash_mismatch_without_cas_lookup() {
        let key = key();
        let world = ValidatedWorldPath::new("home/address-mismatch").unwrap();
        let mut conn = single_event_conn(
            &world,
            "put",
            BodySha256::for_body(b"stored").as_str(),
            &key,
        );
        conn.execute("UPDATE cas_state SET first_retained_seq=1 WHERE id=1", [])
            .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        let address = TimelineAddress::test_only_new(
            world,
            gen,
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"requested"),
        );

        let tx = conn.transaction().unwrap();
        let row = load_event_snapshot(&tx, address.seq()).unwrap().unwrap();

        match timeline_read_from_snapshot(&tx, &address, row).unwrap() {
            TimelineRead::AddressMismatch { requested, actual } => {
                assert_eq!(requested, address);
                assert_eq!(actual, BodySha256::for_body(b"stored"));
            }
            _ => panic!("expected address mismatch"),
        }
    }

    #[test]
    fn timeline_snapshot_reports_never_retained_before_retention_floor() {
        let key = key();
        let world = ValidatedWorldPath::new("home/never-retained").unwrap();
        let mut conn =
            single_event_conn(&world, "put", BodySha256::for_body(b"value").as_str(), &key);
        conn.execute("UPDATE cas_state SET first_retained_seq=2 WHERE id=1", [])
            .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        let address = TimelineAddress::test_only_new(
            world,
            gen,
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"value"),
        );

        let tx = conn.transaction().unwrap();
        let row = load_event_snapshot(&tx, address.seq()).unwrap().unwrap();

        match timeline_read_from_snapshot(&tx, &address, row).unwrap() {
            TimelineRead::NeverRetained { address: got } => assert_eq!(got, address),
            _ => panic!("expected never-retained timeline read"),
        }
    }

    #[test]
    fn timeline_snapshot_reports_corrupt_missing_retained_body() {
        let key = key();
        let world = ValidatedWorldPath::new("home/missing-retained").unwrap();
        let mut conn =
            single_event_conn(&world, "put", BodySha256::for_body(b"value").as_str(), &key);
        conn.execute("UPDATE cas_state SET first_retained_seq=1 WHERE id=1", [])
            .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        let address = TimelineAddress::test_only_new(
            world,
            gen,
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"value"),
        );

        let tx = conn.transaction().unwrap();
        let row = load_event_snapshot(&tx, address.seq()).unwrap().unwrap();

        match timeline_read_from_snapshot(&tx, &address, row).unwrap() {
            TimelineRead::Corrupt {
                address: got,
                reason,
            } => {
                assert_eq!(got, address);
                assert_eq!(reason, TimelineCorruption::MissingBodyForPresentRow);
            }
            _ => panic!("expected corrupt missing retained body"),
        }
    }

    #[tokio::test]
    async fn read_timeline_body_reports_generation_mismatch_without_current_read() {
        let root = temp_root("read-generation-mismatch");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/read-gen-mismatch").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"old"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        let TimelineAddressLookup::Body(address) = verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(1).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap() else {
            panic!("expected body timeline address");
        };
        drop(tracked);

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
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
        let new_gen = world_schema::generation(&conn).unwrap();
        assert_ne!(&new_gen, address.gen());
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        let read =
            read_timeline_body_via_conn(&mut tracked, &address, &engine.core().hmac_key).unwrap();

        match read {
            TimelineRead::GenMismatch { requested, actual } => {
                assert_eq!(requested, address);
                assert_eq!(actual, new_gen);
            }
            _ => panic!("expected generation mismatch"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn read_timeline_body_reports_missing_row_for_same_generation_gap() {
        let root = temp_root("read-missing-row");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/read-missing-row").unwrap();
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
        let gen = world_schema::generation(&conn).unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        let address = TimelineAddress::test_only_new(
            world.clone(),
            gen,
            TimelineSeq::new(99).unwrap(),
            BodySha256::for_body(b"value"),
        );

        match read_timeline_body_via_conn(&mut tracked, &address, &engine.core().hmac_key).unwrap()
        {
            TimelineRead::MissingRow { address: got } => assert_eq!(got, address),
            _ => panic!("expected missing row"),
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
