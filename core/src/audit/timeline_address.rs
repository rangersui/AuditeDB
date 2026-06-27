#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::{params, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    read_cache::TrackedReadConnection,
    timeline::{BodySha256, TimelineAddress, TimelineCorruption, TimelineRead, TimelineSeq},
    world_generation::WorldGeneration,
    world_schema,
};

use super::timeline_row::{
    corrupt, load_event_identity, load_event_snapshot, load_latest_body_head, TimelineBodyRowMatch,
    TimelineEventSnapshot,
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

pub(super) fn timeline_address_from_verified_coordinate_body_event(
    event: super::timeline_dereference::VerifiedCoordinateBodyEvent,
) -> TimelineAddress {
    let (world, gen, seq, body_sha256) = event.into_parts();
    TimelineAddress::from_verified_body_event(VerifiedBodyEvent::new(world, gen, seq, body_sha256))
}

pub(crate) struct VerifiedBodyHead {
    address: TimelineAddress,
    hmac: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TimelineAddressLookup {
    Body(TimelineAddress),
    MissingRow(VerifiedMissingTimelineRow),
    NoBody(VerifiedNonBodyTimelineEvent),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedMissingTimelineRow {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedNonBodyTimelineEvent {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    event_target: String,
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

impl VerifiedMissingTimelineRow {
    fn new(world: ValidatedWorldPath, gen: WorldGeneration, seq: TimelineSeq) -> Self {
        Self { world, gen, seq }
    }

    #[cfg(test)]
    fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    #[cfg(test)]
    fn gen(&self) -> &WorldGeneration {
        &self.gen
    }

    #[cfg(test)]
    fn seq(&self) -> TimelineSeq {
        self.seq
    }
}

impl VerifiedNonBodyTimelineEvent {
    fn new(
        world: ValidatedWorldPath,
        gen: WorldGeneration,
        seq: TimelineSeq,
        event_target: String,
    ) -> Self {
        Self {
            world,
            gen,
            seq,
            event_target,
        }
    }

    #[cfg(test)]
    fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    #[cfg(test)]
    fn gen(&self) -> &WorldGeneration {
        &self.gen
    }

    #[cfg(test)]
    fn seq(&self) -> TimelineSeq {
        self.seq
    }

    #[cfg(test)]
    fn event_target(&self) -> &str {
        &self.event_target
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
    super::require_intact(super::verify_world_tx(&tx, world, key)?)?;

    let gen = world_schema::generation(&tx)?;
    let Some(row) = load_event_identity(&tx, seq)? else {
        let proof = VerifiedMissingTimelineRow::new(world.clone(), gen, seq);
        return Ok(TimelineAddressLookup::MissingRow(proof));
    };

    let kind = row.kind_or_corrupt()?;
    if !kind.class().body_bearing {
        let proof =
            VerifiedNonBodyTimelineEvent::new(world.clone(), gen, seq, row.target().to_owned());
        return Ok(TimelineAddressLookup::NoBody(proof));
    }
    if !row.target_matches(world) {
        return Err(corrupt("events.target does not match requested world").into());
    }
    let body_sha256 = row.body_sha256_or_corrupt()?;
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
    super::require_intact(super::verify_world_tx(&tx, world, key)?)?;
    if let Some(break_report) = super::live_body::verify_tx(&tx)? {
        return Err(super::AuditError::ChainBroken(break_report));
    }

    let Some(head) = load_latest_body_head(&tx)? else {
        tx.commit()?;
        return Ok(None);
    };

    let row = head.event();
    let kind = row.kind_or_corrupt()?;
    if !kind.class().body_bearing {
        return Err(corrupt("latest body query returned a metadata event").into());
    }
    if !row.target_matches(world) {
        return Err(corrupt("events.target does not match requested world").into());
    }
    let body_sha256 = row.body_sha256_or_corrupt()?;
    let gen = world_schema::generation(&tx)?;
    let event = VerifiedBodyEvent::new(world.clone(), gen, head.seq(), body_sha256);
    let address = TimelineAddress::from_verified_body_event(event);
    let head = VerifiedBodyHead::new(address, head.hmac_label().to_owned());
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

fn timeline_read_from_snapshot(
    tx: &rusqlite::Transaction<'_>,
    address: &TimelineAddress,
    row: TimelineEventSnapshot,
) -> rusqlite::Result<TimelineRead> {
    let row = match row.match_body_row(address.world(), address.body_sha256()) {
        TimelineBodyRowMatch::Body(row) => row,
        TimelineBodyRowMatch::NonBody => {
            return Ok(timeline_corrupt(
                address,
                TimelineCorruption::MissingBodyForPresentRow,
            ));
        }
        TimelineBodyRowMatch::BodyHashMismatch(actual) => {
            return Ok(TimelineRead::AddressMismatch {
                requested: address.clone(),
                actual,
            });
        }
        TimelineBodyRowMatch::InvalidEventKind
        | TimelineBodyRowMatch::TargetMismatch
        | TimelineBodyRowMatch::InvalidBodySha256 => {
            return Ok(timeline_corrupt(
                address,
                TimelineCorruption::InvalidEventShape,
            ));
        }
    };

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
    let Some(representation) = row.into_representation(body) else {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    };

    Ok(TimelineRead::body(address.clone(), representation))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        engine::Engine,
        engine_types::{AccessTier, AuditHmacKey, Preconditions, Representation},
        event::AuditEventKind,
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
            TimelineAddressLookup::MissingRow(_) | TimelineAddressLookup::NoBody(_) => {
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
    fn verified_latest_body_head_returns_none_for_metadata_only_chain() {
        let key = key();
        let world = ValidatedWorldPath::new("home/metadata-only").unwrap();
        let conn = single_event_conn(&world, "delete_intent", "", &key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let head = verified_latest_body_head_via_conn(&mut tracked, &world, &key).unwrap();

        assert!(head.is_none());
    }

    #[tokio::test]
    async fn verified_latest_body_head_skips_metadata_tail() {
        let root = temp_root("latest-body-head-metadata-tail");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/latest-head").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        let first_hmac: String = conn
            .query_row("SELECT hmac FROM events WHERE id=1", [], |r| r.get(0))
            .unwrap();
        {
            let tx = conn.transaction().unwrap();
            let audit_tx = super::super::verify_appendable_tx_existing_checked(
                &tx,
                &world,
                &engine.core().hmac_key,
            )
            .unwrap();
            super::super::append_tx_inner(
                &audit_tx,
                AuditEventKind::DeleteIntent,
                world.as_str(),
                &BodySha256::for_body(b""),
                0,
                "",
                &[],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let head =
            verified_latest_body_head_via_conn(&mut tracked, &world, &engine.core().hmac_key)
                .unwrap()
                .unwrap();

        assert_eq!(head.address().world(), &world);
        assert_eq!(head.address().gen(), &gen);
        assert_eq!(head.address().seq().get(), 1);
        assert_eq!(
            head.address().body_sha256(),
            &BodySha256::for_body(b"value")
        );
        assert_eq!(head.hmac(), format!("hmac-{first_hmac}"));

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

        let gen = world_schema::generation(tracked.as_mut_conn()).unwrap();
        match verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(99).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap()
        {
            TimelineAddressLookup::MissingRow(proof) => {
                assert_eq!(proof.world(), &world);
                assert_eq!(proof.gen(), &gen);
                assert_eq!(proof.seq().get(), 99);
            }
            _ => panic!("expected missing row proof"),
        }

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

        let gen = world_schema::generation(tracked.as_mut_conn()).unwrap();
        match verified_timeline_address_via_conn(
            &mut tracked,
            &ledger,
            TimelineSeq::new(1).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap()
        {
            TimelineAddressLookup::NoBody(proof) => {
                assert_eq!(proof.world(), &ledger);
                assert_eq!(proof.gen(), &gen);
                assert_eq!(proof.seq().get(), 1);
                assert_eq!(proof.event_target(), subject.as_str());
            }
            _ => panic!("expected non-body proof"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
