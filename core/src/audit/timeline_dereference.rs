//! Coordinate dereference result contract for timeline reads.
//!
//! A [`TimelineCoordinate`] is wire syntax. This module names the later result
//! states for the resolver that verifies a subject world's audit chain before
//! it returns either a historical body or a proof-bearing negative fact.

#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::{params, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    read_cache::TrackedReadConnection,
    timeline::{
        BodySha256, InvalidBodySha256, TimelineBody, TimelineCoordinate, TimelineCorruption,
        TimelineRead, TimelineSeq,
    },
    world_generation::WorldGeneration,
    world_schema,
};

use super::timeline_row::{load_event_snapshot, TimelineBodyRowMatch, TimelineEventSnapshot};

pub(super) struct VerifiedCoordinateBodyEvent {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    body_sha256: BodySha256,
}

impl VerifiedCoordinateBodyEvent {
    fn new(
        coordinate: &TimelineCoordinate,
        gen: WorldGeneration,
        body_sha256: BodySha256,
    ) -> Option<Self> {
        if coordinate.generation() != &gen || !coordinate.body_sha256().ct_eq(&body_sha256) {
            return None;
        }
        Some(Self {
            world: coordinate.world().clone(),
            gen,
            seq: coordinate.seq(),
            body_sha256,
        })
    }

    pub(super) fn into_parts(
        self,
    ) -> (ValidatedWorldPath, WorldGeneration, TimelineSeq, BodySha256) {
        (self.world, self.gen, self.seq, self.body_sha256)
    }
}

pub(crate) fn dereference_timeline_coordinate_via_conn(
    tracked: &mut TrackedReadConnection,
    coordinate: &TimelineCoordinate,
    key: &AuditHmacKey,
) -> super::AuditResult<TimelineDereference> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    let actual_gen = world_schema::generation(&tx)?;
    super::require_intact(super::verify_world_tx(&tx, coordinate.world(), key)?)?;

    let result = if &actual_gen != coordinate.generation() {
        match VerifiedGenerationMismatch::new(coordinate.clone(), actual_gen) {
            Some(proof) => TimelineDereference::GenMismatch(proof),
            None => corrupt(coordinate, TimelineCorruption::InvalidEventShape),
        }
    } else {
        match load_event_snapshot(&tx, coordinate.seq())? {
            Some(row) => dereference_snapshot(&tx, coordinate, row, actual_gen)?,
            None => TimelineDereference::MissingRow(VerifiedMissingRow::new(coordinate.clone())),
        }
    };
    tx.commit()?;
    Ok(result)
}

fn dereference_snapshot(
    tx: &rusqlite::Transaction<'_>,
    coordinate: &TimelineCoordinate,
    row: TimelineEventSnapshot,
    gen: WorldGeneration,
) -> rusqlite::Result<TimelineDereference> {
    let row = match row.match_body_row_target_first(coordinate.world(), coordinate.body_sha256()) {
        TimelineBodyRowMatch::Body(row) => row,
        TimelineBodyRowMatch::NonBody => {
            return Ok(TimelineDereference::NonBodyEvent(
                VerifiedNonBodyEvent::new(coordinate.clone()),
            ));
        }
        TimelineBodyRowMatch::BodyHashMismatch(actual_body_sha256) => {
            return Ok(
                match VerifiedBodyHashMismatch::new(coordinate.clone(), actual_body_sha256) {
                    Some(proof) => TimelineDereference::BodyHashMismatch(proof),
                    None => corrupt(coordinate, TimelineCorruption::InvalidEventShape),
                },
            );
        }
        TimelineBodyRowMatch::InvalidBodySha256(reason) => {
            return Ok(corrupt(coordinate, invalid_body_sha256_corruption(reason)));
        }
        TimelineBodyRowMatch::InvalidEventKind | TimelineBodyRowMatch::TargetMismatch => {
            return Ok(corrupt(coordinate, TimelineCorruption::InvalidEventShape));
        }
    };

    let Some(event) = VerifiedCoordinateBodyEvent::new(coordinate, gen, row.body_sha256().clone())
    else {
        return Ok(corrupt(coordinate, TimelineCorruption::InvalidEventShape));
    };
    let address =
        super::timeline_address::timeline_address_from_verified_coordinate_body_event(event);
    let Some(body) = tx
        .query_row(
            "SELECT body FROM cas_bodies WHERE body_sha256=?1",
            params![address.body_sha256().as_str()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    else {
        return Ok(corrupt(
            coordinate,
            TimelineCorruption::MissingBodyForPresentRow,
        ));
    };
    let Some(representation) = row.into_representation(body) else {
        return Ok(corrupt(coordinate, TimelineCorruption::InvalidEventShape));
    };

    match TimelineRead::body(address, representation) {
        TimelineRead::Body(body) => Ok(TimelineDereference::Body(body)),
        TimelineRead::Corrupt { reason, .. } => Ok(corrupt(coordinate, reason)),
        TimelineRead::GenMismatch { .. }
        | TimelineRead::MissingRow { .. }
        | TimelineRead::NeverRetained { .. }
        | TimelineRead::AddressMismatch { .. }
        | TimelineRead::Unproven { .. } => {
            Ok(corrupt(coordinate, TimelineCorruption::InvalidEventShape))
        }
    }
}

fn corrupt(coordinate: &TimelineCoordinate, reason: TimelineCorruption) -> TimelineDereference {
    TimelineDereference::Corrupt {
        coordinate: coordinate.clone(),
        reason,
    }
}

fn invalid_body_sha256_corruption(reason: InvalidBodySha256) -> TimelineCorruption {
    match reason {
        InvalidBodySha256::WrongLength | InvalidBodySha256::NotLowerHex => {
            TimelineCorruption::InvalidEventShape
        }
    }
}

/// Verified generation mismatch for coordinate-based timeline dereference.
///
/// This is a proof value, not a plain error bag. Callers can inspect it, but
/// cannot construct one without going through this module's resolver path after
/// it verifies the subject world's audit chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGenerationMismatch {
    requested: TimelineCoordinate,
    actual: WorldGeneration,
}

/// Verified body-hash mismatch for coordinate-based timeline dereference.
///
/// The event row exists and has been verified at the requested world,
/// generation, and sequence, but the row's body hash differs from the untrusted
/// coordinate supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBodyHashMismatch {
    requested: TimelineCoordinate,
    actual_body_sha256: BodySha256,
}

/// Verified non-body event for coordinate-based timeline dereference.
///
/// The requested world/generation/sequence exists in an intact audit chain, but
/// that event does not carry a historical body. The requested body hash remains
/// caller-supplied syntax, not a proven row fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNonBodyEvent {
    requested: TimelineCoordinate,
}

/// Verified row absence for coordinate-based timeline dereference.
///
/// The subject world exists, its generation matches the coordinate, and its
/// audit chain is intact, but no row exists at the requested sequence. The
/// requested body hash remains caller-supplied syntax, not a proven row fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMissingRow {
    requested: TimelineCoordinate,
}

/// Result of dereferencing an untrusted [`TimelineCoordinate`].
///
/// This is intentionally separate from [`crate::TimelineRead`].
/// [`crate::TimelineRead`] is for already proof-bearing timeline addresses.
/// Coordinate dereference starts before that proof exists, so every verified
/// historical negative outcome carries a sealed proof value and unproven
/// absence stays distinct. Delete and pruning outcomes stay out of the v1
/// coordinate contract until their own proof types exist.
///
/// Public callers cannot mint verified negative outcomes with raw constructors:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_generation: elastik_core::WorldGeneration = todo!();
///
/// let _ = elastik_core::VerifiedGenerationMismatch::new(requested, actual_generation);
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_hash: elastik_core::BodySha256 = todo!();
///
/// let _ = elastik_core::VerifiedBodyHashMismatch::new(requested, actual_hash);
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedNonBodyEvent::new(requested.clone());
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedMissingRow::new(requested);
/// # }
/// ```
///
/// Nor can they construct proofs with struct literals:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_generation: elastik_core::WorldGeneration = todo!();
///
/// let _ = elastik_core::VerifiedGenerationMismatch {
///     requested,
///     actual: actual_generation,
/// };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_hash: elastik_core::BodySha256 = todo!();
///
/// let _ = elastik_core::VerifiedBodyHashMismatch {
///     requested,
///     actual_body_sha256: actual_hash,
/// };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedNonBodyEvent { requested };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedMissingRow { requested };
/// # }
/// ```
///
/// A raw coordinate also cannot stand in for a verified proof:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::TimelineDereference::MissingRow(requested);
/// # }
/// ```
#[non_exhaustive]
pub enum TimelineDereference {
    /// The addressed historical body was found.
    Body(TimelineBody),
    /// The subject world exists and verified, but belongs to a different
    /// generation than the coordinate requested.
    GenMismatch(VerifiedGenerationMismatch),
    /// The event row exists and verified, but promised a different body hash.
    BodyHashMismatch(VerifiedBodyHashMismatch),
    /// The event row exists and verified, but it is metadata-only.
    NonBodyEvent(VerifiedNonBodyEvent),
    /// The subject world exists and verified, but the sequence row is absent.
    MissingRow(VerifiedMissingRow),
    /// No bounded proof source can currently prove the requested coordinate.
    UnprovenCoordinate(TimelineCoordinate),
    /// Integrity failure while resolving the coordinate.
    Corrupt {
        /// Coordinate being resolved when corruption was detected.
        coordinate: TimelineCoordinate,
        /// Integrity failure category.
        reason: TimelineCorruption,
    },
}

impl VerifiedGenerationMismatch {
    fn new(requested: TimelineCoordinate, actual: WorldGeneration) -> Option<Self> {
        if requested.generation() == &actual {
            return None;
        }
        Some(Self { requested, actual })
    }

    /// Returns the untrusted coordinate after the resolver proved the mismatch.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }

    /// Returns the actual generation stored in the subject world.
    pub fn actual(&self) -> &WorldGeneration {
        &self.actual
    }
}

impl VerifiedBodyHashMismatch {
    fn new(requested: TimelineCoordinate, actual_body_sha256: BodySha256) -> Option<Self> {
        if requested.body_sha256().ct_eq(&actual_body_sha256) {
            return None;
        }
        Some(Self {
            requested,
            actual_body_sha256,
        })
    }

    /// Returns the untrusted coordinate after the resolver proved the mismatch.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }

    /// Returns the body digest found in the verified event row.
    pub fn actual_body_sha256(&self) -> &BodySha256 {
        &self.actual_body_sha256
    }
}

impl VerifiedNonBodyEvent {
    fn new(requested: TimelineCoordinate) -> Self {
        Self { requested }
    }

    /// Returns the requested coordinate after the resolver proved the row is
    /// non-body-bearing.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }
}

impl VerifiedMissingRow {
    fn new(requested: TimelineCoordinate) -> Self {
        Self { requested }
    }

    /// Returns the requested coordinate after the resolver proved the row is
    /// absent.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        engine::Engine,
        engine_types::{AccessTier, Preconditions, Representation, ValidatedWorldPath},
    };
    use bytes::Bytes;
    use rusqlite::Connection;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn coordinate_with_hash(seq: i64, hash: &str) -> TimelineCoordinate {
        TimelineCoordinate::from_wire_parts(
            "home/timeline",
            "0123456789abcdef0123456789abcdef",
            seq,
            hash,
        )
        .unwrap()
    }

    fn coordinate(seq: i64) -> TimelineCoordinate {
        coordinate_with_hash(
            seq,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    fn other_body_hash() -> BodySha256 {
        BodySha256::new("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").unwrap()
    }

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-audit-timeline-deref-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn coordinate_for_event(
        engine: &Engine,
        world: &ValidatedWorldPath,
        id: i64,
    ) -> TimelineCoordinate {
        let conn =
            Connection::open(crate::world::world_db(&engine.core().data, world.as_str())).unwrap();
        let generation = world_schema::generation(&conn).unwrap();
        let body_sha256: String = conn
            .query_row("SELECT body_sha256 FROM events WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        TimelineCoordinate::from_wire_parts(world.as_str(), generation.as_str(), id, body_sha256)
            .unwrap()
    }

    fn dereference(engine: &Engine, coordinate: &TimelineCoordinate) -> TimelineDereference {
        let conn = Connection::open(crate::world::world_db(
            &engine.core().data,
            coordinate.world().as_str(),
        ))
        .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        dereference_timeline_coordinate_via_conn(&mut tracked, coordinate, &engine.core().hmac_key)
            .unwrap()
    }

    fn single_metadata_event_conn(
        event_type: &str,
        target: &str,
        key: &AuditHmacKey,
    ) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE stage_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                generation TEXT NOT NULL,
                body BLOB DEFAULT x'',
                content_type TEXT DEFAULT 'application/octet-stream'
            );
            INSERT INTO stage_meta(id, generation, body)
                VALUES(1, '0123456789abcdef0123456789abcdef', x'');
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
        let meta_sha256 = super::super::meta_sha256_canonical("", &[]);
        let hmac = super::super::event_hmac(
            key,
            super::super::EventHmacInput {
                prev: "",
                event_type,
                target,
                generation: &generation,
                body_sha256: "",
                size: 0,
                content_type: "",
                meta_sha256: &meta_sha256,
            },
        );
        conn.execute(
            r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                                  content_type, meta_sha256, hmac, prev_hmac)
               VALUES(datetime('now'), ?1, ?2, '', 0, '', ?3, ?4, '')"#,
            rusqlite::params![event_type, target, meta_sha256, hmac],
        )
        .unwrap();
        conn
    }

    #[test]
    fn timeline_dereference_negative_outcomes_carry_verified_proofs() {
        let requested = coordinate(42);
        let actual_gen = WorldGeneration::new("fedcba9876543210fedcba9876543210").unwrap();
        let actual_hash = other_body_hash();

        let gen_mismatch =
            VerifiedGenerationMismatch::new(requested.clone(), actual_gen.clone()).unwrap();
        assert_eq!(gen_mismatch.requested(), &requested);
        assert_eq!(gen_mismatch.actual(), &actual_gen);

        let body_hash_mismatch =
            VerifiedBodyHashMismatch::new(requested.clone(), actual_hash.clone()).unwrap();
        assert_eq!(body_hash_mismatch.requested(), &requested);
        assert_eq!(body_hash_mismatch.actual_body_sha256(), &actual_hash);

        let non_body = VerifiedNonBodyEvent::new(requested.clone());
        assert_eq!(non_body.requested(), &requested);

        let missing = VerifiedMissingRow::new(requested.clone());
        assert_eq!(missing.requested(), &requested);

        let results = [
            TimelineDereference::GenMismatch(gen_mismatch),
            TimelineDereference::BodyHashMismatch(body_hash_mismatch),
            TimelineDereference::NonBodyEvent(non_body),
            TimelineDereference::MissingRow(missing),
            TimelineDereference::UnprovenCoordinate(requested.clone()),
        ];

        for result in results {
            match result {
                TimelineDereference::GenMismatch(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::BodyHashMismatch(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::NonBodyEvent(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::MissingRow(proof) => assert_eq!(proof.requested(), &requested),
                TimelineDereference::UnprovenCoordinate(coord) => assert_eq!(coord, requested),
                TimelineDereference::Body(_) | TimelineDereference::Corrupt { .. } => {
                    panic!("unexpected dereference state")
                }
            }
        }
    }

    #[test]
    fn mismatch_proofs_reject_non_mismatches() {
        let requested = coordinate(42);
        assert!(
            VerifiedGenerationMismatch::new(requested.clone(), requested.generation().clone())
                .is_none()
        );
        assert!(
            VerifiedBodyHashMismatch::new(requested.clone(), requested.body_sha256().clone())
                .is_none()
        );
    }

    #[tokio::test]
    async fn coordinate_resolver_returns_historical_body() {
        let root = temp_root("body");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-body").unwrap();

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

        let coordinate = coordinate_for_event(&engine, &world, 1);
        match dereference(&engine, &coordinate) {
            TimelineDereference::Body(body) => {
                assert_eq!(body.address().world(), &world);
                assert_eq!(body.address().seq().get(), 1);
                assert_eq!(body.representation().body.as_ref(), b"old");
            }
            _ => panic!("expected body"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn coordinate_resolver_returns_body_hash_mismatch_and_missing_row() {
        let root = temp_root("negative");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-negative").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let coordinate = coordinate_for_event(&engine, &world, 1);
        let wrong_hash = other_body_hash();
        let mismatch = TimelineCoordinate::from_wire_parts(
            world.as_str(),
            coordinate.generation().as_str(),
            1,
            wrong_hash.as_str(),
        )
        .unwrap();
        match dereference(&engine, &mismatch) {
            TimelineDereference::BodyHashMismatch(proof) => {
                assert_eq!(proof.requested(), &mismatch);
                assert_eq!(proof.actual_body_sha256(), coordinate.body_sha256());
            }
            _ => panic!("expected hash mismatch"),
        }

        let missing = TimelineCoordinate::from_wire_parts(
            world.as_str(),
            coordinate.generation().as_str(),
            99,
            coordinate.body_sha256().as_str(),
        )
        .unwrap();
        match dereference(&engine, &missing) {
            TimelineDereference::MissingRow(proof) => assert_eq!(proof.requested(), &missing),
            _ => panic!("expected missing row"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn coordinate_resolver_returns_generation_mismatch_after_chain_verification() {
        let root = temp_root("generation-mismatch");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-generation").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let actual = coordinate_for_event(&engine, &world, 1);
        let requested = TimelineCoordinate::from_wire_parts(
            world.as_str(),
            "fedcba9876543210fedcba9876543210",
            actual.seq().get(),
            actual.body_sha256().as_str(),
        )
        .unwrap();

        match dereference(&engine, &requested) {
            TimelineDereference::GenMismatch(proof) => {
                assert_eq!(proof.requested(), &requested);
                assert_eq!(proof.actual(), actual.generation());
            }
            _ => panic!("expected generation mismatch"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn coordinate_resolver_returns_non_body_event_after_chain_verification() {
        let key = key();
        let world = ValidatedWorldPath::new("home/timeline-metadata").unwrap();
        let conn = single_metadata_event_conn("delete_intent", world.as_str(), &key);
        let coordinate = TimelineCoordinate::from_wire_parts(
            world.as_str(),
            "0123456789abcdef0123456789abcdef",
            1,
            other_body_hash().as_str(),
        )
        .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        match dereference_timeline_coordinate_via_conn(&mut tracked, &coordinate, &key).unwrap() {
            TimelineDereference::NonBodyEvent(proof) => {
                assert_eq!(proof.requested(), &coordinate)
            }
            _ => panic!("expected non-body event"),
        }
    }

    #[test]
    fn coordinate_resolver_rejects_wrong_target_non_body_event() {
        let key = key();
        let world = ValidatedWorldPath::new("home/timeline-metadata-target").unwrap();
        let conn = single_metadata_event_conn("delete_intent", "home/other", &key);
        let coordinate = TimelineCoordinate::from_wire_parts(
            world.as_str(),
            "0123456789abcdef0123456789abcdef",
            1,
            other_body_hash().as_str(),
        )
        .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        match dereference_timeline_coordinate_via_conn(&mut tracked, &coordinate, &key).unwrap() {
            TimelineDereference::Corrupt {
                coordinate: got,
                reason: TimelineCorruption::InvalidEventShape,
            } => assert_eq!(got, coordinate),
            _ => panic!("wrong-target metadata event must be corrupt"),
        }
    }
}
