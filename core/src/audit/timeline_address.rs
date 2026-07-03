#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::{params, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::AuditEventKind,
    read_cache::TrackedReadConnection,
    timeline::{
        BodySha256, DeleteSubjectProof, InvalidBodySha256, TimelineAddress, TimelineCorruption,
        TimelineRead, TimelineSeq,
    },
    world_generation::WorldGeneration,
    world_schema,
};

use super::timeline_row::{
    corrupt, load_event_identity, load_event_snapshot, load_latest_body_head,
    MatchedTimelineBodyRow, TimelineBodyRowMatch, TimelineEventSnapshot,
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

pub(crate) struct VerifiedExpiredTimelineBody {
    address: TimelineAddress,
    content_type: String,
    size: i64,
    hmac: String,
}

pub(crate) enum VerifiedReplayEvent {
    Body(VerifiedReplayBodyEvent),
    NonBody(VerifiedReplayNonBodyEvent),
}

pub(crate) struct VerifiedReplayBodyEvent {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    kind: AuditEventKind,
    address: TimelineAddress,
    payload: VerifiedReplayPayload,
    hmac: String,
}

pub(crate) struct VerifiedReplayNonBodyEvent {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    kind: AuditEventKind,
    event_target: ValidatedWorldPath,
    payload: VerifiedReplayPayload,
    delete_subject: Option<DeleteSubjectProof>,
    hmac: String,
}

struct VerifiedReplayNonBodyEventParts {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    kind: AuditEventKind,
    event_target: ValidatedWorldPath,
    payload: VerifiedReplayPayload,
    delete_subject: Option<DeleteSubjectProof>,
    hmac: String,
}

struct VerifiedReplayPayload {
    body_sha256: BodySha256,
    size: i64,
    content_type: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TimelineAddressLookup {
    Body(TimelineAddress),
    MissingRow(VerifiedMissingTimelineRow),
    NoBody(VerifiedNonBodyTimelineEvent),
}

pub(crate) enum VerifiedReplayAfter {
    Events(Vec<VerifiedReplayEvent>),
    GenerationMismatch,
    MissingMarker,
    ReplayLimitExceeded,
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

impl VerifiedExpiredTimelineBody {
    fn new(address: TimelineAddress, content_type: String, size: i64, hmac: String) -> Self {
        Self {
            address,
            content_type,
            size,
            hmac,
        }
    }

    pub(crate) fn address(&self) -> &TimelineAddress {
        &self.address
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
    }

    pub(crate) fn size(&self) -> i64 {
        self.size
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }
}

impl VerifiedReplayEvent {
    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        match self {
            Self::Body(event) => event.world(),
            Self::NonBody(event) => event.world(),
        }
    }

    pub(crate) fn gen(&self) -> &WorldGeneration {
        match self {
            Self::Body(event) => event.gen(),
            Self::NonBody(event) => event.gen(),
        }
    }

    pub(crate) fn seq(&self) -> TimelineSeq {
        match self {
            Self::Body(event) => event.seq(),
            Self::NonBody(event) => event.seq(),
        }
    }

    pub(crate) fn kind(&self) -> AuditEventKind {
        match self {
            Self::Body(event) => event.kind(),
            Self::NonBody(event) => event.kind(),
        }
    }

    pub(crate) fn hmac(&self) -> &str {
        match self {
            Self::Body(event) => event.hmac(),
            Self::NonBody(event) => event.hmac(),
        }
    }
}

impl VerifiedReplayBodyEvent {
    fn new(
        world: ValidatedWorldPath,
        gen: WorldGeneration,
        seq: TimelineSeq,
        kind: AuditEventKind,
        address: TimelineAddress,
        payload: VerifiedReplayPayload,
        hmac: String,
    ) -> Self {
        Self {
            world,
            gen,
            seq,
            kind,
            address,
            payload,
            hmac,
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

    pub(crate) fn kind(&self) -> AuditEventKind {
        self.kind
    }

    pub(crate) fn timeline_address(&self) -> &TimelineAddress {
        &self.address
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        self.payload.body_sha256()
    }

    pub(crate) fn size(&self) -> i64 {
        self.payload.size()
    }

    pub(crate) fn content_type(&self) -> &str {
        self.payload.content_type()
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }
}

impl VerifiedReplayNonBodyEvent {
    fn new(parts: VerifiedReplayNonBodyEventParts) -> Self {
        Self {
            world: parts.world,
            gen: parts.gen,
            seq: parts.seq,
            kind: parts.kind,
            event_target: parts.event_target,
            payload: parts.payload,
            delete_subject: parts.delete_subject,
            hmac: parts.hmac,
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

    pub(crate) fn kind(&self) -> AuditEventKind {
        self.kind
    }

    pub(crate) fn event_target(&self) -> &ValidatedWorldPath {
        &self.event_target
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        self.payload.body_sha256()
    }

    pub(crate) fn size(&self) -> i64 {
        self.payload.size()
    }

    pub(crate) fn content_type(&self) -> &str {
        self.payload.content_type()
    }

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject.as_ref()
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }
}

impl VerifiedReplayPayload {
    fn new(body_sha256: BodySha256, size: i64, content_type: String) -> Self {
        Self {
            body_sha256,
            size,
            content_type,
        }
    }

    fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }

    fn size(&self) -> i64 {
        self.size
    }

    fn content_type(&self) -> &str {
        &self.content_type
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
    super::require_world_intact_tx(&tx, world, key)?;

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

pub(crate) fn verified_replay_events_after_via_conn(
    tracked: &mut TrackedReadConnection,
    world: &ValidatedWorldPath,
    generation: &WorldGeneration,
    after: TimelineSeq,
    limit: usize,
    key: &AuditHmacKey,
) -> super::AuditResult<VerifiedReplayAfter> {
    let conn = tracked.as_mut_conn();
    let tx = conn.transaction()?;
    super::require_world_intact_tx(&tx, world, key)?;

    let actual_gen = world_schema::generation(&tx)?;
    if &actual_gen != generation {
        tx.commit()?;
        return Ok(VerifiedReplayAfter::GenerationMismatch);
    }

    let Some(marker) = load_event_identity(&tx, after)? else {
        tx.commit()?;
        return Ok(VerifiedReplayAfter::MissingMarker);
    };
    let marker_kind = marker.kind_or_corrupt()?;
    if marker_kind.class().body_bearing && !marker.target_matches(world) {
        return Err(corrupt("events.target does not match requested world").into());
    }

    let mut events = Vec::new();
    let mut over_limit = false;
    {
        let query_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut stmt = tx.prepare(
            "SELECT id, event_type, target, body_sha256, size, content_type, hmac
             FROM events
             WHERE id>?1
             ORDER BY id ASC
             LIMIT ?2",
        )?;
        let mut rows = stmt.query(params![after.get(), query_limit])?;
        while let Some(row) = rows.next()? {
            if events.len() >= limit {
                over_limit = true;
                break;
            }
            let raw_seq: i64 = row.get(0)?;
            let seq =
                TimelineSeq::new(raw_seq).map_err(|_| corrupt("events.id is not positive"))?;
            let event_type: String = row.get(1)?;
            let kind = AuditEventKind::from_storage(&event_type)
                .ok_or_else(|| corrupt("events.event_type is not a known audit event"))?;
            let target: String = row.get(2)?;
            let raw_body_sha256: String = row.get(3)?;
            let size: i64 = row.get(4)?;
            if size < 0 {
                return Err(corrupt("events.size is negative").into());
            }
            let content_type: String = row.get(5)?;
            let raw_hmac: String = row.get(6)?;
            let body_sha256 = BodySha256::new(raw_body_sha256)
                .map_err(|err| corrupt(&format!("events.body_sha256 is invalid: {err:?}")))?;
            let payload = VerifiedReplayPayload::new(body_sha256.clone(), size, content_type);
            let event = if kind.class().body_bearing {
                if target != world.as_str() {
                    return Err(corrupt("events.target does not match requested world").into());
                }
                let body_event =
                    VerifiedBodyEvent::new(world.clone(), actual_gen.clone(), seq, body_sha256);
                let address = TimelineAddress::from_verified_body_event(body_event);
                VerifiedReplayEvent::Body(VerifiedReplayBodyEvent::new(
                    world.clone(),
                    actual_gen.clone(),
                    seq,
                    kind,
                    address,
                    payload,
                    raw_hmac,
                ))
            } else if !kind.class().notifies {
                return Err(corrupt("events.event_type is not subscribable").into());
            } else if let Ok(event_target) = ValidatedWorldPath::from_canonical(target) {
                let delete_subject = delete_subject_proof_for_replay_event(
                    &tx,
                    seq,
                    kind,
                    &event_target,
                    &body_sha256,
                )?;
                VerifiedReplayEvent::NonBody(VerifiedReplayNonBodyEvent::new(
                    VerifiedReplayNonBodyEventParts {
                        world: world.clone(),
                        gen: actual_gen.clone(),
                        seq,
                        kind,
                        event_target,
                        payload,
                        delete_subject,
                        hmac: raw_hmac,
                    },
                ))
            } else {
                return Err(corrupt("events.target is not a canonical world").into());
            };
            events.push(event);
        }
    }
    tx.commit()?;
    if over_limit {
        return Ok(VerifiedReplayAfter::ReplayLimitExceeded);
    }
    Ok(VerifiedReplayAfter::Events(events))
}

fn delete_subject_proof_for_replay_event(
    tx: &rusqlite::Transaction<'_>,
    seq: TimelineSeq,
    kind: AuditEventKind,
    target: &ValidatedWorldPath,
    body_sha256: &BodySha256,
) -> rusqlite::Result<Option<DeleteSubjectProof>> {
    if !matches!(
        kind,
        AuditEventKind::DeleteIntent
            | AuditEventKind::DeleteCommit
            | AuditEventKind::DeleteCommitFailed
    ) {
        return Ok(None);
    }

    let mut headers = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT name, value FROM event_headers
             WHERE event_id=?1 AND name LIKE 'auditedb-delete-subject-%'
             ORDER BY name, value",
        )?;
        let rows = stmt.query_map(params![seq.get()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for header in rows {
            headers.push(header?);
        }
    }

    super::headers::delete_subject_proof_from_headers(target, body_sha256, &headers)
        .map_err(|err| corrupt(&format!("delete subject proof is invalid: {err:?}")))
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
        TimelineBodyRowMatch::NonBody(_) => {
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
        TimelineBodyRowMatch::InvalidBodySha256(reason) => {
            return Ok(timeline_corrupt(
                address,
                invalid_body_sha256_corruption(reason),
            ));
        }
        TimelineBodyRowMatch::InvalidEventKind
        | TimelineBodyRowMatch::InvalidEventShape
        | TimelineBodyRowMatch::TargetMismatch => {
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
        return missing_timeline_body_read(tx, address, row);
    };
    let Some((representation, hmac)) = row.into_representation_with_hmac(body) else {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::InvalidEventShape,
        ));
    };

    Ok(TimelineRead::body(address.clone(), representation, hmac))
}

fn timeline_corrupt(address: &TimelineAddress, reason: TimelineCorruption) -> TimelineRead {
    TimelineRead::Corrupt {
        address: address.clone(),
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

pub(super) fn missing_timeline_body_read(
    tx: &rusqlite::Transaction<'_>,
    address: &TimelineAddress,
    row: MatchedTimelineBodyRow,
) -> rusqlite::Result<TimelineRead> {
    let first_retained_seq = first_retained_seq(tx)?;
    if first_retained_seq.is_some_and(|seq| address.seq() >= seq) {
        return Ok(timeline_corrupt(
            address,
            TimelineCorruption::MissingBodyForPresentRow,
        ));
    }

    let proof = VerifiedExpiredTimelineBody::new(
        address.clone(),
        row.content_type().to_owned(),
        row.size(),
        row.hmac().to_owned(),
    );
    Ok(TimelineRead::expired(proof))
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
            "auditedb-audit-timeline-address-{name}-{}-{nonce}",
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
        let (timestamp, target, size, content_type, meta_sha256, prev_hmac): (
            String,
            String,
            i64,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT timestamp, target, size, content_type, meta_sha256, prev_hmac FROM events WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        let world = ValidatedWorldPath::new(&target).unwrap();
        let timestamp = super::super::AuditTimestamp::from_storage(timestamp).unwrap();
        let hmac = super::super::event_hmac(
            key,
            super::super::EventHmacInput {
                prev: &prev_hmac,
                world: &world,
                timestamp: &timestamp,
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

    fn single_event_conn(
        world: &ValidatedWorldPath,
        event_type: &str,
        body_sha256: &str,
        key: &AuditHmacKey,
    ) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
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
            CREATE TABLE world_format(
                id INTEGER PRIMARY KEY CHECK(id=1),
                version INTEGER NOT NULL
                    CHECK(typeof(version)='integer')
                    CHECK(version=2)
            );
            INSERT INTO world_format(id, version) VALUES(1, 2);
            CREATE TABLE cas_bodies(
                body_sha256 TEXT NOT NULL PRIMARY KEY
                    CHECK(typeof(body_sha256)='text')
                    CHECK(length(body_sha256)=64)
                    CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
                body BLOB NOT NULL
                    CHECK(typeof(body)='blob')
            ) WITHOUT ROWID;
            CREATE TABLE cas_state(
                id INTEGER PRIMARY KEY CHECK(id=1),
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
        let generation = world_schema::generation(&conn).unwrap();
        let headers = if matches!(
            event_type,
            "delete_intent" | "delete_commit" | "delete_commit_failed"
        ) {
            vec![
                (
                    super::super::headers::DELETE_SUBJECT_WORLD.to_owned(),
                    world.as_str().to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_GENERATION.to_owned(),
                    "0123456789abcdef0123456789abcdef".to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_SEQ.to_owned(),
                    "1".to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_BODY_SHA256.to_owned(),
                    body_sha256.to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_HMAC.to_owned(),
                    format!("hmac-{}", "a".repeat(64)),
                ),
            ]
        } else {
            Vec::new()
        };
        let canonical = super::super::canonical_headers(&headers);
        let meta_sha256 =
            super::super::meta_sha256_canonical("application/octet-stream", &canonical);
        let timestamp =
            super::super::AuditTimestamp::from_storage("2026-01-02T03:04:05.678Z".to_owned())
                .unwrap();
        let hmac = super::super::event_hmac(
            key,
            super::super::EventHmacInput {
                prev: "",
                world,
                timestamp: &timestamp,
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
               VALUES(?1, ?2, ?3, ?4, 0, 'application/octet-stream', ?5, ?6, '')"#,
            rusqlite::params![
                timestamp.as_str(),
                event_type,
                world.as_str(),
                body_sha256,
                meta_sha256,
                hmac
            ],
        )
        .unwrap();
        for (name, value) in headers {
            conn.execute(
                "INSERT INTO event_headers(event_id, name, value) VALUES(1, ?1, ?2)",
                rusqlite::params![name, value],
            )
            .unwrap();
        }
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
            TimelineSeq::new(2).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap();

        match lookup {
            TimelineAddressLookup::Body(address) => {
                assert_eq!(address.world(), &world);
                assert_eq!(address.gen(), &gen);
                assert_eq!(address.seq().get(), 2);
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
    async fn read_timeline_body_returns_expired_after_retention_floor_advances() {
        let root = temp_root("historical-expired");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/history-expired").unwrap();

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
                    "application/octet-stream",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let address = {
            let conn = rusqlite::Connection::open(crate::world::world_db(
                &engine.core().data,
                world.as_str(),
            ))
            .unwrap();
            let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
            let TimelineAddressLookup::Body(address) = verified_timeline_address_via_conn(
                &mut tracked,
                &world,
                TimelineSeq::new(2).unwrap(),
                &engine.core().hmac_key,
            )
            .unwrap() else {
                panic!("expected first body timeline address");
            };
            address
        };

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        conn.execute(
            "DELETE FROM cas_bodies WHERE body_sha256=?1",
            [address.body_sha256().as_str()],
        )
        .unwrap();
        conn.execute("UPDATE cas_state SET first_retained_seq=3 WHERE id=1", [])
            .unwrap();
        drop(conn);

        let conn =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, world.as_str()))
                .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);
        let read =
            read_timeline_body_via_conn(&mut tracked, &address, &engine.core().hmac_key).unwrap();

        match read {
            TimelineRead::Expired(expired) => {
                assert_eq!(expired.address(), &address);
                assert_eq!(expired.content_type(), "text/plain");
                assert_eq!(expired.size(), 3);
                assert!(!expired.hmac().is_empty());
            }
            _ => panic!("expected expired historical body"),
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
            TimelineSeq::new(2).unwrap(),
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
                .await
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
        let empty_hash = BodySha256::for_body(b"");
        let conn = single_event_conn(&world, "delete_intent", empty_hash.as_str(), &key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let head = verified_latest_body_head_via_conn(&mut tracked, &world, &key).unwrap();

        assert!(head.is_none());
    }

    #[tokio::test]
    async fn replay_after_verifies_chain_before_generation_mismatch() {
        let root = temp_root("replay-gen-mismatch-broken-chain");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(key())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/replay-gen-mismatch-broken-chain").unwrap();
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
        let original_gen = world_schema::generation(&conn).unwrap();
        conn.execute(
            "UPDATE stage_meta SET generation='fedcba9876543210fedcba9876543210' WHERE id=1",
            [],
        )
        .unwrap();
        conn.execute("UPDATE events SET hmac='bad' WHERE id=2", [])
            .unwrap();
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        let result = verified_replay_events_after_via_conn(
            &mut tracked,
            &world,
            &original_gen,
            TimelineSeq::new(1).unwrap(),
            8,
            &engine.core().hmac_key,
        );

        assert!(matches!(
            result,
            Err(super::super::AuditError::ChainBroken(_))
        ));
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
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
            .query_row("SELECT hmac FROM events WHERE id=2", [], |r| r.get(0))
            .unwrap();
        {
            let tx = conn.transaction().unwrap();
            let audit_tx = super::super::verify_appendable_tx_existing_checked(
                &tx,
                &world,
                &engine.core().hmac_key,
            )
            .unwrap();
            let delete_headers = [
                (
                    super::super::headers::DELETE_SUBJECT_WORLD.to_owned(),
                    world.as_str().to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_GENERATION.to_owned(),
                    gen.as_str().to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_SEQ.to_owned(),
                    "2".to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_BODY_SHA256.to_owned(),
                    BodySha256::for_body(b"value").as_str().to_owned(),
                ),
                (
                    super::super::headers::DELETE_SUBJECT_HMAC.to_owned(),
                    format!("hmac-{first_hmac}"),
                ),
            ];
            super::super::append_tx_inner(
                &audit_tx,
                AuditEventKind::DeleteIntent,
                &world,
                &BodySha256::for_body(b"value"),
                0,
                "",
                &delete_headers,
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
        assert_eq!(head.address().seq().get(), 2);
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
    fn timeline_snapshot_reports_expired_before_retention_floor() {
        let key = key();
        let world = ValidatedWorldPath::new("home/expired").unwrap();
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
            TimelineRead::Expired(expired) => {
                assert_eq!(expired.address(), &address);
                assert_eq!(expired.content_type(), "application/octet-stream");
                assert_eq!(expired.size(), 0);
                assert!(!expired.hmac().is_empty());
            }
            _ => panic!("expected expired timeline read"),
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
            TimelineSeq::new(2).unwrap(),
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
                TimelineSeq::new(2).unwrap(),
                &engine.core().hmac_key,
            ),
            Err(super::super::AuditError::ChainBroken(_))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verified_timeline_address_rejects_unknown_event_type_before_minting() {
        let key = key();
        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let conn = single_event_conn(&ledger, "custom", "", &key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        match verified_timeline_address_via_conn(
            &mut tracked,
            &ledger,
            TimelineSeq::new(1).unwrap(),
            &key,
        ) {
            Err(super::super::AuditError::ChainBroken(report)) => {
                assert_eq!(report.expected, "known-event-type");
                assert_eq!(report.actual, "event-type-custom");
            }
            other => panic!("expected unknown event type to break verification, got {other:?}"),
        }
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
        resign_event(&conn, 2, "put", "not-a-valid-hash", &engine.core().hmac_key);
        let mut tracked = crate::read_cache::test_only_wrap_raw_connection(conn);

        match verified_timeline_address_via_conn(
            &mut tracked,
            &world,
            TimelineSeq::new(2).unwrap(),
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
            TimelineSeq::new(2).unwrap(),
            &engine.core().hmac_key,
        )
        .unwrap()
        {
            TimelineAddressLookup::NoBody(proof) => {
                assert_eq!(proof.world(), &ledger);
                assert_eq!(proof.gen(), &gen);
                assert_eq!(proof.seq().get(), 2);
                assert_eq!(proof.event_target(), subject.as_str());
            }
            _ => panic!("expected non-body proof"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
