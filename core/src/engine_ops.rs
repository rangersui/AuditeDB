//! Engine operation seam over protocol-neutral world transitions.
//!
//! Public `Engine` methods delegate here, keeping one path from facade to
//! read, write, delete, subscribe, and introspection transitions.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::collections::VecDeque;

use bytes::Bytes;

use crate::{
    audit::timeline_dereference::TimelineDereference,
    auth,
    delete_ops::{self, DeleteRequest, DeleteTraceHooks},
    engine::{Engine, EngineError},
    engine_error::{read_error_to_engine, write_error_to_engine},
    engine_subscription::{
        ChangeEvent, EngineSubscription, SubscribePattern, SubscriptionRecvError,
        SubscriptionResume,
    },
    engine_types::{
        AccessTier, Preconditions, ReadResult, Representation, ValidatedWorldPath, WriteKind,
        WriteResult,
    },
    etag, event,
    timeline::{TimelineAddress, TimelineCoordinate, TimelineRead},
    world_ops, world_read_ops, AuthGate, Core,
};

pub(crate) use crate::engine_error::{log_blocking_storage_error, log_storage_error};

pub(crate) struct EngineOps<'a> {
    core: &'a Core,
}

struct SubscribePermit {
    pattern: SubscribePattern,
    slot: tokio::sync::OwnedSemaphorePermit,
}

impl<'a> EngineOps<'a> {
    pub(crate) fn new(core: &'a Core) -> Self {
        Self { core }
    }

    pub(crate) fn core(&self) -> &'a Core {
        self.core
    }

    pub(crate) fn read(
        &self,
        world: &ValidatedWorldPath,
        tier: auth::Tier,
    ) -> Result<Option<ReadResult>, EngineError> {
        let permit = world_read_ops::authorize_read(self.core, world, tier)?;
        match world_read_ops::read_world(self.core, &permit)
            .map_err(|err| read_error_to_engine(err, Some(world.as_str())))?
        {
            world_read_ops::ReadOutcome::Found { stage, etag } => Ok(Some(ReadResult::new(
                Representation::new(Bytes::from(stage.body), stage.content_type, stage.headers),
                etag,
            ))),
            world_read_ops::ReadOutcome::Missing => Ok(None),
        }
    }

    pub(crate) fn read_timeline_body(
        &self,
        address: &TimelineAddress,
        tier: auth::Tier,
    ) -> Result<TimelineRead, EngineError> {
        let permit = world_read_ops::authorize_read(self.core, address.world(), tier)?;
        world_read_ops::read_timeline_body(self.core, &permit, address)
            .map_err(|err| read_error_to_engine(err, Some(address.world().as_str())))
    }

    pub(crate) fn dereference_timeline_coordinate(
        &self,
        coordinate: &TimelineCoordinate,
        tier: auth::Tier,
    ) -> Result<TimelineDereference, EngineError> {
        let permit = world_read_ops::authorize_read(self.core, coordinate.world(), tier)?;
        world_read_ops::dereference_timeline_coordinate(self.core, &permit, coordinate)
            .map_err(|err| read_error_to_engine(err, Some(coordinate.world().as_str())))
    }

    pub(crate) async fn replace<H: world_ops::WriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        let outcome = world_ops::replace_write(
            self.core,
            &permit,
            world_ops::ReplaceRequest {
                body: representation.body,
                content_type: representation.content_type,
                headers: representation.headers,
                preconditions: preconditions.into(),
            },
            hooks,
        )
        .await
        .map_err(|err| write_error_to_engine(err, Some(world.as_str())))?;
        Ok(outcome.into())
    }

    pub(crate) async fn append<H: world_ops::WriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        let outcome = world_ops::append_write(
            self.core,
            &permit,
            world_ops::AppendRequest {
                body,
                preconditions: preconditions.into(),
            },
            hooks,
        )
        .await
        .map_err(|err| write_error_to_engine(err, Some(world.as_str())))?;
        Ok(outcome.into())
    }

    pub(crate) async fn delete<H: DeleteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        req: DeleteRequest,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<(), delete_ops::DeleteError> {
        let permit = delete_ops::authorize_delete(world, tier)?;
        delete_ops::delete(self.core, &permit, req, hooks).await
    }

    pub(crate) fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
        resume: SubscriptionResume,
    ) -> Result<EngineSubscription, EngineError> {
        let permit = self.authorize_subscribe(pattern, tier)?;
        Ok(self.open_subscription(permit, resume))
    }

    fn authorize_subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
    ) -> Result<SubscribePermit, EngineError> {
        if !crate::can_read(self.core, tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        if *self.core.shutdown.borrow() {
            return Err(EngineError::ShuttingDown);
        }
        let slot = self
            .core
            .listen_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::SubscriptionLimit)?;
        Ok(SubscribePermit {
            pattern: pattern.clone(),
            slot,
        })
    }

    fn open_subscription(
        &self,
        permit: SubscribePermit,
        resume: SubscriptionResume,
    ) -> EngineSubscription {
        let rx = self.core.events.subscribe();
        let (interruption, replay, live_floor) = replay_after(self.core, resume, &permit.pattern);
        let replay_mode = resume.is_replay();
        let mut initial = VecDeque::new();
        if let Some(err) = interruption {
            initial.push_back(Err(err.into()));
        }
        initial.extend(replay.into_iter().map(Ok));
        EngineSubscription::new(
            permit.slot,
            initial,
            rx,
            permit.pattern,
            replay_mode,
            live_floor,
            self.core.shutdown.clone(),
        )
    }
}

impl Engine {
    /// Reads a world's full representation.
    ///
    /// This is a synchronous API. It may open or reuse a SQLite connection and
    /// read from storage on the caller thread. Async adapters that cannot block
    /// an executor worker should call it from their own blocking-worker
    /// boundary.
    ///
    /// # Returns
    /// - `Ok(Some(ReadResult))` if the world exists.
    /// - `Ok(None)` if the world does not exist (callers that want 404
    ///   semantics handle this).
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::TransientStorage`] for SQLite `BUSY`/`LOCKED`.
    /// - [`EngineError::InsufficientStorage`] for full-disk failures.
    /// - [`EngineError::Storage`] for other storage errors.
    pub fn read(
        &self,
        world: &ValidatedWorldPath,
        tier: AccessTier,
    ) -> Result<Option<ReadResult>, EngineError> {
        EngineOps::new(self.core()).read(world, tier.into())
    }

    /// Reads the body snapshot addressed by an audited timeline address.
    ///
    /// This is a synchronous API with the same blocking profile as
    /// [`Engine::read`]. It may reuse a cached SQLite connection and verify the
    /// audit chain on the caller thread. Async adapters that cannot block an
    /// executor worker should call it from their blocking-worker boundary.
    ///
    /// Unlike [`Engine::read`], this method does not return `Option`: a
    /// timeline address names a historical fact. Missing local storage becomes
    /// [`TimelineRead::Unproven`] until delete-ledger proof can bind the absence
    /// to the requested address. This method never falls back to the current
    /// live body.
    ///
    /// # Errors
    /// Returns [`EngineError::Auth`] for insufficient read tier, and the normal
    /// storage-classified [`EngineError`] variants for SQLite/audit failures.
    pub fn read_timeline_body(
        &self,
        address: &TimelineAddress,
        tier: AccessTier,
    ) -> Result<TimelineRead, EngineError> {
        EngineOps::new(self.core()).read_timeline_body(address, tier.into())
    }

    /// Dereferences untrusted timeline wire syntax into a historical outcome.
    ///
    /// The coordinate's world is read-authorized first; the core resolver then
    /// verifies the subject audit row before minting an internal
    /// [`TimelineAddress`](crate::TimelineAddress). Missing proof remains
    /// [`TimelineDereference::UnprovenCoordinate`]. This synchronous API has the
    /// same blocking profile as [`Engine::read`] and never falls back to the
    /// current live body.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::TransientStorage`] for SQLite `BUSY`/`LOCKED`.
    /// - [`EngineError::InsufficientStorage`] for full-disk failures.
    /// - [`EngineError::Storage`] for audit-chain corruption or other storage
    ///   failures.
    pub fn dereference_timeline_coordinate(
        &self,
        coordinate: &TimelineCoordinate,
        tier: AccessTier,
    ) -> Result<TimelineDereference, EngineError> {
        EngineOps::new(self.core()).dereference_timeline_coordinate(coordinate, tier.into())
    }

    /// Replaces a world with the provided representation.
    ///
    /// This is an async API. Awaiting it runs the complete ordered write
    /// transition: auth proof, per-world write lock, precondition check,
    /// storage update, audit-chain append for durable worlds, and subscriber
    /// notification.
    ///
    /// Creates the world if it does not exist; otherwise overwrites the
    /// body, content type, and headers. Durable worlds advance the audit chain;
    /// memory worlds update only their transient body, metadata, and SHA-256
    /// ETag.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below the namespace's write
    ///   requirement (`Write` for `home/`, `Approve` for system
    ///   namespaces).
    /// - [`EngineError::PayloadTooLarge`] if the body exceeds the per-world
    ///   cap.
    /// - [`EngineError::PreconditionFailed`] if `preconditions` reject the
    ///   write.
    /// - [`EngineError::QuotaExceeded`] for durable-storage quota failures.
    /// - [`EngineError::TransientStorage`] /
    ///   [`EngineError::InsufficientStorage`] / [`EngineError::Storage`]
    ///   for storage-layer failures.
    pub async fn replace(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .replace(
                world,
                representation,
                preconditions,
                tier.into(),
                &NoopWriteTrace,
            )
            .await
    }

    /// Appends bytes to a world's body.
    ///
    /// This is an async API with the same ordered write boundary as
    /// [`Engine::replace`]. It appends to the existing body instead of replacing
    /// the full representation.
    ///
    /// Append does **not** create a missing world. Use [`Engine::replace`] to
    /// create the initial representation, then append to it.
    ///
    /// Same auth requirements and error variants as [`Engine::replace`].
    /// The world's content type and metadata headers are unchanged. Durable
    /// worlds advance the audit chain; memory worlds update only their
    /// transient body and SHA-256 ETag.
    ///
    /// # Errors
    /// Same as [`Engine::replace`], plus [`EngineError::NotFound`] if the
    /// world does not already exist.
    pub async fn append(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .append(world, body, preconditions, tier.into(), &NoopWriteTrace)
            .await
    }

    /// Deletes a world with default, empty audit metadata.
    ///
    /// This is an async API. Deletion is a physical file deletion for durable
    /// worlds, so the transition writes delete intent, drains the read cache,
    /// removes the world, writes delete commit, and notifies subscribers in
    /// order.
    ///
    /// Deleting a missing world returns [`EngineError::NotFound`]. It does not
    /// create a tombstone world or append a delete ledger entry for a world the
    /// engine could not prove existed.
    ///
    /// Convenience wrapper around the delete transition that records empty
    /// content-type and headers in the audit intent. Adapters that need to
    /// preserve the deleted representation's metadata in the audit log
    /// should call [`Engine::delete_traced`] with a populated
    /// [`crate::DeleteMetadata`].
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Approve`.
    /// - [`EngineError::AppendOnly`] for append-only worlds (e.g.
    ///   `var/log/deletes`).
    /// - [`EngineError::PreconditionFailed`] / [`EngineError::NotFound`].
    /// - [`EngineError::TransientStorage`] /
    ///   [`EngineError::InsufficientStorage`] / [`EngineError::Storage`]
    ///   for storage-layer failures.
    pub async fn delete(
        &self,
        world: &ValidatedWorldPath,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<(), EngineError> {
        EngineOps::new(self.core())
            .delete(
                world,
                DeleteRequest {
                    preconditions,
                    content_type: String::new(),
                    headers: Vec::new(),
                },
                tier.into(),
                &NoopDeleteTrace,
            )
            .await
            .map_err(Into::into)
    }

    /// Subscribes to change events matching `pattern`.
    ///
    /// Opening a subscription is synchronous: this method validates auth,
    /// reserves a subscription slot, and prepares replay state. Receiving
    /// events is async through [`EngineSubscription::recv`].
    ///
    /// If `resume` is [`SubscriptionResume::after_event_id`], the subscription
    /// replays every event after that id from the in-memory ring before
    /// switching to the live stream. Replay is bounded by the configured
    /// `listen_replay_max`; if the cursor is older than the ring's floor, the
    /// first `recv` call yields a [`crate::SubscriptionRecvError::Lagged`]
    /// error.
    ///
    /// The returned [`EngineSubscription`] holds a subscription slot until
    /// dropped; drop it promptly when finished so other subscribers can
    /// join.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::SubscriptionLimit`] if the slot pool is full.
    /// - [`EngineError::ShuttingDown`] if [`Engine::shutdown`] has been
    ///   called.
    pub fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: AccessTier,
        resume: SubscriptionResume,
    ) -> Result<EngineSubscription, EngineError> {
        EngineOps::new(self.core()).subscribe(pattern, tier.into(), resume)
    }
}

struct NoopWriteTrace;

impl world_ops::WriteTraceHooks for NoopWriteTrace {}

struct NoopDeleteTrace;

impl DeleteTraceHooks for NoopDeleteTrace {}

/// Non-terminal condition surfaced before replay switches to live delivery.
///
/// This is deliberately narrower than [`SubscriptionRecvError`]: replay setup
/// can report loss or a stale cursor, but it cannot honestly report `Closed`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayInterruption {
    /// The ring evicted `skipped` events between the cursor and the oldest
    /// retained event.
    Lagged { skipped: u64 },
    /// The cursor is from an id space ahead of this process's current counter.
    CursorAhead { since: u64, newest: u64 },
}

impl From<ReplayInterruption> for SubscriptionRecvError {
    fn from(value: ReplayInterruption) -> Self {
        match value {
            ReplayInterruption::Lagged { skipped } => Self::Lagged { skipped },
            ReplayInterruption::CursorAhead { since, newest } => {
                Self::CursorAhead { since, newest }
            }
        }
    }
}

pub(crate) fn replay_after(
    core: &Core,
    resume: SubscriptionResume,
    pattern: &SubscribePattern,
) -> (Option<ReplayInterruption>, Vec<ChangeEvent>, u64) {
    let Some(last_id) = resume.after_event_id_raw() else {
        return (None, Vec::new(), 0);
    };
    let log = core
        .event_log
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let newest = crate::state::last_issued_event_id(&core.next_event);
    if last_id > newest {
        return (
            Some(ReplayInterruption::CursorAhead {
                since: last_id,
                newest,
            }),
            Vec::new(),
            0,
        );
    }
    let gap = log.front().and_then(|oldest| {
        let expected_next = last_id.saturating_add(1);
        if expected_next < oldest.id {
            Some(oldest.id - expected_next)
        } else {
            None
        }
    });
    let replay: Vec<ChangeEvent> = log
        .iter()
        .filter(|change| change.id > last_id && event::matches(pattern.as_str(), &change.path))
        .cloned()
        .map(Into::into)
        .collect();
    let live_floor = replay.last().map(|change| change.id).unwrap_or(last_id);
    (
        gap.map(|skipped| ReplayInterruption::Lagged { skipped }),
        replay,
        live_floor,
    )
}

impl From<Preconditions> for etag::Preconditions {
    fn from(value: Preconditions) -> Self {
        etag::Preconditions::new(
            value.if_match.into_iter().map(Into::into).collect(),
            value.if_none_match.into_iter().map(Into::into).collect(),
        )
    }
}

impl From<etag::Preconditions> for Preconditions {
    fn from(value: etag::Preconditions) -> Self {
        let (if_match, if_none_match) = value.into_parts();
        Self::new(
            if_match.into_iter().map(Into::into).collect(),
            if_none_match.into_iter().map(Into::into).collect(),
        )
    }
}

impl From<world_ops::WriteOutcome> for WriteResult {
    fn from(value: world_ops::WriteOutcome) -> Self {
        Self::new(
            match value.status_kind {
                world_ops::WriteStatusKind::Created => WriteKind::Created,
                world_ops::WriteStatusKind::Updated => WriteKind::Updated,
            },
            value.etag,
        )
    }
}

impl From<AccessTier> for auth::Tier {
    fn from(value: AccessTier) -> Self {
        match value {
            AccessTier::Anon => Self::Anon,
            AccessTier::Read => Self::Read,
            AccessTier::Write => Self::Write,
            AccessTier::Approve => Self::Approve,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::{
        engine_types::{AuditHmacKey, ChangeVerb},
        timeline::{BodySha256, TimelineAddress, TimelineRead, TimelineSeq},
        world, world_schema,
    };

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-engine-ops-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn test_engine(name: &str) -> (Engine, PathBuf) {
        let root = temp_root(name);
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .max_listen_connections(1)
            .build()
            .unwrap();
        (engine, root)
    }

    fn timeline_address_for_body(
        engine: &Engine,
        world_path: &ValidatedWorldPath,
        seq: i64,
        body: &[u8],
    ) -> TimelineAddress {
        let conn =
            rusqlite::Connection::open(world::world_db(&engine.core().data, world_path.as_str()))
                .unwrap();
        let gen = world_schema::generation(&conn).unwrap();
        TimelineAddress::test_only_new(
            world_path.clone(),
            gen,
            TimelineSeq::new(seq).unwrap(),
            BodySha256::for_body(body),
        )
    }

    #[test]
    fn replay_after_reports_ring_gap_and_replays_available_events() {
        let (engine, root) = test_engine("replay-gap");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            for id in 10..=12 {
                log.push_back(event::ChangeEvent {
                    id,
                    verb: ChangeVerb::Replace,
                    path: format!("/home/task/{id}"),
                    etag: format!("hmac-{id}"),
                    timeline_address: None,
                });
            }
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, 12);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core(),
            SubscriptionResume::after_event_id(5),
            &pattern,
        );

        assert_eq!(
            interruption,
            Some(ReplayInterruption::Lagged { skipped: 4 })
        );
        assert_eq!(replay.len(), 3);
        assert_eq!(replay[0].id, 10);
        assert_eq!(replay[0].path.as_str(), "home/task/10");
        assert_eq!(floor, 12);

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replay_after_handles_max_last_event_id_without_overflow() {
        let (engine, root) = test_engine("replay-max-last-id");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            log.push_back(event::ChangeEvent {
                id: u64::MAX,
                verb: ChangeVerb::Replace,
                path: "/home/task/max".to_string(),
                etag: "hmac-max".to_string(),
                timeline_address: None,
            });
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, u64::MAX);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core(),
            SubscriptionResume::after_event_id(u64::MAX),
            &pattern,
        );

        assert_eq!(interruption, None);
        assert!(replay.is_empty());
        assert_eq!(floor, u64::MAX);

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replay_after_flags_cursor_ahead_of_current_process() {
        let (engine, root) = test_engine("replay-ahead");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            log.push_back(event::ChangeEvent {
                id: 1,
                verb: ChangeVerb::Replace,
                path: "/home/task/a".to_string(),
                etag: "hmac-1".to_string(),
                timeline_address: None,
            });
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, 1);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core(),
            SubscriptionResume::after_event_id(42),
            &pattern,
        );

        assert_eq!(
            interruption,
            Some(ReplayInterruption::CursorAhead {
                since: 42,
                newest: 1
            })
        );
        assert!(replay.is_empty());
        assert_eq!(floor, 0, "foreign cursor must not become live floor");

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_delete_requires_approve_and_removes_world() {
        let (engine, root) = test_engine("delete");
        let world = ValidatedWorldPath::new("home/delete-me").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"alive"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert!(matches!(
            engine
                .delete(&world, Preconditions::none(), AccessTier::Write)
                .await,
            Err(EngineError::Auth(AuthGate::Delete))
        ));

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_none());

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_delete_ledger_subject_generation_survives_recreate() {
        let (engine, root) = test_engine("delete-recreate");
        let world = ValidatedWorldPath::new("home/delete-recreate").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let first_conn = rusqlite::Connection::open(crate::world::world_db(
            engine.core().data.as_path(),
            world.as_str(),
        ))
        .unwrap();
        let first_generation = crate::world_schema::generation(&first_conn).unwrap();
        drop(first_conn);

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let second_conn = rusqlite::Connection::open(crate::world::world_db(
            engine.core().data.as_path(),
            world.as_str(),
        ))
        .unwrap();
        let second_generation = crate::world_schema::generation(&second_conn).unwrap();
        drop(second_conn);
        assert_ne!(first_generation, second_generation);

        let ledger =
            rusqlite::Connection::open(crate::world::world_db(&root, "var/log/deletes")).unwrap();
        let stored_generation: String = ledger
            .query_row(
                "SELECT value FROM event_headers
                 WHERE event_id=1 AND name=?1",
                [crate::audit::DELETE_SUBJECT_GENERATION],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored_generation, first_generation.as_str());
        assert_ne!(stored_generation, second_generation.as_str());

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_read_timeline_body_returns_historical_body() {
        let (engine, root) = test_engine("timeline-public-read");
        let world = ValidatedWorldPath::new("home/timeline-public-read").unwrap();

        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"old"),
                    "text/plain",
                    vec![("x-meta-version".to_owned(), "one".to_owned())],
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let address = timeline_address_for_body(&engine, &world, 1, b"old");

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"new"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        match engine
            .read_timeline_body(&address, AccessTier::Read)
            .expect("timeline read succeeds")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.address(), &address);
                assert_eq!(body.representation().body, Bytes::from_static(b"old"));
                assert_eq!(body.representation().content_type, "text/plain");
                assert_eq!(
                    body.representation().headers.as_slice(),
                    [("x-meta-version".to_owned(), "one".to_owned())]
                );
            }
            _ => panic!("expected historical body"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn engine_read_timeline_body_requires_read_tier() {
        let root = temp_root("timeline-public-auth");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-auth").unwrap();
        let address = TimelineAddress::test_only_new(
            world,
            crate::world_generation::WorldGeneration::new("0123456789abcdef0123456789abcdef")
                .unwrap(),
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"value"),
        );

        assert!(matches!(
            engine.read_timeline_body(&address, AccessTier::Anon),
            Err(EngineError::Auth(AuthGate::Read))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_read_timeline_body_maps_missing_world_to_unproven() {
        let (engine, root) = test_engine("timeline-public-unproven");
        let world = ValidatedWorldPath::new("home/timeline-unproven").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"old"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let address = timeline_address_for_body(&engine, &world, 1, b"old");

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        match engine
            .read_timeline_body(&address, AccessTier::Read)
            .expect("missing durable world is a typed read outcome")
        {
            TimelineRead::Unproven { address: got } => assert_eq!(got, address),
            _ => panic!("expected unproven"),
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscribe_requires_read_tier_and_replays_since_id() {
        let root = temp_root("subscribe");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .build()
            .unwrap();
        let pattern = SubscribePattern::new("home/events/*");

        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none()),
            Err(EngineError::Auth(AuthGate::Read))
        ));

        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"event"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Read,
                SubscriptionResume::after_event_id(0),
            )
            .expect("read tier subscribes");
        let event = subscription.recv().await.expect("replay event");
        assert_eq!(event.verb, ChangeVerb::Replace);
        assert_eq!(event.path.as_str(), "home/events/a");
        let address = event
            .timeline_address
            .as_ref()
            .expect("durable body write event carries timeline address");
        match engine
            .read_timeline_body(address, AccessTier::Read)
            .expect("event address resolves")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"event"));
            }
            _ => panic!("expected event address body"),
        }

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_timeline_address_survives_later_overwrite() {
        let (engine, root) = test_engine("subscribe-address-overwrite");
        let pattern = SubscribePattern::new("home/events/*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .expect("subscription opens");
        let world = ValidatedWorldPath::new("home/events/race").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"B"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let event_b = subscription.recv().await.expect("event B");
        let address_b = event_b
            .timeline_address
            .clone()
            .expect("durable event B carries timeline address");

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"C"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let current = engine
            .read(&world, AccessTier::Anon)
            .unwrap()
            .expect("current body exists");
        assert_eq!(current.representation.body, Bytes::from_static(b"C"));
        match engine
            .read_timeline_body(&address_b, AccessTier::Anon)
            .expect("event B address resolves after overwrite")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"B"));
            }
            _ => panic!("expected event B body"),
        }

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_memory_events_do_not_carry_timeline_address() {
        let (engine, root) = test_engine("subscribe-memory-no-address");
        let pattern = SubscribePattern::new("tmp/events/*");
        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(0),
            )
            .expect("subscription opens");
        let world = ValidatedWorldPath::new("tmp/events/a").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"memory"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let event = subscription.recv().await.expect("memory event");
        assert_eq!(event.verb, ChangeVerb::Replace);
        assert_eq!(event.path.as_str(), "tmp/events/a");
        assert!(event.timeline_address.is_none());

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_delete_events_do_not_carry_timeline_address() {
        let (engine, root) = test_engine("subscribe-delete-no-address");
        let world = ValidatedWorldPath::new("home/events/delete").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let pattern = SubscribePattern::new("home/events/*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .expect("subscription opens");
        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        let event = subscription.recv().await.expect("delete event");
        assert_eq!(event.verb, ChangeVerb::Delete);
        assert_eq!(event.path.as_str(), "home/events/delete");
        assert!(event.timeline_address.is_none());

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_append_events_carry_timeline_address() {
        let (engine, root) = test_engine("subscribe-append-address");
        let world = ValidatedWorldPath::new("home/events/append").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"base"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let pattern = SubscribePattern::new("home/events/*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .expect("subscription opens");
        engine
            .append(
                &world,
                Bytes::from_static(b"-tail"),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let event = subscription.recv().await.expect("append event");
        assert_eq!(event.verb, ChangeVerb::Append);
        assert_eq!(event.path.as_str(), "home/events/append");
        let address = event
            .timeline_address
            .as_ref()
            .expect("durable append event carries timeline address");
        match engine
            .read_timeline_body(address, AccessTier::Anon)
            .expect("append event address resolves")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"base-tail"));
            }
            _ => panic!("expected append event address body"),
        }

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_with_stale_cursor_signals_then_streams_live() {
        let recv_budget = Duration::from_secs(10);
        let (engine, root) = test_engine("subscribe-stale-cursor");
        let pattern = SubscribePattern::new("home/stale/*");
        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(42),
            )
            .expect("subscription opens with stale cursor");

        let first = tokio::time::timeout(recv_budget, subscription.recv())
            .await
            .expect("first recv must not block");
        assert!(matches!(
            first,
            Err(SubscriptionRecvError::CursorAhead {
                since: 42,
                newest: 0
            })
        ));

        let world = ValidatedWorldPath::new("home/stale/a").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"alive"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let change = tokio::time::timeout(recv_budget, subscription.recv())
            .await
            .expect("live recv must not block after cursor warning")
            .expect("live event must flow after cursor warning");
        assert_eq!(change.path.as_str(), "home/stale/a");

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn engine_subscribe_enforces_slot_cap_at_entry() {
        let (engine, root) = test_engine("subscribe-cap");
        let pattern = SubscribePattern::new("*");
        let first = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .expect("first subscription consumes the sole slot");
        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none()),
            Err(EngineError::SubscriptionLimit)
        ));

        drop(first);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn engine_subscribe_denied_auth_does_not_consume_slot() {
        let root = temp_root("subscribe-auth-slot");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .max_listen_connections(1)
            .build()
            .unwrap();
        let pattern = SubscribePattern::new("*");

        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none()),
            Err(EngineError::Auth(AuthGate::Read))
        ));
        let subscription = engine
            .subscribe(&pattern, AccessTier::Read, SubscriptionResume::none())
            .expect("failed auth must not consume the only slot");

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_closed_is_terminal() {
        let (engine, root) = test_engine("subscribe-closed");
        let pattern = SubscribePattern::new("*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .expect("subscription opens before shutdown");

        engine.shutdown();
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_drains_replay_before_shutdown() {
        let (engine, root) = test_engine("subscribe-replay-before-shutdown");
        let pattern = SubscribePattern::new("home/replay/*");
        for name in ["home/replay/a", "home/replay/b"] {
            let world = ValidatedWorldPath::new(name).unwrap();
            engine
                .replace(
                    &world,
                    Representation::new(Bytes::from_static(b"event"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(0),
            )
            .expect("subscription opens before shutdown");
        engine.shutdown();
        assert_eq!(
            subscription.recv().await.unwrap().path.as_str(),
            "home/replay/a"
        );
        assert_eq!(
            subscription.recv().await.unwrap().path.as_str(),
            "home/replay/b"
        );
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
