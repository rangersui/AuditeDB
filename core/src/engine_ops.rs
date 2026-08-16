//! Engine operation seam over protocol-neutral world transitions.
//!
//! Public `Engine` methods delegate here, keeping one path from facade to
//! read, write, delete, subscribe, and introspection transitions.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{collections::VecDeque, sync::Arc};

use bytes::Bytes;

use crate::{
    audit::timeline_dereference::TimelineDereference,
    auth, blocking_sqlite,
    delete_ops::{self, DeleteRequest, DeleteTraceHooks},
    engine::{Engine, EngineError},
    engine_error::{read_error_to_engine, write_error_to_engine},
    engine_subscription::{
        ChangeEvent, EngineSubscription, ReplayFence, SubscriptionRecvError,
        SubscriptionResetReason,
    },
    engine_types::{
        AccessTier, Preconditions, ReadResult, Representation, ValidatedWorldPath, WriteKind,
        WriteResult,
    },
    etag,
    event::{self, ChangeDeliveryId},
    subscription_cursor::{ReplayPlan, SubscribePattern, SubscriptionResume},
    subscription_event_id::{ChangeEventIdentity, ChangeTarget, SubscriptionEventId},
    timeline::{TimelineAddress, TimelineCoordinate, TimelineRead},
    world_ops, world_read_ops, AuthGate, Core,
};

use crate::engine_error::blocking_join_to_engine;
pub(crate) use crate::engine_error::{log_blocking_storage_error, log_storage_error};

pub(crate) struct EngineOps {
    core: Arc<Core>,
}

struct SubscribePermit {
    pattern: SubscribePattern,
    slot: tokio::sync::OwnedSemaphorePermit,
}

impl EngineOps {
    pub(crate) fn new(core: Arc<Core>) -> Self {
        Self { core }
    }

    pub(crate) fn core(&self) -> &Core {
        self.core.as_ref()
    }

    fn ensure_not_shutdown(&self) -> Result<(), EngineError> {
        if *self.core.shutdown.borrow() {
            Err(EngineError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    fn begin_file_op(&self) -> Result<crate::state::FileOpPermit, EngineError> {
        self.core.begin_file_op().ok_or(EngineError::ShuttingDown)
    }

    fn ensure_not_shutdown_for_delete(&self) -> Result<(), delete_ops::DeleteError> {
        if *self.core.shutdown.borrow() {
            Err(delete_ops::DeleteError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    pub(crate) fn read(
        &self,
        proof: &mut blocking_sqlite::BlockingSqlite,
        world: &ValidatedWorldPath,
        tier: auth::Tier,
    ) -> Result<Option<ReadResult>, EngineError> {
        let permit = world_read_ops::authorize_read(self.core.as_ref(), world, tier)?;
        let _file_op = self.begin_file_op()?;
        match world_read_ops::read_world(self.core.as_ref(), proof, &permit, &_file_op)
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
        proof: &mut blocking_sqlite::BlockingSqlite,
        address: &TimelineAddress,
        tier: auth::Tier,
    ) -> Result<TimelineRead, EngineError> {
        let permit = world_read_ops::authorize_read(self.core.as_ref(), address.world(), tier)?;
        let _file_op = self.begin_file_op()?;
        world_read_ops::read_timeline_body(self.core.as_ref(), proof, &permit, address, &_file_op)
            .map_err(|err| read_error_to_engine(err, Some(address.world().as_str())))
    }

    pub(crate) fn dereference_timeline_coordinate(
        &self,
        proof: &mut blocking_sqlite::BlockingSqlite,
        coordinate: &TimelineCoordinate,
        tier: auth::Tier,
    ) -> Result<TimelineDereference, EngineError> {
        let permit = world_read_ops::authorize_read(self.core.as_ref(), coordinate.world(), tier)?;
        let _file_op = self.begin_file_op()?;
        world_read_ops::dereference_timeline_coordinate(
            self.core.as_ref(),
            proof,
            &permit,
            coordinate,
            &_file_op,
        )
        .map_err(|err| read_error_to_engine(err, Some(coordinate.world().as_str())))
    }

    pub(crate) async fn replace(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: Arc<dyn world_ops::WriteTraceHooks>,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        self.ensure_not_shutdown()?;
        let req = world_ops::ReplaceRequest::new(
            representation.body,
            representation.content_type,
            representation.headers,
            preconditions.into(),
        )
        .map_err(|message| EngineError::InvalidMetadata { message })?;
        let outcome = world_ops::replace_write(Arc::clone(&self.core), permit, req, hooks)
            .await
            .map_err(|err| write_error_to_engine(err, Some(world.as_str())))?;
        Ok(outcome.into())
    }

    pub(crate) async fn append(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: Arc<dyn world_ops::WriteTraceHooks>,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        self.ensure_not_shutdown()?;
        let outcome = world_ops::append_write(
            Arc::clone(&self.core),
            permit,
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

    pub(crate) async fn delete(
        &self,
        world: &ValidatedWorldPath,
        req: DeleteRequest,
        tier: auth::Tier,
        hooks: Arc<dyn DeleteTraceHooks>,
    ) -> Result<(), delete_ops::DeleteError> {
        let permit = delete_ops::authorize_delete(world, tier)?;
        self.ensure_not_shutdown_for_delete()?;
        delete_ops::delete(Arc::clone(&self.core), permit, req, hooks).await
    }

    pub(crate) async fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
        resume: SubscriptionResume,
    ) -> Result<EngineSubscription, EngineError> {
        let permit = self.authorize_subscribe(pattern, tier)?;
        self.open_subscription(permit, resume).await
    }

    fn authorize_subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
    ) -> Result<SubscribePermit, EngineError> {
        if !crate::can_read(self.core.as_ref(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        self.ensure_not_shutdown()?;
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

    async fn open_subscription(
        &self,
        permit: SubscribePermit,
        resume: SubscriptionResume,
    ) -> Result<EngineSubscription, EngineError> {
        let rx = self.core.events.subscribe();
        let replay_plan = resume.replay_plan(&self.core.listen_epoch);
        let _file_op = self.begin_file_op()?;
        let (interruption, replay, replay_fence) =
            replay_after(Arc::clone(&self.core), replay_plan, &permit.pattern).await?;
        let mut initial = VecDeque::new();
        if let Some(err) = interruption {
            initial.push_back(Err(err.into()));
        }
        initial.extend(replay.into_iter().map(Ok));
        Ok(EngineSubscription::new(
            permit.slot,
            initial,
            rx,
            permit.pattern,
            replay_fence,
            self.core.shutdown.clone(),
        ))
    }
}

impl Engine {
    /// Reads a world's full representation.
    ///
    /// This is an async API. Awaiting it runs SQLite-backed storage work on
    /// the Engine's blocking-worker boundary rather than on the caller's async
    /// executor worker.
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
    pub async fn read(
        &self,
        world: &ValidatedWorldPath,
        tier: AccessTier,
    ) -> Result<Option<ReadResult>, EngineError> {
        let engine = self.clone();
        let world = world.clone();
        blocking_sqlite::run(move |proof| {
            EngineOps::new(engine.core_arc()).read(proof, &world, tier.into())
        })
        .await
        .map_err(blocking_join_to_engine)?
    }

    /// Reads the body snapshot addressed by an audited timeline address.
    ///
    /// This is an async API with the same blocking-worker profile as
    /// [`Engine::read`]. It may reuse a cached SQLite connection and verify the
    /// audit chain inside the Engine's blocking-worker boundary.
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
    pub async fn read_timeline_body(
        &self,
        address: &TimelineAddress,
        tier: AccessTier,
    ) -> Result<TimelineRead, EngineError> {
        let engine = self.clone();
        let address = address.clone();
        blocking_sqlite::run(move |proof| {
            EngineOps::new(engine.core_arc()).read_timeline_body(proof, &address, tier.into())
        })
        .await
        .map_err(blocking_join_to_engine)?
    }

    /// Dereferences untrusted timeline wire syntax into a historical outcome.
    ///
    /// The coordinate's world is read-authorized first; the core resolver then
    /// verifies the subject audit row before minting an internal
    /// [`TimelineAddress`](crate::TimelineAddress). Missing proof remains
    /// [`TimelineDereference::UnprovenCoordinate`]. This async API has the
    /// same blocking-worker profile as [`Engine::read`] and never falls back to
    /// the current live body.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::TransientStorage`] for SQLite `BUSY`/`LOCKED`.
    /// - [`EngineError::InsufficientStorage`] for full-disk failures.
    /// - [`EngineError::Storage`] for audit-chain corruption or other storage
    ///   failures.
    pub async fn dereference_timeline_coordinate(
        &self,
        coordinate: &TimelineCoordinate,
        tier: AccessTier,
    ) -> Result<TimelineDereference, EngineError> {
        let engine = self.clone();
        let coordinate = coordinate.clone();
        blocking_sqlite::run(move |proof| {
            EngineOps::new(engine.core_arc()).dereference_timeline_coordinate(
                proof,
                &coordinate,
                tier.into(),
            )
        })
        .await
        .map_err(blocking_join_to_engine)?
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
    /// - [`EngineError::QuotaExceeded`] for durable-storage or accounted
    ///   memory quota failures.
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
        EngineOps::new(self.core_arc())
            .replace(
                world,
                representation,
                preconditions,
                tier.into(),
                Arc::new(NoopWriteTrace),
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
        EngineOps::new(self.core_arc())
            .append(
                world,
                body,
                preconditions,
                tier.into(),
                Arc::new(NoopWriteTrace),
            )
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
        EngineOps::new(self.core_arc())
            .delete(
                world,
                DeleteRequest::new(preconditions, String::new(), Vec::new()),
                tier.into(),
                Arc::new(NoopDeleteTrace),
            )
            .await
            .map_err(Into::into)
    }

    /// Subscribes to change events matching `pattern`.
    ///
    /// Opening a subscription is async: this method validates auth, reserves a
    /// subscription slot, and may prepare durable replay through the blocking
    /// SQLite gate. Receiving events is async through
    /// [`EngineSubscription::recv`].
    ///
    /// If `resume` carries a durable [`crate::subscription_event_id::SubscriptionEventId`] and
    /// `pattern` is one exact world, the subscription verifies that world's
    /// SQLite audit chain and replays id-bearing chain events after the id
    /// before switching to live delivery. Body writes carry timeline
    /// addresses; non-body ledger rows such as `var/log/deletes` carry durable
    /// ids without body addresses. Wildcard subscriptions still replay only
    /// from the in-memory ring because one SSE id cannot represent progress
    /// for multiple worlds.
    ///
    /// Replay is bounded by the configured `listen_replay_max`; if the marker
    /// cannot be proven or the bounded replay would overflow, the first
    /// `recv` call yields [`crate::SubscriptionRecvError::Reset`].
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
    pub async fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: AccessTier,
        resume: SubscriptionResume,
    ) -> Result<EngineSubscription, EngineError> {
        EngineOps::new(self.core_arc())
            .subscribe(pattern, tier.into(), resume)
            .await
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
    #[cfg(test)]
    Lagged { skipped: u64 },
    /// The supplied durable cursor cannot be spliced into this subscription.
    Reset { reason: SubscriptionResetReason },
    /// The cursor is from an id space ahead of this process's current counter.
    #[cfg(test)]
    CursorAhead { since: u64, newest: u64 },
}

impl From<ReplayInterruption> for SubscriptionRecvError {
    fn from(value: ReplayInterruption) -> Self {
        match value {
            #[cfg(test)]
            ReplayInterruption::Lagged { skipped } => Self::Lagged { skipped },
            ReplayInterruption::Reset { reason } => Self::Reset { reason },
            #[cfg(test)]
            ReplayInterruption::CursorAhead { since, newest } => {
                Self::CursorAhead { since, newest }
            }
        }
    }
}

pub(crate) async fn replay_after(
    core: Arc<Core>,
    replay_plan: ReplayPlan,
    pattern: &SubscribePattern,
) -> Result<(Option<ReplayInterruption>, Vec<ChangeEvent>, ReplayFence), EngineError> {
    match replay_plan {
        ReplayPlan::None => Ok((None, Vec::new(), ReplayFence::None)),
        ReplayPlan::Durable { event_id } => {
            replay_after_durable_event_id(core, event_id, pattern).await
        }
        #[cfg(test)]
        ReplayPlan::Foreign { event_id } => {
            let newest = crate::state::last_issued_event_id(&core.next_event);
            Ok((
                Some(ReplayInterruption::CursorAhead {
                    since: event_id,
                    newest: newest.get(),
                }),
                Vec::new(),
                ReplayFence::None,
            ))
        }
        #[cfg(test)]
        ReplayPlan::Current { event_id } => {
            replay_after_process_event_id(core.as_ref(), event_id, pattern)
        }
    }
}

#[cfg(test)]
fn replay_after_process_event_id(
    core: &Core,
    last_id: ChangeDeliveryId,
    pattern: &SubscribePattern,
) -> Result<(Option<ReplayInterruption>, Vec<ChangeEvent>, ReplayFence), EngineError> {
    let log = core
        .event_log
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let newest = crate::state::last_issued_event_id(&core.next_event);
    if last_id > newest {
        return Ok((
            Some(ReplayInterruption::CursorAhead {
                since: last_id.get(),
                newest: newest.get(),
            }),
            Vec::new(),
            ReplayFence::None,
        ));
    }
    let gap = log.front().and_then(|oldest| {
        let expected_next = last_id.saturating_add(1);
        if expected_next < oldest.id() {
            Some(oldest.id().saturating_sub(expected_next))
        } else {
            None
        }
    });
    let replay_events: Vec<event::ChangeEvent> = log
        .iter()
        .filter(|change| change.id() > last_id && event::matches_world(pattern, change.path()))
        .cloned()
        .collect();
    let live_floor = replay_events
        .last()
        .map(event::ChangeEvent::id)
        .unwrap_or(last_id);
    let replay = replay_events.into_iter().map(Into::into).collect();
    Ok((
        gap.map(|skipped| ReplayInterruption::Lagged { skipped }),
        replay,
        ReplayFence::ProcessLocal { floor: live_floor },
    ))
}

async fn replay_after_durable_event_id(
    core: Arc<Core>,
    event_id: SubscriptionEventId,
    pattern: &SubscribePattern,
) -> Result<(Option<ReplayInterruption>, Vec<ChangeEvent>, ReplayFence), EngineError> {
    if let Some(exact_world) = pattern
        .exact_world()
        .map_err(|_| EngineError::InvalidWorldName)?
    {
        if &exact_world != event_id.world() {
            return Ok((
                Some(ReplayInterruption::Reset {
                    reason: SubscriptionResetReason::RingMiss,
                }),
                Vec::new(),
                ReplayFence::None,
            ));
        }
        return replay_after_durable_chain_event_id(core, event_id).await;
    }

    replay_after_durable_ring_event_id(core.as_ref(), event_id, pattern)
}

fn replay_after_durable_ring_event_id(
    core: &Core,
    event_id: SubscriptionEventId,
    pattern: &SubscribePattern,
) -> Result<(Option<ReplayInterruption>, Vec<ChangeEvent>, ReplayFence), EngineError> {
    let log = core
        .event_log
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Some(marker_index) = log.iter().position(
        |change| matches!(change.identity(), ChangeEventIdentity::Chain(id) if id == event_id),
    ) else {
        return Ok((
            Some(ReplayInterruption::Reset {
                reason: SubscriptionResetReason::RingMiss,
            }),
            Vec::new(),
            ReplayFence::None,
        ));
    };
    let marker_floor = log
        .get(marker_index)
        .map(crate::event::ChangeEvent::id)
        .unwrap_or(ChangeDeliveryId::MIN);
    let replay_events: Vec<event::ChangeEvent> = log
        .iter()
        .skip(marker_index.saturating_add(1))
        .filter(|change| event::matches_world(pattern, change.path()))
        .cloned()
        .collect();
    let live_floor = replay_events
        .last()
        .map(event::ChangeEvent::id)
        .unwrap_or(marker_floor);
    let replay = replay_events.into_iter().map(Into::into).collect();
    Ok((
        None,
        replay,
        ReplayFence::ProcessLocal { floor: live_floor },
    ))
}

async fn replay_after_durable_chain_event_id(
    core: Arc<Core>,
    event_id: SubscriptionEventId,
) -> Result<(Option<ReplayInterruption>, Vec<ChangeEvent>, ReplayFence), EngineError> {
    let Some(file_op) = core.begin_file_op() else {
        return Err(EngineError::ShuttingDown);
    };
    let error_world = event_id.world().clone();
    let event_id_for_replay = event_id.clone();
    let listen_replay_max = core.listen_replay_max;
    let listen_epoch = core.listen_epoch.clone();
    let replay = match blocking_sqlite::run(move |proof| {
        core.replay_chain_events_after(proof, &event_id_for_replay, listen_replay_max, &file_op)
    })
    .await
    .map_err(blocking_join_to_engine)?
    {
        Ok(Some(crate::audit::VerifiedReplayAfter::Events(events))) => events,
        Ok(Some(crate::audit::VerifiedReplayAfter::GenerationMismatch)) => {
            return Ok((
                Some(ReplayInterruption::Reset {
                    reason: SubscriptionResetReason::Incarnation,
                }),
                Vec::new(),
                ReplayFence::None,
            ));
        }
        Ok(Some(crate::audit::VerifiedReplayAfter::MissingMarker)) => {
            return Ok((
                Some(ReplayInterruption::Reset {
                    reason: SubscriptionResetReason::Truncation,
                }),
                Vec::new(),
                ReplayFence::None,
            ));
        }
        Ok(Some(crate::audit::VerifiedReplayAfter::ReplayLimitExceeded)) | Ok(None) => {
            return Ok((
                Some(ReplayInterruption::Reset {
                    reason: SubscriptionResetReason::RingMiss,
                }),
                Vec::new(),
                ReplayFence::None,
            ));
        }
        Err(err) => return Err(audit_replay_error_to_engine(err, &error_world)),
    };

    let mut fence = event_id;
    let mut events = Vec::with_capacity(replay.len());
    for replay_event in replay {
        let verb = replay_event_kind_to_change_verb(replay_event.kind());
        let etag = crate::etag::hmac_etag(replay_event.hmac());
        fence = SubscriptionEventId::from_verified_replay_event(&replay_event);
        let id = replay_diagnostic_id(fence.seq());
        let aux = event::ChangeEventAux::default();
        let target = match &replay_event {
            crate::audit::VerifiedReplayEvent::Body(body) => {
                ChangeTarget::from_verified_replay_body_event(body)
            }
            crate::audit::VerifiedReplayEvent::NonBody(non_body) => {
                if event::EventMetadataKind::from_kind(non_body.kind()).is_none() {
                    return Err(EngineError::Storage);
                }
                ChangeTarget::from_verified_non_body_replay_event(non_body)
            }
        };
        events.push(
            event::ChangeEvent::new_with_aux(id, listen_epoch.clone(), verb, target, etag, aux)
                .into(),
        );
    }

    Ok((None, events, ReplayFence::Durable { floor: fence }))
}

fn replay_event_kind_to_change_verb(
    kind: event::AuditEventKind,
) -> crate::engine_types::ChangeVerb {
    match kind {
        event::AuditEventKind::Put => crate::engine_types::ChangeVerb::Replace,
        event::AuditEventKind::Append => crate::engine_types::ChangeVerb::Append,
        event::AuditEventKind::DeleteIntent
        | event::AuditEventKind::DeleteCommit
        | event::AuditEventKind::DeleteCommitFailed => crate::engine_types::ChangeVerb::Delete,
        event::AuditEventKind::Format => crate::engine_types::ChangeVerb::Format,
    }
}

fn replay_diagnostic_id(seq: crate::timeline::TimelineSeq) -> ChangeDeliveryId {
    ChangeDeliveryId::new(u64::try_from(seq.get()).unwrap_or(u64::MAX))
}

fn audit_replay_error_to_engine(
    err: crate::audit::AuditError,
    world: &ValidatedWorldPath,
) -> EngineError {
    match err {
        crate::audit::AuditError::ChainBroken(break_report) => {
            crate::engine_error::log_audit_chain_error(
                "audit",
                &break_report,
                "subscribe_replay",
                Some(world.as_str()),
            );
            EngineError::Storage
        }
        crate::audit::AuditError::Storage(err) => {
            log_storage_error("storage", &err, "subscribe_replay", Some(world.as_str()));
            match crate::classify_storage_failure(&err) {
                crate::StorageFailureClass::InsufficientStorage => EngineError::InsufficientStorage,
                crate::StorageFailureClass::Transient => EngineError::TransientStorage,
                crate::StorageFailureClass::Other => EngineError::Storage,
            }
        }
    }
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::{
        engine_types::{AuditHmacKey, ChangeVerb},
        subscription_event_id::{ChangeEventIdentity, ChangeTarget},
        timeline::{BodySha256, TimelineAddress, TimelineRead, TimelineSeq},
        world,
        world_generation::WorldGeneration,
        world_schema,
    };

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "auditedb-engine-ops-{name}-{}-{nonce}",
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

    async fn expect_format_event(
        subscription: &mut crate::EngineSubscription,
        world: &ValidatedWorldPath,
    ) -> ChangeEventIdentity {
        let event = subscription.recv().await.expect("format event");
        assert_eq!(event.verb(), ChangeVerb::Format);
        assert_eq!(event.path(), world);
        assert!(event.timeline_address().is_none());
        assert_eq!(
            event.audit_event_type(),
            Some(crate::engine_subscription::AuditEventType::Format)
        );
        assert_eq!(event.audit_event_target(), Some(world));
        assert_eq!(event.body_sha256(), Some(&BodySha256::for_body(b"")));
        assert_eq!(event.body_size(), Some(0));
        assert_eq!(event.content_type(), Some(""));
        event.identity().clone()
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
        let gen =
            world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &conn).unwrap();
        TimelineAddress::test_only_new(
            world_path.clone(),
            gen,
            TimelineSeq::new(seq).unwrap(),
            BodySha256::for_body(body),
        )
    }

    fn generation_for_world(engine: &Engine, world_path: &ValidatedWorldPath) -> WorldGeneration {
        let conn =
            rusqlite::Connection::open(world::world_db(&engine.core().data, world_path.as_str()))
                .unwrap();
        world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &conn).unwrap()
    }

    fn test_key() -> AuditHmacKey {
        AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap()
    }

    fn build_engine_with_key(root: PathBuf, key: &AuditHmacKey) -> Engine {
        Engine::builder()
            .data_root(root)
            .key(key.clone_secret())
            .max_listen_connections(1)
            .build()
            .unwrap()
    }

    fn direct_put(
        root: &std::path::Path,
        world_path: &ValidatedWorldPath,
        body: &'static [u8],
        key: &AuditHmacKey,
    ) {
        world::write_with_audit_checked(root, world_path, body, "text/plain", &[], key)
            .expect("direct fixture write succeeds");
    }

    fn corrupt_first_body_event(root: &std::path::Path, world_path: &ValidatedWorldPath) {
        let conn = rusqlite::Connection::open(world::validated_world_db(root, world_path)).unwrap();
        let changed = conn
            .execute(
                "UPDATE events
                 SET body_sha256='0000000000000000000000000000000000000000000000000000000000000000'
                 WHERE id=(
                    SELECT MIN(id) FROM events WHERE event_type IN ('put', 'append')
                 )",
                [],
            )
            .unwrap();
        assert_eq!(changed, 1, "fixture must corrupt exactly one body event");
    }

    fn append_gate_counts(engine: &Engine) -> (usize, usize) {
        engine
            .core()
            .verified_audit_worlds
            .test_only_append_gate_counts()
    }

    #[tokio::test]
    async fn engine_read_maps_real_sqlite_lock_to_transient_storage() {
        let root = temp_root("engine-read-transient-storage");
        let key = test_key();
        let world = ValidatedWorldPath::new("home/busy").unwrap();
        direct_put(&root, &world, b"before-lock", &key);
        let engine = build_engine_with_key(root.clone(), &key);

        let holder = rusqlite::Connection::open(world::validated_world_db(&root, &world)).unwrap();
        holder
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();

        assert!(matches!(
            engine.read(&world, AccessTier::Read).await,
            Err(EngineError::TransientStorage)
        ));

        drop(holder);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_operations_reject_after_shutdown() {
        let (engine, root) = test_engine("operations-after-shutdown");
        let world = ValidatedWorldPath::new("home/shutdown").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"before"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let head_before_shutdown = engine
            .chain_head(&world, AccessTier::Read)
            .unwrap()
            .expect("seed world should have an audit head");
        engine.shutdown();

        assert!(matches!(
            engine.read(&world, AccessTier::Read).await,
            Err(EngineError::ShuttingDown)
        ));
        assert!(matches!(
            engine
                .replace(
                    &world,
                    Representation::new(Bytes::from_static(b"after"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await,
            Err(EngineError::ShuttingDown)
        ));
        assert!(matches!(
            engine
                .append(
                    &world,
                    Bytes::from_static(b"after"),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await,
            Err(EngineError::ShuttingDown)
        ));
        assert!(matches!(
            engine
                .delete(&world, Preconditions::none(), AccessTier::Approve)
                .await,
            Err(EngineError::ShuttingDown)
        ));
        assert!(matches!(
            engine
                .subscribe(
                    &SubscribePattern::new("home/*"),
                    AccessTier::Read,
                    SubscriptionResume::none(),
                )
                .await,
            Err(EngineError::ShuttingDown)
        ));

        drop(engine);
        let reopened = build_engine_with_key(root.clone(), &test_key());
        let read = reopened
            .read(&world, AccessTier::Read)
            .await
            .unwrap()
            .expect("shutdown must preserve the seeded world");
        assert_eq!(read.representation.body, Bytes::from_static(b"before"));
        assert_eq!(
            reopened.chain_head(&world, AccessTier::Read).unwrap(),
            Some(head_before_shutdown),
            "rejected operations must not advance the audit chain"
        );
        let delete_ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        assert!(reopened
            .read(&delete_ledger, AccessTier::Read)
            .await
            .unwrap()
            .is_none());

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_empty_body_roundtrips_across_storage_backends() {
        let (engine, root) = test_engine("empty-body");

        for name in ["home/empty", "tmp/empty"] {
            let world = ValidatedWorldPath::new(name).unwrap();
            let write = engine
                .replace(
                    &world,
                    Representation::new(Bytes::new(), "application/octet-stream", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
            assert!(matches!(write.kind, WriteKind::Created));

            let read = engine
                .read(&world, AccessTier::Read)
                .await
                .unwrap()
                .expect("empty world should exist");
            assert!(read.representation.body.is_empty());
            assert_eq!(read.representation.content_type, "application/octet-stream");
        }

        let durable = ValidatedWorldPath::new("home/empty").unwrap();
        assert!(matches!(
            engine.verify_audit(&durable, AccessTier::Read).unwrap(),
            crate::AuditVerify::Valid(_)
        ));
        let transient = ValidatedWorldPath::new("tmp/empty").unwrap();
        assert!(matches!(
            engine.verify_audit(&transient, AccessTier::Read).unwrap(),
            crate::AuditVerify::NotApplicable
        ));

        drop(engine);
        let reopened = build_engine_with_key(root.clone(), &test_key());
        let reopened_empty = reopened
            .read(&durable, AccessTier::Read)
            .await
            .unwrap()
            .expect("durable empty world should survive reopen");
        assert!(reopened_empty.representation.body.is_empty());
        assert!(matches!(
            reopened.verify_audit(&durable, AccessTier::Read).unwrap(),
            crate::AuditVerify::Valid(_)
        ));

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_memory_quota_honors_exact_public_boundary_without_failed_write_side_effects() {
        let world = ValidatedWorldPath::new("tmp/exact-quota").unwrap();
        let headers = vec![("x-meta-owner".to_owned(), "quota-test".to_owned())];
        let exact_quota = 128
            + 64
            + world.as_str().len()
            + b"exact".len()
            + "text/plain".len()
            + "x-meta-owner".len()
            + "quota-test".len();
        assert_eq!(exact_quota, 244, "quota oracle must stay independent");

        let exact_root = temp_root("memory-quota-exact");
        let exact = Engine::builder()
            .data_root(exact_root.clone())
            .key(test_key())
            .max_memory_bytes(exact_quota)
            .build()
            .unwrap();
        let write = exact
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"exact"), "text/plain", headers.clone()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        assert!(matches!(write.kind, WriteKind::Created));
        let accepted = exact.df(AccessTier::Read).unwrap();
        assert_eq!(accepted.memory_used, exact_quota);
        assert_eq!(accepted.worlds, 1);
        let events_after_accept = exact.core().event_log.lock().unwrap().len();

        let rejected_headers = vec![
            ("x-meta-owner".to_owned(), "mutated".to_owned()),
            ("x-meta-extra".to_owned(), "present".to_owned()),
        ];
        let rejected_content_type = "application/octet-stream";
        let rejected_body = b"exact!";
        let rejected_projected = 128
            + 64
            + world.as_str().len()
            + rejected_body.len()
            + rejected_content_type.len()
            + rejected_headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>();
        let rejected = match exact
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(rejected_body),
                    rejected_content_type,
                    rejected_headers,
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("one-byte-over replacement must exceed the exact quota"),
        };
        assert!(matches!(
            rejected,
            EngineError::QuotaExceeded {
                used,
                quota,
                projected,
            } if used == exact_quota
                && quota == exact_quota
                && projected == rejected_projected
        ));
        let unchanged = exact.df(AccessTier::Read).unwrap();
        assert_eq!(unchanged.memory_used, accepted.memory_used);
        assert_eq!(unchanged.worlds, accepted.worlds);
        let preserved = exact
            .read(&world, AccessTier::Read)
            .await
            .unwrap()
            .expect("rejected replacement must preserve the world")
            .representation;
        assert_eq!(preserved.body, Bytes::from_static(b"exact"));
        assert_eq!(preserved.content_type, "text/plain");
        assert_eq!(preserved.headers, headers);
        assert_eq!(
            exact.core().event_log.lock().unwrap().len(),
            events_after_accept,
            "rejected replacement must not notify subscribers"
        );
        drop(exact);
        let _ = std::fs::remove_dir_all(exact_root);

        let below_root = temp_root("memory-quota-below");
        let below = Engine::builder()
            .data_root(below_root.clone())
            .key(test_key())
            .max_memory_bytes(exact_quota - 1)
            .build()
            .unwrap();
        let before = below.df(AccessTier::Read).unwrap();
        let events_before = below.core().event_log.lock().unwrap().len();
        let rejected = match below
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"exact"), "text/plain", headers.clone()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("exact payload must fail when the public quota is one byte short"),
        };
        assert!(matches!(
            rejected,
            EngineError::QuotaExceeded {
                used: 0,
                quota,
                projected,
            } if quota == exact_quota - 1 && projected == exact_quota
        ));
        assert!(below
            .read(&world, AccessTier::Read)
            .await
            .unwrap()
            .is_none());
        let after = below.df(AccessTier::Read).unwrap();
        assert_eq!(
            (after.memory_used, after.worlds),
            (before.memory_used, before.worlds)
        );
        assert_eq!(
            below.core().event_log.lock().unwrap().len(),
            events_before,
            "rejected creation must not notify subscribers"
        );

        drop(below);
        let _ = std::fs::remove_dir_all(below_root);
    }

    #[tokio::test]
    async fn engine_append_missing_world_returns_not_found_without_creation() {
        let (engine, root) = test_engine("append-missing");
        let before = engine.df(AccessTier::Read).unwrap();
        let events_before = engine.core().event_log.lock().unwrap().len();

        for name in ["home/missing", "tmp/missing"] {
            let world = ValidatedWorldPath::new(name).unwrap();
            let db_path = world::validated_world_db(&root, &world);
            assert!(!db_path.exists());
            assert!(matches!(
                engine
                    .append(
                        &world,
                        Bytes::from_static(b"tail"),
                        Preconditions::none(),
                        AccessTier::Write,
                    )
                    .await,
                Err(EngineError::NotFound)
            ));
            assert!(!db_path.exists(), "missing append must not create storage");
            assert!(engine
                .read(&world, AccessTier::Read)
                .await
                .unwrap()
                .is_none());
        }

        let after = engine.df(AccessTier::Read).unwrap();
        assert_eq!(
            (
                after.storage_used,
                after.storage_current_body_bytes,
                after.storage_retained_cas_body_bytes,
                after.storage_audit_chain_events,
                after.memory_used,
                after.worlds,
            ),
            (
                before.storage_used,
                before.storage_current_body_bytes,
                before.storage_retained_cas_body_bytes,
                before.storage_audit_chain_events,
                before.memory_used,
                before.worlds,
            ),
            "missing append must not change resource accounting"
        );
        assert_eq!(
            engine.core().event_log.lock().unwrap().len(),
            events_before,
            "missing append must not notify subscribers"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn write_fast_path_uses_tail_after_startup_verified_world() {
        let root = temp_root("write-tail-startup-verified");
        let key = test_key();
        let world = ValidatedWorldPath::new("home/write-tail-startup-verified").unwrap();
        direct_put(&root, &world, b"before-build", &key);

        let engine = build_engine_with_key(root.clone(), &key);
        assert!(
            engine.core().verified_audit_worlds.is_verified(&world),
            "startup full verification must mark existing worlds"
        );
        assert_eq!(append_gate_counts(&engine), (0, 0));

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"after-build"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert_eq!(
            append_gate_counts(&engine),
            (0, 1),
            "startup-verified existing worlds may use the O(1) tail gate"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn external_clean_world_full_verifies_once_then_uses_tail() {
        let root = temp_root("write-tail-external-clean");
        let key = test_key();
        let engine = build_engine_with_key(root.clone(), &key);
        let world = ValidatedWorldPath::new("home/write-tail-external-clean").unwrap();
        direct_put(&root, &world, b"external", &key);

        engine
            .append(
                &world,
                Bytes::from_static(b" first-engine-append"),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        assert!(
            engine.core().verified_audit_worlds.is_verified(&world),
            "first engine append must mark a clean external world after full verification"
        );
        assert_eq!(
            append_gate_counts(&engine),
            (1, 0),
            "cache-miss external worlds must not use the tail gate first"
        );

        engine
            .append(
                &world,
                Bytes::from_static(b" second-engine-append"),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        assert_eq!(
            append_gate_counts(&engine),
            (1, 1),
            "marked worlds switch to the tail gate after one full verification"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn external_corrupt_prefix_rejects_before_tail_fast_path() {
        let root = temp_root("write-tail-external-corrupt");
        let key = test_key();
        let engine = build_engine_with_key(root.clone(), &key);
        let world = ValidatedWorldPath::new("home/write-tail-external-corrupt").unwrap();
        direct_put(&root, &world, b"external-one", &key);
        direct_put(&root, &world, b"external-two", &key);
        corrupt_first_body_event(&root, &world);

        assert!(matches!(
            engine
                .append(
                    &world,
                    Bytes::from_static(b" engine-append"),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await,
            Err(EngineError::Storage)
        ));
        assert!(
            !engine.core().verified_audit_worlds.is_verified(&world),
            "failed full verification must not mark a corrupt external world"
        );
        assert_eq!(
            append_gate_counts(&engine),
            (1, 0),
            "corrupt cache-miss worlds must fail through the full gate, not tail"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn delete_keeps_full_verification_for_startup_marked_worlds() {
        let root = temp_root("write-tail-delete-full-verify");
        let key = test_key();
        let world = ValidatedWorldPath::new("home/write-tail-delete-full-verify").unwrap();
        direct_put(&root, &world, b"before-build-one", &key);
        direct_put(&root, &world, b"before-build-two", &key);
        let engine = build_engine_with_key(root.clone(), &key);
        assert!(engine.core().verified_audit_worlds.is_verified(&world));
        corrupt_first_body_event(&root, &world);

        assert!(matches!(
            engine
                .delete(&world, Preconditions::none(), AccessTier::Approve)
                .await,
            Err(EngineError::Storage)
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn delete_unmarks_world_before_same_name_can_append_again() {
        let root = temp_root("write-tail-delete-unmarks");
        let key = test_key();
        let world = ValidatedWorldPath::new("home/write-tail-delete-unmarks").unwrap();
        direct_put(&root, &world, b"before-build", &key);
        let engine = build_engine_with_key(root.clone(), &key);
        assert!(engine.core().verified_audit_worlds.is_verified(&world));

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        assert!(
            !engine.core().verified_audit_worlds.is_verified(&world),
            "physical delete must revoke the runtime proof for that world name"
        );

        direct_put(&root, &world, b"external-one", &key);
        direct_put(&root, &world, b"external-two", &key);
        corrupt_first_body_event(&root, &world);

        assert!(matches!(
            engine
                .append(
                    &world,
                    Bytes::from_static(b" engine-append"),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await,
            Err(EngineError::Storage)
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replay_after_reports_ring_gap_and_replays_available_events() {
        let (engine, root) = test_engine("replay-gap");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            for id in 10..=12 {
                log.push_back(event::ChangeEvent::new(
                    ChangeDeliveryId::new(id),
                    engine.core().listen_epoch.clone(),
                    ChangeVerb::Replace,
                    ChangeTarget::Ephemeral(
                        ValidatedWorldPath::new(format!("home/task/{id}")).unwrap(),
                    ),
                    format!("hmac-{id}"),
                ));
            }
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, 12);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core_arc(),
            SubscriptionResume::test_only_after_process_event_id(5)
                .replay_plan(&engine.core().listen_epoch),
            &pattern,
        )
        .await
        .unwrap();

        assert_eq!(
            interruption,
            Some(ReplayInterruption::Lagged { skipped: 4 })
        );
        assert_eq!(replay.len(), 3);
        assert_eq!(replay[0].id(), 10);
        assert_eq!(replay[0].path().as_str(), "home/task/10");
        assert_eq!(
            floor,
            ReplayFence::ProcessLocal {
                floor: ChangeDeliveryId::new(12),
            }
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replay_after_handles_max_last_event_id_without_overflow() {
        let (engine, root) = test_engine("replay-max-last-id");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            log.push_back(event::ChangeEvent::new(
                ChangeDeliveryId::new(u64::MAX),
                engine.core().listen_epoch.clone(),
                ChangeVerb::Replace,
                ChangeTarget::Ephemeral(ValidatedWorldPath::new("home/task/max").unwrap()),
                "hmac-max".to_string(),
            ));
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, u64::MAX);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core_arc(),
            SubscriptionResume::test_only_after_process_event_id(u64::MAX)
                .replay_plan(&engine.core().listen_epoch),
            &pattern,
        )
        .await
        .unwrap();

        assert_eq!(interruption, None);
        assert!(replay.is_empty());
        assert_eq!(
            floor,
            ReplayFence::ProcessLocal {
                floor: ChangeDeliveryId::new(u64::MAX),
            }
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replay_after_flags_cursor_ahead_of_current_process() {
        let (engine, root) = test_engine("replay-ahead");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            log.push_back(event::ChangeEvent::new(
                ChangeDeliveryId::new(1),
                engine.core().listen_epoch.clone(),
                ChangeVerb::Replace,
                ChangeTarget::Ephemeral(ValidatedWorldPath::new("home/task/a").unwrap()),
                "hmac-1".to_string(),
            ));
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, 1);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core_arc(),
            SubscriptionResume::test_only_after_process_event_id(42)
                .replay_plan(&engine.core().listen_epoch),
            &pattern,
        )
        .await
        .unwrap();

        assert_eq!(
            interruption,
            Some(ReplayInterruption::CursorAhead {
                since: 42,
                newest: 1,
            })
        );
        assert!(replay.is_empty());
        assert_eq!(
            floor,
            ReplayFence::None,
            "foreign cursor must not become live floor"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replay_after_treats_legacy_decimal_cursor_as_foreign_even_when_id_exists() {
        let (engine, root) = test_engine("replay-legacy-foreign");
        {
            let mut log = engine.core().event_log.lock().unwrap();
            for id in 1..=7 {
                log.push_back(event::ChangeEvent::new(
                    ChangeDeliveryId::new(id),
                    engine.core().listen_epoch.clone(),
                    ChangeVerb::Replace,
                    ChangeTarget::Ephemeral(
                        ValidatedWorldPath::new(format!("home/task/{id}")).unwrap(),
                    ),
                    format!("hmac-{id}"),
                ));
            }
        }
        crate::state::test_only_set_event_counter(&engine.core().next_event, 7);

        let pattern = SubscribePattern::new("home/task/*");
        let (interruption, replay, floor) = replay_after(
            engine.core_arc(),
            SubscriptionResume::test_only_legacy_event_id(5)
                .replay_plan(&engine.core().listen_epoch),
            &pattern,
        )
        .await
        .unwrap();

        assert_eq!(
            interruption,
            Some(ReplayInterruption::CursorAhead {
                since: 5,
                newest: 7,
            })
        );
        assert!(
            replay.is_empty(),
            "legacy decimal cursor must not replay a coincidentally matching fresh id space"
        );
        assert_eq!(floor, ReplayFence::None);

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
        assert!(engine
            .read(&world, AccessTier::Read)
            .await
            .unwrap()
            .is_none());

        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let head_before_second_delete = engine
            .chain_head(&ledger, AccessTier::Read)
            .unwrap()
            .expect("successful delete should create the delete ledger");
        assert!(matches!(
            engine
                .delete(&world, Preconditions::none(), AccessTier::Approve)
                .await,
            Err(EngineError::NotFound)
        ));
        assert_eq!(
            engine.chain_head(&ledger, AccessTier::Read).unwrap(),
            Some(head_before_second_delete),
            "missing-world delete must not append another ledger event"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_rejects_metadata_control_characters() {
        let (engine, root) = test_engine("metadata-control-chars");
        let world = ValidatedWorldPath::new("home/metadata-control-chars").unwrap();

        let result = engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"body"),
                    "text/plain\r\nx-injected: yes",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await;
        assert!(matches!(
            result,
            Err(EngineError::InvalidMetadata {
                message: "metadata-control-character"
            })
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_rejects_public_writes_to_delete_ledger() {
        let (engine, root) = test_engine("delete-ledger-write-wall");
        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();

        assert!(matches!(
            engine
                .replace(
                    &ledger,
                    Representation::new(Bytes::from_static(b"spoof"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await,
            Err(EngineError::Auth(AuthGate::WriteApprove))
        ));
        assert!(matches!(
            engine
                .replace(
                    &ledger,
                    Representation::new(Bytes::from_static(b"spoof"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Approve,
                )
                .await,
            Err(EngineError::AppendOnly)
        ));
        assert!(matches!(
            engine
                .append(
                    &ledger,
                    Bytes::from_static(b"spoof"),
                    Preconditions::none(),
                    AccessTier::Approve,
                )
                .await,
            Err(EngineError::AppendOnly)
        ));
        assert!(engine
            .read(&ledger, AccessTier::Read)
            .await
            .unwrap()
            .is_none());

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
        let first_generation = crate::world_schema::generation(
            &mut crate::blocking_sqlite::test_only_mint(),
            &first_conn,
        )
        .unwrap();
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
        let second_generation = crate::world_schema::generation(
            &mut crate::blocking_sqlite::test_only_mint(),
            &second_conn,
        )
        .unwrap();
        drop(second_conn);
        assert_ne!(first_generation, second_generation);

        let recreated = engine
            .read(&world, AccessTier::Read)
            .await
            .unwrap()
            .expect("recreated world should exist");
        assert_eq!(recreated.representation.body, Bytes::from_static(b"second"));
        assert!(matches!(
            engine.verify_audit(&world, AccessTier::Read).unwrap(),
            crate::AuditVerify::Valid(_)
        ));
        let recreated_head = engine
            .chain_head(&world, AccessTier::Read)
            .unwrap()
            .expect("recreated world should have an audit head");
        assert_eq!(recreated_head.generation, second_generation);
        assert_eq!(
            recreated_head.seq, 2,
            "recreated chain should contain only format plus replacement"
        );

        let ledger =
            rusqlite::Connection::open(crate::world::world_db(&root, "var/log/deletes")).unwrap();
        let stored_generation: String = ledger
            .query_row(
                "SELECT value FROM event_headers
                 WHERE event_id=2 AND name=?1",
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
        let address = timeline_address_for_body(&engine, &world, 2, b"old");

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
            .await
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

    #[tokio::test]
    async fn retained_body_count_prunes_old_cas_and_exposes_expired() {
        let root = temp_root("timeline-retention-count");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-count").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"old"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let old_address = timeline_address_for_body(&engine, &world, 2, b"old");

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
        let new_address = timeline_address_for_body(&engine, &world, 3, b"new");

        match engine
            .read_timeline_body(&old_address, AccessTier::Read)
            .await
            .expect("expired timeline read succeeds")
        {
            TimelineRead::Expired(expired) => {
                assert_eq!(expired.address(), &old_address);
                assert_eq!(expired.content_type(), "text/plain");
                assert_eq!(expired.size(), 3);
                assert!(!expired.hmac().is_empty());
            }
            _ => panic!("expected expired historical body"),
        }
        match engine
            .read_timeline_body(&new_address, AccessTier::Read)
            .await
            .expect("new timeline read succeeds")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.address(), &new_address);
                assert_eq!(body.representation().body, Bytes::from_static(b"new"));
            }
            _ => panic!("expected retained newest body"),
        }

        let conn = rusqlite::Connection::open(world::world_db(&engine.core().data, world.as_str()))
            .unwrap();
        let first_retained_seq: i64 = conn
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let cas_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM cas_bodies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(first_retained_seq, 3);
        assert_eq!(cas_rows, 1);
        assert_eq!(
            engine
                .core()
                .storage_body_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            world::storage_len(&engine.core().data, &world)
                .unwrap()
                .unwrap()
        );
        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, 6);
        assert_eq!(df.storage_current_body_bytes, 3);
        assert_eq!(df.storage_retained_cas_body_bytes, 3);
        assert_eq!(df.storage_audit_chain_events, 3);

        drop(conn);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn current_read_and_write_skip_historical_cas_body_hash_but_verify_fails() {
        let root = temp_root("historical-cas-hot-path-contract");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(3)
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/historical-cas-hot-path-contract").unwrap();

        for body in [b"one".as_slice(), b"two".as_slice(), b"tre".as_slice()] {
            engine
                .replace(
                    &world,
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let corrupt_hash = BodySha256::for_body(b"two");
        let conn = rusqlite::Connection::open(world::world_db(&engine.core().data, world.as_str()))
            .unwrap();
        conn.execute(
            "UPDATE cas_bodies SET body=?1 WHERE body_sha256=?2",
            rusqlite::params![b"bad".as_slice(), corrupt_hash.as_str()],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            engine
                .read(&world, AccessTier::Read)
                .await
                .unwrap()
                .unwrap()
                .representation
                .body,
            Bytes::from_static(b"tre")
        );
        assert!(matches!(
            engine.verify_audit(&world, AccessTier::Read),
            Err(EngineError::Storage)
        ));

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"for"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        assert_eq!(
            engine
                .read(&world, AccessTier::Read)
                .await
                .unwrap()
                .unwrap()
                .representation
                .body,
            Bytes::from_static(b"for")
        );
        assert!(matches!(
            engine.verify_audit(&world, AccessTier::Read),
            Err(EngineError::Storage)
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_allows_replace_after_floor_has_advanced() {
        let root = temp_root("timeline-retention-third-replace");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-third-replace").unwrap();

        for body in [b"one".as_slice(), b"two".as_slice(), b"tre".as_slice()] {
            engine
                .replace(
                    &world,
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let third_address = timeline_address_for_body(&engine, &world, 4, b"tre");
        assert!(matches!(
            engine
                .read_timeline_body(&third_address, AccessTier::Read)
                .await,
            Ok(TimelineRead::Body(_))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_prune_credit_applies_before_quota_rejects_replace() {
        let root = temp_root("timeline-retention-quota-replace");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .max_storage_bytes(Some(6))
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-quota-replace").unwrap();

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

        assert_eq!(
            world::storage_len(&engine.core().data, &world)
                .unwrap()
                .unwrap(),
            6
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_duplicate_body_hash_does_not_overcredit_quota() {
        let root = temp_root("timeline-retention-duplicate-quota");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .max_storage_bytes(Some(6))
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-duplicate-quota").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"abc"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let first_address = timeline_address_for_body(&engine, &world, 2, b"abc");
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"abc"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert_eq!(
            world::storage_len(&engine.core().data, &world)
                .unwrap()
                .unwrap(),
            6
        );
        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, 6);
        assert_eq!(df.storage_current_body_bytes, 3);
        assert_eq!(df.storage_retained_cas_body_bytes, 3);
        assert_eq!(df.storage_audit_chain_events, 3);
        assert!(matches!(
            engine
                .read_timeline_body(&first_address, AccessTier::Read)
                .await,
            Ok(TimelineRead::Body(_))
        ));

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"def"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        assert_eq!(
            world::storage_len(&engine.core().data, &world)
                .unwrap()
                .unwrap(),
            6
        );
        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, 6);
        assert_eq!(df.storage_current_body_bytes, 3);
        assert_eq!(df.storage_retained_cas_body_bytes, 3);
        assert_eq!(df.storage_audit_chain_events, 4);
        assert!(matches!(
            engine
                .read_timeline_body(&first_address, AccessTier::Read)
                .await,
            Ok(TimelineRead::Expired(_))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_prunes_after_append() {
        let root = temp_root("timeline-retention-append");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-append").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"a"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let old_address = timeline_address_for_body(&engine, &world, 2, b"a");
        engine
            .append(
                &world,
                Bytes::from_static(b"b"),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let appended_address = timeline_address_for_body(&engine, &world, 3, b"ab");

        assert!(matches!(
            engine
                .read_timeline_body(&old_address, AccessTier::Read)
                .await
                .unwrap(),
            TimelineRead::Expired(_)
        ));
        match engine
            .read_timeline_body(&appended_address, AccessTier::Read)
            .await
            .unwrap()
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"ab"));
            }
            _ => panic!("expected retained appended body"),
        }

        let conn = rusqlite::Connection::open(world::world_db(&engine.core().data, world.as_str()))
            .unwrap();
        let first_retained_seq: i64 = conn
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(first_retained_seq, 3);
        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, 4);
        assert_eq!(df.storage_current_body_bytes, 2);
        assert_eq!(df.storage_retained_cas_body_bytes, 2);
        assert_eq!(df.storage_audit_chain_events, 3);

        drop(conn);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_allows_append_after_floor_has_advanced() {
        let root = temp_root("timeline-retention-third-append");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-third-append").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"a"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        for body in [b"b".as_slice(), b"c".as_slice()] {
            engine
                .append(
                    &world,
                    Bytes::copy_from_slice(body),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let third_address = timeline_address_for_body(&engine, &world, 4, b"abc");
        assert!(matches!(
            engine
                .read_timeline_body(&third_address, AccessTier::Read)
                .await,
            Ok(TimelineRead::Body(_))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retained_body_count_prune_credit_applies_before_quota_rejects_append() {
        let root = temp_root("timeline-retention-quota-append");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .max_storage_bytes(Some(4))
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/timeline-retention-quota-append").unwrap();

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"a"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .append(
                &world,
                Bytes::from_static(b"b"),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert_eq!(
            world::storage_len(&engine.core().data, &world)
                .unwrap()
                .unwrap(),
            4
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_read_timeline_body_requires_read_tier() {
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
            engine.read_timeline_body(&address, AccessTier::Anon).await,
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
        let address = timeline_address_for_body(&engine, &world, 2, b"old");

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        match engine
            .read_timeline_body(&address, AccessTier::Read)
            .await
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
            engine
                .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
                .await,
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
                SubscriptionResume::test_only_after_process_event_id(0),
            )
            .await
            .expect("read tier subscribes");
        expect_format_event(&mut subscription, &world).await;
        let event = subscription.recv().await.expect("replay event");
        assert_eq!(event.verb(), ChangeVerb::Replace);
        assert_eq!(event.path().as_str(), "home/events/a");
        let address = event
            .timeline_address()
            .expect("durable body write event carries timeline address");
        match engine
            .read_timeline_body(address, AccessTier::Read)
            .await
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
            .await
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
        expect_format_event(&mut subscription, &world).await;
        let event_b = subscription.recv().await.expect("event B");
        let address_b = event_b
            .timeline_address()
            .cloned()
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
            .await
            .unwrap()
            .expect("current body exists");
        assert_eq!(current.representation.body, Bytes::from_static(b"C"));
        match engine
            .read_timeline_body(&address_b, AccessTier::Anon)
            .await
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
    async fn engine_subscription_replays_exact_world_from_chain_after_restart() {
        let root = temp_root("subscribe-chain-restart");
        let world = ValidatedWorldPath::new("home/events/restart").unwrap();
        let first_id = {
            let engine = Engine::builder()
                .data_root(root.clone())
                .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
                .max_listen_connections(1)
                .build()
                .unwrap();
            let pattern = SubscribePattern::new(world.as_str());
            let mut subscription = engine
                .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
                .await
                .expect("subscription opens");

            engine
                .replace(
                    &world,
                    Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
            expect_format_event(&mut subscription, &world).await;
            let first = subscription.recv().await.expect("first live event");
            let ChangeEventIdentity::Chain(first_id) = first.identity() else {
                panic!("durable write should carry chain identity");
            };
            let first_id = first_id.clone();

            engine
                .replace(
                    &world,
                    Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();

            drop(subscription);
            drop(engine);
            first_id
        };

        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .max_listen_connections(1)
            .build()
            .unwrap();
        let pattern = SubscribePattern::new(world.as_str());
        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(first_id.clone()),
            )
            .await
            .expect("chain replay subscription opens");

        let replayed = subscription.recv().await.expect("replayed event");
        assert_eq!(replayed.verb(), ChangeVerb::Replace);
        assert_eq!(replayed.path(), &world);
        assert!(replayed.etag().starts_with("hmac-"));
        assert!(!replayed.etag().starts_with("hmac-hmac-"));
        let ChangeEventIdentity::Chain(replayed_id) = replayed.identity() else {
            panic!("replayed event should carry chain identity");
        };
        assert_eq!(replayed_id.world(), first_id.world());
        assert_eq!(replayed_id.generation(), first_id.generation());
        assert_eq!(replayed_id.seq().get(), first_id.seq().get() + 1);
        let address = replayed
            .timeline_address()
            .expect("replayed body event carries timeline address");
        match engine
            .read_timeline_body(address, AccessTier::Anon)
            .await
            .expect("replayed address resolves")
        {
            TimelineRead::Body(body) => {
                assert_eq!(body.representation().body, Bytes::from_static(b"second"));
            }
            _ => panic!("expected replayed body"),
        }

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_wildcard_durable_resume_replays_in_boot_ring() {
        let (engine, root) = test_engine("subscribe-wildcard-durable-ring");
        let wildcard = SubscribePattern::new("*");
        let mut live = engine
            .subscribe(&wildcard, AccessTier::Anon, SubscriptionResume::none())
            .await
            .expect("subscription opens");
        let first_world = ValidatedWorldPath::new("home/events/wild-a").unwrap();
        engine
            .replace(
                &first_world,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        expect_format_event(&mut live, &first_world).await;
        let first = live.recv().await.expect("first live event");
        let ChangeEventIdentity::Chain(first_id) = first.identity() else {
            panic!("durable write should carry chain identity");
        };
        drop(live);

        let memory_world = ValidatedWorldPath::new("tmp/events/idless").unwrap();
        engine
            .replace(
                &memory_world,
                Representation::new(Bytes::from_static(b"memory"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let second_world = ValidatedWorldPath::new("home/events/wild-b").unwrap();
        engine
            .replace(
                &second_world,
                Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut replay = engine
            .subscribe(
                &wildcard,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(first_id.clone()),
            )
            .await
            .expect("wildcard resume opens");
        let replayed_memory = replay.recv().await.expect("ring memory replay event");
        assert_eq!(replayed_memory.path(), &memory_world);
        assert_eq!(replayed_memory.verb(), ChangeVerb::Replace);
        assert!(matches!(
            replayed_memory.identity(),
            ChangeEventIdentity::Ephemeral
        ));
        assert!(
            replayed_memory.timeline_address().is_none(),
            "id-less memory event remains id-less when replayed from the process ring"
        );

        expect_format_event(&mut replay, &second_world).await;
        let replayed = replay.recv().await.expect("ring durable replay event");
        assert_eq!(replayed.path(), &second_world);
        assert_eq!(replayed.verb(), ChangeVerb::Replace);
        assert!(matches!(replayed.identity(), ChangeEventIdentity::Chain(_)));
        assert!(
            replayed.timeline_address().is_some(),
            "id-bearing body event keeps timeline address"
        );

        drop(replay);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_wildcard_durable_resume_resets_on_ring_miss() {
        let (engine, root) = test_engine("subscribe-wildcard-ring-miss");
        let world = ValidatedWorldPath::new("home/events/wild-miss").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let conn = rusqlite::Connection::open(world::validated_world_db(&root, &world)).unwrap();
        let gen =
            world_schema::generation(&mut crate::blocking_sqlite::test_only_mint(), &conn).unwrap();
        drop(conn);
        engine.core().event_log.lock().unwrap().clear();
        let missing_id =
            SubscriptionEventId::from_timeline_address(&TimelineAddress::test_only_new(
                world.clone(),
                gen,
                TimelineSeq::new(2).unwrap(),
                BodySha256::for_body(b"first"),
            ));

        let mut replay = engine
            .subscribe(
                &SubscribePattern::new("*"),
                AccessTier::Anon,
                SubscriptionResume::after_event_id(missing_id),
            )
            .await
            .expect("wildcard resume opens");
        assert!(matches!(
            replay.recv().await,
            Err(SubscriptionRecvError::Reset {
                reason: SubscriptionResetReason::RingMiss
            })
        ));

        drop(replay);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_replay_rejects_wrong_target_row_before_minting_event() {
        let (engine, root) = test_engine("subscribe-chain-wrong-target");
        let world = ValidatedWorldPath::new("home/events/wrong-target").unwrap();
        let pattern = SubscribePattern::new(world.as_str());
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .await
            .expect("subscription opens");

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let first = subscription.recv().await.expect("first live event");
        let ChangeEventIdentity::Chain(first_id) = first.identity() else {
            panic!("durable write should carry chain identity");
        };

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let conn = rusqlite::Connection::open(world::validated_world_db(&root, &world)).unwrap();
        conn.execute(
            "UPDATE events SET target='home/events/other' WHERE id=?1",
            [first_id.seq().get() + 1],
        )
        .unwrap();
        drop(conn);
        drop(subscription);

        let result = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(first_id.clone()),
            )
            .await;
        match result {
            Err(EngineError::Storage) => {}
            Err(err) => panic!("unexpected replay error: {err:?}"),
            Ok(_) => panic!("replay unexpectedly opened after wrong-target row"),
        }

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
                SubscriptionResume::test_only_after_process_event_id(0),
            )
            .await
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
        assert_eq!(event.verb(), ChangeVerb::Replace);
        assert_eq!(event.path().as_str(), "tmp/events/a");
        assert!(event.timeline_address().is_none());

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
        let subject_generation = generation_for_world(&engine, &world);
        let subject_head = engine
            .chain_head(&world, AccessTier::Read)
            .unwrap()
            .expect("subject has a body-head before delete");

        let pattern = SubscribePattern::new("home/events/*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .await
            .expect("subscription opens");
        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        let event = subscription.recv().await.expect("delete event");
        assert_eq!(event.verb(), ChangeVerb::Delete);
        assert_eq!(event.path().as_str(), "home/events/delete");
        assert!(event.timeline_address().is_none());
        assert_eq!(event.delete_subject_generation(), Some(&subject_generation));
        let proof = event
            .delete_subject()
            .expect("delete ping carries full subject proof");
        assert_eq!(proof.address().world(), &world);
        assert_eq!(proof.address().generation(), &subject_head.generation);
        assert_eq!(proof.address().seq().get(), subject_head.seq);
        assert_eq!(
            proof.address().body_sha256(),
            &BodySha256::for_body(b"gone")
        );
        assert_eq!(proof.hmac(), subject_head.hmac.as_str());

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_delete_ledger_events_are_id_bearing() {
        let (engine, root) = test_engine("subscribe-delete-ledger-live");
        let subject = ValidatedWorldPath::new("home/events/delete-ledger-live").unwrap();
        engine
            .replace(
                &subject,
                Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let subject_generation = generation_for_world(&engine, &subject);
        let subject_head = engine
            .chain_head(&subject, AccessTier::Read)
            .unwrap()
            .expect("subject has a body-head before delete");

        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let pattern = SubscribePattern::new(ledger.as_str());
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .await
            .expect("ledger subscription opens");
        engine
            .delete(&subject, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        let format = subscription.recv().await.expect("ledger format event");
        assert_eq!(format.verb(), ChangeVerb::Format);
        assert_eq!(format.path(), &ledger);
        assert!(format.etag().starts_with("hmac-"));
        assert!(format.timeline_address().is_none());
        let ChangeEventIdentity::Chain(format_id) = format.identity() else {
            panic!("delete ledger format event should carry chain identity");
        };
        assert_eq!(format_id.world(), &ledger);
        assert_eq!(format_id.seq().get(), 1);

        for expected_seq in [2_i64, 3] {
            let event = subscription.recv().await.expect("ledger event");
            assert_eq!(event.verb(), ChangeVerb::Delete);
            assert_eq!(event.path(), &ledger);
            assert!(event.etag().starts_with("hmac-"));
            assert!(event.timeline_address().is_none());
            assert_eq!(event.delete_subject_generation(), Some(&subject_generation));
            let proof = event
                .delete_subject()
                .expect("ledger event carries full subject proof");
            assert_eq!(proof.address().world(), &subject);
            assert_eq!(proof.address().generation(), &subject_head.generation);
            assert_eq!(proof.address().seq().get(), subject_head.seq);
            assert_eq!(
                proof.address().body_sha256(),
                &BodySha256::for_body(b"gone")
            );
            assert_eq!(proof.hmac(), subject_head.hmac.as_str());
            assert_eq!(event.body_sha256(), Some(&BodySha256::for_body(b"gone")));
            assert_eq!(event.body_size(), Some(0));
            assert_eq!(event.content_type(), Some(""));
            let ChangeEventIdentity::Chain(id) = event.identity() else {
                panic!("delete ledger event should carry chain identity");
            };
            assert_eq!(id.world(), &ledger);
            assert_eq!(id.seq().get(), expected_seq);
        }

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_delete_ledger_notifications_follow_chain_order_under_concurrency()
    {
        let (engine, root) = test_engine("subscribe-delete-ledger-concurrent-order");
        let first = ValidatedWorldPath::new("home/events/delete-ledger-order-a").unwrap();
        let second = ValidatedWorldPath::new("home/events/delete-ledger-order-b").unwrap();
        for world in [&first, &second] {
            engine
                .replace(
                    world,
                    Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new(ledger.as_str()),
                AccessTier::Anon,
                SubscriptionResume::none(),
            )
            .await
            .expect("ledger subscription opens");
        let delete_first = {
            let engine = engine.clone();
            let first = first.clone();
            tokio::spawn(async move {
                engine
                    .delete(&first, Preconditions::none(), AccessTier::Approve)
                    .await
                    .unwrap();
            })
        };
        let delete_second = {
            let engine = engine.clone();
            let second = second.clone();
            tokio::spawn(async move {
                engine
                    .delete(&second, Preconditions::none(), AccessTier::Approve)
                    .await
                    .unwrap();
            })
        };

        for expected_seq in 1_i64..=5 {
            let event = subscription.recv().await.expect("ledger event");
            assert_eq!(event.path(), &ledger);
            assert!(event.timeline_address().is_none());
            let ChangeEventIdentity::Chain(id) = event.identity() else {
                panic!("delete ledger stream should carry chain identity");
            };
            assert_eq!(id.world(), &ledger);
            assert_eq!(id.seq().get(), expected_seq);
            if expected_seq == 1 {
                assert_eq!(event.verb(), ChangeVerb::Format);
            } else {
                assert_eq!(event.verb(), ChangeVerb::Delete);
            }
        }

        delete_first.await.unwrap();
        delete_second.await.unwrap();
        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_subject_delete_ping_is_idless_with_ledger_seq() {
        let (engine, root) = test_engine("subscribe-delete-subject-ping");
        let subject = ValidatedWorldPath::new("home/events/delete-subject-ping").unwrap();
        engine
            .replace(
                &subject,
                Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let subject_generation = generation_for_world(&engine, &subject);

        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new(subject.as_str()),
                AccessTier::Anon,
                SubscriptionResume::none(),
            )
            .await
            .expect("subject subscription opens");
        engine
            .delete(&subject, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

        let event = subscription.recv().await.expect("subject delete ping");
        assert_eq!(event.verb(), ChangeVerb::Delete);
        assert_eq!(event.path(), &subject);
        assert_eq!(event.identity(), &ChangeEventIdentity::Ephemeral);
        let ledger_event_id = event
            .delete_ledger_event_id()
            .expect("subject delete ping names delete intent ledger row");
        assert_eq!(ledger_event_id.world().as_str(), "var/log/deletes");
        assert_eq!(ledger_event_id.seq().get(), 2);
        assert_eq!(event.delete_subject_generation(), Some(&subject_generation));
        assert!(event.timeline_address().is_none());
        assert_eq!(event.body_sha256(), None);
        assert_eq!(event.body_size(), None);
        assert_eq!(event.content_type(), None);

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_resets_when_live_event_changes_generation_after_replay() {
        let (engine, root) = test_engine("subscribe-replay-gen-splice");
        let world = ValidatedWorldPath::new("home/events/gen-splice").unwrap();
        let mut live = engine
            .subscribe(
                &SubscribePattern::new(world.as_str()),
                AccessTier::Anon,
                SubscriptionResume::none(),
            )
            .await
            .expect("live subscription opens");
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        expect_format_event(&mut live, &world).await;
        let first = live.recv().await.expect("first event");
        let ChangeEventIdentity::Chain(first_id) = first.identity() else {
            panic!("first write should carry chain identity");
        };
        let first_id = first_id.clone();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        drop(live);

        let mut replay = engine
            .subscribe(
                &SubscribePattern::new(world.as_str()),
                AccessTier::Anon,
                SubscriptionResume::after_event_id(first_id.clone()),
            )
            .await
            .expect("replay subscription opens");
        let replayed = replay.recv().await.expect("second replay");
        assert_eq!(replayed.path(), &world);

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        let delete_ping = replay.recv().await.expect("delete ping passes through");
        assert_eq!(delete_ping.identity(), &ChangeEventIdentity::Ephemeral);
        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"new incarnation"),
                    "text/plain",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert!(matches!(
            replay.recv().await,
            Err(SubscriptionRecvError::Reset {
                reason: SubscriptionResetReason::Incarnation
            })
        ));

        drop(replay);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_replays_delete_ledger_non_body_events_after_restart() {
        let root = temp_root("subscribe-delete-ledger-restart");
        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let (first_id, subject_generation, subject_head) = {
            let engine = Engine::builder()
                .data_root(root.clone())
                .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
                .max_listen_connections(1)
                .build()
                .unwrap();
            let subject = ValidatedWorldPath::new("home/events/delete-ledger-restart").unwrap();
            engine
                .replace(
                    &subject,
                    Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
            let subject_generation = generation_for_world(&engine, &subject);
            let subject_head = engine
                .chain_head(&subject, AccessTier::Read)
                .unwrap()
                .expect("subject has a body-head before delete");

            let pattern = SubscribePattern::new(ledger.as_str());
            let mut subscription = engine
                .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
                .await
                .expect("ledger subscription opens");
            engine
                .delete(&subject, Preconditions::none(), AccessTier::Approve)
                .await
                .unwrap();
            let format = subscription
                .recv()
                .await
                .expect("delete ledger format event");
            assert_eq!(format.verb(), ChangeVerb::Format);
            let ChangeEventIdentity::Chain(format_id) = format.identity() else {
                panic!("delete ledger format should carry chain identity");
            };
            assert_eq!(format_id.world(), &ledger);
            assert_eq!(format_id.seq().get(), 1);

            let intent = subscription.recv().await.expect("delete intent event");
            let ChangeEventIdentity::Chain(first_id) = intent.identity() else {
                panic!("delete intent should carry chain identity");
            };
            let first_id = first_id.clone();
            assert_eq!(first_id.world(), &ledger);
            assert_eq!(first_id.seq().get(), 2);

            drop(subscription);
            drop(engine);
            (first_id, subject_generation, subject_head)
        };

        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .max_listen_connections(1)
            .build()
            .unwrap();
        let pattern = SubscribePattern::new(ledger.as_str());
        let mut subscription = engine
            .subscribe(
                &pattern,
                AccessTier::Anon,
                SubscriptionResume::after_event_id(first_id.clone()),
            )
            .await
            .expect("ledger replay subscription opens");

        let replayed = subscription.recv().await.expect("delete commit replay");
        assert_eq!(replayed.verb(), ChangeVerb::Delete);
        assert_eq!(replayed.path(), &ledger);
        assert!(replayed.timeline_address().is_none());
        assert_eq!(replayed.body_sha256(), Some(&BodySha256::for_body(b"gone")));
        assert_eq!(
            replayed.delete_subject_generation(),
            Some(&subject_generation)
        );
        let proof = replayed
            .delete_subject()
            .expect("replayed delete ledger row carries full subject proof");
        assert_eq!(
            proof.address().world().as_str(),
            "home/events/delete-ledger-restart"
        );
        assert_eq!(proof.address().generation(), &subject_head.generation);
        assert_eq!(proof.address().seq().get(), subject_head.seq);
        assert_eq!(
            proof.address().body_sha256(),
            &BodySha256::for_body(b"gone")
        );
        assert_eq!(proof.hmac(), subject_head.hmac.as_str());
        assert_eq!(replayed.body_size(), Some(0));
        assert_eq!(replayed.content_type(), Some(""));
        let ChangeEventIdentity::Chain(replayed_id) = replayed.identity() else {
            panic!("delete commit replay should carry chain identity");
        };
        assert_eq!(replayed_id.world(), &ledger);
        assert_eq!(replayed_id.generation(), first_id.generation());
        assert_eq!(replayed_id.seq().get(), 3);

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
            .await
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
        assert_eq!(event.verb(), ChangeVerb::Append);
        assert_eq!(event.path().as_str(), "home/events/append");
        let address = event
            .timeline_address()
            .expect("durable append event carries timeline address");
        assert_eq!(event.body_sha256(), Some(address.body_sha256()));
        assert_eq!(event.body_size(), Some(9));
        assert_eq!(event.content_type(), Some("text/plain"));
        match engine
            .read_timeline_body(address, AccessTier::Anon)
            .await
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
                SubscriptionResume::test_only_after_process_event_id(42),
            )
            .await
            .expect("subscription opens with stale cursor");

        let first = tokio::time::timeout(recv_budget, subscription.recv())
            .await
            .expect("first recv must not block");
        assert!(matches!(
            first,
            Err(SubscriptionRecvError::CursorAhead {
                since: 42,
                newest: 0,
                ..
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
        assert_eq!(change.path().as_str(), "home/stale/a");

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscribe_enforces_slot_cap_at_entry() {
        let (engine, root) = test_engine("subscribe-cap");
        let pattern = SubscribePattern::new("*");
        let first = engine
            .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
            .await
            .expect("first subscription consumes the sole slot");
        assert!(matches!(
            engine
                .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
                .await,
            Err(EngineError::SubscriptionLimit)
        ));

        drop(first);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscribe_denied_auth_does_not_consume_slot() {
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
            engine
                .subscribe(&pattern, AccessTier::Anon, SubscriptionResume::none())
                .await,
            Err(EngineError::Auth(AuthGate::Read))
        ));
        let subscription = engine
            .subscribe(&pattern, AccessTier::Read, SubscriptionResume::none())
            .await
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
            .await
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
                SubscriptionResume::test_only_after_process_event_id(0),
            )
            .await
            .expect("subscription opens before shutdown");
        engine.shutdown();
        let replay_a_format = subscription.recv().await.unwrap();
        assert_eq!(replay_a_format.verb(), ChangeVerb::Format);
        assert_eq!(replay_a_format.path().as_str(), "home/replay/a");
        let replay_a_body = subscription.recv().await.unwrap();
        assert_eq!(replay_a_body.verb(), ChangeVerb::Replace);
        assert_eq!(replay_a_body.path().as_str(), "home/replay/a");
        let replay_b_format = subscription.recv().await.unwrap();
        assert_eq!(replay_b_format.verb(), ChangeVerb::Format);
        assert_eq!(replay_b_format.path().as_str(), "home/replay/b");
        let replay_b_body = subscription.recv().await.unwrap();
        assert_eq!(replay_b_body.verb(), ChangeVerb::Replace);
        assert_eq!(replay_b_body.path().as_str(), "home/replay/b");
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
