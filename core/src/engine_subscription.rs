//! Public Engine subscription types.
//!
//! Kept separate from `engine_types.rs` so replay/live stream state does not
//! push the general Engine value types over the production-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::collections::VecDeque;

use tokio::sync::{broadcast, watch, OwnedSemaphorePermit};

use crate::{
    engine_types::{ChangeVerb, ValidatedWorldPath},
    event::ChangeDeliveryId,
    subscription_cursor::SubscribePattern,
    subscription_event_id::{ChangeEventIdentity, SubscriptionEventId},
    timeline::{BodySha256, DeleteSubjectProof, TimelineAddress},
    world_generation::WorldGeneration,
};

/// Protocol-neutral change event delivered to subscribers.
///
/// On targets with native 64-bit atomics, ids advance through the full `u64`
/// range via `AtomicU64`. On 32-bit targets without native 64-bit atomics, a
/// mutex-backed `u64` counter provides the same external id range. The counter
/// uses saturating increments, so `u64::MAX` is the rollover-imminent signal on
/// all platforms.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ChangeEvent {
    /// Diagnostic delivery id.
    ///
    /// This is not a reconnect cursor. Live events use process-local ordering;
    /// replayed chain events may use their historical sequence. Wire protocols
    /// use [`ChangeEvent::identity`] for durable chain events.
    id: u64,
    /// Durable timeline identity when this event corresponds to an audit-chain
    /// row. Ephemeral events deliberately carry no durable cursor.
    identity: ChangeEventIdentity,
    /// Engine mutation that produced the change.
    verb: ChangeVerb,
    /// Canonical world path the change applies to.
    path: ValidatedWorldPath,
    /// Strong ETag after the change. Subject-world delete pings use an empty
    /// string; replayable delete-ledger rows use the ledger row HMAC.
    etag: String,
    /// Audited body address for durable replace/append events.
    ///
    /// `None` for transient memory writes and delete events.
    timeline_address: Option<TimelineAddress>,
    /// Intent ledger event id for an id-less subject-world delete ping.
    delete_ledger_event_id: Option<SubscriptionEventId>,
    /// Full proof of the deleted subject body-head, when proven by delete audit metadata.
    delete_subject: Option<DeleteSubjectProof>,
    /// Audit row kind for durable chain events.
    audit_event_type: Option<AuditEventType>,
    /// Audit row target world for durable chain events.
    audit_event_target: Option<ValidatedWorldPath>,
    /// Audit-row payload digest. Present for durable chain-row events.
    body_sha256: Option<BodySha256>,
    /// Audit-row payload size. Present for durable chain-row events.
    body_size: Option<i64>,
    /// Audit-row content type. Present for durable chain-row events.
    content_type: Option<String>,
}

/// Typed metadata-only audit event kind exposed on subscription events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEventType {
    /// Body replace event.
    Put,
    /// Body append event.
    Append,
    /// Delete intent row in `var/log/deletes`.
    DeleteIntent,
    /// Delete commit row in `var/log/deletes`.
    DeleteCommit,
    /// Delete commit failure row in `var/log/deletes`.
    DeleteCommitFailed,
    /// Storage-format marker row.
    Format,
}

impl AuditEventType {
    /// Stable lowercase wire spelling for protocol adapters.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Append => "append",
            Self::DeleteIntent => "delete_intent",
            Self::DeleteCommit => "delete_commit",
            Self::DeleteCommitFailed => "delete_commit_failed",
            Self::Format => "format",
        }
    }
}

impl From<crate::event::AuditEventKind> for AuditEventType {
    fn from(value: crate::event::AuditEventKind) -> Self {
        match value {
            crate::event::AuditEventKind::Put => Self::Put,
            crate::event::AuditEventKind::Append => Self::Append,
            crate::event::AuditEventKind::DeleteIntent => Self::DeleteIntent,
            crate::event::AuditEventKind::DeleteCommit => Self::DeleteCommit,
            crate::event::AuditEventKind::DeleteCommitFailed => Self::DeleteCommitFailed,
            crate::event::AuditEventKind::Format => Self::Format,
        }
    }
}

/// Subscription to protocol-neutral engine change events.
///
/// Returned synchronously by [`crate::Engine::subscribe`]. Receiving from it is
/// async through [`EngineSubscription::recv`]. The subscription holds a slot
/// permit until dropped — drop it promptly when the caller is done so other
/// subscribers can join.
pub struct EngineSubscription {
    slot: SubscriptionSlot,
    state: SubscriptionState,
}

struct SubscriptionSlot {
    _permit: OwnedSemaphorePermit,
    pending_shutdown: Option<watch::Receiver<bool>>,
}

struct DeferredLiveSubscription {
    rx: broadcast::Receiver<crate::event::ChangeEvent>,
    pattern: SubscribePattern,
    replay_fence: ReplayFence,
}

struct LiveSubscription {
    rx: broadcast::Receiver<crate::event::ChangeEvent>,
    pattern: SubscribePattern,
    replay_fence: ReplayFence,
    shutdown: watch::Receiver<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ReplayFence {
    #[default]
    None,
    ProcessLocal {
        floor: ChangeDeliveryId,
    },
    Durable {
        floor: SubscriptionEventId,
    },
}

/// Reset reason for a subscription resume boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubscriptionResetReason {
    /// The durable world has a different generation from the supplied cursor.
    Incarnation,
    /// The supplied durable row is absent from a permanent audit chain.
    Truncation,
    /// Replay could not be satisfied from the bounded replay surface.
    RingMiss,
    /// The cursor named a memory world, which has no durable timeline.
    Memory,
}

enum SubscriptionState {
    Replaying {
        remaining: VecDeque<Result<ChangeEvent, SubscriptionRecvError>>,
        live: DeferredLiveSubscription,
    },
    Live(LiveSubscription),
    Closed,
}

/// Error returned by [`EngineSubscription::recv`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubscriptionRecvError {
    /// The engine is shutting down or the broadcast channel was closed.
    /// Terminal — subsequent `recv` calls keep returning `Closed`.
    Closed,
    /// The broadcast ring buffer overflowed and `skipped` events were lost.
    /// Recoverable: the next `recv` resumes with fresh live events.
    Lagged {
        /// Number of events the receiver missed.
        skipped: u64,
    },
    /// The supplied resume point cannot be spliced into this subscription.
    ///
    /// Recoverable: the caller should discard its cursor and re-baseline.
    Reset {
        /// Why the cursor was rejected.
        reason: SubscriptionResetReason,
    },
    /// The subscriber's test-only process resume cursor is ahead of every id this engine process
    /// has issued.
    ///
    /// Listen ids are process-local, so this usually means the cursor was
    /// saved before an engine restart. The subscription continues live after
    /// this error; callers must discard or rebase the stale cursor.
    #[cfg(test)]
    CursorAhead {
        /// Cursor presented by the subscriber.
        since: u64,
        /// Newest event id issued by this engine process when the
        /// subscription was opened.
        newest: u64,
    },
}

impl DeferredLiveSubscription {
    fn with_shutdown(self, shutdown: watch::Receiver<bool>) -> LiveSubscription {
        LiveSubscription {
            rx: self.rx,
            pattern: self.pattern,
            replay_fence: self.replay_fence,
            shutdown,
        }
    }
}

impl SubscriptionSlot {
    fn new(permit: OwnedSemaphorePermit, pending_shutdown: Option<watch::Receiver<bool>>) -> Self {
        Self {
            _permit: permit,
            pending_shutdown,
        }
    }

    fn take_pending_shutdown(&mut self) -> Option<watch::Receiver<bool>> {
        self.pending_shutdown.take()
    }
}

impl From<crate::event::ChangeEvent> for ChangeEvent {
    fn from(value: crate::event::ChangeEvent) -> Self {
        let (id, listen_epoch, verb, path, etag, timeline_address, identity, audit_payload, aux) =
            value.into_parts();
        let _ = listen_epoch;
        let audit_event_type = audit_payload.as_ref().map(|payload| payload.kind().into());
        let audit_event_target = audit_payload
            .as_ref()
            .map(|payload| payload.target().clone());
        let body_sha256 = audit_payload
            .as_ref()
            .map(|payload| payload.body_sha256().clone());
        let body_size = audit_payload.as_ref().map(|payload| payload.size());
        let content_type = audit_payload
            .as_ref()
            .map(|payload| payload.content_type().to_owned());
        let delete_subject = audit_payload
            .as_ref()
            .and_then(|payload| payload.delete_subject().cloned())
            .or_else(|| aux.delete_subject().cloned());
        Self {
            id: id.get(),
            identity,
            verb,
            path,
            etag,
            timeline_address,
            delete_ledger_event_id: aux.delete_ledger_event_id().cloned(),
            delete_subject,
            audit_event_type,
            audit_event_target,
            body_sha256,
            body_size,
            content_type,
        }
    }
}

impl ChangeEvent {
    /// Diagnostic process-local delivery id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Durable chain identity for replayable events, or ephemeral for live-only signals.
    pub fn identity(&self) -> &ChangeEventIdentity {
        &self.identity
    }

    /// Engine mutation that produced the event.
    pub fn verb(&self) -> ChangeVerb {
        self.verb
    }

    /// Canonical world path the event applies to.
    pub fn path(&self) -> &ValidatedWorldPath {
        &self.path
    }

    /// Strong ETag after the change, when one exists.
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// Audited body address for durable replace/append events.
    pub fn timeline_address(&self) -> Option<&TimelineAddress> {
        self.timeline_address.as_ref()
    }

    /// Intent ledger event id for an id-less subject-world delete ping.
    pub fn delete_ledger_event_id(&self) -> Option<&SubscriptionEventId> {
        self.delete_ledger_event_id.as_ref()
    }

    /// Full deleted subject proof for delete events, when proven.
    ///
    /// Subject-world delete pings are ephemeral, but this value still binds the
    /// ping to the deleted incarnation and body-head. Delete-ledger rows expose
    /// the same proof from their signed audit metadata.
    pub fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject.as_ref()
    }

    /// Deleted subject-world generation for delete events, when proven.
    ///
    /// Subject-world delete pings are ephemeral, but this value still binds the
    /// ping to the deleted incarnation. Delete-ledger rows expose the same
    /// generation from their signed audit metadata.
    pub fn delete_subject_generation(&self) -> Option<&WorldGeneration> {
        self.delete_subject
            .as_ref()
            .map(DeleteSubjectProof::generation)
    }

    /// Audit row kind for durable chain events.
    pub fn audit_event_type(&self) -> Option<AuditEventType> {
        self.audit_event_type
    }

    /// Audit row target world for durable chain events.
    pub fn audit_event_target(&self) -> Option<&ValidatedWorldPath> {
        self.audit_event_target.as_ref()
    }

    /// Audit-row body digest for durable chain events.
    ///
    /// For replace/append events this is the body hash addressed by
    /// [`ChangeEvent::timeline_address`]. For metadata-only ledger rows it is
    /// the digest signed into that ledger event. Ephemeral signals return
    /// `None`.
    pub fn body_sha256(&self) -> Option<&BodySha256> {
        self.body_sha256.as_ref()
    }

    /// Audit-row size for durable chain events.
    pub fn body_size(&self) -> Option<i64> {
        self.body_size
    }

    /// Audit-row content type for durable chain events.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

impl EngineSubscription {
    pub(crate) fn new(
        slot: OwnedSemaphorePermit,
        replay: VecDeque<Result<ChangeEvent, SubscriptionRecvError>>,
        rx: broadcast::Receiver<crate::event::ChangeEvent>,
        pattern: SubscribePattern,
        replay_fence: ReplayFence,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let live = DeferredLiveSubscription {
            rx,
            pattern,
            replay_fence,
        };
        let (state, pending_shutdown) = if replay.is_empty() {
            (SubscriptionState::Live(live.with_shutdown(shutdown)), None)
        } else {
            (
                SubscriptionState::Replaying {
                    remaining: replay,
                    live,
                },
                Some(shutdown),
            )
        };
        Self {
            slot: SubscriptionSlot::new(slot, pending_shutdown),
            state,
        }
    }

    /// Returns the next change event for this subscription.
    ///
    /// Drains the replay queue first, then switches to the live broadcast
    /// stream. Replay setup installs a fence so live events already covered by
    /// the replay are skipped without making process-local ids part of the
    /// reconnect contract.
    ///
    /// # Errors
    /// - [`SubscriptionRecvError::Closed`] when the engine shut down or the
    ///   underlying channel closed. Terminal: subsequent calls keep
    ///   returning `Closed`.
    /// - [`SubscriptionRecvError::Lagged`] when the broadcast ring buffer
    ///   overflowed and events were lost. Recoverable: the next call resumes
    ///   with fresh events.
    pub async fn recv(&mut self) -> Result<ChangeEvent, SubscriptionRecvError> {
        loop {
            let state = std::mem::replace(&mut self.state, SubscriptionState::Closed);
            match state {
                SubscriptionState::Closed => {
                    self.state = SubscriptionState::Closed;
                    return Err(SubscriptionRecvError::Closed);
                }
                SubscriptionState::Replaying {
                    mut remaining,
                    live,
                } => {
                    if let Some(item) = remaining.pop_front() {
                        self.state = SubscriptionState::Replaying { remaining, live };
                        return item;
                    }
                    // Invariant: Replaying state owns exactly one pending
                    // shutdown receiver until it transitions to Live.
                    #[allow(clippy::expect_used)]
                    let shutdown = self
                        .slot
                        .take_pending_shutdown()
                        .expect("replay state retains pending shutdown receiver");
                    self.state = SubscriptionState::Live(live.with_shutdown(shutdown));
                }
                SubscriptionState::Live(mut live) => {
                    if *live.shutdown.borrow() {
                        self.state = SubscriptionState::Closed;
                        return Err(SubscriptionRecvError::Closed);
                    }
                    tokio::select! {
                        changed = live.shutdown.changed() => {
                            let _ = changed;
                            self.state = SubscriptionState::Closed;
                            return Err(SubscriptionRecvError::Closed);
                        }
                        item = live.rx.recv() => {
                            match item {
                                Ok(change) => match live_change_action(&live.replay_fence, &live.pattern, &change) {
                                    LiveChangeAction::Accept => {
                                        self.state = SubscriptionState::Live(live);
                                        return Ok(change.into());
                                    }
                                    LiveChangeAction::Drop => {
                                        self.state = SubscriptionState::Live(live);
                                    }
                                    LiveChangeAction::Reset(reason) => {
                                        self.state = SubscriptionState::Live(live);
                                        return Err(SubscriptionRecvError::Reset { reason });
                                    }
                                },
                                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                    self.state = SubscriptionState::Live(live);
                                    return Err(SubscriptionRecvError::Lagged { skipped });
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    self.state = SubscriptionState::Closed;
                                    return Err(SubscriptionRecvError::Closed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LiveChangeAction {
    Accept,
    Drop,
    Reset(SubscriptionResetReason),
}

fn live_change_action(
    fence: &ReplayFence,
    pattern: &SubscribePattern,
    change: &crate::event::ChangeEvent,
) -> LiveChangeAction {
    if !crate::event::matches_world(pattern, change.path()) {
        return LiveChangeAction::Drop;
    }

    match fence {
        ReplayFence::None => LiveChangeAction::Accept,
        ReplayFence::ProcessLocal { floor } => match change.identity() {
            ChangeEventIdentity::Ephemeral => LiveChangeAction::Accept,
            ChangeEventIdentity::Chain(_) => {
                if change.id() > *floor {
                    LiveChangeAction::Accept
                } else {
                    LiveChangeAction::Drop
                }
            }
        },
        ReplayFence::Durable { floor } => match change.identity() {
            ChangeEventIdentity::Chain(id) if id.world() == floor.world() => {
                if id.generation() != floor.generation() {
                    LiveChangeAction::Reset(SubscriptionResetReason::Incarnation)
                } else if id.same_chain_at_or_before(floor) {
                    LiveChangeAction::Drop
                } else {
                    LiveChangeAction::Accept
                }
            }
            ChangeEventIdentity::Chain(_) | ChangeEventIdentity::Ephemeral => {
                LiveChangeAction::Accept
            }
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ChangeEventIdentity;
    use crate::{
        engine_types::{ChangeVerb, ValidatedWorldPath},
        event::{self, AuditEventKind, AuditEventPayload, ChangeDeliveryId},
        subscription_cursor::{SubscribePattern, SubscriptionEpoch},
        subscription_event_id::ChangeTarget,
        timeline::{BodySha256, TimelineAddress, TimelineSeq},
        world_generation::WorldGeneration,
    };

    #[test]
    fn change_event_identity_is_chain_for_body_address_and_ephemeral_for_live_only_signal() {
        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        let address = TimelineAddress::test_only_new(
            world.clone(),
            WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap(),
            TimelineSeq::new(3).unwrap(),
            BodySha256::for_body(b"value"),
        );

        let payload = AuditEventPayload::test_only(
            AuditEventKind::Put,
            world.clone(),
            BodySha256::for_body(b"value"),
            5,
            "text/plain",
        );
        let target = ChangeTarget::from_matched_timeline_address(&world, address, payload).unwrap();
        let chain = super::ChangeEvent::from(event::ChangeEvent::new(
            ChangeDeliveryId::new(1),
            SubscriptionEpoch::new("0123456789abcdef0123456789abcdef").unwrap(),
            ChangeVerb::Replace,
            target,
            "hmac-test".to_owned(),
        ));
        assert!(matches!(chain.identity(), ChangeEventIdentity::Chain(_)));

        let ephemeral = super::ChangeEvent::from(event::ChangeEvent::new(
            ChangeDeliveryId::new(2),
            SubscriptionEpoch::new("0123456789abcdef0123456789abcdef").unwrap(),
            ChangeVerb::Delete,
            ChangeTarget::Ephemeral(world),
            String::new(),
        ));
        assert_eq!(ephemeral.identity(), &ChangeEventIdentity::Ephemeral);
    }

    #[test]
    fn process_local_replay_fence_never_drops_ephemeral_events() {
        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        let event = event::ChangeEvent::new(
            ChangeDeliveryId::new(11),
            SubscriptionEpoch::new("0123456789abcdef0123456789abcdef").unwrap(),
            ChangeVerb::Delete,
            ChangeTarget::Ephemeral(world),
            String::new(),
        );

        assert_eq!(
            super::live_change_action(
                &super::ReplayFence::ProcessLocal {
                    floor: ChangeDeliveryId::new(12),
                },
                &SubscribePattern::new("home/events/*"),
                &event,
            ),
            super::LiveChangeAction::Accept
        );
    }

    #[test]
    fn process_local_replay_fence_drops_only_chain_events_at_or_below_floor() {
        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        let address = TimelineAddress::test_only_new(
            world.clone(),
            WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap(),
            TimelineSeq::new(11).unwrap(),
            BodySha256::for_body(b"value"),
        );
        let payload = AuditEventPayload::test_only(
            AuditEventKind::Put,
            world.clone(),
            BodySha256::for_body(b"value"),
            5,
            "text/plain",
        );
        let target = ChangeTarget::from_matched_timeline_address(&world, address, payload).unwrap();
        let event = event::ChangeEvent::new(
            ChangeDeliveryId::new(11),
            SubscriptionEpoch::new("0123456789abcdef0123456789abcdef").unwrap(),
            ChangeVerb::Replace,
            target,
            "hmac-test".to_owned(),
        );

        assert_eq!(
            super::live_change_action(
                &super::ReplayFence::ProcessLocal {
                    floor: ChangeDeliveryId::new(12),
                },
                &SubscribePattern::new("home/events/*"),
                &event,
            ),
            super::LiveChangeAction::Drop
        );
    }
}
