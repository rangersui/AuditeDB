//! Public Engine subscription types.
//!
//! Kept separate from `engine_types.rs` so replay/live stream state does not
//! push the general Engine value types over the production-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{collections::VecDeque, fmt};

use tokio::sync::{broadcast, watch, OwnedSemaphorePermit};

use crate::{
    engine_types::{ChangeVerb, ValidatedWorldPath},
    timeline::TimelineAddress,
};

/// Normalized subscription pattern matching the existing `/listen/*` grammar.
///
/// V1 supports exact matches plus a trailing `*` prefix wildcard. Regex or glob
/// metacharacters elsewhere are treated as literal bytes and may simply match no
/// worlds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribePattern(String);

/// Process-local id space for subscription cursors.
///
/// Event ids are monotonic only within one running [`crate::Engine`]. The
/// epoch makes cursor strings opaque across restarts so adapters cannot
/// accidentally treat a fresh process's `id=5` as the old process's `id=5`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionEpoch(String);

/// Returned when a subscription epoch string is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSubscriptionEpoch;

/// Opaque resume cursor for protocol adapters.
///
/// Rendered as `<32 lowercase hex epoch>:<decimal event id>`. The decimal
/// suffix is still useful for in-process ordering, but it is not a complete
/// identity without the epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionCursor {
    epoch: SubscriptionEpoch,
    event_id: u64,
}

/// Returned when an SSE cursor string is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSubscriptionCursor;

/// Checked resume cursor for an Engine subscription.
///
/// Protocol adapters may parse raw wire values such as `Last-Event-ID`, but
/// core replay code only accepts this named type so a naked event id cannot be
/// confused with a timeline sequence, audit row id, or byte offset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionResume {
    kind: SubscriptionResumeKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum SubscriptionResumeKind {
    #[default]
    None,
    CurrentProcess {
        event_id: u64,
    },
    Cursor(SubscriptionCursor),
    LegacyDecimal {
        event_id: u64,
    },
}

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
    /// Monotonically increasing event id. Use this as `since` for resumed
    /// in-process subscriptions only; wire protocols should persist
    /// [`ChangeEvent::cursor`] instead.
    pub id: u64,
    /// Process-local id space that produced this event id.
    pub listen_epoch: SubscriptionEpoch,
    /// Opaque cursor safe to render as an SSE `id`.
    pub cursor: SubscriptionCursor,
    /// Engine mutation that produced the change.
    pub verb: ChangeVerb,
    /// Canonical world path the change applies to.
    pub path: ValidatedWorldPath,
    /// Strong ETag after the change (empty string for [`ChangeVerb::Delete`]).
    pub etag: String,
    /// Audited body address for durable replace/append events.
    ///
    /// `None` for transient memory writes and delete events.
    pub timeline_address: Option<TimelineAddress>,
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
    replay_mode: bool,
    live_floor: u64,
}

struct LiveSubscription {
    rx: broadcast::Receiver<crate::event::ChangeEvent>,
    pattern: SubscribePattern,
    replay_mode: bool,
    live_floor: u64,
    shutdown: watch::Receiver<bool>,
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
    /// The subscriber's resume cursor is ahead of every id this engine process
    /// has issued.
    ///
    /// Listen ids are process-local, so this usually means the cursor was
    /// saved before an engine restart. The subscription continues live after
    /// this error; callers must discard or rebase the stale cursor.
    CursorAhead {
        /// Cursor presented by the subscriber.
        since: u64,
        /// Newest event id issued by this engine process when the
        /// subscription was opened.
        newest: u64,
        /// Cursor in this process's id space that adapters may use to rebase
        /// automatic reconnect state.
        reset: SubscriptionCursor,
    },
}

impl DeferredLiveSubscription {
    fn with_shutdown(self, shutdown: watch::Receiver<bool>) -> LiveSubscription {
        LiveSubscription {
            rx: self.rx,
            pattern: self.pattern,
            replay_mode: self.replay_mode,
            live_floor: self.live_floor,
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
        Self::new(
            value.id,
            value.listen_epoch,
            value.verb,
            value.path,
            value.etag,
            value.timeline_address,
        )
    }
}

impl SubscribePattern {
    /// Normalizes `raw` into a subscription pattern.
    ///
    /// Empty / `/` / `*` all collapse to the catch-all `*`. Other inputs are
    /// prefixed with `/` if not already present. Trailing `*` is the only
    /// wildcard supported.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "unstable-engine")]
    /// # fn run() {
    /// use elastik_core::SubscribePattern;
    ///
    /// assert_eq!(SubscribePattern::new("").as_str(), "*");
    /// assert_eq!(SubscribePattern::new("/").as_str(), "*");
    /// assert_eq!(SubscribePattern::new("home/tasks").as_str(), "/home/tasks");
    /// assert_eq!(SubscribePattern::new("/home/tasks/*").as_str(), "/home/tasks/*");
    /// # }
    /// ```
    pub fn new(raw: impl AsRef<str>) -> Self {
        Self(crate::event::pattern(raw.as_ref()))
    }

    /// Returns the normalized pattern string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SubscriptionEpoch {
    pub(crate) fn mint() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(hex::encode(bytes)))
    }

    /// Parses a 128-bit lowercase-hex subscription epoch.
    ///
    /// # Errors
    /// Returns [`InvalidSubscriptionEpoch`] unless `raw` is exactly 32
    /// lowercase hexadecimal characters.
    pub fn new(raw: impl Into<String>) -> Result<Self, InvalidSubscriptionEpoch> {
        let raw = raw.into();
        if raw.len() != 32
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidSubscriptionEpoch);
        }
        Ok(Self(raw))
    }

    /// Returns the lowercase-hex epoch string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for InvalidSubscriptionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid subscription epoch")
    }
}

impl std::error::Error for InvalidSubscriptionEpoch {}

impl SubscriptionCursor {
    pub(crate) fn new(epoch: SubscriptionEpoch, event_id: u64) -> Self {
        Self { epoch, event_id }
    }

    /// Parses an opaque SSE event id produced by the Engine.
    ///
    /// # Errors
    /// Returns [`InvalidSubscriptionCursor`] unless `raw` is
    /// `<32 lowercase hex epoch>:<canonical decimal event id>`.
    pub fn from_sse_id(raw: impl AsRef<str>) -> Result<Self, InvalidSubscriptionCursor> {
        let raw = raw.as_ref();
        let Some((epoch, event_id)) = raw.split_once(':') else {
            return Err(InvalidSubscriptionCursor);
        };
        let epoch = SubscriptionEpoch::new(epoch).map_err(|_| InvalidSubscriptionCursor)?;
        if event_id.is_empty() || !event_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidSubscriptionCursor);
        }
        let parsed = event_id
            .parse::<u64>()
            .map_err(|_| InvalidSubscriptionCursor)?;
        if event_id != parsed.to_string() {
            return Err(InvalidSubscriptionCursor);
        }
        Ok(Self {
            epoch,
            event_id: parsed,
        })
    }

    /// Returns the epoch component of this cursor.
    pub fn epoch(&self) -> &SubscriptionEpoch {
        &self.epoch
    }

    /// Returns the event id component of this cursor.
    pub fn event_id(&self) -> u64 {
        self.event_id
    }
}

impl fmt::Display for SubscriptionCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.epoch, self.event_id)
    }
}

impl fmt::Display for InvalidSubscriptionCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid subscription cursor")
    }
}

impl std::error::Error for InvalidSubscriptionCursor {}

impl SubscriptionResume {
    /// Starts a fresh live subscription with no replay cursor.
    pub fn none() -> Self {
        Self {
            kind: SubscriptionResumeKind::None,
        }
    }

    /// Replays events after `id` before switching to live delivery.
    ///
    /// This constructor is for in-process callers that obtained `id` from the
    /// same running [`crate::Engine`]. Wire adapters should persist
    /// [`ChangeEvent::cursor`] and resume with [`SubscriptionResume::after_cursor`].
    pub fn after_event_id(id: u64) -> Self {
        Self {
            kind: SubscriptionResumeKind::CurrentProcess { event_id: id },
        }
    }

    /// Replays events after an opaque cursor before switching to live delivery.
    pub fn after_cursor(cursor: SubscriptionCursor) -> Self {
        Self {
            kind: SubscriptionResumeKind::Cursor(cursor),
        }
    }

    #[doc(hidden)]
    pub fn legacy_event_id(id: u64) -> Self {
        Self {
            kind: SubscriptionResumeKind::LegacyDecimal { event_id: id },
        }
    }

    pub(crate) fn replay_plan(&self, current_epoch: &SubscriptionEpoch) -> ReplayPlan {
        match &self.kind {
            SubscriptionResumeKind::None => ReplayPlan::None,
            SubscriptionResumeKind::CurrentProcess { event_id } => ReplayPlan::Current {
                event_id: *event_id,
            },
            SubscriptionResumeKind::Cursor(cursor) if cursor.epoch() == current_epoch => {
                ReplayPlan::Current {
                    event_id: cursor.event_id(),
                }
            }
            SubscriptionResumeKind::Cursor(cursor) => ReplayPlan::Foreign {
                event_id: cursor.event_id(),
            },
            SubscriptionResumeKind::LegacyDecimal { event_id } => ReplayPlan::Foreign {
                event_id: *event_id,
            },
        }
    }
}

pub(crate) enum ReplayPlan {
    None,
    Current { event_id: u64 },
    Foreign { event_id: u64 },
}

impl ReplayPlan {
    pub(crate) fn is_current_replay(&self) -> bool {
        matches!(self, Self::Current { .. })
    }
}

impl ChangeEvent {
    pub(crate) fn new(
        id: u64,
        listen_epoch: SubscriptionEpoch,
        verb: ChangeVerb,
        path: ValidatedWorldPath,
        etag: String,
        timeline_address: Option<TimelineAddress>,
    ) -> Self {
        let cursor = SubscriptionCursor::new(listen_epoch.clone(), id);
        Self {
            id,
            listen_epoch,
            cursor,
            verb,
            path,
            etag,
            timeline_address,
        }
    }
}

impl EngineSubscription {
    pub(crate) fn new(
        slot: OwnedSemaphorePermit,
        replay: VecDeque<Result<ChangeEvent, SubscriptionRecvError>>,
        rx: broadcast::Receiver<crate::event::ChangeEvent>,
        pattern: SubscribePattern,
        replay_mode: bool,
        live_floor: u64,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let live = DeferredLiveSubscription {
            rx,
            pattern,
            replay_mode,
            live_floor,
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
    /// Drains the replay queue first (in increasing event id order), then
    /// switches to the live broadcast stream. If the caller passed `since` to
    /// [`crate::Engine::subscribe`], events with id `<= since` are filtered,
    /// unless `since` is ahead of this process's id space; in that case
    /// [`SubscriptionRecvError::CursorAhead`] is yielded first and no stale
    /// floor is applied to following live events.
    ///
    /// # Errors
    /// - [`SubscriptionRecvError::Closed`] when the engine shut down or the
    ///   underlying channel closed. Terminal: subsequent calls keep
    ///   returning `Closed`.
    /// - [`SubscriptionRecvError::Lagged`] when the broadcast ring buffer
    ///   overflowed and events were lost. Recoverable: the next call resumes
    ///   with fresh events.
    /// - [`SubscriptionRecvError::CursorAhead`] when `since` points past the
    ///   newest id this process has issued. Recoverable: the next call resumes
    ///   with fresh live events.
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
                                Ok(change)
                                    if (!live.replay_mode || change.id > live.live_floor)
                                        && crate::event::matches_world(live.pattern.as_str(), &change.path) =>
                                {
                                    self.state = SubscriptionState::Live(live);
                                    return Ok(change.into());
                                }
                                Ok(_) => {
                                    self.state = SubscriptionState::Live(live);
                                }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{SubscribePattern, SubscriptionCursor, SubscriptionEpoch};

    #[test]
    fn subscribe_pattern_normalizes_once_at_entry() {
        assert_eq!(SubscribePattern::new("").as_str(), "*");
        assert_eq!(SubscribePattern::new("/").as_str(), "*");
        assert_eq!(SubscribePattern::new("*").as_str(), "*");
        assert_eq!(
            SubscribePattern::new("home/jobs/*").as_str(),
            "/home/jobs/*"
        );
        assert_eq!(
            SubscribePattern::new("/home/jobs/*").as_str(),
            "/home/jobs/*"
        );
    }

    #[test]
    fn subscription_cursor_requires_epoch_and_canonical_decimal() {
        let cursor = SubscriptionCursor::from_sse_id("0123456789abcdef0123456789abcdef:42")
            .expect("canonical cursor parses");
        assert_eq!(cursor.epoch().as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(cursor.event_id(), 42);
        assert_eq!(cursor.to_string(), "0123456789abcdef0123456789abcdef:42");

        assert!(SubscriptionEpoch::new("0123456789abcdef0123456789abcdeF").is_err());
        assert!(SubscriptionCursor::from_sse_id("42").is_err());
        assert!(SubscriptionCursor::from_sse_id("0123456789abcdef0123456789abcdef:0042").is_err());
    }
}
