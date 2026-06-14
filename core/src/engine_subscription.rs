//! Public Engine subscription types.
//!
//! Kept separate from `engine_types.rs` so replay/live stream state does not
//! push the general Engine value types over the production-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::collections::VecDeque;

use tokio::sync::{broadcast, watch, OwnedSemaphorePermit};

use crate::engine_types::{ChangeVerb, ValidatedWorldPath};

/// Normalized subscription pattern matching the existing `/listen/*` grammar.
///
/// V1 supports exact matches plus a trailing `*` prefix wildcard. Regex or glob
/// metacharacters elsewhere are treated as literal bytes and may simply match no
/// worlds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribePattern(String);

/// Checked resume cursor for an Engine subscription.
///
/// Protocol adapters may parse raw wire values such as `Last-Event-ID`, but
/// core replay code only accepts this named type so a naked event id cannot be
/// confused with a timeline sequence, audit row id, or byte offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionResume {
    after_event_id: Option<u64>,
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
    /// subscriptions.
    pub id: u64,
    /// Engine mutation that produced the change.
    pub verb: ChangeVerb,
    /// Canonical world path the change applies to.
    pub path: ValidatedWorldPath,
    /// Strong ETag after the change (empty string for [`ChangeVerb::Delete`]).
    pub etag: String,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        let canonical = value.path.trim_start_matches('/').to_owned();
        let path = ValidatedWorldPath::from_canonical(canonical)
            .expect("listen events are emitted only for validated world paths");
        Self::new(value.id, value.verb, path, value.etag)
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

impl SubscriptionResume {
    /// Starts a fresh live subscription with no replay cursor.
    pub fn none() -> Self {
        Self {
            after_event_id: None,
        }
    }

    /// Replays events after `id` before switching to live delivery.
    pub fn after_event_id(id: u64) -> Self {
        Self {
            after_event_id: Some(id),
        }
    }

    pub(crate) fn after_event_id_raw(self) -> Option<u64> {
        self.after_event_id
    }

    pub(crate) fn is_replay(self) -> bool {
        self.after_event_id.is_some()
    }
}

impl ChangeEvent {
    pub(crate) fn new(id: u64, verb: ChangeVerb, path: ValidatedWorldPath, etag: String) -> Self {
        Self {
            id,
            verb,
            path,
            etag,
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
                                        && crate::event::matches(live.pattern.as_str(), &change.path) =>
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
mod tests {
    use super::SubscribePattern;

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
}
