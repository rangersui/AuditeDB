//! Subscription pattern and resume types.
//!
//! Production resume uses durable audit-chain event ids from
//! `subscription_event_id`. The process-local cursor parser in this module is
//! test-only; it exists to keep legacy ring-replay fixtures from looking like
//! production protocol.

use std::fmt;

use crate::engine_types::ValidatedWorldPath;
#[cfg(test)]
use crate::event::ChangeDeliveryId;
use crate::subscription_event_id::SubscriptionEventId;

/// Normalized subscription pattern matching the existing `/listen/*` grammar.
///
/// V1 supports exact matches plus a trailing `*` prefix wildcard. Regex or glob
/// metacharacters elsewhere are treated as literal bytes and may simply match no
/// worlds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribePattern(String);

/// Process-local id space for subscription delivery events.
///
/// Event ids are monotonic only within one running [`crate::Engine`]. The epoch
/// remains on internal live events so replay splice code can distinguish
/// process-local ordering from durable audit-chain coordinates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SubscriptionEpoch(String);

/// Returned when a subscription epoch string is malformed.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSubscriptionEpoch {
    /// Epochs are rendered as 16 random bytes encoded to 32 hex characters.
    WrongLength,
    /// Epochs must use lowercase hexadecimal.
    NotLowerHex,
}

/// Opaque resume cursor for protocol adapters.
///
/// Rendered as `<32 lowercase hex epoch>:<decimal event id>`. The decimal
/// suffix is still useful for in-process ordering, but it is not a complete
/// identity without the epoch.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubscriptionCursor {
    epoch: SubscriptionEpoch,
    event_id: u64,
}

/// Returned when an SSE cursor string is malformed.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSubscriptionCursor {
    /// The cursor did not contain the `:` delimiter.
    MissingDelimiter,
    /// The epoch portion was malformed.
    Epoch(InvalidSubscriptionEpoch),
    /// The event id portion was empty.
    EmptyEventId,
    /// The event id portion was not decimal.
    EventIdNotDecimal,
    /// The event id did not fit in a `u64`.
    EventIdOutOfRange,
    /// The event id was not in canonical decimal form.
    EventIdNonCanonical,
}

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
    #[cfg(test)]
    CurrentProcess {
        event_id: ChangeDeliveryId,
    },
    Durable(SubscriptionEventId),
    #[cfg(test)]
    LegacyDecimal {
        event_id: u64,
    },
}

pub(crate) enum ReplayPlan {
    None,
    Durable {
        event_id: SubscriptionEventId,
    },
    #[cfg(test)]
    Current {
        event_id: ChangeDeliveryId,
    },
    #[cfg(test)]
    Foreign {
        event_id: u64,
    },
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
    /// use l5::SubscribePattern;
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

    pub(crate) fn exact_world(&self) -> Result<Option<ValidatedWorldPath>, &'static str> {
        if self.0 == "*" || self.0.ends_with('*') {
            return Ok(None);
        }
        let world = self.0.strip_prefix('/').unwrap_or(&self.0);
        ValidatedWorldPath::from_canonical(world.to_owned()).map(Some)
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
    #[cfg(test)]
    pub(crate) fn new(raw: impl Into<String>) -> Result<Self, InvalidSubscriptionEpoch> {
        let raw = raw.into();
        if raw.len() != 32 {
            return Err(InvalidSubscriptionEpoch::WrongLength);
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidSubscriptionEpoch::NotLowerHex);
        }
        Ok(Self(raw))
    }

    /// Returns the lowercase-hex epoch string.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
impl fmt::Display for InvalidSubscriptionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => f.write_str("subscription epoch has wrong length"),
            Self::NotLowerHex => f.write_str("subscription epoch is not lower hex"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for InvalidSubscriptionEpoch {}

#[cfg(test)]
impl SubscriptionCursor {
    /// Parses an opaque SSE event id produced by the Engine.
    ///
    /// # Errors
    /// Returns [`InvalidSubscriptionCursor`] unless `raw` is
    /// `<32 lowercase hex epoch>:<canonical decimal event id>`.
    pub(crate) fn from_sse_id(raw: impl AsRef<str>) -> Result<Self, InvalidSubscriptionCursor> {
        let raw = raw.as_ref();
        let Some((epoch, event_id)) = raw.split_once(':') else {
            return Err(InvalidSubscriptionCursor::MissingDelimiter);
        };
        let epoch = SubscriptionEpoch::new(epoch).map_err(InvalidSubscriptionCursor::Epoch)?;
        if event_id.is_empty() {
            return Err(InvalidSubscriptionCursor::EmptyEventId);
        }
        if !event_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidSubscriptionCursor::EventIdNotDecimal);
        }
        let parsed = event_id
            .parse::<u64>()
            .map_err(|_| InvalidSubscriptionCursor::EventIdOutOfRange)?;
        if event_id != parsed.to_string() {
            return Err(InvalidSubscriptionCursor::EventIdNonCanonical);
        }
        Ok(Self {
            epoch,
            event_id: parsed,
        })
    }

    /// Returns the epoch component of this cursor.
    pub(crate) fn epoch(&self) -> &SubscriptionEpoch {
        &self.epoch
    }

    /// Returns the event id component of this cursor.
    pub(crate) fn event_id(&self) -> u64 {
        self.event_id
    }
}

#[cfg(test)]
impl fmt::Display for SubscriptionCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.epoch, self.event_id)
    }
}

#[cfg(test)]
impl fmt::Display for InvalidSubscriptionCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDelimiter => f.write_str("subscription cursor is missing delimiter"),
            Self::Epoch(err) => write!(f, "invalid subscription cursor epoch: {err}"),
            Self::EmptyEventId => f.write_str("subscription cursor event id is empty"),
            Self::EventIdNotDecimal => f.write_str("subscription cursor event id is not decimal"),
            Self::EventIdOutOfRange => f.write_str("subscription cursor event id is out of range"),
            Self::EventIdNonCanonical => {
                f.write_str("subscription cursor event id is not canonical")
            }
        }
    }
}

#[cfg(test)]
impl std::error::Error for InvalidSubscriptionCursor {}

impl SubscriptionResume {
    /// Starts a fresh live subscription with no replay cursor.
    pub fn none() -> Self {
        Self {
            kind: SubscriptionResumeKind::None,
        }
    }

    /// Requests replay after a durable subscription event id.
    ///
    /// The id names an audit-chain row. It is not a process-local broadcast
    /// counter, so adapters can persist it across reconnects. Exact-world
    /// subscriptions can replay from the durable chain; wildcard subscriptions
    /// can only replay ids that are still in this process's live ring.
    pub fn after_event_id(event_id: SubscriptionEventId) -> Self {
        Self {
            kind: SubscriptionResumeKind::Durable(event_id),
        }
    }

    /// Test-only constructor for process-local replay fixtures.
    #[cfg(test)]
    pub(crate) fn test_only_after_process_event_id(id: u64) -> Self {
        Self {
            kind: SubscriptionResumeKind::CurrentProcess {
                event_id: ChangeDeliveryId::new(id),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_legacy_event_id(id: u64) -> Self {
        Self {
            kind: SubscriptionResumeKind::LegacyDecimal { event_id: id },
        }
    }

    pub(crate) fn replay_plan(&self, _current_epoch: &SubscriptionEpoch) -> ReplayPlan {
        match &self.kind {
            SubscriptionResumeKind::None => ReplayPlan::None,
            SubscriptionResumeKind::Durable(event_id) => ReplayPlan::Durable {
                event_id: event_id.clone(),
            },
            #[cfg(test)]
            SubscriptionResumeKind::CurrentProcess { event_id } => ReplayPlan::Current {
                event_id: *event_id,
            },
            #[cfg(test)]
            SubscriptionResumeKind::LegacyDecimal { event_id } => ReplayPlan::Foreign {
                event_id: *event_id,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        InvalidSubscriptionCursor, InvalidSubscriptionEpoch, SubscribePattern, SubscriptionCursor,
        SubscriptionEpoch,
    };

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
    fn exact_world_reports_validation_errors() {
        assert_eq!(
            SubscribePattern::new("home/jobs/42")
                .exact_world()
                .unwrap()
                .unwrap()
                .as_str(),
            "home/jobs/42"
        );
        assert!(
            SubscribePattern::new("proc/version").exact_world().is_err(),
            "malformed exact patterns must not be silently routed as wildcard replay"
        );
        assert!(SubscribePattern::new("home/jobs/*")
            .exact_world()
            .unwrap()
            .is_none());
    }

    #[test]
    fn subscription_cursor_requires_epoch_and_canonical_decimal() {
        let cursor = SubscriptionCursor::from_sse_id("0123456789abcdef0123456789abcdef:42")
            .expect("canonical cursor parses");
        assert_eq!(cursor.epoch().as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(cursor.event_id(), 42);
        assert_eq!(cursor.to_string(), "0123456789abcdef0123456789abcdef:42");

        assert_eq!(
            SubscriptionEpoch::new("0123456789abcdef0123456789abcdeF").unwrap_err(),
            InvalidSubscriptionEpoch::NotLowerHex
        );
    }

    #[test]
    fn subscription_cursor_reports_exact_malformed_reason() {
        let good_epoch = "0123456789abcdef0123456789abcdef";
        for (value, expected) in [
            ("42", InvalidSubscriptionCursor::MissingDelimiter),
            (
                "0123456789abcdef0123456789abcde:42",
                InvalidSubscriptionCursor::Epoch(InvalidSubscriptionEpoch::WrongLength),
            ),
            (
                "0123456789abcdef0123456789abcdeF:42",
                InvalidSubscriptionCursor::Epoch(InvalidSubscriptionEpoch::NotLowerHex),
            ),
            (
                "0123456789abcdef0123456789abcdef:",
                InvalidSubscriptionCursor::EmptyEventId,
            ),
            (
                "0123456789abcdef0123456789abcdef:x",
                InvalidSubscriptionCursor::EventIdNotDecimal,
            ),
            (
                "0123456789abcdef0123456789abcdef:18446744073709551616",
                InvalidSubscriptionCursor::EventIdOutOfRange,
            ),
            (
                "0123456789abcdef0123456789abcdef:0042",
                InvalidSubscriptionCursor::EventIdNonCanonical,
            ),
        ] {
            assert_eq!(
                SubscriptionCursor::from_sse_id(value).unwrap_err(),
                expected
            );
        }

        assert_eq!(
            SubscriptionCursor::from_sse_id(format!("{good_epoch}:0"))
                .unwrap()
                .event_id(),
            0
        );
    }
}
