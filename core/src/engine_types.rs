//! Public Engine value and proof types.
//!
//! These types are separated from `engine.rs` so the startup/builder logic and
//! the facade's data contracts remain reviewable under the 500-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{collections::VecDeque, fmt};

use bytes::Bytes;
use tokio::sync::{broadcast, watch, OwnedSemaphorePermit};

use crate::auth::{self, NonEmptyBytes};

/// HMAC key material for the audit chain.
///
/// Empty and all-whitespace keys are rejected. The key intentionally has no
/// public `Debug`, `Display`, or `AsRef<[u8]>` implementation.
pub struct SecretBytes {
    bytes: NonEmptyBytes,
}

/// Returned when a secret key constructor receives an empty or all-whitespace
/// byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyKeyError;

/// Canonical world key that passed Engine path validation.
///
/// This is not an HTTP path: adapters must decode and canonicalize their own
/// wire syntax before constructing this proof type. Bare names like `foo` and
/// wire paths like `/foo` are rejected; HTTP maps those to `home/foo` first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ValidatedWorldPath(String);

/// Returned when a world key cannot be represented as an Engine world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidWorldPath;

/// Normalized subscription pattern matching the existing `/listen/*` grammar.
///
/// V1 supports exact matches plus a trailing `*` prefix wildcard. Regex or glob
/// metacharacters elsewhere are treated as literal bytes and may simply match no
/// worlds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribePattern(String);

/// Access tier granted to a caller after token verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessTier {
    Anon,
    Read,
    Write,
    Approve,
}

/// Stored representation passed to write operations.
///
/// Header persistence policy belongs to adapters. The engine treats these
/// pairs as opaque metadata.
pub struct Representation {
    pub body: Bytes,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}

/// Protocol-neutral write preconditions.
pub struct Preconditions {
    pub if_match: Vec<EtagMatcher>,
    pub if_none_match: Vec<EtagMatcher>,
}

/// ETag matcher parsed by adapters before calling the engine.
#[non_exhaustive]
pub enum EtagMatcher {
    Any,
    Strong(String),
    Weak(String),
    Invalid,
}

/// Result of a successful full-representation read.
pub struct ReadResult {
    pub representation: Representation,
    pub etag: String,
}

/// Whether a write created a new world or updated an existing one.
#[non_exhaustive]
pub enum WriteKind {
    Created,
    Updated,
}

/// Result of a successful write.
pub struct WriteResult {
    pub kind: WriteKind,
    pub etag: String,
}

/// Protocol-neutral change event.
///
/// On targets with native 64-bit atomics, ids advance through the full `u64`
/// range via `AtomicU64`. On 32-bit targets without native 64-bit atomics, a
/// mutex-backed `u64` counter provides the same external id range. The counter
/// uses saturating increments, so `u64::MAX` is the rollover-imminent signal on
/// all platforms.
#[derive(Clone, Debug)]
pub struct ChangeEvent {
    pub id: u64,
    pub method: &'static str,
    pub path: ValidatedWorldPath,
    pub etag: String,
}

/// Subscription to protocol-neutral engine change events.
pub struct EngineSubscription {
    _slot: OwnedSemaphorePermit,
    replay: VecDeque<Result<ChangeEvent, SubscriptionRecvError>>,
    rx: broadcast::Receiver<crate::listen::ChangeEvent>,
    pattern: SubscribePattern,
    replay_mode: bool,
    live_floor: u64,
    shutdown: watch::Receiver<bool>,
    closed: bool,
}

/// Error returned by `EngineSubscription::recv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubscriptionRecvError {
    Closed,
    Lagged { skipped: u64 },
}

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, EmptyKeyError> {
        NonEmptyBytes::new(bytes)
            .map(|bytes| Self { bytes })
            .ok_or(EmptyKeyError)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, EmptyKeyError> {
        Self::new(bytes.to_vec())
    }

    /// Transfers the bytes out of the secret wrapper.
    ///
    /// After this call, wipe-on-drop responsibility belongs to the caller that
    /// owns the returned `Vec<u8>`. Today that caller is `Core::hmac_key`.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes.into_vec()
    }
}

impl ValidatedWorldPath {
    pub fn new(world: impl Into<String>) -> Result<Self, InvalidWorldPath> {
        Self::from_canonical(world.into()).map_err(|_| InvalidWorldPath)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_canonical(world: String) -> Result<Self, &'static str> {
        crate::path::validate_world_name(&world)?;
        if !has_canonical_namespace(&world) {
            return Err("world path missing canonical namespace prefix");
        }
        Ok(Self(world))
    }
}

fn has_canonical_namespace(world: &str) -> bool {
    matches!(
        world.split('/').next().unwrap_or(""),
        "home" | "tmp" | "dev" | "sys" | "etc" | "lib" | "boot" | "usr" | "var"
    )
}

impl fmt::Display for ValidatedWorldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for InvalidWorldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid world path")
    }
}

impl std::error::Error for InvalidWorldPath {}

impl From<crate::listen::ChangeEvent> for ChangeEvent {
    fn from(value: crate::listen::ChangeEvent) -> Self {
        let canonical = value.path.trim_start_matches('/').to_owned();
        let path = ValidatedWorldPath::from_canonical(canonical)
            .expect("listen events are emitted only for validated world paths");
        Self {
            id: value.id,
            method: value.method,
            path,
            etag: value.etag,
        }
    }
}

impl SubscribePattern {
    pub fn new(raw: impl AsRef<str>) -> Self {
        Self(crate::listen::pattern(raw.as_ref()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl EngineSubscription {
    pub(crate) fn new(
        slot: OwnedSemaphorePermit,
        replay: VecDeque<Result<ChangeEvent, SubscriptionRecvError>>,
        rx: broadcast::Receiver<crate::listen::ChangeEvent>,
        pattern: SubscribePattern,
        replay_mode: bool,
        live_floor: u64,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            _slot: slot,
            replay,
            rx,
            pattern,
            replay_mode,
            live_floor,
            shutdown,
            closed: false,
        }
    }

    /// Returns one event from replay or the live stream.
    ///
    /// `Lagged` is recoverable: subsequent calls continue with fresh live
    /// events. `Closed` is terminal.
    pub async fn recv(&mut self) -> Result<ChangeEvent, SubscriptionRecvError> {
        if self.closed {
            self.closed = true;
            return Err(SubscriptionRecvError::Closed);
        }
        if let Some(item) = self.replay.pop_front() {
            return item;
        }
        if *self.shutdown.borrow() {
            self.closed = true;
            return Err(SubscriptionRecvError::Closed);
        }

        loop {
            tokio::select! {
                changed = self.shutdown.changed() => {
                    self.closed = true;
                    let _ = changed;
                    return Err(SubscriptionRecvError::Closed);
                }
                item = self.rx.recv() => {
                    match item {
                        Ok(change)
                            if (!self.replay_mode || change.id > self.live_floor)
                                && crate::listen::matches(self.pattern.as_str(), &change.path) =>
                        {
                            return Ok(change.into());
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            return Err(SubscriptionRecvError::Lagged { skipped });
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            self.closed = true;
                            return Err(SubscriptionRecvError::Closed);
                        }
                    }
                }
            }
        }
    }
}

impl Preconditions {
    pub fn none() -> Self {
        Self {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        }
    }
}

impl From<auth::Tier> for AccessTier {
    fn from(tier: auth::Tier) -> Self {
        match tier {
            auth::Tier::Anon => Self::Anon,
            auth::Tier::Read => Self::Read,
            auth::Tier::Write => Self::Write,
            auth::Tier::Approve => Self::Approve,
        }
    }
}

impl fmt::Display for EmptyKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secret key must not be empty or all whitespace")
    }
}

impl std::error::Error for EmptyKeyError {}

#[cfg(test)]
mod tests {
    use super::{SubscribePattern, ValidatedWorldPath};

    #[test]
    fn validated_world_path_accepts_canonical_namespaced_worlds() {
        for world in [
            "home/jobs/42",
            "tmp/frame",
            "dev/gpio",
            "sys/status",
            "etc/config",
            "lib/blob",
            "boot/stage",
            "usr/tool",
            "var/log/deletes",
        ] {
            assert_eq!(ValidatedWorldPath::new(world).unwrap().as_str(), world);
        }
    }

    #[test]
    fn validated_world_path_rejects_wire_paths_and_bare_names() {
        assert!(ValidatedWorldPath::new("/home/jobs/42").is_err());
        assert!(ValidatedWorldPath::new("/foo").is_err());
        assert!(ValidatedWorldPath::new("foo").is_err());
        assert!(ValidatedWorldPath::new("home").is_err());
        assert!(ValidatedWorldPath::new("var/log").is_err());
        assert!(ValidatedWorldPath::new("proc/version").is_err());
        assert!(ValidatedWorldPath::new("home/../etc/key").is_err());
    }

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
