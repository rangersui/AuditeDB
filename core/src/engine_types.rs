//! Public Engine value and proof types.
//!
//! These types are separated from `engine.rs` so the startup/builder logic and
//! the facade's data contracts remain reviewable under the 500-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{collections::VecDeque, fmt};

use bytes::Bytes;
use tokio::sync::{broadcast, watch, OwnedSemaphorePermit};

use crate::auth::{self, NonEmptyBytes};

/// Minimum accepted audit-chain HMAC key length, in bytes.
///
/// RFC 2104 section 3 strongly discourages HMAC keys shorter than L, the hash
/// function output length. SHA-256 outputs 32 bytes, so 32 bytes is the
/// minimum. Shorter keys are rejected before a [`crate::Engine`] can be built,
/// so weak audit-chain keys are not representable as [`AuditHmacKey`].
pub const MIN_HMAC_KEY_BYTES: usize = 32;

/// Secret byte material with zeroing-on-drop behaviour.
///
/// Empty and all-whitespace keys are rejected. The key intentionally has no
/// public `Debug`, `Display`, or `AsRef<[u8]>` implementation.
pub struct SecretBytes {
    bytes: NonEmptyBytes,
}

/// HMAC key material strong enough for the audit chain.
///
/// This is the proof type accepted by [`crate::EngineBuilder::key`]. Callers
/// can only construct it through checked constructors, so a short HMAC key
/// cannot enter the Engine by accident.
pub struct AuditHmacKey {
    secret: SecretBytes,
}

/// Returned when a secret constructor receives an empty or all-whitespace byte
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyKeyError;

/// Returned when audit-chain HMAC key material is empty, whitespace, or too short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidHmacKey {
    /// The input was empty or all whitespace.
    Empty(EmptyKeyError),
    /// The input was shorter than [`MIN_HMAC_KEY_BYTES`].
    TooShort {
        /// Minimum accepted length in bytes.
        min: usize,
        /// Actual input length in bytes.
        actual: usize,
    },
}

/// Canonical world key that passed Engine path validation.
///
/// This is not a wire path: adapters must decode and canonicalize their own
/// syntax before constructing this proof type. Bare names like `foo` and
/// wire paths like `/foo` are rejected; adapters map those to canonical worlds
/// first.
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

/// Checked resume cursor for an Engine subscription.
///
/// Protocol adapters may parse raw wire values such as `Last-Event-ID`, but
/// core replay code only accepts this named type so a naked event id cannot be
/// confused with a timeline sequence, audit row id, or byte offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionResume {
    after_event_id: Option<u64>,
}

/// Access tier granted to a caller after token verification.
///
/// Tiers are linearly inclusive: `Approve` covers `Write`, `Write` covers
/// `Read`, `Read` covers `Anon`. Each engine operation declares the minimum
/// tier it requires; lower tiers fail with [`crate::EngineError::Auth`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessTier {
    /// No token presented. Allowed only on public reads when no read token
    /// is configured.
    Anon,
    /// Read token. Allowed: read, list, subscribe, audit verify.
    Read,
    /// Write token. Allowed: everything `Read` plus ordinary replace/append
    /// in `home/`, `tmp/`, `dev/`, `sys/`, and non-log `var/`.
    Write,
    /// Approve token. Allowed: everything `Write` plus delete + writes into
    /// protected namespaces (`etc/`, `lib/`, `boot/`, `usr/`, `var/log/`).
    Approve,
}

/// Stored representation passed to write operations.
///
/// Header persistence policy belongs to adapters. The engine treats these
/// pairs as opaque metadata and preserves their order as supplied.
#[non_exhaustive]
pub struct Representation {
    /// Opaque payload bytes stored verbatim.
    pub body: Bytes,
    /// MIME type recorded with the body.
    pub content_type: String,
    /// Arbitrary metadata header pairs. Header-name de-duplication and
    /// allow/deny policy belong to the adapter that constructs this struct.
    /// The engine stores and returns the vector order; it does not sort,
    /// normalize, or coalesce entries.
    ///
    /// Browser-facing adapters apply their own filtering because clients may
    /// execute metadata as policy. Other adapters may pass headers through as
    /// opaque key-value metadata.
    pub headers: Vec<(String, String)>,
}

/// Protocol-neutral write preconditions.
///
/// Use [`Preconditions::none`] to skip all checks. Multiple matchers within a
/// list are OR'd; the two lists are AND'd.
///
/// This is the embedded-library form of HTTP `If-Match` and `If-None-Match`.
/// A stale `If-Match` rejects the write with
/// [`crate::EngineError::PreconditionFailed`]. An `If-None-Match: *` style
/// matcher is represented as [`EtagMatcher::Any`] and rejects creation when the
/// world already exists.
#[non_exhaustive]
pub struct Preconditions {
    /// `If-Match`-style matchers. The write proceeds only if **any** matcher
    /// matches the current ETag.
    pub if_match: Vec<EtagMatcher>,
    /// `If-None-Match`-style matchers. The write proceeds only if **no**
    /// matcher matches the current ETag.
    pub if_none_match: Vec<EtagMatcher>,
}

/// ETag matcher parsed by adapters before calling the engine.
#[non_exhaustive]
pub enum EtagMatcher {
    /// Wildcard (`*`) — matches anything.
    Any,
    /// Strong ETag comparison; must match byte-for-byte.
    Strong(String),
    /// Weak ETag comparison; matches if the inner value matches either side
    /// (weak or strong).
    Weak(String),
    /// Adapter-side parse failure. Engine treats this as a never-match for
    /// `If-Match` (rejects the write) and always-match for `If-None-Match`
    /// (rejects the write).
    Invalid,
}

/// Parses a comma-separated ETag matcher list for protocol adapters.
///
/// Hidden because this is adapter plumbing, not the stable high-level Engine
/// shape. Keeping it here still gives every adapter one parser and one matcher
/// semantics instead of hand-rolled copies.
#[doc(hidden)]
pub fn parse_etag_matchers(raw: &str) -> Vec<EtagMatcher> {
    crate::etag::parse_etag_matchers(raw)
        .into_iter()
        .map(Into::into)
        .collect()
}

impl From<EtagMatcher> for crate::etag::EtagMatcher {
    fn from(value: EtagMatcher) -> Self {
        match value {
            EtagMatcher::Any => Self::Any,
            EtagMatcher::Strong(value) => Self::Strong(value),
            EtagMatcher::Weak(value) => Self::Weak(value),
            EtagMatcher::Invalid => Self::Invalid,
        }
    }
}

impl From<crate::etag::EtagMatcher> for EtagMatcher {
    fn from(value: crate::etag::EtagMatcher) -> Self {
        match value {
            crate::etag::EtagMatcher::Any => Self::Any,
            crate::etag::EtagMatcher::Strong(value) => Self::Strong(value),
            crate::etag::EtagMatcher::Weak(value) => Self::Weak(value),
            crate::etag::EtagMatcher::Invalid => Self::Invalid,
        }
    }
}

/// Result of a successful full-representation read.
#[non_exhaustive]
pub struct ReadResult {
    /// The stored representation (body + content-type + metadata headers).
    pub representation: Representation,
    /// Strong ETag for the returned representation.
    pub etag: String,
}

/// Whether a write created a new world or updated an existing one.
#[non_exhaustive]
pub enum WriteKind {
    /// Path did not exist before this write.
    Created,
    /// Path already existed; this write replaced or appended.
    Updated,
}

/// Kind of storage mutation that produced a change event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeVerb {
    /// Full representation replacement.
    Replace,
    /// Payload append.
    Append,
    /// World deletion.
    Delete,
}

/// Result of a successful write.
#[non_exhaustive]
pub struct WriteResult {
    /// Whether the write created a new world or updated an existing one.
    pub kind: WriteKind,
    /// Strong ETag for the new representation.
    pub etag: String,
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

impl SecretBytes {
    /// Wraps owned bytes as secret material.
    ///
    /// # Errors
    /// Returns [`EmptyKeyError`] if the byte slice is empty or all whitespace.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, EmptyKeyError> {
        NonEmptyBytes::new(bytes)
            .map(|bytes| Self { bytes })
            .ok_or(EmptyKeyError)
    }

    /// Copies the slice and wraps it as secret material.
    ///
    /// # Errors
    /// Returns [`EmptyKeyError`] if the slice is empty or all whitespace.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, EmptyKeyError> {
        Self::new(bytes.to_vec())
    }

    /// Borrows the secret bytes for immediate cryptographic use.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates an owned secret copy for `'static` blocking jobs.
    pub(crate) fn clone_secret(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

impl AuditHmacKey {
    /// Wraps owned bytes as an audit-chain HMAC key.
    ///
    /// # Errors
    /// Returns [`InvalidHmacKey`] if the byte slice is empty, all whitespace,
    /// or shorter than [`MIN_HMAC_KEY_BYTES`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, InvalidHmacKey> {
        let secret = SecretBytes::new(bytes).map_err(InvalidHmacKey::Empty)?;
        let actual = secret.as_slice().len();
        if actual < MIN_HMAC_KEY_BYTES {
            return Err(InvalidHmacKey::TooShort {
                min: MIN_HMAC_KEY_BYTES,
                actual,
            });
        }
        Ok(Self { secret })
    }

    /// Copies the slice and wraps it as an audit-chain HMAC key.
    ///
    /// # Errors
    /// Returns [`InvalidHmacKey`] if the slice is empty, all whitespace, or
    /// shorter than [`MIN_HMAC_KEY_BYTES`].
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, InvalidHmacKey> {
        Self::new(bytes.to_vec())
    }

    /// Borrows the key bytes for immediate cryptographic use.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Creates an owned key copy for `'static` blocking jobs.
    pub(crate) fn clone_secret(&self) -> Self {
        Self {
            secret: self.secret.clone_secret(),
        }
    }
}

impl ValidatedWorldPath {
    /// Validates `world` as a canonical engine path.
    ///
    /// Accepts canonical names like `home/foo` or `var/log/deletes`. Rejects
    /// wire paths (`/foo`), bare names (`foo`), unknown namespaces, and any
    /// path with `.`/`..` segments.
    ///
    /// # Errors
    /// Returns [`InvalidWorldPath`] if validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "unstable-engine")]
    /// # fn run() {
    /// use elastik_core::ValidatedWorldPath;
    ///
    /// assert_eq!(
    ///     ValidatedWorldPath::new("home/jobs/42").unwrap().as_str(),
    ///     "home/jobs/42",
    /// );
    /// assert!(ValidatedWorldPath::new("/home/jobs/42").is_err());
    /// assert!(ValidatedWorldPath::new("jobs/42").is_err());
    /// assert!(ValidatedWorldPath::new("home").is_err());
    /// assert!(ValidatedWorldPath::new("proc/version").is_err());
    /// # }
    /// ```
    pub fn new(world: impl Into<String>) -> Result<Self, InvalidWorldPath> {
        Self::from_canonical(world.into()).map_err(|_| InvalidWorldPath)
    }

    /// Returns the canonical string representation (no leading slash).
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
    crate::path::NAMESPACE_PREFIXES.contains(&world.split('/').next().unwrap_or(""))
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

impl Representation {
    /// Builds a stored representation from payload bytes, content type, and
    /// adapter-supplied metadata headers.
    pub fn new(
        body: impl Into<Bytes>,
        content_type: impl Into<String>,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            body: body.into(),
            content_type: content_type.into(),
            headers,
        }
    }
}

impl ReadResult {
    pub(crate) fn new(representation: Representation, etag: String) -> Self {
        Self {
            representation,
            etag,
        }
    }
}

impl WriteResult {
    pub(crate) fn new(kind: WriteKind, etag: String) -> Self {
        Self { kind, etag }
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

impl Preconditions {
    /// Builds protocol-neutral write preconditions from matcher lists.
    pub fn new(if_match: Vec<EtagMatcher>, if_none_match: Vec<EtagMatcher>) -> Self {
        Self {
            if_match,
            if_none_match,
        }
    }

    /// Returns a [`Preconditions`] value with both lists empty (no checks).
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

impl fmt::Display for InvalidHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(err) => err.fmt(f),
            Self::TooShort { min, actual } => {
                write!(f, "HMAC key must be at least {min} bytes; got {actual}")
            }
        }
    }
}

impl std::error::Error for InvalidHmacKey {}

#[cfg(test)]
mod tests {
    use super::{
        AuditHmacKey, EtagMatcher, InvalidHmacKey, Preconditions, Representation, SecretBytes,
        SubscribePattern, ValidatedWorldPath, MIN_HMAC_KEY_BYTES,
    };
    use bytes::Bytes;

    #[test]
    fn audit_hmac_key_rejects_empty_whitespace_and_short_keys() {
        assert!(matches!(
            AuditHmacKey::try_from_slice(b""),
            Err(InvalidHmacKey::Empty(_))
        ));
        assert!(matches!(
            AuditHmacKey::try_from_slice(b" \t\r\n"),
            Err(InvalidHmacKey::Empty(_))
        ));
        match AuditHmacKey::try_from_slice(b"short") {
            Err(err) => assert_eq!(
                err,
                InvalidHmacKey::TooShort {
                    min: MIN_HMAC_KEY_BYTES,
                    actual: 5,
                }
            ),
            Ok(_) => panic!("short HMAC key should be rejected"),
        }
        assert!(matches!(
            AuditHmacKey::try_from_slice(b"0123456789abcdef0123456789abcde"),
            Err(InvalidHmacKey::TooShort {
                min: MIN_HMAC_KEY_BYTES,
                actual: 31,
            })
        ));
        assert!(AuditHmacKey::try_from_slice(b"0123456789abcdef0123456789abcdef").is_ok());

        // SecretBytes remains a generic zeroing container; it is not proof
        // that bytes are strong enough for the audit-chain HMAC key.
        assert!(SecretBytes::try_from_slice(b"short").is_ok());
    }

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

    #[test]
    fn representation_constructor_sets_all_public_fields() {
        let repr = Representation::new(
            Bytes::from_static(b"hello"),
            "text/plain",
            vec![("x-meta-project".to_string(), "demo".to_string())],
        );

        assert_eq!(repr.body, Bytes::from_static(b"hello"));
        assert_eq!(repr.content_type, "text/plain");
        assert_eq!(
            repr.headers,
            vec![("x-meta-project".to_string(), "demo".to_string())]
        );
    }

    #[test]
    fn preconditions_constructor_sets_matcher_lists() {
        let preconditions = Preconditions::new(
            vec![EtagMatcher::Strong("abc".to_string())],
            vec![EtagMatcher::Any],
        );

        assert!(matches!(
            preconditions.if_match.as_slice(),
            [EtagMatcher::Strong(value)] if value == "abc"
        ));
        assert!(matches!(
            preconditions.if_none_match.as_slice(),
            [EtagMatcher::Any]
        ));
    }
}
