//! Public Engine value and proof types.
//!
//! These types are separated from `engine.rs` so the startup/builder logic and
//! the facade's data contracts remain reviewable under the 500-line budget.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::fmt;

use bytes::Bytes;

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AuditHmacKey, EtagMatcher, InvalidHmacKey, Preconditions, Representation, SecretBytes,
        ValidatedWorldPath, MIN_HMAC_KEY_BYTES,
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
