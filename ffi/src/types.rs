use std::{collections::BTreeMap, fmt};

use elastik_core::{
    is_valid_token, AccessTier, AuditVerify, AuthGate, ChangeEvent, ChangeVerb, DeleteMetadata,
    DfSnapshot, EngineBuildError, EngineError, EtagMatcher, PoolSnapshot, Preconditions,
    ReadResult, Representation, SubscriptionResume, WorldUsage, WriteKind, WriteResult,
};

/// Engine construction options for the FFI adapter.
#[derive(Clone, uniffi::Record)]
pub struct FfiEngineConfig {
    pub data_root: String,
    pub hmac_key: Vec<u8>,
    pub read_token: Option<Vec<u8>>,
    pub write_token: Option<Vec<u8>>,
    pub approve_token: Option<Vec<u8>>,
    pub max_world_bytes: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub max_storage_bytes: Option<u64>,
    pub max_listen_connections: Option<u64>,
    pub listen_replay_max: Option<u64>,
    pub read_cache_max_entries: Option<u64>,
}

/// Non-secret Engine settings accepted by the FFI adapter.
///
/// Optional numeric fields are overrides: `None` means the Engine default (or
/// unlimited storage for `max_storage_bytes`). Zero values are normalized to
/// `None` only for Engine fields that treat zero as "use the default";
/// `max_world_bytes` and `max_memory_bytes` keep literal zero caps.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiEngineConfigSummary {
    pub data_root: String,
    pub has_read_token: bool,
    pub has_write_token: bool,
    pub has_approve_token: bool,
    pub max_world_bytes: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub max_storage_bytes: Option<u64>,
    pub max_listen_connections: Option<u64>,
    pub listen_replay_max: Option<u64>,
    pub read_cache_max_entries: Option<u64>,
}

/// Caller access tier after token verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAccessTier {
    Anon,
    Read,
    Write,
    Approve,
    /// The Engine returned a tier this FFI binding does not yet recognize.
    /// Treat as deny-by-default and upgrade the binding.
    Unknown,
}

/// Engine auth gate that rejected an FFI operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAuthGate {
    Read,
    Write,
    WriteApprove,
    Delete,
    /// The Engine returned an auth gate this FFI binding does not yet recognize.
    /// Treat as deny-by-default and upgrade the binding.
    Unknown,
}

impl fmt::Display for FfiAuthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::WriteApprove => "write-approve",
            Self::Delete => "delete",
            Self::Unknown => "unknown",
        })
    }
}

/// Stored metadata header pair.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiHeader {
    pub name: String,
    pub value: String,
}

/// ETag matcher used by FFI write preconditions.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiEtagMatcher {
    Any,
    Strong { etag: String },
    Weak { etag: String },
}

/// Protocol-neutral write preconditions.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPreconditions {
    pub if_match: Vec<FfiEtagMatcher>,
    pub if_none_match: Vec<FfiEtagMatcher>,
}

/// Stored representation passed through Engine read/write verbs.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiRepresentation {
    pub body: Vec<u8>,
    pub content_type: String,
    pub headers: Vec<FfiHeader>,
}

/// Representation metadata recorded in DELETE audit intent/commit events.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDeleteMetadata {
    pub content_type: String,
    pub headers: Vec<FfiHeader>,
}

/// Read result DTO returned by Engine read.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiReadResult {
    pub representation: FfiRepresentation,
    pub etag: String,
}

/// Write result kind returned by Engine write verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiWriteKind {
    Created,
    Updated,
    /// The Engine returned a write kind this FFI binding does not yet recognize.
    /// Treat as successful but unknown and upgrade the binding.
    Unknown,
}

/// Write result DTO returned by Engine write verbs.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiWriteResult {
    pub kind: FfiWriteKind,
    pub etag: String,
}

/// Engine verb that produced a subscription change event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiChangeVerb {
    Replace,
    Append,
    Delete,
    /// The Engine returned a change verb this FFI binding does not yet recognize.
    /// Treat as an unknown change and upgrade the binding.
    Unknown,
}

/// Subscription event DTO returned by Engine subscriptions.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiChangeEvent {
    pub id: u64,
    pub verb: FfiChangeVerb,
    pub path: String,
    pub etag: String,
}

/// Resume cursor for a subscription opened through FFI.
///
/// Foreign callers pass raw integers at the ABI edge, but the adapter converts
/// this record into the core [`SubscriptionResume`] proof before calling the
/// Engine.
#[derive(Clone, Copy, Debug, Default, uniffi::Record)]
pub struct FfiSubscriptionResume {
    pub after_event_id: Option<u64>,
}

/// Result kind returned by `FfiSubscription.next`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSubscriptionNextKind {
    Event,
    Timeout,
    Lagged,
    CursorAhead,
    Closed,
    /// The Engine returned a subscription state this FFI binding does not yet
    /// recognize. Treat as indeterminate and upgrade the binding.
    Unknown,
}

/// Blocking subscription receive result.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiSubscriptionNext {
    pub kind: FfiSubscriptionNextKind,
    pub event: Option<FfiChangeEvent>,
    pub skipped: Option<u64>,
    pub cursor_after_event_id: Option<u64>,
    pub newest_event_id: Option<u64>,
}

/// Per-world body byte usage DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiWorldUsage {
    pub world: String,
    pub bytes: u64,
}

/// Aggregate storage/memory snapshot DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDfSnapshot {
    pub storage_used: u64,
    pub storage_quota: Option<u64>,
    pub memory_used: u64,
    pub memory_quota: u64,
    pub worlds: u64,
}

/// Read-cache + ledger-writer snapshot DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPoolSnapshot {
    pub read_cache_entries: u64,
    pub read_cache_tombstones: u64,
    pub read_cache_hits: u64,
    pub read_cache_misses: u64,
    pub read_cache_capped: u64,
    pub read_cache_evictions: u64,
    pub read_cache_open_fails: u64,
    pub read_cache_max_entries: u64,
    pub ledger_writer_inits: u64,
}

/// Successful audit verification DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAuditValid {
    pub events: u64,
    pub genesis: String,
    pub latest: String,
}

/// Broken audit verification DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAuditBroken {
    pub break_at: u64,
    pub expected: String,
    pub actual: String,
}

/// Audit verification result.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum FfiAuditVerify {
    Valid {
        valid: FfiAuditValid,
    },
    Broken {
        broken: FfiAuditBroken,
    },
    NotApplicable,
    /// The Engine returned an audit state this FFI binding does not yet recognize.
    /// Treat as indeterminate and upgrade the binding.
    Unknown,
}

/// Errors raised by the FFI adapter.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    InvalidConfig {
        message: String,
    },
    InvalidSecret {
        message: String,
    },
    InvalidWorld {
        message: String,
    },
    BuildDataRootIo {
        message: String,
    },
    BuildDataRootLockHeld {
        path: String,
        holder_pid: Option<String>,
    },
    BuildHmacKeyMissing,
    BuildAuditChainCorrupted {
        world: String,
        detail: String,
    },
    BuildStorage {
        sqlite_code: Option<i32>,
        detail: String,
    },
    /// Unmapped Engine build error variant. Indicates this FFI binding is
    /// older than the core that produced the error.
    UnknownBuildError {
        detail: String,
    },
    RuntimeInitFailed {
        message: String,
    },
    Auth {
        gate: FfiAuthGate,
    },
    InvalidWorldName,
    InvalidMetadata {
        message: String,
    },
    NotFound,
    AppendOnly,
    PayloadTooLarge {
        max: u64,
    },
    PreconditionFailed {
        message: String,
    },
    QuotaExceeded {
        used: u64,
        quota: u64,
        projected: u64,
    },
    TransientStorage,
    InsufficientStorage,
    Storage,
    SubscriptionLimit,
    ShuttingDown,
    InternalInvariant {
        message: String,
    },
    /// Unmapped Engine error variant. Indicates this FFI binding is older than
    /// the core that produced the error.
    UnknownEngineError {
        detail: String,
    },
}

impl FfiEngineConfig {
    pub(crate) fn summary(&self) -> FfiEngineConfigSummary {
        FfiEngineConfigSummary {
            data_root: self.data_root.clone(),
            has_read_token: token_configured(&self.read_token),
            has_write_token: token_configured(&self.write_token),
            has_approve_token: token_configured(&self.approve_token),
            // World and memory byte caps are literal Engine caps, so Some(0)
            // remains visible as an explicit "zero bytes allowed" override.
            max_world_bytes: self.max_world_bytes,
            max_memory_bytes: self.max_memory_bytes,
            // These builder knobs define zero as "use the Engine default" or
            // "no durable quota"; the summary reports the normalized setting.
            max_storage_bytes: nonzero_override(self.max_storage_bytes),
            max_listen_connections: nonzero_override(self.max_listen_connections),
            listen_replay_max: nonzero_override(self.listen_replay_max),
            read_cache_max_entries: nonzero_override(self.read_cache_max_entries),
        }
    }
}

fn token_configured(token: &Option<Vec<u8>>) -> bool {
    token.as_deref().map(is_valid_token).unwrap_or(false)
}

fn nonzero_override(value: Option<u64>) -> Option<u64> {
    value.filter(|value| *value > 0)
}

impl TryFrom<FfiAccessTier> for AccessTier {
    type Error = FfiError;

    fn try_from(value: FfiAccessTier) -> Result<Self, Self::Error> {
        match value {
            FfiAccessTier::Anon => Ok(Self::Anon),
            FfiAccessTier::Read => Ok(Self::Read),
            FfiAccessTier::Write => Ok(Self::Write),
            FfiAccessTier::Approve => Ok(Self::Approve),
            FfiAccessTier::Unknown => Err(FfiError::InvalidConfig {
                message: "unknown access tier".to_owned(),
            }),
        }
    }
}

impl From<AccessTier> for FfiAccessTier {
    fn from(value: AccessTier) -> Self {
        match value {
            AccessTier::Anon => Self::Anon,
            AccessTier::Read => Self::Read,
            AccessTier::Write => Self::Write,
            AccessTier::Approve => Self::Approve,
            _ => Self::Unknown,
        }
    }
}

impl From<AuthGate> for FfiAuthGate {
    fn from(value: AuthGate) -> Self {
        match value {
            AuthGate::Read => Self::Read,
            AuthGate::Write => Self::Write,
            AuthGate::WriteApprove => Self::WriteApprove,
            AuthGate::Delete => Self::Delete,
            _ => Self::Unknown,
        }
    }
}

impl From<FfiEtagMatcher> for EtagMatcher {
    fn from(value: FfiEtagMatcher) -> Self {
        match value {
            FfiEtagMatcher::Any => Self::Any,
            FfiEtagMatcher::Strong { etag } => Self::Strong(etag),
            FfiEtagMatcher::Weak { etag } => Self::Weak(etag),
        }
    }
}

impl From<FfiPreconditions> for Preconditions {
    fn from(value: FfiPreconditions) -> Self {
        Self::new(
            value.if_match.into_iter().map(Into::into).collect(),
            value.if_none_match.into_iter().map(Into::into).collect(),
        )
    }
}

impl From<FfiHeader> for (String, String) {
    fn from(value: FfiHeader) -> Self {
        (value.name, value.value)
    }
}

fn representation_headers(headers: Vec<FfiHeader>) -> Vec<(String, String)> {
    let mut out = BTreeMap::new();
    for header in headers {
        out.insert(header.name.to_ascii_lowercase(), header.value);
    }
    out.into_iter().collect()
}

/// Converts an FFI representation into the Engine's protocol-neutral form.
///
/// Headers pass through without filtering. This is intentional: the Engine
/// treats headers as opaque metadata, while the HTTP adapter applies persistence
/// filtering because browsers execute response headers as security policy.
/// Non-browser adapters such as FFI, MQTT, and CoAP treat headers as plain
/// key-value metadata with no execution semantics.
///
/// Header names are still normalized and de-duplicated with deterministic
/// last-wins semantics so durable storage never sees duplicate `meta_headers`
/// primary keys. This mirrors the HTTP adapter's storage-facing shape without
/// importing HTTP allow/deny policy into FFI.
///
/// The HTTP read path applies its L1 hard-deny output filter before serving any
/// stored header to a browser, regardless of which adapter originally wrote it.
impl From<FfiRepresentation> for Representation {
    fn from(value: FfiRepresentation) -> Self {
        Self::new(
            value.body,
            value.content_type,
            representation_headers(value.headers),
        )
    }
}

impl From<FfiDeleteMetadata> for DeleteMetadata {
    fn from(value: FfiDeleteMetadata) -> Self {
        Self::new(
            value.content_type,
            value.headers.into_iter().map(Into::into).collect(),
        )
    }
}

impl From<Representation> for FfiRepresentation {
    fn from(value: Representation) -> Self {
        Self {
            body: value.body.to_vec(),
            content_type: value.content_type,
            headers: value
                .headers
                .into_iter()
                .map(|(name, value)| FfiHeader { name, value })
                .collect(),
        }
    }
}

impl From<ReadResult> for FfiReadResult {
    fn from(value: ReadResult) -> Self {
        Self {
            representation: value.representation.into(),
            etag: value.etag,
        }
    }
}

impl From<WriteResult> for FfiWriteResult {
    fn from(value: WriteResult) -> Self {
        Self {
            kind: value.kind.into(),
            etag: value.etag,
        }
    }
}

impl From<WorldUsage> for FfiWorldUsage {
    fn from(value: WorldUsage) -> Self {
        Self {
            world: value.world.to_string(),
            bytes: value.bytes as u64,
        }
    }
}

impl From<ChangeEvent> for FfiChangeEvent {
    fn from(value: ChangeEvent) -> Self {
        Self {
            id: value.id,
            verb: value.verb.into(),
            path: value.path.to_string(),
            etag: value.etag,
        }
    }
}

impl From<FfiSubscriptionResume> for SubscriptionResume {
    fn from(value: FfiSubscriptionResume) -> Self {
        value
            .after_event_id
            .map(SubscriptionResume::after_event_id)
            .unwrap_or_else(SubscriptionResume::none)
    }
}

impl From<ChangeVerb> for FfiChangeVerb {
    fn from(value: ChangeVerb) -> Self {
        match value {
            ChangeVerb::Replace => Self::Replace,
            ChangeVerb::Append => Self::Append,
            ChangeVerb::Delete => Self::Delete,
            _ => Self::Unknown,
        }
    }
}

impl From<WriteKind> for FfiWriteKind {
    fn from(value: WriteKind) -> Self {
        match value {
            WriteKind::Created => Self::Created,
            WriteKind::Updated => Self::Updated,
            _ => Self::Unknown,
        }
    }
}

impl From<DfSnapshot> for FfiDfSnapshot {
    fn from(value: DfSnapshot) -> Self {
        Self {
            storage_used: value.storage_used as u64,
            storage_quota: value.storage_quota.map(|value| value as u64),
            memory_used: value.memory_used as u64,
            memory_quota: value.memory_quota as u64,
            worlds: value.worlds as u64,
        }
    }
}

impl From<PoolSnapshot> for FfiPoolSnapshot {
    fn from(value: PoolSnapshot) -> Self {
        Self {
            read_cache_entries: value.read_cache_entries as u64,
            read_cache_tombstones: value.read_cache_tombstones as u64,
            read_cache_hits: value.read_cache_hits as u64,
            read_cache_misses: value.read_cache_misses as u64,
            read_cache_capped: value.read_cache_capped as u64,
            read_cache_evictions: value.read_cache_evictions as u64,
            read_cache_open_fails: value.read_cache_open_fails as u64,
            read_cache_max_entries: value.read_cache_max_entries as u64,
            ledger_writer_inits: value.ledger_writer_inits as u64,
        }
    }
}

impl From<AuditVerify> for FfiAuditVerify {
    fn from(value: AuditVerify) -> Self {
        match value {
            AuditVerify::Valid(valid) => Self::Valid {
                valid: FfiAuditValid {
                    events: valid.events as u64,
                    genesis: valid.genesis,
                    latest: valid.latest,
                },
            },
            AuditVerify::Broken(broken) => Self::Broken {
                broken: FfiAuditBroken {
                    break_at: broken.break_at as u64,
                    expected: broken.expected,
                    actual: broken.actual,
                },
            },
            AuditVerify::NotApplicable => Self::NotApplicable,
            _ => Self::Unknown,
        }
    }
}

impl From<EngineBuildError> for FfiError {
    fn from(value: EngineBuildError) -> Self {
        match value {
            EngineBuildError::DataRootIo(err) => Self::BuildDataRootIo {
                message: err.to_string(),
            },
            EngineBuildError::DataRootLockHeld { path, holder_pid } => {
                Self::BuildDataRootLockHeld {
                    path: path.to_string_lossy().into_owned(),
                    holder_pid,
                }
            }
            EngineBuildError::HmacKeyMissing => Self::BuildHmacKeyMissing,
            EngineBuildError::AuditChainCorrupted { world, detail } => {
                Self::BuildAuditChainCorrupted { world, detail }
            }
            EngineBuildError::Storage {
                sqlite_code,
                detail,
            } => Self::BuildStorage {
                sqlite_code,
                detail,
            },
            other => Self::UnknownBuildError {
                detail: format!("{other:?}"),
            },
        }
    }
}

impl From<EngineError> for FfiError {
    fn from(value: EngineError) -> Self {
        match value {
            EngineError::Auth(gate) => Self::Auth { gate: gate.into() },
            EngineError::InvalidWorldName => Self::InvalidWorldName,
            EngineError::InvalidMetadata { message } => Self::InvalidMetadata {
                message: message.to_owned(),
            },
            EngineError::NotFound => Self::NotFound,
            EngineError::AppendOnly => Self::AppendOnly,
            EngineError::PayloadTooLarge { max } => Self::PayloadTooLarge { max: max as u64 },
            EngineError::PreconditionFailed { message } => Self::PreconditionFailed {
                message: message.to_owned(),
            },
            EngineError::QuotaExceeded {
                used,
                quota,
                projected,
            } => Self::QuotaExceeded {
                used: used as u64,
                quota: quota as u64,
                projected: projected as u64,
            },
            EngineError::TransientStorage => Self::TransientStorage,
            EngineError::InsufficientStorage => Self::InsufficientStorage,
            EngineError::Storage => Self::Storage,
            EngineError::SubscriptionLimit => Self::SubscriptionLimit,
            EngineError::ShuttingDown => Self::ShuttingDown,
            EngineError::InternalInvariant(message) => Self::InternalInvariant {
                message: message.to_owned(),
            },
            other => Self::UnknownEngineError {
                detail: format!("{other:?}"),
            },
        }
    }
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { message }
            | Self::InvalidSecret { message }
            | Self::InvalidWorld { message }
            | Self::RuntimeInitFailed { message }
            | Self::BuildDataRootIo { message }
            | Self::PreconditionFailed { message }
            | Self::InvalidMetadata { message }
            | Self::InternalInvariant { message } => f.write_str(message),
            Self::UnknownBuildError { detail } | Self::UnknownEngineError { detail } => {
                f.write_str(detail)
            }
            Self::BuildDataRootLockHeld { path, holder_pid } => match holder_pid {
                Some(pid) => write!(
                    f,
                    "data root writer lock is held (last writer: PID {pid}): {path}"
                ),
                None => write!(f, "data root writer lock is held: {path}"),
            },
            Self::BuildHmacKeyMissing => f.write_str("hmac key missing"),
            Self::BuildAuditChainCorrupted { world, detail } => {
                write!(f, "audit chain corrupted for {world}: {detail}")
            }
            Self::BuildStorage {
                sqlite_code,
                detail,
            } => write!(
                f,
                "storage build failed ({}): {detail}",
                code_label(*sqlite_code)
            ),
            Self::Auth { gate } => write!(f, "auth gate rejected operation: {gate}"),
            Self::InvalidWorldName => f.write_str("invalid world name"),
            Self::NotFound => f.write_str("world not found"),
            Self::AppendOnly => f.write_str("world is append-only"),
            Self::PayloadTooLarge { max } => write!(f, "payload too large (max {max} bytes)"),
            Self::QuotaExceeded {
                used,
                quota,
                projected,
            } => write!(
                f,
                "storage quota exceeded (used {used}, quota {quota}, projected {projected})"
            ),
            Self::TransientStorage => f.write_str("storage temporarily unavailable"),
            Self::InsufficientStorage => f.write_str("insufficient storage"),
            Self::Storage => f.write_str("storage failed"),
            Self::SubscriptionLimit => f.write_str("subscription limit reached"),
            Self::ShuttingDown => f.write_str("engine is shutting down"),
        }
    }
}

fn code_label(sqlite_code: Option<i32>) -> String {
    sqlite_code
        .map(|code| format!("code {code}"))
        .unwrap_or_else(|| "no sqlite code".to_owned())
}

impl std::error::Error for FfiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representation_headers_deduplicate_names_last_wins() {
        let representation = Representation::from(FfiRepresentation {
            body: b"body".to_vec(),
            content_type: "text/plain".to_owned(),
            headers: vec![
                FfiHeader {
                    name: "X-Custom".to_owned(),
                    value: "old".to_owned(),
                },
                FfiHeader {
                    name: "x-other".to_owned(),
                    value: "kept".to_owned(),
                },
                FfiHeader {
                    name: "x-custom".to_owned(),
                    value: "new".to_owned(),
                },
            ],
        });

        assert_eq!(
            representation.headers,
            vec![
                ("x-custom".to_owned(), "new".to_owned()),
                ("x-other".to_owned(), "kept".to_owned()),
            ]
        );
    }
}
