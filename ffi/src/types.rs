use std::fmt;

use elastik_core::{
    is_valid_token, AccessTier, AuditVerify, AuthGate, DfSnapshot, EngineBuildError, EngineError,
    PoolSnapshot, WriteKind,
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

/// Stored representation for future write/read bindings.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiRepresentation {
    pub body: Vec<u8>,
    pub content_type: String,
    pub headers: Vec<FfiHeader>,
}

/// Future read result DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiReadResult {
    pub representation: FfiRepresentation,
    pub etag: String,
}

/// Future write result kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiWriteKind {
    Created,
    Updated,
    /// The Engine returned a write kind this FFI binding does not yet recognize.
    /// Treat as successful but unknown and upgrade the binding.
    Unknown,
}

/// Future write result DTO.
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

/// Future subscription event DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiChangeEvent {
    pub id: u64,
    pub verb: FfiChangeVerb,
    pub path: String,
    pub etag: String,
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
    BuildDataRootIo {
        message: String,
    },
    BuildDataRootLockHeld {
        path: String,
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
    TransientStorage {
        sqlite_code: Option<i32>,
    },
    InsufficientStorage {
        sqlite_code: Option<i32>,
    },
    Storage {
        sqlite_code: Option<i32>,
    },
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
            EngineBuildError::DataRootLockHeld { path } => Self::BuildDataRootLockHeld {
                path: path.to_string_lossy().into_owned(),
            },
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
            EngineError::TransientStorage { sqlite_code } => Self::TransientStorage { sqlite_code },
            EngineError::InsufficientStorage { sqlite_code } => {
                Self::InsufficientStorage { sqlite_code }
            }
            EngineError::Storage { sqlite_code } => Self::Storage { sqlite_code },
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
            | Self::RuntimeInitFailed { message }
            | Self::BuildDataRootIo { message }
            | Self::PreconditionFailed { message }
            | Self::InternalInvariant { message } => f.write_str(message),
            Self::UnknownBuildError { detail } | Self::UnknownEngineError { detail } => {
                f.write_str(detail)
            }
            Self::BuildDataRootLockHeld { path } => {
                write!(f, "data root writer lock is held: {path}")
            }
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
            Self::TransientStorage { sqlite_code } => {
                write!(
                    f,
                    "storage temporarily unavailable ({})",
                    code_label(*sqlite_code)
                )
            }
            Self::InsufficientStorage { sqlite_code } => {
                write!(f, "insufficient storage ({})", code_label(*sqlite_code))
            }
            Self::Storage { sqlite_code } => {
                write!(f, "storage failed ({})", code_label(*sqlite_code))
            }
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
