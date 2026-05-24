use std::fmt;

use elastik_core::{
    AccessTier, AuditVerify, DfSnapshot, EngineBuildError, EngineError, PoolSnapshot, WriteKind,
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
    Unknown,
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
    Unknown,
}

/// Future write result DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiWriteResult {
    pub kind: FfiWriteKind,
    pub etag: String,
}

/// Future subscription event DTO.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiChangeEvent {
    pub id: u64,
    pub method: String,
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

/// Audit verification DTO. Exactly one detail field is populated.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAuditVerify {
    pub kind: FfiAuditVerifyKind,
    pub valid: Option<FfiAuditValid>,
    pub broken: Option<FfiAuditBroken>,
}

/// Audit verification result kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAuditVerifyKind {
    Valid,
    Broken,
    NotApplicable,
    Unknown,
}

/// Errors raised by the FFI adapter.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    InvalidConfig { message: String },
    InvalidSecret { message: String },
    BuildFailed { message: String },
    RuntimeInitFailed { message: String },
    EngineFailed { message: String },
}

impl FfiEngineConfig {
    pub(crate) fn summary(&self) -> FfiEngineConfigSummary {
        FfiEngineConfigSummary {
            data_root: self.data_root.clone(),
            has_read_token: self.read_token.is_some(),
            has_write_token: self.write_token.is_some(),
            has_approve_token: self.approve_token.is_some(),
            max_world_bytes: self.max_world_bytes,
            max_memory_bytes: self.max_memory_bytes,
            max_storage_bytes: self.max_storage_bytes,
            max_listen_connections: self.max_listen_connections,
            listen_replay_max: self.listen_replay_max,
            read_cache_max_entries: self.read_cache_max_entries,
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
            AuditVerify::Valid(valid) => Self {
                kind: FfiAuditVerifyKind::Valid,
                valid: Some(FfiAuditValid {
                    events: valid.events as u64,
                    genesis: valid.genesis,
                    latest: valid.latest,
                }),
                broken: None,
            },
            AuditVerify::Broken(broken) => Self {
                kind: FfiAuditVerifyKind::Broken,
                valid: None,
                broken: Some(FfiAuditBroken {
                    break_at: broken.break_at as u64,
                    expected: broken.expected,
                    actual: broken.actual,
                }),
            },
            AuditVerify::NotApplicable => Self {
                kind: FfiAuditVerifyKind::NotApplicable,
                valid: None,
                broken: None,
            },
            _ => Self {
                kind: FfiAuditVerifyKind::Unknown,
                valid: None,
                broken: None,
            },
        }
    }
}

impl From<EngineBuildError> for FfiError {
    fn from(value: EngineBuildError) -> Self {
        Self::BuildFailed {
            message: format!("{value:?}"),
        }
    }
}

impl From<EngineError> for FfiError {
    fn from(value: EngineError) -> Self {
        Self::EngineFailed {
            message: format!("{value:?}"),
        }
    }
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { message }
            | Self::InvalidSecret { message }
            | Self::BuildFailed { message }
            | Self::RuntimeInitFailed { message }
            | Self::EngineFailed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for FfiError {}
