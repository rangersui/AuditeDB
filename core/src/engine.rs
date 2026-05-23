//! Unstable protocol-neutral Engine facade.
//!
//! This module is always compiled so internal adapters can migrate to it
//! without tying default builds to a public API feature. External crates only
//! see these types through crate-root re-exports when `unstable-engine` is
//! enabled.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{
    collections::VecDeque,
    fmt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc, Mutex as StdMutex,
    },
};

use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Semaphore};

use crate::{
    audit,
    auth::{self, AuthGate, NonEmptyBytes},
    config::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES,
    },
    engine_types::{AccessTier, SecretBytes},
    http_semantics::HeaderAllowlist,
    read_cache::{ReadCache, DEFAULT_READ_CACHE_MAX_ENTRIES},
    state::{new_event_counter, Core},
    storage_class, store, world,
};

/// Public handle for the protocol-neutral Elastik engine.
///
/// `Engine` is cloneable and owns the startup writer lock for the data root.
/// Dropping the last clone releases the lock.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    core: Arc<Core>,
    shutdown_tx: watch::Sender<bool>,
    _data_lock: StdMutex<rusqlite::Connection>,
}

/// Builder for an `Engine`.
///
/// The builder is the only public construction path. New fields can gain
/// defaults without breaking callers.
pub struct EngineBuilder {
    data_root: PathBuf,
    key: Option<SecretBytes>,
    tokens: auth::Tokens,
    max_world_bytes: usize,
    max_memory_bytes: usize,
    max_storage_bytes: Option<usize>,
    max_listen_connections: usize,
    listen_replay_max: usize,
    read_cache_max_entries: usize,
    persist_header_allowlist: HeaderAllowlist,
    persist_header_user_deny: HeaderAllowlist,
}

/// Errors that can occur while constructing an `Engine`.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineBuildError {
    DataRootIo(std::io::Error),
    DataRootLockHeld {
        path: PathBuf,
    },
    HmacKeyMissing,
    AuditChainCorrupted {
        world: String,
        detail: String,
    },
    Storage {
        sqlite_code: Option<i32>,
        detail: String,
    },
}

/// Runtime operation errors reported by the engine facade.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    Auth(AuthGate),
    InvalidWorldName,
    NotFound,
    PayloadTooLarge {
        max: usize,
    },
    PreconditionFailed {
        message: &'static str,
    },
    QuotaExceeded {
        used: usize,
        quota: usize,
        projected: usize,
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
    InternalInvariant(&'static str),
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self {
            data_root: PathBuf::from("./data"),
            key: None,
            tokens: auth::Tokens {
                read: None,
                write: None,
                approve: None,
            },
            max_world_bytes: DEFAULT_MAX_WORLD_BYTES,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_storage_bytes: None,
            max_listen_connections: DEFAULT_MAX_LISTEN_CONNECTIONS,
            listen_replay_max: DEFAULT_LISTEN_REPLAY_MAX,
            read_cache_max_entries: DEFAULT_READ_CACHE_MAX_ENTRIES,
            persist_header_allowlist: HeaderAllowlist::empty(),
            persist_header_user_deny: HeaderAllowlist::empty(),
        }
    }
}

impl EngineBuilder {
    pub fn data_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_root = path.into();
        self
    }

    pub fn key(mut self, key: SecretBytes) -> Self {
        self.key = Some(key);
        self
    }

    pub fn read_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.read = NonEmptyBytes::new(token);
        self
    }

    pub fn write_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.write = NonEmptyBytes::new(token);
        self
    }

    pub fn approve_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.approve = NonEmptyBytes::new(token);
        self
    }

    pub fn max_world_bytes(mut self, value: usize) -> Self {
        self.max_world_bytes = value;
        self
    }

    pub fn max_memory_bytes(mut self, value: usize) -> Self {
        self.max_memory_bytes = value;
        self
    }

    pub fn max_storage_bytes(mut self, value: Option<usize>) -> Self {
        self.max_storage_bytes = value.filter(|value| *value > 0);
        self
    }

    pub fn max_listen_connections(mut self, value: usize) -> Self {
        self.max_listen_connections = nonzero_or_default(value, DEFAULT_MAX_LISTEN_CONNECTIONS);
        self
    }

    pub fn listen_replay_max(mut self, value: usize) -> Self {
        self.listen_replay_max = nonzero_or_default(value, DEFAULT_LISTEN_REPLAY_MAX);
        self
    }

    pub fn read_cache_max_entries(mut self, value: usize) -> Self {
        self.read_cache_max_entries = nonzero_or_default(value, DEFAULT_READ_CACHE_MAX_ENTRIES);
        self
    }

    pub fn build(self) -> Result<Engine, EngineBuildError> {
        std::fs::create_dir_all(&self.data_root).map_err(EngineBuildError::DataRootIo)?;
        let data_lock = crate::acquire_data_root_writer_lock(&self.data_root)
            .map_err(|err| map_writer_lock_error(&self.data_root, err))?;
        let hmac_key = self.key.ok_or(EngineBuildError::HmacKeyMissing)?.into_vec();

        verify_all_worlds_with_names(&self.data_root, &hmac_key)?;
        let durable_sizes = world::sizes(&self.data_root).map_err(|err| {
            if storage_class::is_transient_storage_error(&err) {
                EngineBuildError::DataRootLockHeld {
                    path: self.data_root.clone(),
                }
            } else {
                EngineBuildError::Storage {
                    sqlite_code: sqlite_code(&err),
                    detail: err.to_string(),
                }
            }
        })?;
        let storage_body_bytes = durable_sizes.iter().map(|(_, size)| *size).sum();
        let durable_world_count = durable_sizes.len();
        let delete_ledger_created = durable_sizes
            .iter()
            .any(|(world_name, _)| world_name == "var/log/deletes");

        let (events, _) = broadcast::channel(self.listen_replay_max);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let core = Arc::new(Core {
            data: self.data_root,
            tokens: self.tokens,
            hmac_key,
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: self.max_world_bytes,
            max_memory_bytes: self.max_memory_bytes,
            max_storage_bytes: self.max_storage_bytes,
            storage_body_bytes: Arc::new(AtomicUsize::new(storage_body_bytes)),
            durable_world_count: Arc::new(AtomicUsize::new(durable_world_count)),
            delete_ledger_created: Arc::new(AtomicBool::new(delete_ledger_created)),
            events,
            listen_slots: Arc::new(Semaphore::new(self.max_listen_connections)),
            listen_replay_max: self.listen_replay_max,
            event_log: Arc::new(StdMutex::new(VecDeque::with_capacity(
                self.listen_replay_max,
            ))),
            shutdown: shutdown_rx,
            next_event: new_event_counter(),
            next_request: Arc::new(AtomicUsize::new(0)),
            world_locks: Arc::new(DashMap::new()),
            ledger: Arc::new(crate::ledger::LedgerWriter::new()),
            read_cache: Arc::new(ReadCache::new(self.read_cache_max_entries)),
            persist_header_allowlist: Arc::new(self.persist_header_allowlist),
            persist_header_user_deny: Arc::new(self.persist_header_user_deny),
        });

        Ok(Engine {
            inner: Arc::new(EngineInner {
                core,
                shutdown_tx,
                _data_lock: StdMutex::new(data_lock),
            }),
        })
    }
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    pub(crate) fn core(&self) -> &Core {
        self.inner.core.as_ref()
    }

    /// Maps raw token bytes to an access tier.
    ///
    /// Invalid, unknown, or empty token bytes return `AccessTier::Anon`.
    pub fn verify_token(&self, token: &[u8]) -> AccessTier {
        self.inner.core.tokens.check_token_bytes(token).into()
    }

    /// Starts orderly shutdown. Repeated calls are no-ops.
    pub fn shutdown(&self) {
        self.inner.shutdown_tx.send_if_modified(|shutdown| {
            if *shutdown {
                false
            } else {
                *shutdown = true;
                true
            }
        });
    }
}

impl EngineError {
    pub fn sqlite_code(&self) -> Option<i32> {
        match self {
            Self::TransientStorage { sqlite_code }
            | Self::InsufficientStorage { sqlite_code }
            | Self::Storage { sqlite_code } => *sqlite_code,
            Self::Auth(_)
            | Self::InvalidWorldName
            | Self::NotFound
            | Self::PayloadTooLarge { .. }
            | Self::PreconditionFailed { .. }
            | Self::QuotaExceeded { .. }
            | Self::SubscriptionLimit
            | Self::ShuttingDown
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

fn nonzero_or_default(value: usize, default: usize) -> usize {
    match value {
        0 => default,
        value => value,
    }
}

pub(crate) fn sqlite_code(err: &rusqlite::Error) -> Option<i32> {
    err.sqlite_error_code().map(|code| code as i32)
}

fn map_writer_lock_error(data_root: &std::path::Path, err: rusqlite::Error) -> EngineBuildError {
    if storage_class::is_transient_storage_error(&err) {
        return EngineBuildError::DataRootLockHeld {
            path: data_root.to_path_buf(),
        };
    }
    EngineBuildError::Storage {
        sqlite_code: sqlite_code(&err),
        detail: format!("writer lock open failed: {err}"),
    }
}

fn verify_all_worlds_with_names(
    data_root: &std::path::Path,
    key: &[u8],
) -> Result<(), EngineBuildError> {
    let worlds = world::list(data_root).map_err(|err| EngineBuildError::Storage {
        sqlite_code: sqlite_code(&err),
        detail: format!("list worlds for audit verification failed: {err}"),
    })?;
    for world_name in worlds {
        audit::verify_world(data_root, &world_name, key).map_err(|err| {
            if storage_class::is_transient_storage_error(&err) {
                EngineBuildError::DataRootLockHeld {
                    path: data_root.to_path_buf(),
                }
            } else if storage_class::is_insufficient_storage_error(&err) {
                EngineBuildError::Storage {
                    sqlite_code: sqlite_code(&err),
                    detail: format!(
                        "audit verification for {world_name} failed with sqlite code {:?}: {err}",
                        sqlite_code(&err)
                    ),
                }
            } else if audit::is_audit_chain_broken_error(&err) {
                EngineBuildError::AuditChainCorrupted {
                    world: world_name.clone(),
                    detail: err.to_string(),
                }
            } else {
                EngineBuildError::Storage {
                    sqlite_code: sqlite_code(&err),
                    detail: format!("audit verification for {world_name} failed: {err}"),
                }
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-engine-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn secret_bytes_rejects_empty_keys() {
        assert!(SecretBytes::new(Vec::new()).is_err());
        assert!(SecretBytes::try_from_slice(b"").is_err());
        assert!(SecretBytes::try_from_slice(b" \t\r\n").is_err());
        assert!(SecretBytes::try_from_slice("\u{2003}\n".as_bytes()).is_err());
        assert!(SecretBytes::try_from_slice(b"key").is_ok());
        assert!(SecretBytes::try_from_slice(&[0xff, b'k', b'e', b'y']).is_ok());
    }

    #[test]
    fn verify_token_maps_raw_bytes_to_access_tier() {
        let root = temp_root("verify-token");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .read_token(b"reader".to_vec())
            .write_token(b"writer".to_vec())
            .approve_token(b"approve".to_vec())
            .build()
            .unwrap();

        assert_eq!(engine.verify_token(b""), AccessTier::Anon);
        assert_eq!(engine.verify_token(b"missing"), AccessTier::Anon);
        assert_eq!(engine.verify_token(b"reader"), AccessTier::Read);
        assert_eq!(engine.verify_token(b"writer"), AccessTier::Write);
        assert_eq!(engine.verify_token(b"approve"), AccessTier::Approve);

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn token_setters_treat_empty_and_whitespace_as_unset() {
        let root = temp_root("token-whitespace");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .read_token(b" \t\n".to_vec())
            .write_token(Vec::new())
            .approve_token("\u{2003}\n".as_bytes().to_vec())
            .build()
            .unwrap();

        assert_eq!(engine.verify_token(b" \t\n"), AccessTier::Anon);
        assert_eq!(
            engine.verify_token("\u{2003}\n".as_bytes()),
            AccessTier::Anon
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn zero_numeric_limits_match_env_default_semantics() {
        let root = temp_root("zero-limits");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .max_storage_bytes(Some(0))
            .max_listen_connections(0)
            .listen_replay_max(0)
            .read_cache_max_entries(0)
            .build()
            .unwrap();

        assert_eq!(engine.inner.core.max_storage_bytes, None);
        assert_eq!(
            engine.inner.core.listen_slots.available_permits(),
            DEFAULT_MAX_LISTEN_CONNECTIONS
        );
        assert_eq!(
            engine.inner.core.listen_replay_max,
            DEFAULT_LISTEN_REPLAY_MAX
        );
        assert_eq!(
            engine.inner.core.read_cache.max_entries,
            DEFAULT_READ_CACHE_MAX_ENTRIES
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shutdown_is_idempotent_without_extra_notifications() {
        let root = temp_root("shutdown-idempotent");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .build()
            .unwrap();
        let mut shutdown = engine.inner.core.shutdown.clone();

        assert!(!*shutdown.borrow());
        engine.shutdown();
        assert!(shutdown.has_changed().unwrap());
        assert!(*shutdown.borrow_and_update());

        engine.shutdown();
        assert!(!shutdown.has_changed().unwrap());

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_holds_the_data_root_writer_lock() {
        let root = temp_root("writer-lock");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .build()
            .unwrap();

        let second = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .build();

        assert!(matches!(
            second,
            Err(EngineBuildError::DataRootLockHeld { .. })
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_verifies_audit_chains_before_returning_engine() {
        let root = temp_root("audit-verify");
        let key = b"key".to_vec();
        let write_result = world::write_with_audit_checked(
            &root,
            "home/audit",
            b"body",
            "text/plain",
            &[],
            &key,
            None,
        );
        assert!(write_result.is_ok(), "fixture write should succeed");
        let db = world::world_db(&root, "home/audit");
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute(
            "UPDATE events SET body_sha256='tampered' WHERE id=(SELECT max(id) FROM events)",
            [],
        )
        .unwrap();
        drop(conn);

        let result = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::new(key).unwrap())
            .build();

        assert!(matches!(
            result,
            Err(EngineBuildError::AuditChainCorrupted { .. })
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_classifies_non_chain_verify_failures_as_storage_errors() {
        let root = temp_root("audit-storage-error");
        let key = b"key".to_vec();
        let write_result = world::write_with_audit_checked(
            &root,
            "home/schema",
            b"body",
            "text/plain",
            &[],
            &key,
            None,
        );
        assert!(write_result.is_ok(), "fixture write should succeed");
        let db = world::world_db(&root, "home/schema");
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("DROP TABLE events", []).unwrap();
        drop(conn);

        let result = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::new(key).unwrap())
            .build();

        match result {
            Err(EngineBuildError::Storage {
                sqlite_code: Some(_),
                detail,
            }) => assert!(detail.contains("audit verification for home/schema failed")),
            other => panic!("expected storage error with sqlite code, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(root);
    }
}
