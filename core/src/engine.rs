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
    defaults::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
    },
    engine_types::{AccessTier, SecretBytes},
    read_cache::ReadCache,
    state::{new_event_counter, Core},
    storage_class, store, world,
};

/// Public handle for the protocol-neutral Elastik engine.
///
/// `Engine` is cloneable and owns the startup writer lock for the data root.
/// Dropping the last clone releases the lock.
///
/// The facade is protocol-neutral: callers pass canonical world paths,
/// representation bytes, preconditions, and access tiers. It does not parse
/// HTTP, read environment variables, or bind sockets.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    core: Arc<Core>,
    shutdown_tx: watch::Sender<bool>,
    _data_lock: StdMutex<rusqlite::Connection>,
}

/// Adapter-side handle for waiting on Engine shutdown without exposing Tokio's
/// watch channel type in the public facade.
#[cfg(feature = "unstable-engine")]
#[doc(hidden)]
pub struct ShutdownToken {
    rx: watch::Receiver<bool>,
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
}

/// Errors that can occur while constructing an [`Engine`].
///
/// Build failures are setup-time failures: they happen once at
/// [`EngineBuilder::build`] and never as part of per-operation runtime errors,
/// which are reported as [`EngineError`].
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineBuildError {
    /// Creating the `data_root` directory or its writer-lock file failed.
    DataRootIo(std::io::Error),
    /// Another process holds the writer lock on `data_root`.
    DataRootLockHeld {
        /// The data root that failed to acquire the writer lock.
        path: PathBuf,
        /// Best-effort PID last written by the process that attempted to hold
        /// the lock. This is diagnostic only, not a fencing proof.
        holder_pid: Option<String>,
    },
    /// [`EngineBuilder::key`] was never called.
    HmacKeyMissing,
    /// Startup audit verification found a tampered HMAC chain.
    AuditChainCorrupted {
        /// Canonical name of the world whose chain failed verification.
        world: String,
        /// Human-readable failure detail (do not parse).
        detail: String,
    },
    /// Storage layer failure during startup (schema, IO, or quota).
    Storage {
        /// Underlying SQLite extended result code, when available.
        sqlite_code: Option<i32>,
        /// Human-readable failure detail (do not parse).
        detail: String,
    },
}

/// Runtime operation errors reported by the Engine facade.
///
/// Distinct from [`EngineBuildError`]: these are per-operation failures
/// returned by [`Engine::read`], [`Engine::replace`], [`Engine::append`],
/// [`Engine::delete`], [`Engine::subscribe`], and the introspection methods.
/// The enum is `#[non_exhaustive]`; match on the variants you care about and
/// route the rest through a default arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// Caller's tier is too low for the requested gate.
    Auth(AuthGate),
    /// The supplied world name failed canonical-path validation.
    InvalidWorldName,
    /// The world does not exist.
    NotFound,
    /// The target world is append-only and refuses delete/overwrite (for
    /// example `var/log/deletes`).
    AppendOnly,
    /// Request body exceeded the per-world byte limit.
    PayloadTooLarge {
        /// Configured maximum body length, in bytes.
        max: usize,
    },
    /// An `If-Match` / `If-None-Match` precondition rejected the write.
    PreconditionFailed {
        /// Static reason string (`stale`, `exists`, ...).
        message: &'static str,
    },
    /// Write would exceed the configured durable storage quota.
    QuotaExceeded {
        /// Bytes already in use.
        used: usize,
        /// Configured quota ceiling.
        quota: usize,
        /// Projected total if the write were applied.
        projected: usize,
    },
    /// Storage is temporarily unavailable (e.g. SQLite `BUSY`/`LOCKED`).
    /// Callers should retry with backoff.
    TransientStorage,
    /// Storage backing exhausted (full disk, IO failure that maps to
    /// "no space left"). Callers must surface this as 5xx-class to operators.
    InsufficientStorage,
    /// Generic storage failure that is neither transient nor insufficient.
    Storage,
    /// Subscription slot semaphore is exhausted.
    SubscriptionLimit,
    /// [`Engine::shutdown`] has been called; do not start new operations.
    ShuttingDown,
    /// Internal invariant violation. Indicates a bug in the engine.
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
        }
    }
}

impl EngineBuilder {
    /// Sets the directory where durable worlds and the audit log live.
    ///
    /// Default: `./data`. The directory is created by
    /// [`EngineBuilder::build`] if missing.
    pub fn data_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_root = path.into();
        self
    }

    /// Sets the HMAC key that protects the audit chain. Required.
    pub fn key(mut self, key: SecretBytes) -> Self {
        self.key = Some(key);
        self
    }

    /// Sets the optional read-tier token.
    ///
    /// Empty or all-whitespace bytes are treated as "unset" — they never
    /// silently grant access.
    pub fn read_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.read = NonEmptyBytes::new(token);
        self
    }

    /// Sets the optional write-tier token (covers read + write).
    ///
    /// Empty or all-whitespace bytes are treated as "unset" — they never
    /// silently grant access.
    pub fn write_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.write = NonEmptyBytes::new(token);
        self
    }

    /// Sets the optional approve-tier token (covers read + write + system
    /// writes + delete).
    ///
    /// Empty or all-whitespace bytes are treated as "unset" — they never
    /// silently grant access.
    pub fn approve_token(mut self, token: impl Into<Vec<u8>>) -> Self {
        self.tokens.approve = NonEmptyBytes::new(token);
        self
    }

    /// Caps the per-world payload size in bytes. Defaults to 64 MiB.
    pub fn max_world_bytes(mut self, value: usize) -> Self {
        self.max_world_bytes = value;
        self
    }

    /// Caps the in-memory backend's total bytes. Defaults to 256 MiB.
    pub fn max_memory_bytes(mut self, value: usize) -> Self {
        self.max_memory_bytes = value;
        self
    }

    /// Sets an optional durable storage quota in bytes.
    ///
    /// `Some(0)` is treated as "no quota". Writes that would push the total
    /// past the quota fail with [`EngineError::QuotaExceeded`].
    pub fn max_storage_bytes(mut self, value: Option<usize>) -> Self {
        self.max_storage_bytes = value.filter(|value| *value > 0);
        self
    }

    /// Sets the maximum simultaneous subscription slots. `0` reverts to the
    /// default (1024).
    pub fn max_listen_connections(mut self, value: usize) -> Self {
        self.max_listen_connections = nonzero_or_default(value, DEFAULT_MAX_LISTEN_CONNECTIONS);
        self
    }

    /// Sets the per-subscription replay ring depth. `0` reverts to the
    /// default (1024).
    pub fn listen_replay_max(mut self, value: usize) -> Self {
        self.listen_replay_max = nonzero_or_default(value, DEFAULT_LISTEN_REPLAY_MAX);
        self
    }

    /// Sets the read cache's maximum tracked entries. `0` reverts to the
    /// default (5000).
    pub fn read_cache_max_entries(mut self, value: usize) -> Self {
        self.read_cache_max_entries = nonzero_or_default(value, DEFAULT_READ_CACHE_MAX_ENTRIES);
        self
    }

    /// Acquires the data-root writer lock, verifies every audit chain, and
    /// returns a ready-to-serve [`Engine`].
    ///
    /// This is a synchronous startup boundary. It may create directories,
    /// acquire the SQLite-backed process lock, scan durable worlds, and verify
    /// HMAC audit chains before returning. Do this during application startup,
    /// before accepting requests.
    ///
    /// # Errors
    /// - [`EngineBuildError::HmacKeyMissing`] if [`EngineBuilder::key`] was
    ///   never called.
    /// - [`EngineBuildError::DataRootIo`] for filesystem errors creating
    ///   `data_root`.
    /// - [`EngineBuildError::DataRootLockHeld`] if another process holds the
    ///   writer lock.
    /// - [`EngineBuildError::AuditChainCorrupted`] if any existing world's
    ///   HMAC chain fails verification.
    /// - [`EngineBuildError::Storage`] for other storage-layer failures.
    pub fn build(self) -> Result<Engine, EngineBuildError> {
        std::fs::create_dir_all(&self.data_root).map_err(EngineBuildError::DataRootIo)?;
        let data_lock = crate::acquire_data_root_writer_lock(&self.data_root)
            .map_err(|err| map_writer_lock_error(&self.data_root, err))?;
        let hmac_key = self.key.ok_or(EngineBuildError::HmacKeyMissing)?;

        verify_all_worlds_with_names(&self.data_root, hmac_key.as_slice())?;
        let durable_sizes = world::sizes(&self.data_root).map_err(|err| {
            match storage_class::classify_storage_failure(&err) {
                storage_class::StorageFailureClass::Transient => {
                    EngineBuildError::DataRootLockHeld {
                        path: self.data_root.clone(),
                        holder_pid: None,
                    }
                }
                storage_class::StorageFailureClass::InsufficientStorage
                | storage_class::StorageFailureClass::Other => EngineBuildError::Storage {
                    sqlite_code: sqlite_code(&err),
                    detail: err.to_string(),
                },
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
            world_locks: Arc::new(DashMap::new()),
            ledger: Arc::new(crate::ledger::LedgerWriter::new()),
            read_cache: Arc::new(ReadCache::new(self.read_cache_max_entries)),
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
    /// Returns a fresh [`EngineBuilder`] populated with crate defaults.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    pub(crate) fn core(&self) -> &Core {
        self.inner.core.as_ref()
    }

    /// Subscribes to the engine shutdown signal.
    ///
    /// Returned receiver yields `true` exactly once when [`Engine::shutdown`]
    /// is called. Intended for adapter graceful-shutdown loops; not part of
    /// the documented stable surface.
    #[cfg(feature = "unstable-engine")]
    #[doc(hidden)]
    pub fn shutdown_receiver(&self) -> ShutdownToken {
        ShutdownToken {
            rx: self.inner.shutdown_tx.subscribe(),
        }
    }

    /// Maps raw token bytes to an [`AccessTier`].
    ///
    /// Constant-time comparison against configured tokens. Returns
    /// [`AccessTier::Anon`] for empty, unrecognized, or invalid token bytes;
    /// returns the highest matching tier otherwise.
    pub fn verify_token(&self, token: &[u8]) -> AccessTier {
        self.inner.core.tokens.check_token_bytes(token).into()
    }

    /// Returns whether `tier` satisfies the engine's configured read gate.
    ///
    /// Adapters use this for non-world read-only surfaces that still need to
    /// mirror `/proc/*` read policy, such as protocol-local metrics.
    pub fn allows_read(&self, tier: AccessTier) -> bool {
        crate::can_read(self.core(), tier.into())
    }

    /// Starts orderly shutdown.
    ///
    /// Sets the engine-owned shutdown signal so subscribers
    /// ([`crate::EngineSubscription`] recv loops, adapter graceful-shutdown
    /// futures) can drain in-flight work. Repeated calls are no-ops; only
    /// the first call flips the signal.
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

#[cfg(feature = "unstable-engine")]
impl ShutdownToken {
    /// Returns whether shutdown has already been requested.
    pub fn is_shutdown(&self) -> bool {
        *self.rx.borrow()
    }

    /// Waits until shutdown is requested or the Engine owner is dropped.
    pub async fn wait(&mut self) {
        if self.is_shutdown() {
            return;
        }
        let _ = self.rx.changed().await;
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

fn map_writer_lock_error(
    data_root: &std::path::Path,
    err: crate::data_lock::DataRootWriterLockError,
) -> EngineBuildError {
    let sqlite_err = err.sqlite_error();
    match storage_class::classify_storage_failure(sqlite_err) {
        storage_class::StorageFailureClass::Transient => EngineBuildError::DataRootLockHeld {
            path: data_root.to_path_buf(),
            holder_pid: err.holder_pid().map(str::to_owned),
        },
        storage_class::StorageFailureClass::InsufficientStorage
        | storage_class::StorageFailureClass::Other => EngineBuildError::Storage {
            sqlite_code: sqlite_code(sqlite_err),
            detail: format!("writer lock open failed: {sqlite_err}"),
        },
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
        audit::verify_world(data_root, &world_name, key).map_err(|err| match err {
            audit::AuditError::ChainBroken(break_report) => {
                EngineBuildError::AuditChainCorrupted {
                    world: world_name.clone(),
                    detail: audit::AuditError::ChainBroken(break_report).to_string(),
                }
            }
            audit::AuditError::Storage(err) => match storage_class::classify_storage_failure(&err)
            {
                storage_class::StorageFailureClass::Transient => {
                    EngineBuildError::DataRootLockHeld {
                        path: data_root.to_path_buf(),
                        holder_pid: None,
                    }
                }
                storage_class::StorageFailureClass::InsufficientStorage => {
                    EngineBuildError::Storage {
                        sqlite_code: sqlite_code(&err),
                        detail: format!(
                            "audit verification for {world_name} failed with sqlite code {:?}: {err}",
                            sqlite_code(&err)
                        ),
                    }
                }
                storage_class::StorageFailureClass::Other => EngineBuildError::Storage {
                    sqlite_code: sqlite_code(&err),
                    detail: format!("audit verification for {world_name} failed: {err}"),
                },
            },
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

        match second {
            Err(EngineBuildError::DataRootLockHeld { holder_pid, .. }) => {
                let expected_pid = std::process::id().to_string();
                assert_eq!(holder_pid.as_deref(), Some(expected_pid.as_str()));
            }
            other => panic!("expected data root writer lock error, got {other:?}"),
        }

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
