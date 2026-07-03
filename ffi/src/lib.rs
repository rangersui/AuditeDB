//! UniFFI adapter for the protocol-neutral L5 Engine.
//!
//! This crate is intentionally separate from `l5`: it is an adapter
//! peer of HTTP and CoAP, not a new core surface. This stack binds Engine
//! methods directly and keeps HTTP route/status vocabulary out of the ABI.

// UniFFI's export macro references deprecated smoke exports inside this crate.
// The deprecation remains part of the generated ABI for downstream consumers.
#![allow(deprecated)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use l5::{
    AuditHmacKey, ChangeEvent, Engine, EngineDeleteTraceHooks, SubscribePattern,
    SubscriptionRecvError, SubscriptionResume, ValidatedWorldPath,
};
use tokio::{
    runtime::{Builder as RuntimeBuilder, Runtime},
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
    time::timeout,
};

mod types;

pub use types::*;

uniffi::setup_scaffolding!();

/// UniFFI-owned handle around the protocol-neutral L5 Engine.
#[derive(uniffi::Object)]
pub struct FfiEngine {
    engine: Engine,
    runtime: Arc<Runtime>,
    config: FfiEngineConfigSummary,
}

/// UniFFI-owned blocking receiver for Engine subscription events.
#[derive(uniffi::Object)]
pub struct FfiSubscription {
    events: Mutex<mpsc::Receiver<FfiSubscriptionNext>>,
    cancel: watch::Sender<bool>,
    pump: Mutex<Option<JoinHandle<()>>>,
    runtime: Arc<Runtime>,
}

const FFI_SUBSCRIPTION_BUFFER: usize = 1024;

struct NoopDeleteTrace;

impl EngineDeleteTraceHooks for NoopDeleteTrace {}

#[uniffi::export]
impl FfiEngine {
    /// Opens an Engine and embeds a Tokio runtime for async Engine verbs.
    #[uniffi::constructor]
    pub fn open(config: FfiEngineConfig) -> Result<Arc<Self>, FfiError> {
        let summary = config.summary();
        let mut builder = Engine::builder().data_root(config.data_root);
        let key = AuditHmacKey::new(config.hmac_key).map_err(|err| FfiError::InvalidSecret {
            message: err.to_string(),
        })?;
        builder = builder.key(key);

        if let Some(token) = config.read_token {
            builder = builder.read_token(token);
        }
        if let Some(token) = config.write_token {
            builder = builder.write_token(token);
        }
        if let Some(token) = config.approve_token {
            builder = builder.approve_token(token);
        }
        if let Some(value) = optional_usize("max_world_bytes", config.max_world_bytes)? {
            builder = builder.max_world_bytes(value);
        }
        if let Some(value) = optional_usize("max_memory_bytes", config.max_memory_bytes)? {
            builder = builder.max_memory_bytes(value);
        }
        builder = builder.max_storage_bytes(optional_usize(
            "max_storage_bytes",
            config.max_storage_bytes,
        )?);
        if let Some(value) =
            optional_usize("max_listen_connections", config.max_listen_connections)?
        {
            builder = builder.max_listen_connections(value);
        }
        if let Some(value) = optional_usize("listen_replay_max", config.listen_replay_max)? {
            builder = builder.listen_replay_max(value);
        }
        if let Some(value) =
            optional_usize("read_cache_max_entries", config.read_cache_max_entries)?
        {
            builder = builder.read_cache_max_entries(value);
        }

        let engine = builder.build()?;
        let runtime = Arc::new(
            RuntimeBuilder::new_multi_thread()
                .enable_all()
                .thread_name("l5-ffi")
                .build()
                .map_err(|err| FfiError::RuntimeInitFailed {
                    message: err.to_string(),
                })?,
        );

        Ok(Arc::new(Self {
            engine,
            runtime,
            config: summary,
        }))
    }

    /// Returns non-secret configuration accepted by the adapter.
    pub fn config_summary(&self) -> FfiEngineConfigSummary {
        self.config.clone()
    }

    /// Verifies raw token bytes against the Engine token tiers.
    pub fn verify_token(&self, token: Vec<u8>) -> FfiAccessTier {
        self.engine.verify_token(&token).into()
    }

    /// Starts orderly Engine shutdown.
    pub fn shutdown(&self) {
        self.engine.shutdown();
    }

    /// Names the runtime model this handle owns.
    #[allow(deprecated)]
    #[deprecated(note = "Layer 2 smoke export only; real Engine verbs replace this surface.")]
    pub fn runtime_model(&self) -> String {
        let _ = self.runtime.handle();
        "embedded Tokio runtime; async Engine verbs block inside the FFI handle".to_owned()
    }

    /// Reads a world's full representation.
    pub fn read(
        &self,
        world: String,
        tier: FfiAccessTier,
    ) -> Result<Option<FfiReadResult>, FfiError> {
        let world = validated_world(world)?;
        Ok(self
            .runtime
            .block_on(self.engine.read(&world, tier.try_into()?))?
            .map(Into::into))
    }

    /// Dereferences an exact historical timeline coordinate.
    ///
    /// Foreign callers pass raw coordinate fields at the ABI boundary. The FFI
    /// adapter immediately validates them into the core `TimelineCoordinate`
    /// proof before the Engine touches storage.
    pub fn dereference_timeline_coordinate(
        &self,
        coordinate: FfiTimelineCoordinate,
        tier: FfiAccessTier,
    ) -> Result<FfiTimelineDereference, FfiError> {
        let coordinate = coordinate.try_into_core()?;
        Ok(self
            .runtime
            .block_on(
                self.engine
                    .dereference_timeline_coordinate(&coordinate, tier.try_into()?),
            )?
            .into())
    }

    /// Replaces a world with the provided representation.
    pub fn replace(
        &self,
        world: String,
        representation: FfiRepresentation,
        preconditions: FfiPreconditions,
        tier: FfiAccessTier,
    ) -> Result<FfiWriteResult, FfiError> {
        let world = validated_world(world)?;
        let result = self.runtime.block_on(self.engine.replace(
            &world,
            representation.into(),
            preconditions.into(),
            tier.try_into()?,
        ))?;
        Ok(result.into())
    }

    /// Appends bytes to a world's body.
    pub fn append(
        &self,
        world: String,
        body: Vec<u8>,
        preconditions: FfiPreconditions,
        tier: FfiAccessTier,
    ) -> Result<FfiWriteResult, FfiError> {
        let world = validated_world(world)?;
        let result = self.runtime.block_on(self.engine.append(
            &world,
            body.into(),
            preconditions.into(),
            tier.try_into()?,
        ))?;
        Ok(result.into())
    }

    /// Deletes a world.
    pub fn delete(
        &self,
        world: String,
        preconditions: FfiPreconditions,
        tier: FfiAccessTier,
    ) -> Result<(), FfiError> {
        let world = validated_world(world)?;
        Ok(self.runtime.block_on(self.engine.delete(
            &world,
            preconditions.into(),
            tier.try_into()?,
        ))?)
    }

    /// Deletes a world while preserving representation metadata in delete audit rows.
    pub fn delete_with_metadata(
        &self,
        world: String,
        metadata: FfiDeleteMetadata,
        preconditions: FfiPreconditions,
        tier: FfiAccessTier,
    ) -> Result<(), FfiError> {
        let world = validated_world(world)?;
        Ok(self.runtime.block_on(self.engine.delete_traced(
            &world,
            metadata.into(),
            preconditions.into(),
            tier.try_into()?,
            Arc::new(NoopDeleteTrace),
        ))?)
    }

    /// Lists every canonical world known to the Engine.
    ///
    /// Returned strings are canonical Engine worlds that round-trip through
    /// `read`, `replace`, `append`, `delete`, and `audit_verify` without
    /// validation failure.
    pub fn worlds(&self, tier: FfiAccessTier) -> Result<Vec<String>, FfiError> {
        Ok(self
            .engine
            .list_worlds(tier.try_into()?)?
            .into_iter()
            .map(|world| world.to_string())
            .collect())
    }

    /// Returns per-world byte usage.
    pub fn du(&self, tier: FfiAccessTier) -> Result<Vec<FfiWorldUsage>, FfiError> {
        Ok(self
            .engine
            .du(tier.try_into()?)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Returns aggregate storage and memory usage.
    pub fn df(&self, tier: FfiAccessTier) -> Result<FfiDfSnapshot, FfiError> {
        Ok(self.engine.df(tier.try_into()?)?.into())
    }

    /// Returns read-cache and ledger-writer counters.
    pub fn pool(&self, tier: FfiAccessTier) -> Result<FfiPoolSnapshot, FfiError> {
        Ok(self.engine.pool(tier.try_into()?)?.into())
    }

    /// Verifies one world's HMAC audit chain.
    pub fn audit_verify(
        &self,
        world: String,
        tier: FfiAccessTier,
    ) -> Result<FfiAuditVerify, FfiError> {
        let world = validated_world(world)?;
        Ok(self.engine.verify_audit(&world, tier.try_into()?)?.into())
    }

    /// Opens a protocol-neutral Engine subscription.
    ///
    /// `pattern` is an Engine subscription pattern such as `*` or
    /// `home/tasks/*`; it is not a `/listen/*` HTTP route.
    pub fn subscribe(
        &self,
        pattern: String,
        tier: FfiAccessTier,
        resume: FfiSubscriptionResume,
    ) -> Result<Arc<FfiSubscription>, FfiError> {
        let pattern = SubscribePattern::new(pattern);
        let resume = SubscriptionResume::try_from(resume)?;
        let mut subscription =
            self.runtime
                .block_on(self.engine.subscribe(&pattern, tier.try_into()?, resume))?;
        let (events_tx, events_rx) = mpsc::channel(FFI_SUBSCRIPTION_BUFFER);
        let (cancel, mut cancel_rx) = watch::channel(false);
        let pump = self.runtime.spawn(async move {
            loop {
                tokio::select! {
                    changed = cancel_rx.changed() => {
                        let _ = changed;
                        break;
                    }
                    item = subscription.recv() => {
                        let (next, terminal) = subscription_next_from_recv(item);
                        let sent = tokio::select! {
                            changed = cancel_rx.changed() => {
                                let _ = changed;
                                break;
                            }
                            sent = events_tx.send(next) => sent,
                        };
                        if sent.is_err() || terminal {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Arc::new(FfiSubscription {
            events: Mutex::new(events_rx),
            cancel,
            pump: Mutex::new(Some(pump)),
            runtime: Arc::clone(&self.runtime),
        }))
    }
}

#[uniffi::export]
impl FfiSubscription {
    /// Blocks until the next event, timeout, lag, or close.
    ///
    /// This is a blocking receive, not busy polling. A timeout returns
    /// `Timeout` so foreign callers can periodically check their own
    /// cancellation condition without crossing a callback boundary. Calling
    /// `close()` wakes a blocked `next()` by closing the internal event
    /// receiver; callers do not need to wait for `timeout_ms` to elapse.
    pub fn next(&self, timeout_ms: u64) -> FfiSubscriptionNext {
        match self.runtime.block_on(async {
            let mut events = self.events.lock().await;
            timeout(Duration::from_millis(timeout_ms), events.recv()).await
        }) {
            Ok(Some(next)) => next,
            Ok(None) => FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Closed,
                event: None,
                skipped: None,
                reset_reason: None,
            },
            Err(_) => FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Timeout,
                event: None,
                skipped: None,
                reset_reason: None,
            },
        }
    }

    /// Closes the subscription and releases the underlying Engine listen slot.
    ///
    /// Dropping the object also cancels, but `close()` lets garbage-collected
    /// languages release the Engine subscription slot deterministically.
    pub fn close(&self) {
        let _ = self.cancel.send(true);
        self.runtime.block_on(async {
            if let Some(pump) = self.pump.lock().await.take() {
                let _ = pump.await;
            }
            let mut events = self.events.lock().await;
            events.close();
            while events.try_recv().is_ok() {}
        });
    }
}

impl Drop for FfiSubscription {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Ok(mut pump) = self.pump.try_lock() {
            if let Some(pump) = pump.take() {
                pump.abort();
            }
        }
    }
}

impl Drop for FfiEngine {
    fn drop(&mut self) {
        self.engine.shutdown();
    }
}

/// Returns the FFI adapter package version.
#[uniffi::export]
pub fn ffi_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Names the architectural boundary this adapter is allowed to cross.
///
/// This smoke export remains as a cheap boundary check alongside the real
/// Engine-bound methods: HTTP/server vocabulary must stay out of the FFI API.
#[allow(deprecated)]
#[deprecated(note = "Layer 1/2 smoke export only; use real Engine-bound FFI methods.")]
#[uniffi::export]
pub fn ffi_engine_boundary() -> String {
    "Engine adapter only: no HTTP routes, no /proc paths, no status codes".to_owned()
}

fn optional_usize(name: &'static str, value: Option<u64>) -> Result<Option<usize>, FfiError> {
    value
        .map(|value| {
            usize::try_from(value).map_err(|_| FfiError::InvalidConfig {
                message: format!("{name} exceeds this platform's usize range"),
            })
        })
        .transpose()
}

fn validated_world(world: String) -> Result<ValidatedWorldPath, FfiError> {
    ValidatedWorldPath::new(world.clone()).map_err(|err| FfiError::InvalidWorld {
        message: format!("{err}: {world}"),
    })
}

fn subscription_next_from_recv(
    result: Result<ChangeEvent, SubscriptionRecvError>,
) -> (FfiSubscriptionNext, bool) {
    match result {
        Ok(event) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Event,
                event: Some(event.into()),
                skipped: None,
                reset_reason: None,
            },
            false,
        ),
        Err(SubscriptionRecvError::Lagged { skipped }) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Lagged,
                event: None,
                skipped: Some(skipped),
                reset_reason: None,
            },
            false,
        ),
        Err(SubscriptionRecvError::Reset { reason }) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Reset,
                event: None,
                skipped: None,
                reset_reason: Some(reason.into()),
            },
            false,
        ),
        Err(SubscriptionRecvError::Closed) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Closed,
                event: None,
                skipped: None,
                reset_reason: None,
            },
            true,
        ),
        Err(_) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Unknown,
                event: None,
                skipped: None,
                reset_reason: None,
            },
            true,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use l5::{AuditVerify, EngineBuildError, EngineError, SubscriptionEventId};
    use std::{
        path::{Path, PathBuf},
        sync::mpsc as std_mpsc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[test]
    #[allow(deprecated)]
    fn scaffold_reports_version_and_boundary() {
        assert_eq!(ffi_version(), env!("CARGO_PKG_VERSION"));
        assert!(ffi_engine_boundary().contains("Engine adapter only"));
    }

    #[test]
    #[allow(deprecated)]
    fn engine_handle_opens_and_verifies_tokens() {
        let dir = unique_test_dir("opens");
        let engine = FfiEngine::open(FfiEngineConfig {
            data_root: dir.clone(),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: Some(b"read".to_vec()),
            write_token: Some(b"write".to_vec()),
            approve_token: Some(b"approve".to_vec()),
            max_world_bytes: None,
            max_memory_bytes: None,
            max_storage_bytes: None,
            max_listen_connections: None,
            listen_replay_max: None,
            read_cache_max_entries: Some(2),
        })
        .expect("engine opens");

        assert_eq!(engine.config_summary().data_root, dir);
        assert_eq!(engine.verify_token(b"read".to_vec()), FfiAccessTier::Read);
        assert_eq!(engine.verify_token(b"write".to_vec()), FfiAccessTier::Write);
        assert_eq!(
            engine.verify_token(b"approve".to_vec()),
            FfiAccessTier::Approve
        );
        assert_eq!(engine.verify_token(b"bad".to_vec()), FfiAccessTier::Anon);
        assert!(engine.runtime_model().contains("embedded Tokio runtime"));
        engine.shutdown();
    }

    #[test]
    fn engine_handle_drop_shuts_down_cleanly() {
        let engine = FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir("drop-shutdown"),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: None,
            write_token: None,
            approve_token: None,
            max_world_bytes: None,
            max_memory_bytes: None,
            max_storage_bytes: None,
            max_listen_connections: None,
            listen_replay_max: None,
            read_cache_max_entries: None,
        })
        .expect("engine opens");

        drop(engine);
    }

    #[test]
    fn config_summary_uses_engine_normalization_rules() {
        let engine = FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir("summary-normalization"),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: Some(b" \t\n".to_vec()),
            write_token: Some(Vec::new()),
            approve_token: Some(vec![0xff, 0xfe]),
            max_world_bytes: Some(0),
            max_memory_bytes: Some(0),
            max_storage_bytes: Some(0),
            max_listen_connections: Some(0),
            listen_replay_max: Some(0),
            read_cache_max_entries: Some(0),
        })
        .expect("engine opens");
        let summary = engine.config_summary();

        assert!(!summary.has_read_token);
        assert!(!summary.has_write_token);
        assert!(summary.has_approve_token);
        assert_eq!(summary.max_world_bytes, Some(0));
        assert_eq!(summary.max_memory_bytes, Some(0));
        assert_eq!(summary.max_storage_bytes, None);
        assert_eq!(summary.max_listen_connections, None);
        assert_eq!(summary.listen_replay_max, None);
        assert_eq!(summary.read_cache_max_entries, None);
        assert_eq!(
            engine.verify_token(vec![0xff, 0xfe]),
            FfiAccessTier::Approve
        );
    }

    #[test]
    fn change_event_uses_engine_verb_enum() {
        let event = FfiChangeEvent {
            id: 1,
            cursor: Some("home/doc@0123456789abcdef0123456789abcdef=1".to_owned()),
            verb: FfiChangeVerb::Replace,
            path: "home/doc".to_owned(),
            etag: "abc".to_owned(),
            timeline_world: None,
            timeline_generation: None,
            timeline_seq: None,
            timeline_body_sha256: None,
            delete_ledger_cursor: None,
            delete_ledger_seq: None,
            delete_subject_generation: None,
            audit_event_type: None,
            audit_event_target: None,
            body_sha256: None,
            body_size: None,
            content_type: None,
        };

        assert_eq!(event.verb, FfiChangeVerb::Replace);
    }

    #[test]
    fn engine_verbs_roundtrip_bytes_and_introspection() {
        let engine = test_engine("verbs");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };

        assert!(engine
            .read("home/doc".to_owned(), FfiAccessTier::Read)
            .expect("read missing succeeds")
            .is_none());

        let created = engine
            .replace(
                "home/doc".to_owned(),
                FfiRepresentation {
                    body: b"hello".to_vec(),
                    content_type: "text/plain".to_owned(),
                    headers: vec![FfiHeader {
                        name: "x-meta".to_owned(),
                        value: "one".to_owned(),
                    }],
                },
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("replace succeeds");
        assert_eq!(created.kind, FfiWriteKind::Created);

        let appended = engine
            .append(
                "home/doc".to_owned(),
                b" world".to_vec(),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("append succeeds");
        assert_eq!(appended.kind, FfiWriteKind::Updated);

        let read = engine
            .read("home/doc".to_owned(), FfiAccessTier::Read)
            .expect("read succeeds")
            .expect("world exists");
        assert_eq!(read.representation.body, b"hello world");
        assert_eq!(read.representation.content_type, "text/plain");

        let injected = engine
            .replace(
                "home/metadata-injection".to_owned(),
                FfiRepresentation {
                    body: b"body".to_vec(),
                    content_type: "text/plain\r\nx-injected: yes".to_owned(),
                    headers: Vec::new(),
                },
                none.clone(),
                FfiAccessTier::Write,
            )
            .unwrap_err();
        assert!(matches!(
            injected,
            FfiError::InvalidMetadata { ref message }
                if message == "metadata-control-character"
        ));

        assert_eq!(
            engine.worlds(FfiAccessTier::Read).expect("worlds"),
            vec!["home/doc".to_owned()]
        );
        for world in engine.worlds(FfiAccessTier::Read).expect("worlds") {
            assert!(engine
                .read(world, FfiAccessTier::Read)
                .expect("listed world round-trips")
                .is_some());
        }
        let usage = engine.du(FfiAccessTier::Read).expect("du");
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].world, "home/doc");
        assert_eq!(usage[0].bytes, 27);
        assert_eq!(usage[0].current_body_bytes, 11);
        assert_eq!(usage[0].retained_cas_body_bytes, 16);
        assert_eq!(usage[0].audit_chain_events, 3);
        let df = engine.df(FfiAccessTier::Read).expect("df");
        assert_eq!(df.storage_used, 27);
        assert_eq!(df.storage_current_body_bytes, 11);
        assert_eq!(df.storage_retained_cas_body_bytes, 16);
        assert_eq!(df.storage_audit_chain_events, 3);
        assert_eq!(df.worlds, 1);
        assert_eq!(
            engine
                .pool(FfiAccessTier::Read)
                .expect("pool")
                .read_cache_max_entries,
            2
        );
        assert!(matches!(
            engine
                .audit_verify("home/doc".to_owned(), FfiAccessTier::Read)
                .expect("audit verify"),
            FfiAuditVerify::Valid { .. }
        ));

        engine
            .delete("home/doc".to_owned(), none, FfiAccessTier::Approve)
            .expect("delete succeeds");
        assert!(engine
            .read("home/doc".to_owned(), FfiAccessTier::Read)
            .expect("read deleted succeeds")
            .is_none());
    }

    #[test]
    fn delete_with_metadata_preserves_delete_audit_metadata() {
        let dir = unique_test_dir("delete-meta");
        let engine = FfiEngine::open(FfiEngineConfig {
            data_root: dir.clone(),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: None,
            write_token: None,
            approve_token: None,
            max_world_bytes: None,
            max_memory_bytes: None,
            max_storage_bytes: None,
            max_listen_connections: None,
            listen_replay_max: None,
            read_cache_max_entries: Some(2),
        })
        .expect("engine opens");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };

        engine
            .replace(
                "home/delete-meta".to_owned(),
                FfiRepresentation {
                    body: b"delete me".to_vec(),
                    content_type: "application/octet-stream".to_owned(),
                    headers: Vec::new(),
                },
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("replace succeeds");
        engine
            .delete_with_metadata(
                "home/delete-meta".to_owned(),
                FfiDeleteMetadata {
                    content_type: "text/plain; charset=utf-8".to_owned(),
                    headers: vec![FfiHeader {
                        name: "x-meta-author".to_owned(),
                        value: "ranger".to_owned(),
                    }],
                },
                none,
                FfiAccessTier::Approve,
            )
            .expect("delete succeeds");

        let ledger = rusqlite::Connection::open(test_world_db(&dir, "var/log/deletes"))
            .expect("delete ledger opens");
        let rows = ledger
            .prepare(
                "SELECT event_type, content_type FROM events \
                 WHERE event_type IN ('delete_intent', 'delete_commit') ORDER BY id",
            )
            .expect("prepare event query")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query event rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect event rows");
        assert_eq!(
            rows,
            vec![
                (
                    "delete_intent".to_owned(),
                    "text/plain; charset=utf-8".to_owned()
                ),
                (
                    "delete_commit".to_owned(),
                    "text/plain; charset=utf-8".to_owned()
                ),
            ]
        );
        let author_rows: i64 = ledger
            .query_row(
                "SELECT COUNT(*) FROM event_headers WHERE name='x-meta-author' AND value='ranger'",
                [],
                |row| row.get(0),
            )
            .expect("metadata header rows exist");
        assert_eq!(author_rows, 2);
    }

    #[test]
    fn delete_with_metadata_rejects_reserved_delete_subject_headers() {
        let engine = test_engine("delete-meta-reserved");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        engine
            .replace(
                "home/delete-meta-reserved".to_owned(),
                small_representation(b"delete me"),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("replace succeeds");

        let err = engine
            .delete_with_metadata(
                "home/delete-meta-reserved".to_owned(),
                FfiDeleteMetadata {
                    content_type: "text/plain".to_owned(),
                    headers: vec![FfiHeader {
                        name: "auditedb-delete-subject-seq".to_owned(),
                        value: "fake".to_owned(),
                    }],
                },
                none,
                FfiAccessTier::Approve,
            )
            .expect_err("reserved header should be rejected");

        assert!(matches!(
            err,
            FfiError::InvalidMetadata { ref message }
                if message == "reserved-delete-subject-header"
        ));
        assert!(engine
            .read("home/delete-meta-reserved".to_owned(), FfiAccessTier::Read)
            .expect("read after rejected delete")
            .is_some());
    }

    #[test]
    fn delete_with_metadata_rejects_control_characters() {
        let engine = test_engine("delete-meta-control-chars");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        engine
            .replace(
                "home/delete-meta-control-chars".to_owned(),
                small_representation(b"delete me"),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("replace succeeds");

        let err = engine
            .delete_with_metadata(
                "home/delete-meta-control-chars".to_owned(),
                FfiDeleteMetadata {
                    content_type: "text/plain\r\nx-injected: yes".to_owned(),
                    headers: Vec::new(),
                },
                none,
                FfiAccessTier::Approve,
            )
            .expect_err("control characters should be rejected");

        assert!(matches!(
            err,
            FfiError::InvalidMetadata { ref message }
                if message == "metadata-control-character"
        ));
        assert!(engine
            .read(
                "home/delete-meta-control-chars".to_owned(),
                FfiAccessTier::Read
            )
            .expect("read after rejected delete")
            .is_some());
    }

    #[test]
    fn engine_verbs_reject_noncanonical_worlds() {
        let engine = test_engine("invalid-world");
        let err = engine
            .read("/home/doc".to_owned(), FfiAccessTier::Read)
            .expect_err("wire paths are not Engine worlds");
        match err {
            FfiError::InvalidWorld { message } => {
                assert!(message.contains("invalid world path"));
                assert!(message.contains("/home/doc"));
            }
            other => panic!("expected invalid world error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_tier_is_rejected_at_boundary() {
        let engine = test_engine("unknown-tier");
        let err = engine
            .read("home/doc".to_owned(), FfiAccessTier::Unknown)
            .expect_err("unknown tier must not silently downgrade");
        assert!(matches!(err, FfiError::InvalidConfig { .. }));
    }

    #[test]
    fn write_preconditions_reject_stale_etags() {
        let engine = test_engine("precondition-if-match");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        engine
            .replace(
                "home/doc".to_owned(),
                small_representation(b"first"),
                none,
                FfiAccessTier::Write,
            )
            .expect("create succeeds");

        let stale = FfiPreconditions {
            if_match: vec![FfiEtagMatcher::Strong {
                etag: "wrong-etag".to_owned(),
            }],
            if_none_match: Vec::new(),
        };
        let err = engine
            .replace(
                "home/doc".to_owned(),
                small_representation(b"second"),
                stale,
                FfiAccessTier::Write,
            )
            .expect_err("stale If-Match rejected");
        assert!(matches!(err, FfiError::PreconditionFailed { .. }));
    }

    #[test]
    fn subscription_next_drains_replay_then_live_events() {
        let engine = test_engine("subscribe");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        let initial_subscription = engine
            .subscribe(
                "home/events/*".to_owned(),
                FfiAccessTier::Read,
                resume_none(),
            )
            .expect("initial subscription opens");
        engine
            .replace(
                "home/events/a".to_owned(),
                FfiRepresentation {
                    body: b"first".to_vec(),
                    content_type: "text/plain".to_owned(),
                    headers: Vec::new(),
                },
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("first write succeeds");
        let format = initial_subscription.next(1_000);
        assert_eq!(format.kind, FfiSubscriptionNextKind::Event);
        let format_event = format.event.expect("format event");
        assert_eq!(format_event.verb, FfiChangeVerb::Format);
        assert_eq!(format_event.path, "home/events/a");
        assert_eq!(format_event.timeline_world, None);
        assert!(format_event.cursor.is_some());
        assert!(format_event.body_sha256.is_some());
        assert_eq!(format_event.body_size, Some(0));
        assert_eq!(format_event.content_type.as_deref(), Some(""));

        let first = initial_subscription.next(1_000);
        assert_eq!(first.kind, FfiSubscriptionNextKind::Event);
        let first_event = first.event.expect("first live event");
        let first_coordinate = FfiTimelineCoordinate {
            world: first_event.timeline_world.clone().expect("timeline world"),
            generation: first_event
                .timeline_generation
                .clone()
                .expect("timeline generation"),
            seq: first_event.timeline_seq.expect("timeline seq"),
            body_sha256: first_event
                .timeline_body_sha256
                .clone()
                .expect("timeline body hash"),
        };
        assert_eq!(
            first_event.body_sha256.as_deref(),
            first_event.timeline_body_sha256.as_deref()
        );
        assert_eq!(first_event.body_size, Some(5));
        assert_eq!(first_event.content_type.as_deref(), Some("text/plain"));
        let first_cursor = first_event.cursor.expect("first event has durable cursor");
        initial_subscription.close();

        engine
            .append(
                "home/events/a".to_owned(),
                b" replay".to_vec(),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("second write succeeds");
        let data_root = engine.config_summary().data_root;
        let conn = rusqlite::Connection::open(test_world_db(&data_root, "home/events/a")).unwrap();
        let expected_hmac: String = conn
            .query_row(
                "SELECT hmac FROM events WHERE id=?1",
                [first_coordinate.seq],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);
        let historical = engine
            .dereference_timeline_coordinate(first_coordinate.clone(), FfiAccessTier::Read)
            .expect("timeline coordinate dereferences after overwrite");
        assert_eq!(historical.kind, FfiTimelineDereferenceKind::Body);
        assert_eq!(historical.hmac.as_deref(), Some(expected_hmac.as_str()));
        assert_eq!(
            historical
                .representation
                .expect("historical representation")
                .body,
            b"first"
        );
        assert_eq!(historical.coordinate, Some(first_coordinate.clone()));

        let subscription = engine
            .subscribe(
                "home/events/a".to_owned(),
                FfiAccessTier::Read,
                resume_after_cursor(first_cursor),
            )
            .expect("subscription opens");
        let replay = subscription.next(1_000);
        assert_eq!(replay.kind, FfiSubscriptionNextKind::Event);
        let event = replay.event.expect("replay event");
        assert_eq!(event.verb, FfiChangeVerb::Append);
        assert_eq!(event.path, "home/events/a");
        assert_eq!(
            event.body_sha256.as_deref(),
            event.timeline_body_sha256.as_deref()
        );
        assert_eq!(event.body_size, Some(12));
        assert_eq!(event.content_type.as_deref(), Some("text/plain"));
        let cursor = event.cursor.expect("replay event has durable cursor");
        assert!(cursor.contains('@'));
        assert!(cursor.contains('='));

        let timeout = subscription.next(1);
        assert_eq!(timeout.kind, FfiSubscriptionNextKind::Timeout);
        assert!(timeout.event.is_none());

        engine
            .append(
                "home/events/a".to_owned(),
                b" live".to_vec(),
                none,
                FfiAccessTier::Write,
            )
            .expect("append succeeds");
        let live = subscription.next(1_000);
        assert_eq!(live.kind, FfiSubscriptionNextKind::Event);
        let event = live.event.expect("live event");
        assert_eq!(event.verb, FfiChangeVerb::Append);
        assert_eq!(event.path, "home/events/a");
        assert_eq!(event.body_size, Some(17));
        assert_eq!(event.content_type.as_deref(), Some("text/plain"));

        let conn = rusqlite::Connection::open(test_world_db(&data_root, "home/events/a")).unwrap();
        conn.execute(
            "DELETE FROM cas_bodies WHERE body_sha256=?1",
            [first_event
                .timeline_body_sha256
                .expect("timeline body hash")],
        )
        .unwrap();
        conn.execute("UPDATE cas_state SET first_retained_seq=3 WHERE id=1", [])
            .unwrap();
        drop(conn);
        let expired = engine
            .dereference_timeline_coordinate(first_coordinate.clone(), FfiAccessTier::Read)
            .expect("expired timeline coordinate dereferences");
        assert_eq!(expired.kind, FfiTimelineDereferenceKind::Expired);
        assert!(expired.representation.is_none());
        assert_eq!(expired.coordinate, Some(first_coordinate.clone()));
        assert_eq!(expired.content_type.as_deref(), Some("text/plain"));
        assert_eq!(expired.size, Some(5));
        assert!(expired.hmac.as_deref().is_some_and(|hmac| !hmac.is_empty()));
    }

    #[test]
    fn subscription_replays_delete_ledger_non_body_events() {
        let engine = test_engine("subscribe-delete-ledger");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        engine
            .replace(
                "home/events/delete-ledger".to_owned(),
                small_representation(b"delete me"),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("subject write succeeds");
        let initial = engine
            .subscribe(
                "var/log/deletes".to_owned(),
                FfiAccessTier::Read,
                resume_none(),
            )
            .expect("ledger subscription opens");

        engine
            .delete(
                "home/events/delete-ledger".to_owned(),
                none,
                FfiAccessTier::Approve,
            )
            .expect("delete succeeds");
        let format = initial.next(1_000);
        assert_eq!(format.kind, FfiSubscriptionNextKind::Event);
        let format_event = format.event.expect("delete ledger format event");
        assert_eq!(format_event.verb, FfiChangeVerb::Format);
        assert_eq!(format_event.path, "var/log/deletes");
        assert_eq!(format_event.body_size, Some(0));

        let first = initial.next(1_000);
        assert_eq!(first.kind, FfiSubscriptionNextKind::Event);
        let first_event = first.event.expect("delete intent event");
        assert_eq!(first_event.verb, FfiChangeVerb::Delete);
        assert_eq!(first_event.path, "var/log/deletes");
        let first_cursor = first_event.cursor.clone().expect("ledger event has cursor");
        assert!(first_cursor.starts_with("var/log/deletes@"));
        assert_eq!(first_event.timeline_world, None);
        assert_eq!(first_event.timeline_generation, None);
        assert_eq!(first_event.timeline_seq, None);
        assert_eq!(first_event.timeline_body_sha256, None);
        assert_eq!(
            first_event.audit_event_type.as_deref(),
            Some("delete_intent")
        );
        assert_eq!(
            first_event.audit_event_target.as_deref(),
            Some("home/events/delete-ledger")
        );
        assert!(first_event
            .delete_subject_generation
            .as_deref()
            .is_some_and(|generation| generation.len() == 32));
        assert!(first_event
            .body_sha256
            .as_deref()
            .is_some_and(|hash| hash.len() == 64));
        assert_eq!(first_event.body_size, Some(0));
        assert_eq!(first_event.content_type.as_deref(), Some(""));
        let first_id =
            SubscriptionEventId::from_sse_id(&first_cursor).expect("ledger cursor parses");
        let non_body_deref = engine
            .dereference_timeline_coordinate(
                FfiTimelineCoordinate {
                    world: first_id.world().as_str().to_owned(),
                    generation: first_id.generation().as_str().to_owned(),
                    seq: first_id.seq().get(),
                    body_sha256: first_event
                        .body_sha256
                        .clone()
                        .expect("delete intent carries payload hash"),
                },
                FfiAccessTier::Read,
            )
            .expect("delete intent coordinate dereferences as non-body");
        assert_eq!(
            non_body_deref.kind,
            FfiTimelineDereferenceKind::NonBodyEvent
        );
        assert_eq!(non_body_deref.event_type.as_deref(), Some("delete_intent"));
        assert_eq!(
            non_body_deref.event_target.as_deref(),
            Some("home/events/delete-ledger")
        );
        assert_eq!(non_body_deref.size, Some(0));
        assert_eq!(non_body_deref.content_type.as_deref(), Some(""));
        assert_eq!(
            non_body_deref.delete_subject_generation,
            first_event.delete_subject_generation
        );
        assert!(non_body_deref
            .event_body_sha256
            .as_deref()
            .is_some_and(|hash| hash.len() == 64));
        assert!(non_body_deref
            .hmac
            .as_deref()
            .is_some_and(|hmac| hmac.len() == 64));
        initial.close();

        let replay = engine
            .subscribe(
                "var/log/deletes".to_owned(),
                FfiAccessTier::Read,
                resume_after_cursor(first_cursor),
            )
            .expect("ledger replay subscription opens");
        let second = replay.next(1_000);
        assert_eq!(second.kind, FfiSubscriptionNextKind::Event);
        let second_event = second.event.expect("delete commit replay");
        assert_eq!(second_event.verb, FfiChangeVerb::Delete);
        assert_eq!(second_event.path, "var/log/deletes");
        assert_eq!(second_event.timeline_world, None);
        assert_eq!(second_event.timeline_generation, None);
        assert_eq!(second_event.timeline_seq, None);
        assert_eq!(second_event.timeline_body_sha256, None);
        assert!(second_event
            .body_sha256
            .as_deref()
            .is_some_and(|hash| hash.len() == 64));
        assert_eq!(
            second_event.delete_subject_generation,
            first_event.delete_subject_generation
        );
        assert_eq!(second_event.body_size, Some(0));
        assert_eq!(second_event.content_type.as_deref(), Some(""));
        let second_id = SubscriptionEventId::from_sse_id(
            second_event
                .cursor
                .as_ref()
                .expect("replay event has cursor"),
        )
        .expect("replay cursor parses");
        assert_eq!(second_id.world(), first_id.world());
        assert_eq!(second_id.generation(), first_id.generation());
        assert_eq!(second_id.seq().get(), first_id.seq().get() + 1);
    }

    #[test]
    fn subscription_subject_delete_ping_has_no_ffi_cursor() {
        let engine = test_engine("subscribe-subject-delete");
        let none = FfiPreconditions {
            if_match: Vec::new(),
            if_none_match: Vec::new(),
        };
        engine
            .replace(
                "home/events/delete-subject".to_owned(),
                small_representation(b"delete me"),
                none.clone(),
                FfiAccessTier::Write,
            )
            .expect("subject write succeeds");
        let subscription = engine
            .subscribe(
                "home/events/delete-subject".to_owned(),
                FfiAccessTier::Read,
                resume_none(),
            )
            .expect("subject subscription opens");

        engine
            .delete(
                "home/events/delete-subject".to_owned(),
                none,
                FfiAccessTier::Approve,
            )
            .expect("delete succeeds");
        let next = subscription.next(1_000);
        assert_eq!(next.kind, FfiSubscriptionNextKind::Event);
        let event = next.event.expect("subject delete event");
        assert_eq!(event.verb, FfiChangeVerb::Delete);
        assert_eq!(event.path, "home/events/delete-subject");
        assert_eq!(event.cursor, None);
        assert!(
            event
                .delete_ledger_cursor
                .as_deref()
                .is_some_and(|cursor| cursor.starts_with("var/log/deletes@")),
            "{event:?}"
        );
        assert_eq!(event.delete_ledger_seq, Some(2));
        assert!(event
            .delete_subject_generation
            .as_deref()
            .is_some_and(|generation| generation.len() == 32));
        assert_eq!(event.body_sha256, None);
        assert_eq!(event.body_size, None);
        assert_eq!(event.content_type, None);
    }

    #[test]
    fn timeline_coordinate_rejects_raw_invalid_ffi_fields() {
        let engine = test_engine("timeline-invalid-coordinate");
        let good = FfiTimelineCoordinate {
            world: "home/timeline".to_owned(),
            generation: "0123456789abcdef0123456789abcdef".to_owned(),
            seq: 1,
            body_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        for (label, coordinate) in [
            (
                "memory world",
                FfiTimelineCoordinate {
                    world: "tmp/not-durable".to_owned(),
                    ..good.clone()
                },
            ),
            (
                "uppercase generation",
                FfiTimelineCoordinate {
                    generation: "A123456789abcdef0123456789abcdef".to_owned(),
                    ..good.clone()
                },
            ),
            (
                "zero sequence",
                FfiTimelineCoordinate {
                    seq: 0,
                    ..good.clone()
                },
            ),
            (
                "bad body hash",
                FfiTimelineCoordinate {
                    body_sha256: "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                    ..good.clone()
                },
            ),
        ] {
            match engine.dereference_timeline_coordinate(coordinate, FfiAccessTier::Read) {
                Err(FfiError::InvalidConfig { .. }) => {}
                Err(other) => panic!("{label} returned wrong error: {other:?}"),
                Ok(_) => panic!("{label} should fail at FFI boundary"),
            }
        }
    }

    #[test]
    fn subscription_rejects_non_durable_resume_cursor() {
        let engine = test_engine("subscribe-invalid-resume");
        let err = match engine.subscribe(
            "home/stale/*".to_owned(),
            FfiAccessTier::Read,
            resume_after_cursor("42".to_owned()),
        ) {
            Ok(_) => panic!("non-durable subscription resume should fail"),
            Err(err) => err,
        };
        match err {
            FfiError::InvalidConfig { message } => {
                assert!(message.contains("subscription event id is missing seq delimiter"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn subscription_next_reports_closed_after_shutdown() {
        let engine = test_engine("subscribe-closed");
        let subscription = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
            .expect("subscription opens");
        engine.shutdown();

        let closed = subscription.next(1_000);
        assert_eq!(closed.kind, FfiSubscriptionNextKind::Closed);
        assert!(closed.event.is_none());
    }

    #[test]
    fn subscription_close_releases_receiver_without_waiting_for_drop() {
        let engine = FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir("subscribe-explicit-close"),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: None,
            write_token: None,
            approve_token: None,
            max_world_bytes: None,
            max_memory_bytes: None,
            max_storage_bytes: None,
            max_listen_connections: Some(1),
            listen_replay_max: None,
            read_cache_max_entries: Some(2),
        })
        .expect("engine opens");

        let subscription = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
            .expect("first subscription opens");
        assert!(
            engine
                .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
                .is_err(),
            "listen slot cap should be held while subscription is open"
        );

        subscription.close();
        let closed = subscription.next(100);
        assert_eq!(closed.kind, FfiSubscriptionNextKind::Closed);

        let replacement = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
            .expect("explicit close releases listen slot");
        replacement.close();
    }

    #[test]
    fn subscription_close_wakes_blocking_next() {
        let engine = test_engine("subscribe-close-wakes-blocking-next");
        let subscription = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
            .expect("subscription opens");
        let (started_tx, started_rx) = std_mpsc::channel();
        let waiting = Arc::clone(&subscription);

        let handle = std::thread::spawn(move || {
            started_tx.send(()).expect("signal next waiter started");
            waiting.next(1_000)
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("next waiter should start");

        subscription.close();

        let closed = handle.join().expect("next waiter should join");
        assert_eq!(closed.kind, FfiSubscriptionNextKind::Closed);
        assert!(closed.event.is_none());
    }

    #[test]
    fn subscription_next_survives_engine_handle_drop() {
        let engine = test_engine("subscribe-drop-engine");
        let subscription = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, resume_none())
            .expect("subscription opens");

        drop(engine);

        let next = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| subscription.next(10)))
            .expect("subscription next must not panic after engine handle drop");
        assert!(matches!(
            next.kind,
            FfiSubscriptionNextKind::Closed | FfiSubscriptionNextKind::Timeout
        ));
        assert!(next.event.is_none());
    }

    #[test]
    fn engine_handle_rejects_invalid_hmac_keys() {
        for (label, hmac_key) in [
            ("empty-key", b"   ".to_vec()),
            ("short-key", b"short".to_vec()),
        ] {
            let result = FfiEngine::open(FfiEngineConfig {
                data_root: unique_test_dir(label),
                hmac_key,
                read_token: None,
                write_token: None,
                approve_token: None,
                max_world_bytes: None,
                max_memory_bytes: None,
                max_storage_bytes: None,
                max_listen_connections: None,
                listen_replay_max: None,
                read_cache_max_entries: None,
            });
            let Err(err) = result else {
                panic!("{label} should fail");
            };
            assert!(matches!(err, FfiError::InvalidSecret { .. }));
        }
    }

    #[test]
    fn numeric_config_rejects_values_outside_usize_range() {
        if usize::BITS >= 64 {
            return;
        }
        let err = optional_usize("read_cache_max_entries", Some(u64::MAX))
            .expect_err("oversized usize should fail");
        assert!(matches!(err, FfiError::InvalidConfig { .. }));
    }

    #[test]
    fn engine_errors_cross_ffi_with_structured_details() {
        let not_found: FfiError = EngineError::NotFound.into();
        assert!(matches!(not_found, FfiError::NotFound));

        let quota: FfiError = EngineError::QuotaExceeded {
            used: 80,
            quota: 100,
            projected: 120,
        }
        .into();
        match quota {
            FfiError::QuotaExceeded {
                used,
                quota,
                projected,
            } => {
                assert_eq!(used, 80);
                assert_eq!(quota, 100);
                assert_eq!(projected, 120);
            }
            other => panic!("expected structured quota error, got {other:?}"),
        }

        let transient: FfiError = EngineError::TransientStorage.into();
        assert!(matches!(transient, FfiError::TransientStorage));
        assert!(!transient.to_string().contains("Some("));
        assert!(!transient.to_string().contains("sqlite"));

        let invalid_metadata: FfiError = EngineError::InvalidMetadata {
            message: "reserved-delete-subject-header",
        }
        .into();
        assert!(matches!(
            invalid_metadata,
            FfiError::InvalidMetadata { ref message }
                if message == "reserved-delete-subject-header"
        ));
    }

    #[test]
    fn auth_gate_crosses_ffi_with_structured_variant() {
        use l5::AuthGate;

        for (core_gate, ffi_gate) in [
            (AuthGate::Read, FfiAuthGate::Read),
            (AuthGate::Write, FfiAuthGate::Write),
            (AuthGate::WriteApprove, FfiAuthGate::WriteApprove),
            (AuthGate::Delete, FfiAuthGate::Delete),
        ] {
            let err: FfiError = EngineError::Auth(core_gate).into();
            assert!(matches!(err, FfiError::Auth { gate } if gate == ffi_gate));
        }

        assert_eq!(FfiAuthGate::Delete.to_string(), "delete");
    }

    #[test]
    fn build_errors_cross_ffi_with_stable_variant() {
        let err: FfiError = EngineBuildError::HmacKeyMissing.into();
        assert!(matches!(err, FfiError::BuildHmacKeyMissing));
        assert_eq!(err.to_string(), "hmac key missing");

        let err: FfiError = EngineBuildError::DataRootLockHeld {
            path: std::path::PathBuf::from("data"),
            holder_pid: Some("12345".to_owned()),
        }
        .into();
        assert!(matches!(
            err,
            FfiError::BuildDataRootLockHeld {
                ref holder_pid,
                ..
            } if holder_pid.as_deref() == Some("12345")
        ));
        assert_eq!(
            err.to_string(),
            "data root writer lock is held (last writer: PID 12345): data"
        );
    }

    #[test]
    fn audit_verify_crosses_ffi_as_data_carrying_enum() {
        let not_applicable: FfiAuditVerify = AuditVerify::NotApplicable.into();
        assert!(matches!(not_applicable, FfiAuditVerify::NotApplicable));

        let valid = FfiAuditVerify::Valid {
            valid: FfiAuditValid {
                events: 2,
                genesis: "g".to_owned(),
                latest: "l".to_owned(),
            },
        };
        match valid {
            FfiAuditVerify::Valid { valid } => {
                assert_eq!(valid.events, 2);
                assert_eq!(valid.genesis, "g");
                assert_eq!(valid.latest, "l");
            }
            other => panic!("expected valid audit variant, got {other:?}"),
        }
    }

    fn unique_test_dir(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("l5-ffi-{label}-{nanos}"))
            .to_string_lossy()
            .into_owned()
    }

    fn test_world_db(data_root: &str, world: &str) -> PathBuf {
        Path::new(data_root)
            .join(world.replace('/', "%2F"))
            .join("universe.db")
    }

    fn test_engine(label: &str) -> Arc<FfiEngine> {
        FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir(label),
            hmac_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            read_token: None,
            write_token: None,
            approve_token: None,
            max_world_bytes: None,
            max_memory_bytes: None,
            max_storage_bytes: None,
            max_listen_connections: None,
            listen_replay_max: None,
            read_cache_max_entries: Some(2),
        })
        .expect("engine opens")
    }

    fn small_representation(body: &[u8]) -> FfiRepresentation {
        FfiRepresentation {
            body: body.to_vec(),
            content_type: "text/plain".to_owned(),
            headers: Vec::new(),
        }
    }

    fn resume_none() -> FfiSubscriptionResume {
        FfiSubscriptionResume { after_cursor: None }
    }

    fn resume_after_cursor(cursor: String) -> FfiSubscriptionResume {
        FfiSubscriptionResume {
            after_cursor: Some(cursor),
        }
    }
}
