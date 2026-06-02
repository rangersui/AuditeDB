//! UniFFI adapter for Elastik's protocol-neutral Engine.
//!
//! This crate is intentionally separate from `elastik-core`: it is an adapter
//! peer of HTTP and CoAP, not a new core surface. This stack binds Engine
//! methods directly and keeps HTTP route/status vocabulary out of the ABI.

// UniFFI's export macro references deprecated smoke exports inside this crate.
// The deprecation remains part of the generated ABI for downstream consumers.
#![allow(deprecated)]

use std::{sync::Arc, time::Duration};

use elastik_core::{
    ChangeEvent, Engine, SecretBytes, SubscribePattern, SubscriptionRecvError, ValidatedWorldPath,
};
use tokio::{
    runtime::{Builder as RuntimeBuilder, Handle, Runtime},
    sync::{mpsc, watch, Mutex},
    time::timeout,
};

mod types;

pub use types::*;

uniffi::setup_scaffolding!();

/// UniFFI-owned handle around Elastik's protocol-neutral Engine.
#[derive(uniffi::Object)]
pub struct FfiEngine {
    engine: Engine,
    runtime: Runtime,
    config: FfiEngineConfigSummary,
}

/// UniFFI-owned blocking receiver for Engine subscription events.
#[derive(uniffi::Object)]
pub struct FfiSubscription {
    events: Mutex<mpsc::Receiver<FfiSubscriptionNext>>,
    cancel: watch::Sender<bool>,
    runtime: Handle,
}

const FFI_SUBSCRIPTION_BUFFER: usize = 1024;

#[uniffi::export]
impl FfiEngine {
    /// Opens an Engine and embeds a Tokio runtime for future async verbs.
    #[uniffi::constructor]
    pub fn open(config: FfiEngineConfig) -> Result<Arc<Self>, FfiError> {
        let summary = config.summary();
        let mut builder = Engine::builder().data_root(config.data_root);
        let key = SecretBytes::new(config.hmac_key).map_err(|err| FfiError::InvalidSecret {
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
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("elastik-ffi")
            .build()
            .map_err(|err| FfiError::RuntimeInitFailed {
                message: err.to_string(),
            })?;

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
        Ok(self.engine.read(&world, tier.try_into()?)?.map(Into::into))
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
        since: Option<u64>,
    ) -> Result<Arc<FfiSubscription>, FfiError> {
        let pattern = SubscribePattern::new(pattern);
        let mut subscription = self.engine.subscribe(&pattern, tier.try_into()?, since)?;
        let (events_tx, events_rx) = mpsc::channel(FFI_SUBSCRIPTION_BUFFER);
        let (cancel, mut cancel_rx) = watch::channel(false);
        self.runtime.spawn(async move {
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
            runtime: self.runtime.handle().clone(),
        }))
    }
}

#[uniffi::export]
impl FfiSubscription {
    /// Blocks until the next event, timeout, lag, or close.
    ///
    /// This is a blocking receive, not busy polling. A timeout returns
    /// `Timeout` so foreign callers can periodically check their own
    /// cancellation condition without crossing a callback boundary.
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
            },
            Err(_) => FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Timeout,
                event: None,
                skipped: None,
            },
        }
    }
}

impl Drop for FfiSubscription {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
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
            },
            false,
        ),
        Err(SubscriptionRecvError::Lagged { skipped }) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Lagged,
                event: None,
                skipped: Some(skipped),
            },
            false,
        ),
        Err(SubscriptionRecvError::Closed) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Closed,
                event: None,
                skipped: None,
            },
            true,
        ),
        Err(_) => (
            FfiSubscriptionNext {
                kind: FfiSubscriptionNextKind::Unknown,
                event: None,
                skipped: None,
            },
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastik_core::{AuditVerify, EngineBuildError, EngineError};
    use std::time::{SystemTime, UNIX_EPOCH};

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
            hmac_key: b"ffi-test-key".to_vec(),
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
            hmac_key: b"ffi-test-key".to_vec(),
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
            hmac_key: b"ffi-test-key".to_vec(),
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
            verb: FfiChangeVerb::Replace,
            path: "home/doc".to_owned(),
            etag: "abc".to_owned(),
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
        assert_eq!(
            engine.du(FfiAccessTier::Read).expect("du")[0].world,
            "home/doc"
        );
        assert_eq!(engine.df(FfiAccessTier::Read).expect("df").worlds, 1);
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

        let subscription = engine
            .subscribe("home/events/*".to_owned(), FfiAccessTier::Read, Some(0))
            .expect("subscription opens");
        let replay = subscription.next(1_000);
        assert_eq!(replay.kind, FfiSubscriptionNextKind::Event);
        let event = replay.event.expect("replay event");
        assert_eq!(event.verb, FfiChangeVerb::Replace);
        assert_eq!(event.path, "home/events/a");

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
    }

    #[test]
    fn subscription_next_reports_closed_after_shutdown() {
        let engine = test_engine("subscribe-closed");
        let subscription = engine
            .subscribe("*".to_owned(), FfiAccessTier::Read, None)
            .expect("subscription opens");
        engine.shutdown();

        let closed = subscription.next(1_000);
        assert_eq!(closed.kind, FfiSubscriptionNextKind::Closed);
        assert!(closed.event.is_none());
    }

    #[test]
    fn engine_handle_rejects_empty_key() {
        let result = FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir("empty-key"),
            hmac_key: b"   ".to_vec(),
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
            panic!("empty key should fail");
        };
        assert!(matches!(err, FfiError::InvalidSecret { .. }));
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

        let transient: FfiError = EngineError::TransientStorage {
            sqlite_code: Some(5),
        }
        .into();
        assert!(matches!(
            transient,
            FfiError::TransientStorage {
                sqlite_code: Some(5)
            }
        ));
        assert!(!transient.to_string().contains("Some(5)"));
        assert!(transient.to_string().contains("code 5"));
    }

    #[test]
    fn auth_gate_crosses_ffi_with_structured_variant() {
        use elastik_core::AuthGate;

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
            .join(format!("elastik-ffi-{label}-{nanos}"))
            .to_string_lossy()
            .into_owned()
    }

    fn test_engine(label: &str) -> Arc<FfiEngine> {
        FfiEngine::open(FfiEngineConfig {
            data_root: unique_test_dir(label),
            hmac_key: b"ffi-test-key".to_vec(),
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
}
