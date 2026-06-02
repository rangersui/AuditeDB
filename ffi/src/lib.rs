//! UniFFI adapter for Elastik's protocol-neutral Engine.
//!
//! This crate is intentionally separate from `elastik-core`: it is an adapter
//! peer of HTTP and CoAP, not a new core surface. This layer adds the
//! Engine-owned FFI handle; later stack layers bind Engine methods.

// UniFFI's export macro references deprecated smoke exports inside this crate.
// The deprecation remains part of the generated ABI for downstream consumers.
#![allow(deprecated)]

use std::sync::Arc;

use elastik_core::{Engine, SecretBytes};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

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
/// This smoke export exists to make Layer 1 reviewable without binding any
/// Engine verbs yet. Future layers should replace this with real Engine-bound
/// types and keep HTTP/server vocabulary out of the FFI API.
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
}
