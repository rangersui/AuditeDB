//! Unstable traced Engine entry points.
//!
//! These traits let bin-side adapters preserve the existing operator-visible
//! step traces without exposing `Core`, `EngineOps`, or storage-vendor errors.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use bytes::Bytes;

use crate::{
    delete_ops::{self, DeleteRequest},
    engine::{Engine, EngineError},
    engine_ops::EngineOps,
    engine_types::{AccessTier, Preconditions, Representation, ValidatedWorldPath, WriteResult},
    world_ops,
};

/// Trace hooks for [`Engine::replace_traced`] / [`Engine::append_traced`].
///
/// All methods default to no-ops. Implement only the hooks an adapter cares
/// about — typical use is a single per-operation struct that flips a flag or
/// emits a structured trace line on each callback.
///
/// Successful durable writes fire hooks in this order:
/// `lock_acquired` -> optional `quota_check` -> `sqlite_committed` ->
/// `notify_sent`. Transient memory writes skip `quota_check`.
pub trait EngineWriteTraceHooks {
    /// The per-world write lock was acquired.
    fn lock_acquired(&self) {}
    /// Quota was checked. `used` is the durable storage usage before this
    /// write; `quota` is the configured cap.
    fn quota_check(&self, _used: usize, _quota: usize) {}
    /// SQLite transaction committed and the new ETag is known.
    fn sqlite_committed(&self, _etag: &str) {}
    /// `notify_sent` fired the broadcast event for subscribers.
    fn notify_sent(&self) {}
}

/// Trace hooks for [`Engine::delete_traced`]'s intent/delete/commit protocol.
///
/// All methods default to no-ops. Hooks fire in protocol order; the
/// `audit_intent_failed` / `audit_commit_failed*` hooks fire only on the
/// corresponding failure path.
///
/// Successful deletes fire hooks in this order: `lock_acquired` ->
/// `audit_intent` -> `read_cache_drained` -> `physical_deleted` ->
/// `counter_decremented` -> `notify_sent` -> `audit_commit`.
pub trait EngineDeleteTraceHooks {
    /// The per-world write lock was acquired.
    fn lock_acquired(&self, _world: &str) {}
    /// The audit-intent ledger row was written successfully.
    fn audit_intent(&self) {}
    /// Diagnostic-only debug rendering when the delete audit intent append fails.
    ///
    /// Do not parse this string programmatically; match [`EngineError`]
    /// variants for stable decisions.
    fn audit_intent_failed(&self, _err: &str) {}
    /// In-flight reads were drained from the read cache.
    fn read_cache_drained(&self) {}
    /// The underlying SQLite database file was unlinked.
    fn physical_deleted(&self) {}
    /// The durable-world counter and storage-used counter were updated.
    fn counter_decremented(&self) {}
    /// The delete broadcast event was sent to subscribers.
    fn notify_sent(&self) {}
    /// Diagnostic-only debug rendering of the internal blocking storage error.
    ///
    /// Do not parse this string programmatically; match [`EngineError`]
    /// variants for stable decisions.
    fn audit_commit_failed(&self, _err: &str) {}
    /// `audit_commit_failed` was followed by a successful `delete_commit_failed`
    /// ledger entry — the audit chain reflects the partial state.
    fn audit_commit_failed_event_logged(&self) {}
    /// Diagnostic-only debug rendering of the internal blocking storage error.
    ///
    /// Do not parse this string programmatically; match [`EngineError`]
    /// variants for stable decisions.
    fn audit_commit_failed_event_failed(&self, _err: &str) {}
    /// The audit-commit ledger row was written successfully.
    fn audit_commit(&self) {}
}

/// Metadata recorded with a delete audit intent.
///
/// Adapters that want the deleted representation's content-type and
/// metadata headers preserved in the audit log fill this struct; pass
/// [`DeleteMetadata::default`] to record empty metadata. The plain
/// [`crate::Engine::delete`] convenience method always records empty
/// metadata.
///
/// Header names beginning with `auditedb-delete-subject-` are reserved for the
/// engine's internal subject-coordinate proof in the delete ledger. Supplying
/// one of those names to [`crate::Engine::delete_traced`] fails with
/// [`EngineError::InvalidMetadata`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct DeleteMetadata {
    /// Content type recorded in the delete audit intent.
    pub content_type: String,
    /// Representation headers recorded in the delete audit intent.
    pub headers: Vec<(String, String)>,
}

impl DeleteMetadata {
    /// Constructs a [`DeleteMetadata`] from a content type and header list.
    pub fn new(content_type: impl Into<String>, headers: Vec<(String, String)>) -> Self {
        Self {
            content_type: content_type.into(),
            headers,
        }
    }
}

struct PublicWriteTrace<'a, H: ?Sized>(&'a H);

impl<H: EngineWriteTraceHooks + ?Sized> world_ops::WriteTraceHooks for PublicWriteTrace<'_, H> {
    fn lock_acquired(&self) {
        self.0.lock_acquired();
    }

    fn quota_check(&self, used: usize, quota: usize) {
        self.0.quota_check(used, quota);
    }

    fn sqlite_committed(&self, etag: &str) {
        self.0.sqlite_committed(etag);
    }

    fn notify_sent(&self) {
        self.0.notify_sent();
    }
}

struct PublicDeleteTrace<'a, H: ?Sized>(&'a H);

impl<H: EngineDeleteTraceHooks + ?Sized> delete_ops::DeleteTraceHooks for PublicDeleteTrace<'_, H> {
    fn lock_acquired(&self, world: &str) {
        self.0.lock_acquired(world);
    }

    fn audit_intent(&self) {
        self.0.audit_intent();
    }

    fn read_cache_drained(&self) {
        self.0.read_cache_drained();
    }

    fn physical_deleted(&self) {
        self.0.physical_deleted();
    }

    fn counter_decremented(&self) {
        self.0.counter_decremented();
    }

    fn notify_sent(&self) {
        self.0.notify_sent();
    }

    fn audit_commit_failed(&self, err: &crate::BlockingSqliteError) {
        self.0.audit_commit_failed(&format!("{err:?}"));
    }

    fn audit_commit_failed_event_logged(&self) {
        self.0.audit_commit_failed_event_logged();
    }

    fn audit_commit_failed_event_failed(&self, err: &crate::BlockingSqliteError) {
        self.0.audit_commit_failed_event_failed(&format!("{err:?}"));
    }

    fn audit_commit(&self) {
        self.0.audit_commit();
    }
}

impl Engine {
    /// Same as [`crate::Engine::replace`] but invokes `hooks` on each
    /// protocol phase.
    ///
    /// This is an async API with the same storage and audit semantics as
    /// [`crate::Engine::replace`].
    ///
    /// Adapters use this to drive structured trace output or per-operation
    /// metrics without paying the hook cost in non-traced call sites.
    ///
    /// # Errors
    /// Same as [`crate::Engine::replace`].
    pub async fn replace_traced<H: EngineWriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: AccessTier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .replace(
                world,
                representation,
                preconditions,
                tier.into(),
                &PublicWriteTrace(hooks),
            )
            .await
    }

    /// Same as [`crate::Engine::append`] but invokes `hooks` on each
    /// protocol phase.
    ///
    /// This is an async API with the same storage and audit semantics as
    /// [`crate::Engine::append`].
    ///
    /// # Errors
    /// Same as [`crate::Engine::append`].
    pub async fn append_traced<H: EngineWriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: AccessTier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .append(
                world,
                body,
                preconditions,
                tier.into(),
                &PublicWriteTrace(hooks),
            )
            .await
    }

    /// Same as [`crate::Engine::delete`] but invokes `hooks` on each
    /// protocol phase and records the supplied [`DeleteMetadata`] in the
    /// audit intent.
    ///
    /// This is an async API with the same physical-delete semantics as
    /// [`crate::Engine::delete`].
    ///
    /// Adapters that want to surface the deleted representation's content
    /// type and headers in operator audit views should use this method
    /// instead of [`crate::Engine::delete`] (which records empty metadata).
    ///
    /// # Errors
    /// Same as [`crate::Engine::delete`], plus the hook-side
    /// `audit_intent_failed` callback fires before the
    /// [`EngineError::Storage`] / [`EngineError::TransientStorage`] /
    /// [`EngineError::InsufficientStorage`] / [`EngineError::InternalInvariant`]
    /// result is returned when the audit-intent write itself fails. Returns
    /// [`EngineError::InvalidMetadata`] if `metadata.headers` uses a reserved
    /// delete-subject header name.
    pub async fn delete_traced<H: EngineDeleteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        metadata: DeleteMetadata,
        preconditions: Preconditions,
        tier: AccessTier,
        hooks: &H,
    ) -> Result<(), EngineError> {
        let result = EngineOps::new(self.core())
            .delete(
                world,
                DeleteRequest::new(preconditions, metadata.content_type, metadata.headers),
                tier.into(),
                &PublicDeleteTrace(hooks),
            )
            .await;
        if let Err(delete_ops::DeleteError::AuditIntent { err, .. }) = &result {
            hooks.audit_intent_failed(&format!("{err:?}"));
        }
        result.map_err(Into::into)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::engine_types::AuditHmacKey;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Spy(Mutex<Vec<String>>);

    impl Spy {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }

        fn push(&self, value: impl Into<String>) {
            self.0.lock().unwrap().push(value.into());
        }

        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    impl EngineWriteTraceHooks for Spy {
        fn lock_acquired(&self) {
            self.push("lock_acquired");
        }

        fn quota_check(&self, used: usize, quota: usize) {
            self.push(format!("quota_check:{used}:{quota}"));
        }

        fn sqlite_committed(&self, etag: &str) {
            self.push(format!("sqlite_committed:{etag}"));
        }

        fn notify_sent(&self) {
            self.push("notify_sent");
        }
    }

    impl EngineDeleteTraceHooks for Spy {
        fn lock_acquired(&self, world: &str) {
            self.push(format!("lock_acquired:{world}"));
        }

        fn audit_commit_failed(&self, err: &str) {
            self.push(format!("audit_commit_failed:{err}"));
        }
    }

    fn test_engine(name: &str) -> (Engine, std::path::PathBuf) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "auditedb-engine-trace-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        (engine, root)
    }

    #[test]
    fn public_write_trace_forwards_internal_hook_boundaries() {
        let spy = Spy::new();
        let trace = PublicWriteTrace(&spy);

        world_ops::WriteTraceHooks::lock_acquired(&trace);
        world_ops::WriteTraceHooks::quota_check(&trace, 3, 5);
        world_ops::WriteTraceHooks::sqlite_committed(&trace, "etag123");
        world_ops::WriteTraceHooks::notify_sent(&trace);

        assert_eq!(
            spy.take(),
            [
                "lock_acquired",
                "quota_check:3:5",
                "sqlite_committed:etag123",
                "notify_sent"
            ]
        );
    }

    #[test]
    fn public_delete_trace_forwards_without_exposing_internal_error_type() {
        let spy = Spy::new();
        let trace = PublicDeleteTrace(&spy);

        delete_ops::DeleteTraceHooks::lock_acquired(&trace, "home/task");
        delete_ops::DeleteTraceHooks::audit_commit_failed(
            &trace,
            &crate::BlockingSqliteError::Worker,
        );

        assert_eq!(
            spy.take(),
            ["lock_acquired:home/task", "audit_commit_failed:Worker"]
        );
    }

    #[tokio::test]
    async fn delete_traced_checks_auth_before_metadata() {
        let (engine, root) = test_engine("delete-auth-before-metadata");
        let world = ValidatedWorldPath::new("home/delete-auth-before-metadata").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"body"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let err = engine
            .delete_traced(
                &world,
                DeleteMetadata::new("text/plain\r\nx-bad: y", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
                &Spy::new(),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, EngineError::Auth(crate::AuthGate::Delete)));
        let _ = std::fs::remove_dir_all(root);
    }
}
