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

/// Trace hooks for replace/append write transitions.
pub trait EngineWriteTraceHooks {
    fn lock_acquired(&self) {}
    fn quota_check(&self, _used: usize, _quota: usize) {}
    fn sqlite_committed(&self, _etag: &str) {}
    fn notify_sent(&self) {}
}

/// Trace hooks for DELETE's intent/delete/commit protocol.
pub trait EngineDeleteTraceHooks {
    fn lock_acquired(&self, _world: &str) {}
    fn audit_intent(&self) {}
    fn read_cache_drained(&self) {}
    fn physical_deleted(&self) {}
    fn counter_decremented(&self) {}
    fn notify_sent(&self) {}
    /// Diagnostic-only debug rendering of the internal blocking storage error.
    ///
    /// Do not parse this string programmatically; use `EngineError` categories
    /// and `sqlite_code()` for stable decisions.
    fn audit_commit_failed(&self, _err: &str) {}
    fn audit_commit_failed_event_logged(&self) {}
    /// Diagnostic-only debug rendering of the internal blocking storage error.
    ///
    /// Do not parse this string programmatically; use `EngineError` categories
    /// and `sqlite_code()` for stable decisions.
    fn audit_commit_failed_event_failed(&self, _err: &str) {}
    fn audit_commit(&self) {}
}

/// Metadata recorded with a DELETE audit intent.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct DeleteMetadata {
    /// Content type recorded in the DELETE audit intent.
    pub content_type: String,
    /// Representation headers recorded in the DELETE audit intent.
    pub headers: Vec<(String, String)>,
}

impl DeleteMetadata {
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

    pub async fn delete_traced<H: EngineDeleteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        metadata: DeleteMetadata,
        preconditions: Preconditions,
        tier: AccessTier,
        hooks: &H,
    ) -> Result<(), EngineError> {
        EngineOps::new(self.core())
            .delete(
                world,
                DeleteRequest {
                    preconditions,
                    content_type: metadata.content_type,
                    headers: metadata.headers,
                },
                tier.into(),
                &PublicDeleteTrace(hooks),
            )
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
}
