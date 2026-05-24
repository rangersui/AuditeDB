//! Engine operation seam over protocol-neutral world transitions.
//!
//! HTTP and CoAP still live inside the library crate today, so they use the
//! crate-private `EngineOps` view. Public `Engine` methods delegate here too,
//! keeping one path from facade to `world_ops`.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::collections::VecDeque;

use bytes::Bytes;

use crate::{
    auth,
    delete_ops::{self, DeleteRequest, DeleteTraceHooks},
    engine::{self, Engine, EngineError},
    engine_types::{
        AccessTier, ChangeEvent, EngineSubscription, Preconditions, ReadResult, Representation,
        SubscribePattern, SubscriptionRecvError, ValidatedWorldPath, WriteKind, WriteResult,
    },
    etag, event, world_ops, AuthGate, BlockingSqliteError, Core,
};

pub(crate) struct EngineOps<'a> {
    core: &'a Core,
}

struct SubscribePermit {
    pattern: SubscribePattern,
    slot: tokio::sync::OwnedSemaphorePermit,
}

impl<'a> EngineOps<'a> {
    pub(crate) fn new(core: &'a Core) -> Self {
        Self { core }
    }

    pub(crate) fn core(&self) -> &'a Core {
        self.core
    }

    pub(crate) fn read(
        &self,
        world: &ValidatedWorldPath,
        tier: auth::Tier,
    ) -> Result<Option<ReadResult>, EngineError> {
        let permit = world_ops::authorize_read(self.core, world, tier)?;
        match world_ops::read_world(self.core, &permit)
            .map_err(|err| read_error_to_engine(err, Some(world.as_str())))?
        {
            world_ops::ReadOutcome::Found { stage, etag } => Ok(Some(ReadResult {
                representation: Representation {
                    body: Bytes::from(stage.body),
                    content_type: stage.content_type,
                    headers: stage.headers,
                },
                etag,
            })),
            world_ops::ReadOutcome::Missing => Ok(None),
        }
    }

    pub(crate) async fn replace<H: world_ops::WriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        let outcome = world_ops::replace_write(
            self.core,
            &permit,
            world_ops::ReplaceRequest {
                body: representation.body,
                content_type: representation.content_type,
                headers: representation.headers,
                preconditions: preconditions.into(),
            },
            hooks,
        )
        .await
        .map_err(|err| write_error_to_engine(err, Some(world.as_str())))?;
        Ok(outcome.into())
    }

    pub(crate) async fn append<H: world_ops::WriteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<WriteResult, EngineError> {
        let permit = world_ops::authorize_write(world, tier)?;
        let outcome = world_ops::append_write(
            self.core,
            &permit,
            world_ops::AppendRequest {
                body,
                preconditions: preconditions.into(),
            },
            hooks,
        )
        .await
        .map_err(|err| write_error_to_engine(err, Some(world.as_str())))?;
        Ok(outcome.into())
    }

    pub(crate) async fn delete<H: DeleteTraceHooks + ?Sized>(
        &self,
        world: &ValidatedWorldPath,
        req: DeleteRequest,
        tier: auth::Tier,
        hooks: &H,
    ) -> Result<(), delete_ops::DeleteError> {
        let permit = delete_ops::authorize_delete(world, tier)?;
        delete_ops::delete(self.core, &permit, req, hooks).await
    }

    pub(crate) fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
        since: Option<u64>,
    ) -> Result<EngineSubscription, EngineError> {
        let permit = self.authorize_subscribe(pattern, tier)?;
        Ok(self.open_subscription(permit, since))
    }

    fn authorize_subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: auth::Tier,
    ) -> Result<SubscribePermit, EngineError> {
        if !crate::can_read(self.core, tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        if *self.core.shutdown.borrow() {
            return Err(EngineError::ShuttingDown);
        }
        let slot = self
            .core
            .listen_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::SubscriptionLimit)?;
        Ok(SubscribePermit {
            pattern: pattern.clone(),
            slot,
        })
    }

    fn open_subscription(&self, permit: SubscribePermit, since: Option<u64>) -> EngineSubscription {
        let rx = self.core.events.subscribe();
        let (lag, replay, live_floor) = replay_after(self.core, since, &permit.pattern);
        let replay_mode = since.is_some();
        let mut initial = VecDeque::new();
        if let Some(skipped) = lag {
            initial.push_back(Err(SubscriptionRecvError::Lagged { skipped }));
        }
        initial.extend(replay.into_iter().map(Ok));
        EngineSubscription::new(
            permit.slot,
            initial,
            rx,
            permit.pattern,
            replay_mode,
            live_floor,
            self.core.shutdown.clone(),
        )
    }
}

impl Engine {
    /// Reads a world's full representation.
    ///
    /// # Returns
    /// - `Ok(Some(ReadResult))` if the world exists.
    /// - `Ok(None)` if the world does not exist (callers that want 404
    ///   semantics handle this).
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::TransientStorage`] for SQLite `BUSY`/`LOCKED`.
    /// - [`EngineError::InsufficientStorage`] for full-disk failures.
    /// - [`EngineError::Storage`] for other storage errors.
    pub fn read(
        &self,
        world: &ValidatedWorldPath,
        tier: AccessTier,
    ) -> Result<Option<ReadResult>, EngineError> {
        EngineOps::new(self.core()).read(world, tier.into())
    }

    /// Replaces a world with the provided representation.
    ///
    /// Creates the world if it does not exist; otherwise overwrites the
    /// body, content type, and headers, then advances the audit chain.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below the namespace's write
    ///   requirement (`Write` for `home/`, `Approve` for system
    ///   namespaces).
    /// - [`EngineError::PayloadTooLarge`] if the body exceeds the per-world
    ///   cap.
    /// - [`EngineError::PreconditionFailed`] if `preconditions` reject the
    ///   write.
    /// - [`EngineError::QuotaExceeded`] for durable-storage quota failures.
    /// - [`EngineError::TransientStorage`] /
    ///   [`EngineError::InsufficientStorage`] / [`EngineError::Storage`]
    ///   for storage-layer failures.
    pub async fn replace(
        &self,
        world: &ValidatedWorldPath,
        representation: Representation,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .replace(
                world,
                representation,
                preconditions,
                tier.into(),
                &NoopWriteTrace,
            )
            .await
    }

    /// Appends bytes to a world's body and advances the audit chain.
    ///
    /// Same auth requirements and error variants as [`Engine::replace`].
    /// The world's content type and metadata headers are unchanged.
    ///
    /// # Errors
    /// Same as [`Engine::replace`].
    pub async fn append(
        &self,
        world: &ValidatedWorldPath,
        body: Bytes,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<WriteResult, EngineError> {
        EngineOps::new(self.core())
            .append(world, body, preconditions, tier.into(), &NoopWriteTrace)
            .await
    }

    /// Deletes a world with default, empty audit metadata.
    ///
    /// Convenience wrapper around the DELETE protocol that records empty
    /// content-type and headers in the audit intent. Adapters that need to
    /// preserve the deleted representation's metadata in the audit log
    /// should call [`Engine::delete_traced`] with a populated
    /// [`crate::DeleteMetadata`].
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Approve`.
    /// - [`EngineError::AppendOnly`] for append-only worlds (e.g.
    ///   `var/log/deletes`).
    /// - [`EngineError::PreconditionFailed`] / [`EngineError::NotFound`].
    /// - [`EngineError::TransientStorage`] /
    ///   [`EngineError::InsufficientStorage`] / [`EngineError::Storage`]
    ///   for storage-layer failures.
    pub async fn delete(
        &self,
        world: &ValidatedWorldPath,
        preconditions: Preconditions,
        tier: AccessTier,
    ) -> Result<(), EngineError> {
        EngineOps::new(self.core())
            .delete(
                world,
                DeleteRequest {
                    preconditions,
                    content_type: String::new(),
                    headers: Vec::new(),
                },
                tier.into(),
                &NoopDeleteTrace,
            )
            .await
            .map_err(Into::into)
    }

    /// Subscribes to change events matching `pattern`.
    ///
    /// If `since` is `Some(id)`, the subscription replays every event with
    /// `id > since` from the in-memory ring before switching to the live
    /// stream. Replay is bounded by the configured `listen_replay_max`; if
    /// `since` is older than the ring's floor, the first `recv` call yields
    /// a [`crate::SubscriptionRecvError::Lagged`] error.
    ///
    /// The returned [`EngineSubscription`] holds a subscription slot until
    /// dropped; drop it promptly when finished so other subscribers can
    /// join.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::SubscriptionLimit`] if the slot pool is full.
    /// - [`EngineError::ShuttingDown`] if [`Engine::shutdown`] has been
    ///   called.
    pub fn subscribe(
        &self,
        pattern: &SubscribePattern,
        tier: AccessTier,
        since: Option<u64>,
    ) -> Result<EngineSubscription, EngineError> {
        EngineOps::new(self.core()).subscribe(pattern, tier.into(), since)
    }
}

struct NoopWriteTrace;

impl world_ops::WriteTraceHooks for NoopWriteTrace {}

struct NoopDeleteTrace;

impl DeleteTraceHooks for NoopDeleteTrace {}

pub(crate) fn replay_after(
    core: &Core,
    since: Option<u64>,
    pattern: &SubscribePattern,
) -> (Option<u64>, Vec<ChangeEvent>, u64) {
    let Some(last_id) = since else {
        return (None, Vec::new(), 0);
    };
    let log = core
        .event_log
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let gap = log.front().and_then(|oldest| {
        let expected_next = last_id.saturating_add(1);
        if expected_next < oldest.id {
            Some(oldest.id - expected_next)
        } else {
            None
        }
    });
    let replay: Vec<ChangeEvent> = log
        .iter()
        .filter(|change| change.id > last_id && event::matches(pattern.as_str(), &change.path))
        .cloned()
        .map(Into::into)
        .collect();
    let live_floor = replay.last().map(|change| change.id).unwrap_or(last_id);
    (gap, replay, live_floor)
}

impl From<Preconditions> for etag::Preconditions {
    fn from(value: Preconditions) -> Self {
        etag::Preconditions::new(
            value.if_match.into_iter().map(Into::into).collect(),
            value.if_none_match.into_iter().map(Into::into).collect(),
        )
    }
}

impl From<etag::Preconditions> for Preconditions {
    fn from(value: etag::Preconditions) -> Self {
        let (if_match, if_none_match) = value.into_parts();
        Self {
            if_match: if_match.into_iter().map(Into::into).collect(),
            if_none_match: if_none_match.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<world_ops::WriteOutcome> for WriteResult {
    fn from(value: world_ops::WriteOutcome) -> Self {
        Self {
            kind: match value.status_kind {
                world_ops::WriteStatusKind::Created => WriteKind::Created,
                world_ops::WriteStatusKind::Updated => WriteKind::Updated,
            },
            etag: value.etag,
        }
    }
}

impl From<AccessTier> for auth::Tier {
    fn from(value: AccessTier) -> Self {
        match value {
            AccessTier::Anon => Self::Anon,
            AccessTier::Read => Self::Read,
            AccessTier::Write => Self::Write,
            AccessTier::Approve => Self::Approve,
        }
    }
}

impl From<world_ops::ReadError> for EngineError {
    fn from(value: world_ops::ReadError) -> Self {
        read_error_to_engine(value, None)
    }
}

impl From<world_ops::WriteError> for EngineError {
    fn from(value: world_ops::WriteError) -> Self {
        write_error_to_engine(value, None)
    }
}

fn storage_op_label(op: world_ops::StorageOp) -> &'static str {
    match op {
        world_ops::StorageOp::Read => "read",
        world_ops::StorageOp::WriteAudit => "write_audit",
    }
}

fn read_error_to_engine(value: world_ops::ReadError, world: Option<&str>) -> EngineError {
    match value {
        world_ops::ReadError::Auth(gate) => EngineError::Auth(gate),
        world_ops::ReadError::TransientStorage { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::TransientStorage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::ReadError::InsufficientStorage { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::InsufficientStorage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::ReadError::StorageRead { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::Storage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::ReadError::PermitWorldMismatch => {
            EngineError::InternalInvariant("read permit world mismatch")
        }
    }
}

fn write_error_to_engine(value: world_ops::WriteError, world: Option<&str>) -> EngineError {
    match value {
        world_ops::WriteError::Auth(gate) => EngineError::Auth(gate),
        world_ops::WriteError::PayloadTooLarge { max } => EngineError::PayloadTooLarge { max },
        world_ops::WriteError::PreconditionFailed { message } => {
            EngineError::PreconditionFailed { message }
        }
        world_ops::WriteError::NotFound => EngineError::NotFound,
        world_ops::WriteError::QuotaExceeded {
            used,
            quota,
            projected,
        } => EngineError::QuotaExceeded {
            used,
            quota,
            projected,
        },
        world_ops::WriteError::TransientStorage { scope, err, op } => {
            log_storage_error(scope, &err, storage_op_label(op), world);
            EngineError::TransientStorage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::WriteError::InsufficientStorage { scope, err, op } => {
            log_storage_error(scope, &err, storage_op_label(op), world);
            EngineError::InsufficientStorage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::WriteError::StorageRead { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::Storage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::WriteError::StorageWriteAudit { scope, err } => {
            log_storage_error(scope, &err, "write_audit", world);
            EngineError::Storage {
                sqlite_code: engine::sqlite_code(&err),
            }
        }
        world_ops::WriteError::Internal(message) => EngineError::InternalInvariant(message),
    }
}

pub(crate) fn log_storage_error(
    scope: &'static str,
    err: &rusqlite::Error,
    operation: &'static str,
    world: Option<&str>,
) {
    #[cfg(feature = "unstable-engine")]
    tracing::error!(
        scope,
        operation,
        world = world.unwrap_or(""),
        sqlite_code = ?engine::sqlite_code(err),
        error = %err,
        "engine storage error"
    );

    #[cfg(not(feature = "unstable-engine"))]
    match world {
        Some(world) => {
            eprintln!("elastik-core internal {scope} ({operation}) world={world}: {err}");
        }
        None => eprintln!("elastik-core internal {scope} ({operation}): {err}"),
    }
}

pub(crate) fn log_blocking_storage_error(
    scope: &'static str,
    err: &BlockingSqliteError,
    operation: &'static str,
    world: Option<&str>,
) {
    match err {
        BlockingSqliteError::Sqlite(err) => log_storage_error(scope, err, operation, world),
        BlockingSqliteError::Worker => {
            #[cfg(feature = "unstable-engine")]
            tracing::error!(
                scope,
                operation,
                world = world.unwrap_or(""),
                "engine storage worker failed"
            );

            #[cfg(not(feature = "unstable-engine"))]
            match world {
                Some(world) => {
                    eprintln!(
                        "elastik-core internal {scope} ({operation}) world={world}: sqlite worker failed"
                    );
                }
                None => {
                    eprintln!("elastik-core internal {scope} ({operation}): sqlite worker failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::engine_types::SecretBytes;

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-engine-ops-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn test_engine(name: &str) -> (Engine, PathBuf) {
        let root = temp_root(name);
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .max_listen_connections(1)
            .build()
            .unwrap();
        (engine, root)
    }

    #[tokio::test]
    async fn engine_delete_requires_approve_and_removes_world() {
        let (engine, root) = test_engine("delete");
        let world = ValidatedWorldPath::new("home/delete-me").unwrap();
        engine
            .replace(
                &world,
                Representation {
                    body: Bytes::from_static(b"alive"),
                    content_type: "text/plain".to_owned(),
                    headers: Vec::new(),
                },
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        assert!(matches!(
            engine
                .delete(&world, Preconditions::none(), AccessTier::Write)
                .await,
            Err(EngineError::Auth(AuthGate::Delete))
        ));

        engine
            .delete(&world, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_none());

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscribe_requires_read_tier_and_replays_since_id() {
        let root = temp_root("subscribe");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .read_token(b"reader".to_vec())
            .build()
            .unwrap();
        let pattern = SubscribePattern::new("home/events/*");

        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, None),
            Err(EngineError::Auth(AuthGate::Read))
        ));

        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        engine
            .replace(
                &world,
                Representation {
                    body: Bytes::from_static(b"event"),
                    content_type: "text/plain".to_owned(),
                    headers: Vec::new(),
                },
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Read, Some(0))
            .expect("read tier subscribes");
        let event = subscription.recv().await.expect("replay event");
        assert_eq!(event.method, "PUT");
        assert_eq!(event.path.as_str(), "home/events/a");

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn engine_subscribe_enforces_slot_cap_at_entry() {
        let (engine, root) = test_engine("subscribe-cap");
        let pattern = SubscribePattern::new("*");
        let first = engine
            .subscribe(&pattern, AccessTier::Anon, None)
            .expect("first subscription consumes the sole slot");
        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, None),
            Err(EngineError::SubscriptionLimit)
        ));

        drop(first);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn engine_subscribe_denied_auth_does_not_consume_slot() {
        let root = temp_root("subscribe-auth-slot");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(SecretBytes::try_from_slice(b"key").unwrap())
            .read_token(b"reader".to_vec())
            .max_listen_connections(1)
            .build()
            .unwrap();
        let pattern = SubscribePattern::new("*");

        assert!(matches!(
            engine.subscribe(&pattern, AccessTier::Anon, None),
            Err(EngineError::Auth(AuthGate::Read))
        ));
        let subscription = engine
            .subscribe(&pattern, AccessTier::Read, None)
            .expect("failed auth must not consume the only slot");

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_closed_is_terminal() {
        let (engine, root) = test_engine("subscribe-closed");
        let pattern = SubscribePattern::new("*");
        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, None)
            .expect("subscription opens before shutdown");

        engine.shutdown();
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_subscription_drains_replay_before_shutdown() {
        let (engine, root) = test_engine("subscribe-replay-before-shutdown");
        let pattern = SubscribePattern::new("home/replay/*");
        for name in ["home/replay/a", "home/replay/b"] {
            let world = ValidatedWorldPath::new(name).unwrap();
            engine
                .replace(
                    &world,
                    Representation {
                        body: Bytes::from_static(b"event"),
                        content_type: "text/plain".to_owned(),
                        headers: Vec::new(),
                    },
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let mut subscription = engine
            .subscribe(&pattern, AccessTier::Anon, Some(0))
            .expect("subscription opens before shutdown");
        engine.shutdown();
        assert_eq!(
            subscription.recv().await.unwrap().path.as_str(),
            "home/replay/a"
        );
        assert_eq!(
            subscription.recv().await.unwrap().path.as_str(),
            "home/replay/b"
        );
        assert!(matches!(
            subscription.recv().await,
            Err(SubscriptionRecvError::Closed)
        ));

        drop(subscription);
        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
