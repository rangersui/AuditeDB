#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! # L5 Engine
//!
//! `l5` is a protocol-neutral storage engine: canonical paths, opaque
//! bytes, content-addressed versioning, an HMAC-chained audit log, and a
//! four-tier access model. **SQLite for files.**
//!
//! As a Rust library, L5 is an embedded flat key-value engine. One key stores
//! one byte value plus metadata and audit history. There is no HTTP
//! server, no environment-variable loader, and no socket listener in this
//! crate; adapters add those surfaces on top.
//!
//! ## Public API shape
//!
//! The public facade is intentionally small. The call shape is mixed:
//! metadata-only methods return immediately on the caller thread, while
//! storage-touching methods are async and must be awaited by the caller's
//! runtime.
//!
//! | Operation | Method | Call shape |
//! | --- | --- | --- |
//! | Build engine | [`Engine::builder`] -> [`EngineBuilder::build`] | sync |
//! | Read value | [`Engine::read`] | async |
//! | Replace value | [`Engine::replace`] | async |
//! | Append bytes | [`Engine::append`] | async |
//! | Delete value | [`Engine::delete`] | async |
//! | Open subscription | [`Engine::subscribe`] | sync |
//! | Receive subscription event | [`EngineSubscription::recv`] | async |
//! | List / inspect | [`Engine::list_worlds`], [`Engine::du`], [`Engine::df`], [`Engine::pool`] | sync |
//! | Verify audit chain | [`Engine::verify_audit`] | sync |
//! | Auth helpers | [`Engine::verify_token`], [`Engine::allows_read`] | sync |
//! | Shutdown signal | [`Engine::shutdown`] | sync |
//!
//! Storage-touching methods are async because durable reads, writes, appends,
//! deletes, audit updates, and subscriber notifications cross the Engine's
//! blocking-worker boundary and ordered transition points.
//!
//! [`Engine::subscribe`] only opens the subscription and reserves a slot. The
//! stream itself is consumed with async [`EngineSubscription::recv`].
//!
//! ## Quick start
//!
//! ```no_run
//! # #[cfg(feature = "unstable-engine")]
//! # async fn run() {
//! use l5::{
//!     AccessTier, AuditHmacKey, Engine, Preconditions, Representation, ValidatedWorldPath,
//! };
//! use bytes::Bytes;
//!
//! let engine = Engine::builder()
//!     .data_root("./data")
//!     .key(AuditHmacKey::new(b"0123456789abcdef0123456789abcdef".to_vec()).expect("hmac key"))
//!     .build()
//!     .expect("engine builds");
//!
//! let world = ValidatedWorldPath::new("home/hello").expect("canonical path");
//!
//! // Store bytes at a path. Mutating operations are async.
//! engine
//!     .replace(
//!         &world,
//!         Representation::new(Bytes::from_static(b"hi"), "text/plain", Vec::new()),
//!         Preconditions::none(),
//!         AccessTier::Write,
//!     )
//!     .await
//!     .expect("write succeeds");
//!
//! // Retrieve bytes by path. Reads are async.
//! let read = engine.read(&world, AccessTier::Read).await.expect("read succeeds");
//! assert!(read.is_some());
//! # }
//! ```
//!
//! ## Compare-and-set write
//!
//! Use the ETag returned by a read or write as the value clock for the next
//! write.
//!
//! ```no_run
//! # #[cfg(feature = "unstable-engine")]
//! # async fn run(engine: l5::Engine, world: l5::ValidatedWorldPath) {
//! use l5::{
//!     AccessTier, EtagMatcher, Preconditions, Representation,
//! };
//! use bytes::Bytes;
//!
//! let current = engine
//!     .read(&world, AccessTier::Read)
//!     .await
//!     .expect("read")
//!     .expect("world exists");
//!
//! let next = Representation::new(Bytes::from_static(b"next"), "text/plain", Vec::new());
//! let cas = Preconditions::new(vec![EtagMatcher::Strong(current.etag)], Vec::new());
//!
//! engine
//!     .replace(&world, next, cas, AccessTier::Write)
//!     .await
//!     .expect("etag still current");
//! # }
//! ```
//!
//! ## Subscribe to changes
//!
//! Opening a subscription is sync; receiving events is async. Persist
//! durable [`ChangeEvent::identity`] values and resume with
//! [`SubscriptionResume::after_event_id`] when a protocol needs reconnect
//! replay.
//!
//! ```no_run
//! # #[cfg(feature = "unstable-engine")]
//! # async fn run(engine: l5::Engine) {
//! use l5::{AccessTier, SubscribePattern, SubscriptionResume};
//!
//! let pattern = SubscribePattern::new("/home/tasks/*");
//! let mut sub = engine
//!     .subscribe(&pattern, AccessTier::Read, SubscriptionResume::none())
//!     .expect("subscription opens");
//!
//! let event = sub.recv().await.expect("change event");
//! println!("{} changed with {:?}", event.path(), event.verb());
//! # }
//! ```
//!
//! ## What the library does
//!
//! - **Bytes at paths.** Canonical `home/`, `tmp/`, `dev/`, `sys/`, `etc/`,
//!   `lib/`, `boot/`, `usr/`, `var/` namespaces decide durable-vs-transient
//!   without per-call configuration.
//! - **Versions everything.** Every successful write returns an ETag; reads,
//!   replaces, and appends honour `Preconditions::if_match` / `if_none_match`.
//! - **Audits durable writes.** Durable worlds append to an HMAC-chained
//!   ledger; `Engine::verify_audit` returns a typed [`AuditVerify`] result and
//!   refuses to start when an existing chain is corrupted.
//! - **Authenticates everything.** [`AccessTier`] (Anon / Read / Write /
//!   Approve) plus token-bytes verification via [`Engine::verify_token`].
//! - **Subscribes to changes.** [`Engine::subscribe`] returns an
//!   [`EngineSubscription`] with replay-then-live ordering.
//!
//! ## What the library does *not* do
//!
//! No protocol adapters and no server runtime. Those live in the `auditedb`
//! package's `auditedb` binary and consume this library through the
//! unstable public [`Engine`] API. In a minimal library-only build, the library
//! does not read environment variables, does not bind sockets, and does not
//! depend on protocol-adapter transport crates.
//!
//! ## Feature flags
//!
//! - `bundled-sqlite` *(default)* — link a bundled SQLite via `rusqlite/bundled`.
//! - `unstable-engine` — expose the public [`Engine`] facade. **The API shape
//!   is allowed to change between minor versions while this gate stays.**
//!
//! Binary adapter features such as `coap`, `mqtt`, and `multi-thread` live in
//! `bin/Cargo.toml`, not in this library package.
//!
//! Minimal library-only build from the repository root:
//! `cargo build --manifest-path core/Cargo.toml --lib --no-default-features
//! --features bundled-sqlite,unstable-engine`.
mod audit;
mod auth;
mod blocking_sqlite;
mod chain_stamp;
mod data_lock;
mod defaults;
mod delete_ops;
mod engine;
mod engine_error;
mod engine_introspection;
mod engine_ops;
mod engine_subscription;
mod engine_trace;
mod engine_types;
mod etag;
mod event;
mod ledger;
mod path;
mod read_cache;
mod state;
mod storage_class;
mod store;
mod subscription_cursor;
mod subscription_event_id;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test_support;
mod timeline;
mod world;
mod world_generation;
mod world_ops;
mod world_read_ops;
mod world_schema;

// Re-export protocol-neutral helpers at the crate root.
pub(crate) use crate::state::*;
pub(crate) use crate::storage_class::*;
#[cfg(feature = "unstable-engine")]
pub use audit::{
    TimelineDereference, VerifiedBodyHashMismatch, VerifiedExpiredBody, VerifiedGenerationMismatch,
    VerifiedMissingRow, VerifiedNonBodyEvent,
};
#[cfg(not(feature = "unstable-engine"))]
pub(crate) use auth::AuthGate;
#[cfg(feature = "unstable-engine")]
pub use auth::{is_valid_token, AuthGate};
#[cfg(feature = "unstable-engine")]
pub use chain_stamp::{
    ChainEventCount, ChainSeq, ChainStamp, ChainStampMissing, ChainStampRead, InvalidChainSeq,
    VerifiedChainHmac,
};
pub(crate) use data_lock::acquire_data_root_writer_lock;
#[cfg(feature = "unstable-engine")]
pub use defaults::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES, DEFAULT_RETAINED_BODY_COUNT,
};
#[cfg(feature = "unstable-engine")]
#[doc(hidden)]
pub use engine::ShutdownToken;
#[cfg(feature = "unstable-engine")]
pub use engine::{Engine, EngineBuildError, EngineBuilder, EngineError};
#[cfg(feature = "unstable-engine")]
pub use engine_introspection::{
    AuditBroken, AuditValid, AuditVerify, DfSnapshot, HeadStamp, InvalidProcPath, PoolSnapshot,
    ProcEndpoint, ValidatedProcPath, WorldUsage,
};
#[cfg(feature = "unstable-engine")]
pub use engine_subscription::{
    ChangeEvent, EngineSubscription, SubscriptionRecvError, SubscriptionResetReason,
};
#[cfg(feature = "unstable-engine")]
pub use engine_trace::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
#[cfg(feature = "unstable-engine")]
pub use engine_types::{
    parse_etag_matchers, AccessTier, AuditHmacKey, ChangeVerb, EmptyKeyError, EtagMatcher,
    InvalidHmacKey, InvalidWorldPath, Preconditions, ReadResult, Representation, SecretBytes,
    ValidatedWorldPath, WriteKind, WriteResult, MIN_HMAC_KEY_BYTES,
};
#[cfg(feature = "unstable-engine")]
pub use path::{validate_world_name, MAX_DISK_WORLD_NAME_BYTES, NAMESPACE_PREFIXES};
#[cfg(feature = "unstable-engine")]
pub use subscription_cursor::{SubscribePattern, SubscriptionResume};
#[cfg(feature = "unstable-engine")]
pub use subscription_event_id::{
    ChangeEventIdentity, InvalidSubscriptionEventId, SubscriptionEventId,
};
#[cfg(feature = "unstable-engine")]
pub use timeline::{
    BodySha256, DeleteSubjectProof, InvalidTimelineCoordinate, TimelineAddress, TimelineBody,
    TimelineCoordinate, TimelineCorruption, TimelineExpiredBody, TimelineRead, TimelineSeq,
};
#[cfg(feature = "unstable-engine")]
pub use world_generation::WorldGeneration;

// ─── helpers ────────────────────────────────────────────────────────

pub(crate) fn can_delete(tier: auth::Tier) -> bool {
    matches!(tier, auth::Tier::Approve)
}

// (memory_write_projected_bytes / memory_append_projected_bytes were
// removed: the snapshot-based projection they computed could be observed
// by two concurrent writers before either had committed, letting them
// both pass and overshoot max_memory_bytes once the global write_lock was
// gone. Quota is now enforced inside MemoryStore::write_with_quota /
// append_with_quota, atomically with the write itself.)

// `require_read` (auth gate for proc handlers) lives in proc.rs now,
// next to its only callers.

pub(crate) fn can_read(core: &Core, tier: auth::Tier) -> bool {
    !core.tokens.read_required()
        || matches!(
            tier,
            auth::Tier::Read | auth::Tier::Write | auth::Tier::Approve
        )
}
