#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! # AuditeDB — powered by the Elastik L5 Engine
//!
//! `elastik-core` is a protocol-neutral storage engine: canonical paths, opaque
//! bytes, content-addressed versioning, an HMAC-chained audit log, and a
//! four-tier access model. **SQLite for files.**
//!
//! As a Rust library, AuditeDB is an embedded flat key-value engine. One key
//! stores one byte value plus metadata and audit history. There is no HTTP
//! server, no environment-variable loader, and no socket listener in this
//! crate; adapters add those surfaces on top.
//!
//! ## Public API shape
//!
//! The public facade is intentionally small. The call shape is mixed:
//! synchronous methods return immediately on the caller thread, while async
//! methods must be awaited by the caller's runtime.
//!
//! | Operation | Method | Call shape |
//! | --- | --- | --- |
//! | Build engine | [`Engine::builder`] -> [`EngineBuilder::build`] | sync |
//! | Read value | [`Engine::read`] | sync |
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
//! The sync methods can perform storage work on the caller thread. If an
//! adapter is running inside an async executor and must not block that worker,
//! call sync storage methods from that adapter's blocking-worker boundary.
//! Mutating methods are async because durable writes, appends, deletes, audit
//! updates, and subscriber notifications are ordered engine transitions.
//!
//! [`Engine::subscribe`] only opens the subscription and reserves a slot. The
//! stream itself is consumed with async [`EngineSubscription::recv`].
//!
//! ## Quick start
//!
//! ```no_run
//! # #[cfg(feature = "unstable-engine")]
//! # async fn run() {
//! use elastik_core::{
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
//! // Retrieve bytes by path. Reads are sync.
//! let read = engine.read(&world, AccessTier::Read).expect("read succeeds");
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
//! # async fn run(engine: elastik_core::Engine, world: elastik_core::ValidatedWorldPath) {
//! use elastik_core::{
//!     AccessTier, EtagMatcher, Preconditions, Representation,
//! };
//! use bytes::Bytes;
//!
//! let current = engine
//!     .read(&world, AccessTier::Read)
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
//! Opening a subscription is sync; receiving events is async. Pass
//! [`SubscriptionResume::after_event_id`] to replay recent events before
//! switching to live delivery.
//!
//! ```no_run
//! # #[cfg(feature = "unstable-engine")]
//! # async fn run(engine: elastik_core::Engine) {
//! use elastik_core::{AccessTier, SubscribePattern, SubscriptionResume};
//!
//! let pattern = SubscribePattern::new("/home/tasks/*");
//! let mut sub = engine
//!     .subscribe(&pattern, AccessTier::Read, SubscriptionResume::none())
//!     .expect("subscription opens");
//!
//! let event = sub.recv().await.expect("change event");
//! println!("{} changed with {:?}", event.path, event.verb);
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
//! No protocol adapters and no server runtime. Those live in the `elastik-bin`
//! package's `elastik-core` binary and consume this library through the
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
#[cfg(test)]
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
#[cfg(not(feature = "unstable-engine"))]
pub(crate) use auth::AuthGate;
#[cfg(feature = "unstable-engine")]
pub use auth::{is_valid_token, AuthGate};
pub(crate) use data_lock::acquire_data_root_writer_lock;
#[cfg(feature = "unstable-engine")]
pub use defaults::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
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
    ChangeEvent, EngineSubscription, SubscribePattern, SubscriptionRecvError, SubscriptionResume,
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
pub use path::{validate_world_name, NAMESPACE_PREFIXES};
#[cfg(feature = "unstable-engine")]
pub use timeline::{
    BodySha256, InvalidTimelineCoordinate, TimelineAddress, TimelineBody, TimelineCoordinate,
    TimelineCorruption, TimelineRead, TimelineSeq,
};
#[cfg(feature = "unstable-engine")]
pub use world_generation::WorldGeneration;

// ─── helpers ────────────────────────────────────────────────────────

pub(crate) fn can_write(world_name: &str, tier: auth::Tier) -> bool {
    // Harvard gate: /lib/, /etc/, /boot/, /usr/, and audit logs
    // require approve. /home/, /tmp/, /dev/, /sys/, and non-log
    // /var/ worlds accept the normal token. Anon refused.
    let needs_approve = needs_write_approve(world_name);
    match tier {
        auth::Tier::Anon => false,
        auth::Tier::Read => false,
        auth::Tier::Write => !needs_approve,
        auth::Tier::Approve => true,
    }
}

/// Mirrors the harvard-gate decision in `can_write`. Lifted out so
/// `handler::execute_put` / `execute_post` can classify a rejected
/// write as `Auth(Write)` vs `Auth(WriteApprove)` for the FSM trace
/// without re-deriving the predicate.
pub(crate) fn needs_write_approve(world_name: &str) -> bool {
    exact_or_child(world_name, "lib")
        || exact_or_child(world_name, "etc")
        || exact_or_child(world_name, "boot")
        || exact_or_child(world_name, "usr")
        || exact_or_child(world_name, "var/log")
}

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

pub(crate) fn exact_or_child(world_name: &str, prefix: &str) -> bool {
    world_name == prefix
        || world_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) fn can_read(core: &Core, tier: auth::Tier) -> bool {
    !core.tokens.read_required()
        || matches!(
            tier,
            auth::Tier::Read | auth::Tier::Write | auth::Tier::Approve
        )
}
