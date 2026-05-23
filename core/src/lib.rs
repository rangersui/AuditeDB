//! elastik-core -- bedrock HTTP+SQLite+HMAC.
//!
//! This library target currently exists so the `elastik-core` binary can be a
//! tiny Tokio runtime launcher. The engine API is intentionally internal and
//! unstable; runtime use remains env-driven through the binary documented in
//! the repository README.
//!
//! The core has one semantic interface: method + path + representation bytes.
//! HTTP is the first-class surface. SCoAP is a small UDP-curl surface because
//! CoAP has semantic zero distance from HTTP. Everything else must arrive
//! through SDK/client adapters that collapse it into the same tuple.
//!
//! v5.0 grammar:
//!
//! ```text
//! GET    /<world>                -> body bytes with stored Content-Type
//! HEAD   /<world>                -> metadata headers, no body
//! PUT    /<world>                -> replace body, update meta, audit
//! POST   /<world>                -> append to body, no meta change, audit
//! DELETE /<world>                -> drop world (sqlite) or evict (memory)
//! GET    /proc/worlds            -> text/plain, one world per line
//! GET    /proc/version           -> "elastik-core <ver> (rust)\n"
//! ```
//!
//! Path prefix decides backend (one core, one port, no two daemons):
//!
//! ```text
//! /home/* /etc/* /lib/* /boot/* /usr/* /var/*  -> SQLite, durable, audited
//! /tmp/*  /dev/*  /sys/*                       -> memory, transient
//! ```
//!
//! Out of scope (deliberately):
//!   protocol bridges      -> SDK clients / external endpoint apps
//!   AI shaping/routing    -> SDK clients / external endpoint apps
//!   /lib/* code running   -> never in core; /lib is inert storage
//!   application behavior  -> outside core, expressed as HTTP
//!
//! Env:
//!   ELASTIK_HOST           default 127.0.0.1
//!   ELASTIK_PORT           default 3105
//!   ELASTIK_COAP_PORT      optional; enables SCoAP/UDP when set
//!                          (requires binary built with `coap` feature)
//!   ELASTIK_COAP_HOST      default 127.0.0.1 when CoAP is enabled
//!   ELASTIK_DATA           default ./data
//!   ELASTIK_READ_TOKEN     T1 token  (optional read gate)
//!   ELASTIK_WRITE_TOKEN    T2 token  (writes to /home/*, includes read)
//!   ELASTIK_APPROVE_TOKEN  T3 token  (system writes/deletes, includes read)
//!   ELASTIK_KEY            HMAC key for the audit chain (required)
//!   ELASTIK_MAX_STORAGE_BYTES optional durable storage quota
//!   ELASTIK_TRACE_PIPELINE optional; "1" enables the FSM trace on stderr
mod audit;
mod auth;
#[cfg(feature = "coap")]
#[path = "server/coap.rs"]
mod coap;
#[cfg(feature = "coap")]
#[path = "server/coap_errors.rs"]
mod coap_errors;
mod config;
mod delete_ops;
mod engine;
mod engine_introspection;
mod engine_ops;
mod engine_trace;
mod engine_types;
mod etag;
#[path = "server/handler.rs"]
mod handler;
mod http_range;
mod http_semantics;
mod ledger;
#[path = "server/listen.rs"]
mod listen;
#[path = "server/middleware.rs"]
mod middleware;
mod path;
#[path = "server/pipeline.rs"]
mod pipeline;
#[path = "server/proc.rs"]
mod proc;
mod read_cache;
#[path = "server/response.rs"]
mod response;
#[path = "server/route.rs"]
mod route;
mod server;
mod state;
mod storage_class;
mod store;
mod world;
mod world_ops;

// Re-export the small pure-function modules at the crate root so
// sibling modules keep referring to `crate::not_found` /
// `crate::canonicalize_path` / `crate::Phase` / `crate::Core` etc.
// without per-extraction import churn.
pub(crate) use crate::path::*;
pub(crate) use crate::pipeline::*;
pub(crate) use crate::proc::*;
pub(crate) use crate::response::*;
pub(crate) use crate::state::*;
pub(crate) use crate::storage_class::*;
#[cfg(feature = "unstable-engine")]
pub use auth::AuthGate;
#[cfg(not(feature = "unstable-engine"))]
pub(crate) use auth::AuthGate;
#[cfg(feature = "unstable-engine")]
pub use engine::{Engine, EngineBuildError, EngineBuilder, EngineError};
#[cfg(feature = "unstable-engine")]
pub use engine_introspection::{
    AuditBroken, AuditValid, AuditVerify, DfSnapshot, InvalidProcPath, PoolSnapshot, ProcEndpoint,
    ValidatedProcPath, WorldUsage,
};
#[cfg(feature = "unstable-engine")]
pub use engine_trace::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
#[cfg(feature = "unstable-engine")]
pub use engine_types::{
    AccessTier, ChangeEvent, EmptyKeyError, EngineSubscription, EtagMatcher, InvalidWorldPath,
    Preconditions, ReadResult, Representation, SecretBytes, SubscribePattern,
    SubscriptionRecvError, ValidatedWorldPath, WriteKind, WriteResult,
};

use std::path::Path;
use std::time::Duration;

#[cfg(test)]
pub(crate) use crate::config::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES,
};

// Re-exported to crate root for `proc.rs` (root_hint, proc_version)
// and main()'s startup banner. The other namespace constants
// (ROOT_ALLOW, PROC_ALLOW, AUDIT_VERIFY_ALLOW) live in proc.rs now.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const WORLD_ALLOW: &str = "GET, HEAD, PUT, POST, DELETE, OPTIONS";

#[doc(hidden)]
pub async fn run_from_env() {
    server::run_from_env().await;
}

fn acquire_data_root_writer_lock(data: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let c = rusqlite::Connection::open(data.join(".elastik-writer-lock.sqlite3"))?;
    c.busy_timeout(Duration::from_millis(0))?;
    c.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS writer_lock(
            id INTEGER PRIMARY KEY CHECK(id=1),
            holder TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO writer_lock(id, holder) VALUES(1, '');
        BEGIN IMMEDIATE;
        "#,
    )?;
    c.execute(
        "UPDATE writer_lock SET holder=?1 WHERE id=1",
        [std::process::id().to_string()],
    )?;
    Ok(c)
}

// `/` and `/proc/*` route handlers (root_hint, proc_version, proc_worlds,
// proc_du, proc_df, proc_audit_verify, proc_reserved) live in `proc.rs`
// and are re-exported at the crate root, so the route table below and
// the inline tests in this file reach them by short name.

// ─── /<world> all five methods ──────────────────────────────────────
// Path validation and canonicalization (canonicalize_path,
// valid_world_name, validate_world_name, is_dot_segment,
// strip_dot_token, is_reserved_world_name) live in `path.rs` and
// are re-exported at the crate root.

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

// Response constructors (not_found, unauthorized, bad_request,
// payload_too_large, insufficient_storage,
// storage_temporarily_unavailable, storage_quota_exceeded,
// options_response, method_not_allowed, precondition_failed,
// server_error, storage_error, is_insufficient_storage_error,
// is_transient_storage_error, audit_valid, audit_broken,
// audit_header_value, audit_not_applicable, proc_text_response,
// du_body, df_body, world_list_body,
// to_header_map) live in `response.rs` and are re-exported at the
// crate root. Helpers below use them through that re-export.

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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "coap")]
    use crate::config::coap_bind_from_env;
    use crate::config::{
        env_nonzero_usize, env_optional_usize, hmac_key_from_env_value, listen_addr,
        should_warn_public_read,
    };
    use crate::etag as et;
    use crate::handler::{execute_delete, execute_get, execute_head, execute_post, execute_put};
    use crate::http_semantics as hs;
    use crate::middleware::{add_core_response_headers, stamp_core_response_headers};
    use crate::route::world_handler;
    use axum::body::Bytes;
    use axum::extract::{Path as AxPath, State};
    use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
    use axum::response::Response;
    use axum::routing::any;
    use axum::Router;
    use dashmap::DashMap;
    use std::collections::VecDeque;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex, Mutex as TestMutex, OnceLock};
    use tokio::sync::{broadcast, watch, Semaphore};

    /// PR 4c: 50 unit tests below were renamed mechanically from
    /// `handle_*` (sync `&Core -> Response`) to `execute_*` (async
    /// `&Core, &TraceCtx -> Phase`). The verb-handler entry point
    /// returns `Phase`, but the assertions all operate on the
    /// underlying `Response`. This helper unwraps the three terminal
    /// `Phase` variants `execute_*` can return so tests can keep
    /// asserting on `.status()` / `.headers()` without scaffolding
    /// per call site.
    fn unwrap_response(phase: Phase) -> Response {
        match phase {
            Phase::ExecutedRead(r) | Phase::CommittedWrite(r) | Phase::Done(r) => r,
            Phase::Error { resp, .. } => resp,
            // execute_* never returns a non-terminal Phase; reaching
            // any of these would be a bug in the handler module.
            Phase::Received { .. }
            | Phase::Authenticated { .. }
            | Phase::PathValidated { .. }
            | Phase::Dispatched { .. } => {
                panic!("execute_* returned a non-terminal Phase variant")
            }
        }
    }

    fn world_path(world: &str) -> crate::engine_types::ValidatedWorldPath {
        crate::engine_types::ValidatedWorldPath::new(world).unwrap()
    }

    fn env_lock() -> &'static TestMutex<()> {
        static LOCK: OnceLock<TestMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TestMutex::new(()))
    }

    #[cfg(feature = "coap")]
    struct CoapEnvGuard {
        host: Option<String>,
        port: Option<String>,
    }

    #[cfg(feature = "coap")]
    impl CoapEnvGuard {
        fn capture() -> Self {
            Self {
                host: std::env::var("ELASTIK_COAP_HOST").ok(),
                port: std::env::var("ELASTIK_COAP_PORT").ok(),
            }
        }
    }

    #[cfg(feature = "coap")]
    impl Drop for CoapEnvGuard {
        fn drop(&mut self) {
            match &self.host {
                Some(v) => std::env::set_var("ELASTIK_COAP_HOST", v),
                None => std::env::remove_var("ELASTIK_COAP_HOST"),
            }
            match &self.port {
                Some(v) => std::env::set_var("ELASTIK_COAP_PORT", v),
                None => std::env::remove_var("ELASTIK_COAP_PORT"),
            }
        }
    }

    #[test]
    fn hmac_key_requires_nonempty_semantic_content() {
        assert!(hmac_key_from_env_value(None).is_none());
        assert!(hmac_key_from_env_value(Some(String::new())).is_none());
        assert!(hmac_key_from_env_value(Some(" \t\n".to_string())).is_none());
        assert_eq!(
            hmac_key_from_env_value(Some(" secret ".to_string())).unwrap(),
            b" secret ".to_vec()
        );
    }

    #[test]
    fn resource_cap_env_zero_falls_back_to_default() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("ELASTIK_TEST_ZERO_CAP_{}", std::process::id());
        std::env::set_var(&key, "0");
        assert_eq!(env_nonzero_usize(&key, 7), 7);
        std::env::set_var(&key, "9");
        assert_eq!(env_nonzero_usize(&key, 7), 9);
        std::env::remove_var(&key);
    }

    #[test]
    fn optional_storage_quota_zero_is_unlimited() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("ELASTIK_TEST_STORAGE_CAP_{}", std::process::id());
        std::env::remove_var(&key);
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, " \t ");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "0");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "11");
        assert_eq!(env_optional_usize(&key), Some(11));
        std::env::set_var(&key, "10GB");
        assert!(std::panic::catch_unwind(|| env_optional_usize(&key)).is_err());
        std::env::remove_var(&key);
    }

    #[test]
    fn data_root_writer_lock_is_exclusive() {
        let dir =
            std::env::temp_dir().join(format!("elastik-data-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = acquire_data_root_writer_lock(&dir).unwrap();
        assert!(acquire_data_root_writer_lock(&dir).is_err());
        drop(first);
        let second = acquire_data_root_writer_lock(&dir).unwrap();
        drop(second);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sqlite_disk_full_maps_to_507() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert!(is_insufficient_storage_error(&err));

        let resp = storage_error("test", err);
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[test]
    fn sqlite_busy_and_locked_map_to_503_retry_after() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            let err = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(is_transient_storage_error(&err));

            let resp = storage_error("test", err);
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                resp.headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
                Some("1")
            );
        }
    }

    #[test]
    fn non_storage_sqlite_errors_stay_500() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            None,
        );
        assert!(!is_insufficient_storage_error(&err));

        let resp = storage_error("test", err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn durable_storage_quota_returns_507_without_writing() {
        let (mut core, dir) = test_core("storage-quota");
        core.max_storage_bytes = Some(4);
        let headers = HeaderMap::new();

        let first = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"1234"),
                auth::Tier::Write,
                world_path("home/a"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(first.status(), StatusCode::CREATED);

        let over = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"5"),
                auth::Tier::Write,
                world_path("home/b"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(over.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(over.headers().get("x-storage-usage").unwrap(), "4");
        assert_eq!(over.headers().get("x-storage-quota").unwrap(), "4");
        assert_eq!(over.headers().get("x-storage-needed").unwrap(), "1");
        assert!(core.read_world("home/b").unwrap().is_none());

        let append = unwrap_response(
            execute_post(
                headers.clone(),
                Bytes::from_static(b"5"),
                auth::Tier::Write,
                world_path("home/a"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(append.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(append.headers().get("x-storage-usage").unwrap(), "4");
        assert_eq!(append.headers().get("x-storage-quota").unwrap(), "4");
        assert_eq!(append.headers().get("x-storage-needed").unwrap(), "1");
        assert_eq!(
            core.read_world("home/a").unwrap().unwrap().body,
            b"1234".to_vec()
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn concurrent_puts_to_distinct_worlds_do_not_overshoot_quota() {
        // Regression: under per-world locks, the previous "snapshot then
        // write then adjust" pattern let two concurrent PUTs to different
        // worlds both observe usage below quota, both commit, and only
        // afterwards push the counter past quota (lost-update race).
        // Atomic CAS reservation in `Core::reserve_storage` closes that
        // race. This test fires N concurrent PUTs each just under the
        // quota and asserts that ANY mix of accept/reject keeps the
        // counter coherent and never overshoots.
        let (mut core, dir) = test_core("quota-race");
        let quota = 100;
        core.max_storage_bytes = Some(quota);
        let core = Arc::new(core);

        let workers = 16;
        let body_len = 12; // 16 * 12 = 192 > quota: definitely contention
        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers {
            let core = core.clone();
            handles.push(tokio::spawn(async move {
                let path = format!("home/race/{i}");
                let body = Bytes::copy_from_slice(&vec![b'x'; body_len]);
                unwrap_response(
                    execute_put(
                        HeaderMap::new(),
                        body,
                        auth::Tier::Write,
                        world_path(&path),
                        &core,
                        &TraceCtx::disabled(),
                    )
                    .await,
                )
            }));
        }

        let mut accepted: usize = 0;
        for handle in handles {
            let resp = handle.await.unwrap();
            match resp.status() {
                StatusCode::CREATED | StatusCode::OK => accepted += 1,
                StatusCode::INSUFFICIENT_STORAGE => {}
                other => panic!("unexpected status: {other}"),
            }
        }

        let used = core.storage_body_bytes.load(Ordering::Relaxed);
        let counted = accepted * body_len;
        assert_eq!(used, counted, "counter must equal sum of accepted bodies");
        assert!(
            used <= quota,
            "counter must never exceed quota: {used} > {quota}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn concurrent_memory_puts_do_not_overshoot_max_memory_bytes() {
        // Mirror of concurrent_puts_to_distinct_worlds_do_not_overshoot_quota
        // for memory worlds. Per-world locks let writes to /tmp/a and
        // /tmp/b run concurrently; before this fix each one would read
        // total_bytes() as a snapshot, both pass the budget check, and
        // both commit -- overshooting ELASTIK_MAX_MEMORY_BYTES. With the
        // check + write fused under the MemoryStore HashMap mutex inside
        // write_with_quota, only the writes whose accept order keeps the
        // running total under the cap can commit.
        let (mut core, dir) = test_core("memory-quota-race");
        let cap = 100;
        core.max_memory_bytes = cap;
        let core = Arc::new(core);

        let workers = 16;
        let body_len = 12; // 16 * 12 = 192 > cap: forced contention
        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers {
            let core = core.clone();
            handles.push(tokio::spawn(async move {
                let path = format!("tmp/race/{i}");
                let body = Bytes::copy_from_slice(&vec![b'm'; body_len]);
                unwrap_response(
                    execute_put(
                        HeaderMap::new(),
                        body,
                        auth::Tier::Write,
                        world_path(&path),
                        &core,
                        &TraceCtx::disabled(),
                    )
                    .await,
                )
            }));
        }

        let mut accepted: usize = 0;
        for handle in handles {
            let resp = handle.await.unwrap();
            match resp.status() {
                StatusCode::CREATED | StatusCode::OK => accepted += 1,
                StatusCode::PAYLOAD_TOO_LARGE => {}
                other => panic!("unexpected status: {other}"),
            }
        }

        let used = core.mem.total_bytes();
        let counted = accepted * body_len;
        assert_eq!(
            used, counted,
            "memory total must equal sum of accepted bodies"
        );
        assert!(
            used <= cap,
            "memory total must never exceed cap: {used} > {cap}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn var_log_requires_approve_token() {
        assert!(!can_write("var/log", auth::Tier::Anon));
        assert!(!can_write("var/log", auth::Tier::Read));
        assert!(!can_write("var/log", auth::Tier::Write));
        assert!(can_write("var/log", auth::Tier::Approve));
        assert!(!can_write("var/log/deletes", auth::Tier::Anon));
        assert!(!can_write("var/log/deletes", auth::Tier::Read));
        assert!(!can_write("var/log/deletes", auth::Tier::Write));
        assert!(can_write("var/log/deletes", auth::Tier::Approve));
    }

    #[test]
    fn delete_requires_approve_token() {
        assert!(!can_delete(auth::Tier::Anon));
        assert!(!can_delete(auth::Tier::Read));
        assert!(!can_delete(auth::Tier::Write));
        assert!(can_delete(auth::Tier::Approve));
    }

    #[test]
    fn listen_addr_brackets_ipv6_hosts() {
        assert_eq!(listen_addr("127.0.0.1", 3105), "127.0.0.1:3105");
        assert_eq!(listen_addr("0.0.0.0", 3105), "0.0.0.0:3105");
        assert_eq!(listen_addr("::1", 3105), "[::1]:3105");
        assert_eq!(listen_addr("localhost", 3105), "localhost:3105");
    }

    #[cfg(feature = "coap")]
    #[test]
    fn coap_bind_is_opt_in_by_port_env() {
        let _lock = env_lock().lock().unwrap();
        let _guard = CoapEnvGuard::capture();
        std::env::remove_var("ELASTIK_COAP_HOST");
        std::env::remove_var("ELASTIK_COAP_PORT");

        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_HOST", "0.0.0.0");
        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_PORT", "5683");
        assert_eq!(coap_bind_from_env(), Some(("0.0.0.0".to_owned(), 5683)));

        std::env::set_var("ELASTIK_COAP_HOST", "127.0.0.1");
        std::env::set_var("ELASTIK_COAP_PORT", " ");
        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_PORT", "not-a-port");
        assert_eq!(coap_bind_from_env(), None);
    }

    #[test]
    fn non_loopback_public_read_gets_warning_flag() {
        let mut tokens = auth::Tokens {
            read: None,
            write: None,
            approve: None,
        };
        assert!(!should_warn_public_read(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            &tokens
        ));
        assert!(should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            &tokens
        ));

        tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());
        assert!(!should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            &tokens
        ));
    }

    #[tokio::test]
    async fn put_and_post_enforce_world_size_cap() {
        let (mut core, dir) = test_core("world-size-cap");
        core.max_world_bytes = 4;
        let headers = HeaderMap::new();

        let too_big = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"12345"),
                auth::Tier::Write,
                world_path("home/too-big"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let ok = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"1234"),
                auth::Tier::Write,
                world_path("home/four"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(ok.status(), StatusCode::CREATED);

        let append = unwrap_response(
            execute_post(
                headers.clone(),
                Bytes::from_static(b"5"),
                auth::Tier::Write,
                world_path("home/four"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(append.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn memory_backend_enforces_total_quota() {
        let (mut core, dir) = test_core("memory-quota");
        core.max_memory_bytes = 4;
        let headers = HeaderMap::new();

        let first = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"12"),
                auth::Tier::Write,
                world_path("tmp/a"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(first.status(), StatusCode::CREATED);
        let second = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"34"),
                auth::Tier::Write,
                world_path("tmp/b"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(second.status(), StatusCode::CREATED);
        let third = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"5"),
                auth::Tier::Write,
                world_path("tmp/c"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(third.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn system_namespace_roots_require_approve_even_if_called_directly() {
        for name in ["lib", "etc", "boot", "usr"] {
            assert!(!can_write(name, auth::Tier::Anon), "{name}");
            assert!(!can_write(name, auth::Tier::Read), "{name}");
            assert!(!can_write(name, auth::Tier::Write), "{name}");
            assert!(can_write(name, auth::Tier::Approve), "{name}");
        }
    }

    #[test]
    fn non_log_var_still_accepts_auth_token() {
        assert!(!can_write("var/cache/rag", auth::Tier::Anon));
        assert!(!can_write("var/cache/rag", auth::Tier::Read));
        assert!(can_write("var/cache/rag", auth::Tier::Write));
        assert!(can_write("var/cache/rag", auth::Tier::Approve));
    }

    #[test]
    fn read_token_is_optional_but_gates_reads_when_set() {
        let (mut core, dir) = test_core("read-token");
        assert!(can_read(&core, auth::Tier::Anon));

        core.tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());
        assert!(!can_read(&core, auth::Tier::Anon));
        assert!(can_read(&core, auth::Tier::Read));
        assert!(can_read(&core, auth::Tier::Write));
        assert!(can_read(&core, auth::Tier::Approve));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn get_and_head_require_read_token_when_enabled() {
        let (mut core, dir) = test_core("read-token-handlers");
        core.write_world("home/private", b"secret", "text/plain", &[])
            .unwrap();
        core.tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());

        let headers = HeaderMap::new();
        let get_anon = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/private"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get_anon.status(), StatusCode::UNAUTHORIZED);
        let head_reader = unwrap_response(
            execute_head(
                headers.clone(),
                auth::Tier::Read,
                world_path("home/private"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(head_reader.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unauthorized_responses_advertise_bearer_challenge() {
        let resp = unauthorized("read requires read token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"elastik\""
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn core_response_headers_are_core_owned() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("*"));
        headers.insert("x-request-id", HeaderValue::from_static("stale"));
        headers.insert("x-elapsed-us", HeaderValue::from_static("999"));
        headers.insert("x-content-type-options", HeaderValue::from_static("sniff"));

        stamp_core_response_headers(42, 7, &mut headers);

        assert_eq!(headers.get("x-request-id").unwrap(), "42");
        assert_eq!(headers.get("x-elapsed-us").unwrap(), "7");
        assert_eq!(headers.get(header::VARY).unwrap(), "Authorization");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    }

    #[test]
    fn poisoned_persisted_headers_are_not_replayed() {
        let mut out = Vec::new();
        hs::apply_meta_headers(
            &[
                (
                    "x-custom".to_owned(),
                    "evil\r\nset-cookie: admin=true".to_owned(),
                ),
                ("set-cookie".to_owned(), "sid=admin; Path=/".to_owned()),
                ("clear-site-data".to_owned(), "\"cookies\"".to_owned()),
                ("bad name".to_owned(), "ok".to_owned()),
                ("x-safe".to_owned(), "ok".to_owned()),
            ],
            &mut out,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.as_str(), "x-safe");
        assert_eq!(out[0].1, "ok");
    }

    #[test]
    fn canonicalize_preserves_explicit_namespaces() {
        assert_eq!(canonicalize_path("/home/tmp/foo"), "home/tmp/foo");
        assert_eq!(canonicalize_path("/home/etc/foo"), "home/etc/foo");
        assert_eq!(canonicalize_path("/tmp/foo"), "tmp/foo");
        assert_eq!(canonicalize_path("/etc/foo"), "etc/foo");
        assert_eq!(canonicalize_path("/foo"), "home/foo");
    }

    #[test]
    fn control_bytes_are_not_valid_world_names() {
        assert!(valid_world_name("home/ok"));
        assert!(!valid_world_name("home/bad\nname"));
        assert!(!valid_world_name(""));
    }

    #[test]
    fn dot_segments_empty_segments_and_backslashes_are_not_valid_world_names() {
        assert!(!valid_world_name("home/../etc/secret"));
        assert!(!valid_world_name("home/%2E%2E/etc/secret"));
        assert!(!valid_world_name("home/./x"));
        assert!(!valid_world_name("home//x"));
        assert!(!valid_world_name("home/x/"));
        assert!(!valid_world_name("home\\x"));
        assert_eq!(
            validate_world_name("home/%2E%2E/etc/secret"),
            Err("world path contains dot or encoded-dot segment")
        );
        assert_eq!(
            validate_world_name("home//x"),
            Err("world path has empty segment")
        );
        assert_eq!(
            validate_world_name("home\\x"),
            Err("world path contains backslash")
        );
    }

    #[test]
    fn namespace_roots_and_proc_subtree_are_not_world_names() {
        for name in [
            "home",
            "tmp",
            "dev",
            "sys",
            "proc",
            "proc/anything",
            "etc",
            "lib",
            "boot",
            "usr",
            "var",
            "var/log",
        ] {
            assert!(!valid_world_name(name), "{name}");
        }
        assert!(valid_world_name("home/x"));
        assert!(valid_world_name("var/log/deletes"));
    }

    #[test]
    fn byte_ranges_cover_normal_open_and_suffix_forms() {
        let mut h = HeaderMap::new();
        assert_eq!(hs::parse_range(&h, 10), Ok(None));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((2, 5))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=7-"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=-3"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=8-99"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((8, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=11-12"));
        assert_eq!(hs::parse_range(&h, 10), Err(()));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));
        assert_eq!(hs::parse_range(&h, 10), Ok(None));
    }

    #[tokio::test]
    async fn get_and_head_honor_single_byte_range() {
        let (core, dir) = test_core("range-handler");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/range"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            get.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 1-3/6"
        );
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

        let head = unwrap_response(
            execute_head(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/range"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(head.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            head.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 1-3/6"
        );
        assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn get_and_head_advertise_accept_ranges_on_full_body() {
        let (core, dir) = test_core("accept-ranges");
        core.write_world("home/ranges", b"abcdef", "text/plain", &[])
            .unwrap();
        let headers = HeaderMap::new();

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/ranges"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let head = unwrap_response(
            execute_head(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/ranges"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unsatisfied_range_returns_416_with_content_range() {
        let (core, dir) = test_core("range-416");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=99-100"));

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/range"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            get.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes */6"
        );
        assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn multi_range_is_ignored_and_returns_full_body() {
        let (core, dir) = test_core("multi-range");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/range"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::OK);
        assert!(get.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn world_reads_advertise_monitor_and_collection_links() {
        let (core, dir) = test_core("link-headers");
        core.write_world("home/links", b"hello", "text/plain", &[])
            .unwrap();
        let headers = HeaderMap::new();

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/links"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
        assert_eq!(links.len(), 2);
        assert!(links
            .iter()
            .any(|v| *v == "</listen/home/links>; rel=\"monitor\""));
        assert!(links
            .iter()
            .any(|v| *v == "</proc/worlds>; rel=\"collection\""));

        let head = unwrap_response(
            execute_head(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/links"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(head.headers().get_all(header::LINK).iter().count(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn if_range_controls_whether_range_is_applied() {
        let mut h = HeaderMap::new();
        h.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("\"hmac-current\""),
        );
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(Some((1, 3))));

        h.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(None));

        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("W/\"hmac-current\""),
        );
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(None));
    }

    #[tokio::test]
    async fn stale_if_range_returns_full_body() {
        let (core, dir) = test_core("if-range-stale");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
        headers.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/range"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::OK);
        assert!(get.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn get_and_head_honor_if_none_match_cache_revalidation() {
        let (core, dir) = test_core("read-if-none-match");
        let h = world::write_with_audit(
            &core.data,
            "home/cache",
            b"cached body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let etag = format!("\"{}\"", et::hmac_etag(&h));
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/cache"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(get.headers().get(header::ETAG).unwrap(), etag.as_str());
        assert!(get
            .headers()
            .get_all(header::LINK)
            .iter()
            .any(|v| v == "</listen/home/cache>; rel=\"monitor\""));

        let head = unwrap_response(
            execute_head(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/cache"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(head.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(head.headers().get(header::ETAG).unwrap(), etag.as_str());

        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"hmac-stale\""),
        );
        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/cache"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn options_and_405_advertise_allow_headers() {
        // PR 4c: `handle_world_method` was retired. OPTIONS is now
        // answered directly in `world_handler` (policy-free, never
        // enters the FSM); PATCH and any other unsupported method
        // are rejected by `pipeline::dispatch` with `MethodNotAllowed`.
        let (core, dir) = test_core("allow");
        let core = std::sync::Arc::new(core);

        let options = options_response(WORLD_ALLOW);
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let patch = pipeline::run(
            Method::PATCH,
            "home/allow".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            0,
        )
        .await;
        assert_eq!(patch.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(patch.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn root_and_proc_endpoints_advertise_head_options_and_405() {
        let root_head = root_hint(Method::HEAD).await;
        assert_eq!(root_head.status(), StatusCode::OK);
        assert_eq!(
            root_head.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(root_head.headers().get(header::CONTENT_LENGTH).is_some());

        let root_options = root_hint(Method::OPTIONS).await;
        assert_eq!(root_options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            root_options.headers().get(header::ALLOW).unwrap(),
            ROOT_ALLOW
        );

        let root_post = root_hint(Method::POST).await;
        assert_eq!(root_post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(root_post.headers().get(header::ALLOW).unwrap(), ROOT_ALLOW);

        let version_head = proc_version(Method::HEAD).await;
        assert_eq!(version_head.status(), StatusCode::OK);
        assert!(version_head.headers().get(header::CONTENT_LENGTH).is_some());

        let version_delete = proc_version(Method::DELETE).await;
        assert_eq!(version_delete.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            version_delete.headers().get(header::ALLOW).unwrap(),
            PROC_ALLOW
        );
    }

    #[tokio::test]
    async fn proc_worlds_head_options_and_405_are_plain_http() {
        let (core, dir) = test_core("proc-worlds-http");
        core.write_world("home/a", b"a", "text/plain", &[]).unwrap();
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let head = proc_worlds(State(state.clone()), Method::HEAD, headers.clone()).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(head.headers().get(header::CONTENT_LENGTH).is_some());

        let options = proc_worlds(State(state.clone()), Method::OPTIONS, headers.clone()).await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let delete = proc_worlds(State(state), Method::DELETE, headers).await;
        assert_eq!(delete.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(delete.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_namespace_is_reserved_beyond_declared_endpoints() {
        let not_found = proc_reserved(Method::GET).await;
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let head = proc_reserved(Method::HEAD).await;
        assert_eq!(head.status(), StatusCode::NOT_FOUND);

        let options = proc_reserved(Method::OPTIONS).await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let put = proc_reserved(Method::PUT).await;
        assert_eq!(put.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(put.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_valid_chain_in_headers() {
        let (core, dir) = test_core("proc-audit-valid");
        let h = world::write_with_audit(
            &core.data,
            "home/audit-ok",
            b"hello",
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
            &core.hmac_key,
        )
        .unwrap();
        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-ok/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "true");
        assert_eq!(resp.headers().get("x-audit-events").unwrap(), "1");
        assert_eq!(
            resp.headers().get("x-audit-latest").unwrap(),
            &format!("hmac-{h}")
        );
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "0");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_broken_chain_in_headers() {
        let (core, dir) = test_core("proc-audit-broken");
        world::write_with_audit(
            &core.data,
            "home/audit-broken",
            b"hello",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let db = world::world_db(&core.data, "home/audit-broken");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-broken/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "false");
        assert_eq!(resp.headers().get("x-audit-break-at").unwrap(), "0");
        assert_eq!(resp.headers().get("x-audit-actual").unwrap(), "hmac-bad");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_escapes_tampered_header_values() {
        let (core, dir) = test_core("proc-audit-header-escape");
        world::write_with_audit(
            &core.data,
            "home/audit-escaped",
            b"hello",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let db = world::world_db(&core.data, "home/audit-escaped");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute(
            "UPDATE events SET hmac=? WHERE id=1",
            ["bad\nInjected: yes"],
        )
        .unwrap();

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-escaped/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers().get("x-audit-actual").unwrap(),
            "hmac-bad\\x0aInjected: yes"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_memory_world_not_applicable() {
        let (core, dir) = test_core("proc-audit-memory");
        core.write_world("tmp/scratch", b"draft", "text/plain", &[])
            .unwrap();
        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("tmp/scratch/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "n/a");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_missing_disk_world_does_not_create_db() {
        let (core, dir) = test_core("proc-audit-missing-no-create");
        let db = world::world_db(&core.data, "home/missing-audit");
        assert!(!db.exists());

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/missing-audit/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!db.exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn put_created_returns_location() {
        let (core, dir) = test_core("put-location");
        let headers = HeaderMap::new();
        let resp = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"new"),
                auth::Tier::Write,
                world_path("home/created"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/home/created"
        );

        let resp = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"again"),
                auth::Tier::Write,
                world_path("home/created"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::LOCATION).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn location_and_link_headers_percent_encode_world_urls() {
        let (core, dir) = test_core("encoded-headers");
        let headers = HeaderMap::new();
        let resp = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"new"),
                auth::Tier::Write,
                world_path("home/café report"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/home/caf%C3%A9%20report"
        );

        let get = unwrap_response(
            execute_get(
                headers.clone(),
                auth::Tier::Anon,
                world_path("home/café report"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
        assert!(links
            .iter()
            .any(|v| *v == "</listen/home/caf%C3%A9%20report>; rel=\"monitor\""));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unicode_worlds_roundtrip_body_headers_and_proc_listing() {
        let (core, dir) = test_core("unicode-roundtrip");
        let headers = vec![(
            "content-disposition".to_string(),
            "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf".to_string(),
        )];
        core.write_world(
            "home/销售/报告",
            "你好，世界".as_bytes(),
            "text/plain; charset=utf-8",
            &headers,
        )
        .unwrap();

        let req_headers = HeaderMap::new();
        let get = unwrap_response(
            execute_get(
                req_headers.clone(),
                auth::Tier::Anon,
                world_path("home/销售/报告"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            get.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf"
        );
        assert!(
            get.headers()
                .get_all(header::LINK)
                .iter()
                .any(|v| *v
                    == "</listen/home/%E9%94%80%E5%94%AE/%E6%8A%A5%E5%91%8A>; rel=\"monitor\"")
        );

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(world_list_body(&names.unwrap()), "home/销售/报告\n");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn etag_lists_match_http_strong_and_weak_rules() {
        assert!(et::etag_list_strong_matches("\"hmac-abc\"", "hmac-abc"));
        assert!(et::etag_list_strong_matches(
            "\"other\", \"hmac-abc\"",
            "hmac-abc"
        ));
        assert!(et::etag_list_strong_matches("*", "hmac-abc"));
        assert!(!et::etag_list_strong_matches("W/\"hmac-abc\"", "hmac-abc"));
        assert!(!et::etag_list_strong_matches("\"other\"", "hmac-abc"));

        assert!(et::etag_list_weak_matches("W/\"hmac-abc\"", "hmac-abc"));
    }

    #[test]
    fn if_none_match_star_blocks_existing_world() {
        let (core, dir) = test_core("if-none-match-star");
        core.write_world("home/cas", b"one", "text/plain; charset=utf-8", &[])
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));

        assert!(hs::check_write_preconditions(&core, "home/cas", &headers).is_err());
        assert!(hs::check_write_preconditions(&core, "home/new", &headers).is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn put_and_post_honor_write_preconditions_at_handler_level() {
        let (core, dir) = test_core("write-preconditions");
        let h = world::write_with_audit(
            &core.data,
            "home/cas",
            b"one",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        let put = unwrap_response(
            execute_put(
                stale.clone(),
                Bytes::from_static(b"two"),
                auth::Tier::Write,
                world_path("home/cas"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(put.status(), StatusCode::PRECONDITION_FAILED);

        let post = unwrap_response(
            execute_post(
                stale.clone(),
                Bytes::from_static(b" plus"),
                auth::Tier::Write,
                world_path("home/cas"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(post.status(), StatusCode::PRECONDITION_FAILED);

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", et::hmac_etag(&h))).unwrap(),
        );
        let post = unwrap_response(
            execute_post(
                good.clone(),
                Bytes::from_static(b" plus"),
                auth::Tier::Write,
                world_path("home/cas"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(post.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn if_match_accepts_current_hmac_etag_only() {
        let (core, dir) = test_core("if-match-hmac");
        core.write_world("home/cas", b"one", "text/plain; charset=utf-8", &[])
            .unwrap();
        let mut conn = world::open(&core.data, "home/cas").unwrap();
        let h = audit::append_with_conn_existing(
            &mut conn,
            "put",
            "home/cas",
            &world::sha256_hex(b"one"),
            3,
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        drop(conn);
        let etag = format!("\"{}\"", et::hmac_etag(&h));

        let mut good = HeaderMap::new();
        good.insert(header::IF_MATCH, HeaderValue::from_str(&etag).unwrap());
        assert!(hs::check_write_preconditions(&core, "home/cas", &good).is_ok());

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        assert!(hs::check_write_preconditions(&core, "home/cas", &stale).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_content_type_preserves_http_content_type_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        );
        assert_eq!(hs::request_content_type(&headers), "application/pdf");

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        assert_eq!(
            hs::request_content_type(&headers),
            "text/html; charset=utf-8"
        );

        headers.clear();
        assert_eq!(
            hs::request_content_type(&headers),
            "application/octet-stream"
        );
    }

    #[test]
    fn request_meta_headers_persist_default_representation_headers_only() {
        // L2 (DEFAULT_PERSIST_HEADERS) covers standard representation
        // headers that round-trip with the body without the operator
        // configuring anything. Custom headers (x-author,
        // x-future-http-thing, x-meta-*) are NOT persisted under the
        // empty allowlist -- the operator must opt in via
        // ELASTIK_PERSIST_HEADERS. Layer 1 hard-deny stays in force
        // either way.
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"report.pdf\""),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, HEAD"),
        );
        headers.insert(
            "access-control-expose-headers",
            HeaderValue::from_static("ETag"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert("permissions-policy", HeaderValue::from_static("camera=()"));
        headers.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        headers.insert("x-future-http-thing", HeaderValue::from_static("ok"));
        headers.insert("x-meta-author", HeaderValue::from_static("ranger"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("{} {}", "Bearer", "secret")).unwrap(),
        );
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("{} {}", "Bearer", "secret")).unwrap(),
        );
        headers.insert(header::COOKIE, HeaderValue::from_static("sid=secret"));
        headers.insert(header::SET_COOKIE, HeaderValue::from_static("sid=secret"));
        headers.insert(header::HOST, HeaderValue::from_static("localhost:3105"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::TRAILER, HeaderValue::from_static("expires"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("http2-settings", HeaderValue::from_static("abc"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("999"));
        headers.insert(header::ETAG, HeaderValue::from_static("\"fake\""));
        headers.insert(header::ALLOW, HeaderValue::from_static("GET"));
        headers.insert(header::LOCATION, HeaderValue::from_static("/elsewhere"));
        headers.insert(header::LINK, HeaderValue::from_static("</x>; rel=\"next\""));
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"x\""),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        headers.insert("accept-charset", HeaderValue::from_static("utf-8"));
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"abc\""));
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"abc\""));
        headers.insert(header::IF_RANGE, HeaderValue::from_static("\"abc\""));
        headers.insert(
            header::IF_MODIFIED_SINCE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(
            header::IF_UNMODIFIED_SINCE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        headers.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\""));
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://example.com/"),
        );
        headers.insert(header::USER_AGENT, HeaderValue::from_static("curl"));
        headers.insert(header::SERVER, HeaderValue::from_static("fake"));
        headers.insert(
            header::DATE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(header::AGE, HeaderValue::from_static("10"));
        headers.insert(header::VARY, HeaderValue::from_static("*"));
        headers.insert("via", HeaderValue::from_static("1.1 proxy"));
        headers.insert("forwarded", HeaderValue::from_static("for=127.0.0.1"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("true-client-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("client-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("clear-site-data", HeaderValue::from_static("\"cookies\""));
        // Distributed tracing pollutants (W3C + Zipkin + AWS X-Ray).
        // Auto-injected by APM agents; if persisted, next reader
        // replays writer's trace ID and corrupts downstream tracing.
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        headers.insert(
            "tracestate",
            HeaderValue::from_static("rojo=00f067aa0ba902b7"),
        );
        headers.insert(
            "baggage",
            HeaderValue::from_static("userId=alice,serverNode=DF%2028"),
        );
        headers.insert(
            "b3",
            HeaderValue::from_static("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"),
        );
        headers.insert(
            "x-b3-traceid",
            HeaderValue::from_static("80f198ee56343ba864fe8b2a57d3eff7"),
        );
        headers.insert("x-b3-spanid", HeaderValue::from_static("e457b5a2e4d86bd1"));
        headers.insert("x-b3-sampled", HeaderValue::from_static("1"));
        headers.insert(
            "x-amzn-trace-id",
            HeaderValue::from_static("Root=1-5759e988-bd862e3fe1be46a994272793"),
        );
        headers.insert("cf-ray", HeaderValue::from_static("8f1234567abcdef0-IAD"));
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert(
            "cf-visitor",
            HeaderValue::from_static("{\"scheme\":\"https\"}"),
        );
        // HTTP transport version markers.
        headers.insert(
            "http3-settings",
            HeaderValue::from_static("AAMAAABkAARAAgAAAAAEAIAAAAA"),
        );
        headers.insert("pragma", HeaderValue::from_static("no-cache"));

        let allowlist = hs::HeaderAllowlist::empty();
        let user_deny = hs::HeaderAllowlist::empty();
        let meta = hs::request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        assert!(meta.contains(&("content-encoding".to_string(), "gzip".to_string())));
        assert!(meta.contains(&("content-language".to_string(), "zh-CN".to_string())));
        assert!(meta.contains(&(
            "content-disposition".to_string(),
            "attachment; filename=\"report.pdf\"".to_string()
        )));
        assert!(meta.contains(&("cache-control".to_string(), "max-age=60".to_string())));
        assert!(meta.contains(&("access-control-allow-origin".to_string(), "*".to_string())));
        assert!(meta.contains(&(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string()
        )));
        assert!(meta.contains(&("x-frame-options".to_string(), "DENY".to_string())));
        assert!(meta.contains(&("permissions-policy".to_string(), "camera=()".to_string())));
        assert!(meta.contains(&(
            "cross-origin-resource-policy".to_string(),
            "same-origin".to_string()
        )));
        // Custom headers (no `x-` shortcut, no auto-allowlist for
        // x-meta-*) MUST NOT persist under the empty allowlist.
        assert!(
            !has("x-meta-author"),
            "x-meta-* is opt-in via ELASTIK_PERSIST_HEADERS"
        );
        assert!(
            !has("x-future-http-thing"),
            "unknown x- headers default-deny"
        );

        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "host",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "http2-settings",
            "content-type",
            "content-length",
            "etag",
            "allow",
            "location",
            "link",
            "www-authenticate",
            "accept",
            "accept-encoding",
            "accept-language",
            "accept-charset",
            "range",
            "if-match",
            "if-none-match",
            "if-range",
            "if-modified-since",
            "if-unmodified-since",
            "expect",
            "sec-fetch-mode",
            "sec-ch-ua",
            "dnt",
            "origin",
            "referer",
            "user-agent",
            "server",
            "date",
            "age",
            "vary",
            "x-request-id",
            "x-elapsed-us",
            "x-elapsed-ms",
            "x-content-type-options",
            "via",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
            "true-client-ip",
            "client-ip",
            "clear-site-data",
            // Distributed tracing pollutants.
            "traceparent",
            "tracestate",
            "baggage",
            "b3",
            "x-b3-traceid",
            "x-b3-spanid",
            "x-b3-sampled",
            // Cloud-provider runtime injections.
            "x-amzn-trace-id",
            "cf-ray",
            "cf-connecting-ip",
            "cf-visitor",
            // Transport version markers + HTTP/1.0 living fossil.
            "http3-settings",
            "pragma",
        ] {
            assert!(!has(name), "{name} should not be persisted");
        }
    }

    #[test]
    fn request_meta_headers_deduplicate_repeated_names_last_wins() {
        let mut headers = HeaderMap::new();
        headers.append("x-meta-author", HeaderValue::from_static("alice"));
        headers.append("x-meta-author", HeaderValue::from_static("bob"));

        // Allowlist x-meta-* so the dedup behaviour is observable;
        // the empty allowlist would correctly drop both entries.
        let allowlist = hs::HeaderAllowlist::parse("x-meta-*");
        let user_deny = hs::HeaderAllowlist::empty();
        let meta = hs::request_meta_headers(&headers, &allowlist, &user_deny);

        assert_eq!(meta, vec![("x-meta-author".to_string(), "bob".to_string())]);
    }

    #[test]
    fn request_meta_headers_user_allowlist_persists_custom_headers() {
        // Layer 3 (user allowlist) opens custom-header round-trip
        // on top of the default-allow set. Exact match and prefix
        // match (`x-my-*`) both work.
        let mut headers = HeaderMap::new();
        headers.insert("x-author", HeaderValue::from_static("ranger"));
        headers.insert("x-version", HeaderValue::from_static("7.1.0"));
        headers.insert("x-my-tag", HeaderValue::from_static("custom"));
        headers.insert("x-my-region", HeaderValue::from_static("ap-east-1"));
        headers.insert("x-other", HeaderValue::from_static("not-allowlisted"));
        // L1 hard deny -- must lose to user allowlist below.
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        // L2 default-allow stays on top of L3.
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );

        let allowlist = hs::HeaderAllowlist::parse("x-author,x-version,x-my-*,traceparent");
        let user_deny = hs::HeaderAllowlist::empty();
        let meta = hs::request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // L3 named exact: persisted.
        assert!(has("x-author"));
        assert!(has("x-version"));
        // L3 prefix wildcard: persisted.
        assert!(has("x-my-tag"));
        assert!(has("x-my-region"));
        // Not allowlisted -> default-deny (L3 didn't match, L2 doesn't cover).
        assert!(!has("x-other"));
        // L1 hard deny ALWAYS wins -- even if traceparent is in the
        // user allowlist, it never persists.
        assert!(
            !has("traceparent"),
            "L1 hard deny must override user allowlist; tracing context never persists"
        );
        // L2 default-allow still applies alongside L3.
        assert!(has("cache-control"));
    }

    #[test]
    fn request_meta_headers_user_deny_subtracts_from_default_allow() {
        // Layer 1.5 (user deny / ELASTIK_DENY_HEADERS) lets an
        // operator subtract a header from the built-in
        // DEFAULT_PERSIST_HEADERS without recompiling. Order:
        //   L1 hard deny > L1.5 user deny > L2 default > L3 user allow.
        let mut headers = HeaderMap::new();
        // L2 defaults that should normally persist:
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert("permissions-policy", HeaderValue::from_static("camera=()"));
        // L3-allowlisted custom that user_deny should also win over:
        headers.insert("x-author", HeaderValue::from_static("ranger"));

        // Operator says: drop cache-control + permissions-policy
        // from defaults; also kill any allowlisted x-author (user
        // deny beats user allow).
        let allowlist = hs::HeaderAllowlist::parse("x-author");
        let user_deny = hs::HeaderAllowlist::parse("cache-control,permissions-policy,x-author");
        let meta = hs::request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // L2 defaults the operator denied -> dropped.
        assert!(
            !has("cache-control"),
            "user-deny must subtract from L2 default-allow"
        );
        assert!(!has("permissions-policy"));
        // L2 default not in user_deny -> still persisted.
        assert!(has("content-encoding"));
        // L3 allowlisted but also user_denied -> deny wins.
        assert!(
            !has("x-author"),
            "user-deny must override user-allow when both match"
        );
    }

    #[test]
    fn request_meta_headers_is_case_insensitive_per_rfc_7230() {
        // RFC 7230: HTTP header field names are case-insensitive.
        // axum's HeaderMap canonicalizes incoming names to
        // lowercase via `HeaderName::as_str`; this test pins that
        // axum-side normalization PLUS verifies that the
        // env-var-side parser lowercases its input.
        let mut headers = HeaderMap::new();
        // Insert with mixed case -- axum stores keys in lowercase
        // canonical form, so the iteration in
        // `request_meta_headers` sees lowercase.
        headers.insert("X-Author", HeaderValue::from_static("ranger"));
        headers.insert("CACHE-CONTROL", HeaderValue::from_static("max-age=60"));
        headers.insert("Traceparent", HeaderValue::from_static("00-...-01"));
        headers.insert("X-Forwarded-For", HeaderValue::from_static("203.0.113.7"));

        // Operator wrote ELASTIK_PERSIST_HEADERS with mixed case --
        // parser lowercases.
        let allowlist = hs::HeaderAllowlist::parse("X-AUTHOR, X-Version");
        let user_deny = hs::HeaderAllowlist::empty();
        let meta = hs::request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // Mixed-case allowlist entry persists the (lowercase-stored)
        // input header.
        assert!(has("x-author"), "X-Author allowlisted as X-AUTHOR persists");
        // L2 default catches CACHE-CONTROL regardless of input case.
        assert!(has("cache-control"));
        // L1 hard-deny still blocks tracing context regardless of
        // input case.
        assert!(!has("traceparent"));
        assert!(!has("x-forwarded-for"));

        // Stored header names are always lowercase canonical form.
        for (name, _) in &meta {
            assert_eq!(
                name,
                &name.to_ascii_lowercase(),
                "stored meta keys must be lowercase"
            );
        }
    }

    #[test]
    fn header_allowlist_parser_handles_whitespace_dedup_and_wildcards() {
        // Whitespace per entry trimmed; case folded; duplicates de-duped;
        // empty / all-* entries skipped.
        let allow = hs::HeaderAllowlist::parse(
            "  X-Author , x-version, x-my-*, x-version, , *, x-my-* , x-AUTHOR",
        );
        assert!(allow.matches("x-author"));
        assert!(allow.matches("x-version"));
        assert!(allow.matches("x-my-tag"));
        assert!(allow.matches("x-my-region"));
        assert!(!allow.matches("x-other"));
        assert!(!allow.matches(""));
        // A bare `*` in the env doesn't open the floodgates.
        assert!(!allow.matches("anything-else"));

        // Empty input == empty allowlist.
        assert!(hs::HeaderAllowlist::parse("").is_empty());
        assert!(hs::HeaderAllowlist::parse("   ,  ,").is_empty());
    }

    #[tokio::test]
    async fn get_returns_stored_standard_representation_headers() {
        let (core, dir) = test_core("representation-headers");
        let headers = vec![
            ("content-encoding".to_string(), "gzip".to_string()),
            (
                "content-disposition".to_string(),
                "attachment; filename=\"report.pdf\"".to_string(),
            ),
            ("access-control-allow-origin".to_string(), "*".to_string()),
            (
                "content-security-policy".to_string(),
                "default-src 'self'".to_string(),
            ),
            ("x-frame-options".to_string(), "DENY".to_string()),
        ];
        core.write_world(
            "home/gzip",
            b"compressed bytes",
            "application/pdf",
            &headers,
        )
        .unwrap();

        let req_headers = HeaderMap::new();
        let resp = unwrap_response(
            execute_get(
                req_headers.clone(),
                auth::Tier::Anon,
                world_path("home/gzip"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"report.pdf\""
        );
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn worlds_store_content_type_not_private_extensions() {
        let (core, dir) = test_core("content-type");
        core.write_world("home/pdf", b"%PDF-1.7", "application/pdf", &[])
            .unwrap();

        let stage = core.read_world("home/pdf").unwrap().unwrap();
        assert_eq!(stage.content_type, "application/pdf");
        assert_eq!(stage.body, b"%PDF-1.7");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn storage_prefix_routes_memory_and_disk_modes() {
        assert!(!store::is_memory_world("home/report"));
        assert!(!store::is_memory_world("etc/config"));
        assert!(store::is_memory_world("tmp/scratch"));
        assert!(store::is_memory_world("dev/fb0"));
        assert!(store::is_memory_world("sys/status"));
        assert!(store::is_persistent("home/report"));
        assert!(!store::is_persistent("tmp/scratch"));
    }

    #[test]
    fn memory_worlds_do_not_create_sqlite_files_or_audit_chain() {
        let (core, dir) = test_core("memory-world");
        core.write_world(
            "tmp/scratch",
            b"draft",
            "text/plain; charset=utf-8",
            &[("x-meta-owner".to_string(), "agent".to_string())],
        )
        .unwrap();

        let stage = core.read_world("tmp/scratch").unwrap().unwrap();
        assert_eq!(stage.body, b"draft");
        assert_eq!(stage.content_type, "text/plain; charset=utf-8");
        assert_eq!(
            stage.headers,
            vec![("x-meta-owner".to_string(), "agent".to_string())]
        );
        assert!(!world::world_db(&core.data, "tmp/scratch").exists());
        assert!(audit::latest_hmac(&core.data, "tmp/scratch").is_none());

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(names.unwrap(), vec!["tmp/scratch".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disk_worlds_create_sqlite_files_and_audit_chain_when_using_audit_path() {
        let (core, dir) = test_core("disk-world");
        let h = world::write_with_audit(
            &core.data,
            "home/report",
            b"final",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let stage = core.read_world("home/report").unwrap().unwrap();
        assert_eq!(stage.body, b"final");
        assert!(world::world_db(&core.data, "home/report").exists());
        assert_eq!(audit::latest_hmac(&core.data, "home/report"), Some(h));

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(names.unwrap(), vec!["home/report".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_keeps_historical_metadata_without_json_payload() {
        let (core, dir) = test_core("audit-meta");
        let headers = vec![("x-meta-author".to_string(), "ranger".to_string())];
        let h = world::write_with_audit(
            &core.data,
            "home/audit-meta",
            b"hello",
            "text/plain; charset=utf-8",
            &headers,
            &core.hmac_key,
        )
        .unwrap();

        let c = rusqlite::Connection::open(world::world_db(&core.data, "home/audit-meta")).unwrap();
        let (content_type, meta_sha256): (String, String) = c
            .query_row(
                "SELECT content_type, meta_sha256 FROM events WHERE hmac=?",
                [h],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert_eq!(
            meta_sha256,
            audit::meta_sha256("text/plain; charset=utf-8", &headers)
        );

        let author: String = c
            .query_row(
                "SELECT value FROM event_headers WHERE name='x-meta-author'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(author, "ranger");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn post_audit_uses_existing_representation_metadata() {
        let (core, dir) = test_core("post-audit-meta");
        let headers = vec![
            ("content-encoding".to_string(), "gzip".to_string()),
            ("x-meta-author".to_string(), "ranger".to_string()),
        ];
        world::write_with_audit(
            &core.data,
            "home/post-audit-meta",
            b"hello",
            "text/plain",
            &headers,
            &core.hmac_key,
        )
        .unwrap();

        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        );
        req_headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        let resp = unwrap_response(
            execute_post(
                req_headers.clone(),
                Bytes::from_static(b" world"),
                auth::Tier::Write,
                world_path("home/post-audit-meta"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let c = rusqlite::Connection::open(world::world_db(&core.data, "home/post-audit-meta"))
            .unwrap();
        let (content_type, meta_sha256): (String, String) = c
            .query_row(
                "SELECT content_type, meta_sha256 FROM events WHERE event_type='append'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(content_type, "text/plain");
        assert_eq!(meta_sha256, audit::meta_sha256("text/plain", &headers));

        let language_count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM event_headers WHERE name='content-language'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(language_count, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_honors_if_match_before_audit_or_remove() {
        let (core, dir) = test_core("delete-if-match");
        let h = world::write_with_audit(
            &core.data,
            "home/delete-cas",
            b"alive",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        let resp = unwrap_response(
            execute_delete(
                stale.clone(),
                auth::Tier::Approve,
                world_path("home/delete-cas"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(core.read_world("home/delete-cas").unwrap().is_some());

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", et::hmac_etag(&h))).unwrap(),
        );
        let resp = unwrap_response(
            execute_delete(
                good.clone(),
                auth::Tier::Approve,
                world_path("home/delete-cas"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(core.read_world("home/delete-cas").unwrap().is_none());
        assert!(core.read_world("var/log/deletes").unwrap().is_some());
        assert!(matches!(
            core.cached_verify_chain("var/log/deletes").unwrap(),
            Some(audit::VerifyReport::Valid(_))
        ));
        let ledger = world::open_existing(&core.data, "var/log/deletes")
            .unwrap()
            .unwrap();
        let mut stmt = ledger
            .prepare("SELECT event_type FROM events ORDER BY id")
            .unwrap();
        let events: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(events, vec!["delete_intent", "delete_commit"]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_returns_500_when_commit_audit_fails_after_physical_delete() {
        let (core, dir) = test_core("delete-commit-audit-fail");
        core.write_world("home/delete-degraded", b"alive", "text/plain", &[])
            .unwrap();
        world::write_with_audit(
            &core.data,
            "var/log/deletes",
            b"ledger",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        core.delete_ledger_created.store(true, Ordering::Relaxed);
        {
            let c =
                rusqlite::Connection::open(world::world_db(&core.data, "var/log/deletes")).unwrap();
            c.execute_batch(
                r#"
                CREATE TRIGGER fail_delete_commit
                BEFORE INSERT ON events
                WHEN NEW.event_type='delete_commit'
                BEGIN
                    SELECT RAISE(FAIL, 'delete_commit blocked');
                END;
                "#,
            )
            .unwrap();
        }

        let resp = unwrap_response(
            execute_delete(
                HeaderMap::new(),
                auth::Tier::Approve,
                world_path("home/delete-degraded"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(core.read_world("home/delete-degraded").unwrap().is_none());
        let ledger = world::open_existing(&core.data, "var/log/deletes")
            .unwrap()
            .unwrap();
        let events = ledger
            .prepare("SELECT event_type FROM events ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events, vec!["put", "delete_intent", "delete_commit_failed"]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_rejects_auth_token_and_append_only_ledger() {
        let (core, dir) = test_core("delete-policy");
        world::write_with_audit(
            &core.data,
            "home/delete-policy",
            b"alive",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit(
            &core.data,
            "var/log/deletes",
            b"ledger",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let headers = HeaderMap::new();

        let auth_delete = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Write,
                world_path("home/delete-policy"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(auth_delete.status(), StatusCode::UNAUTHORIZED);
        assert!(core.read_world("home/delete-policy").unwrap().is_some());

        let ledger_delete = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Approve,
                world_path("var/log/deletes"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(ledger_delete.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ledger_delete
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer realm=\"elastik\""
        );
        assert_eq!(
            ledger_delete.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response_text(ledger_delete).await,
            "auth required: delete ledger is append-only\n"
        );
        assert!(core.read_world("var/log/deletes").unwrap().is_some());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_missing_world_does_not_write_delete_ledger() {
        let (core, dir) = test_core("delete-missing");
        let headers = HeaderMap::new();
        let resp = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Approve,
                world_path("home/missing"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(core.read_world("var/log/deletes").unwrap().is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn proc_worlds_body_is_plain_lines() {
        assert_eq!(world_list_body(&[]), "");
        assert_eq!(
            world_list_body(&["home/a".to_owned(), "tmp/b".to_owned()]),
            "home/a\ntmp/b\n"
        );
    }

    #[tokio::test]
    async fn proc_du_and_df_report_resource_usage() {
        let (mut core, dir) = test_core("proc-du-df");
        core.max_storage_bytes = Some(10);
        core.write_world("home/hello", b"hello", "text/plain", &[])
            .unwrap();
        core.write_world("tmp/scratch", b"data", "text/plain", &[])
            .unwrap();
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let du = proc_du(State(state.clone()), Method::GET, headers.clone()).await;
        assert_eq!(du.status(), StatusCode::OK);
        let du_body = response_text(du).await;
        assert!(du_body.contains("home/hello\t5\n"));
        assert!(du_body.contains("tmp/scratch\t4\n"));

        let df = proc_df(State(state.clone()), Method::GET, headers.clone()).await;
        assert_eq!(df.status(), StatusCode::OK);
        let df_body = response_text(df).await;
        assert!(df_body.contains("storage\t5\t10\t5\n"));
        assert!(df_body.contains("memory\t4\t268435456\t268435452\n"));
        assert!(df_body.contains("worlds\t2\tunlimited\tunlimited\n"));

        let head = proc_du(State(state), Method::HEAD, headers).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "27");
        assert_eq!(response_text(head).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_du_and_df_require_read_token_when_enabled() {
        let (mut core, dir) = test_core("proc-du-df-read-token");
        core.tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let du = proc_du(State(state.clone()), Method::GET, headers.clone()).await;
        assert_eq!(du.status(), StatusCode::UNAUTHORIZED);

        let df = proc_df(State(state), Method::GET, headers).await;
        assert_eq!(df.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_df_world_count_tracks_durable_put_and_delete() {
        let (core, dir) = test_core("proc-df-world-count");
        let headers = HeaderMap::new();

        let put = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"x"),
                auth::Tier::Write,
                world_path("home/count"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(put.status(), StatusCode::CREATED);

        let state = Arc::new(core);
        let before = proc_df(State(state.clone()), Method::GET, headers.clone()).await;
        assert!(response_text(before)
            .await
            .contains("worlds\t1\tunlimited\tunlimited\n"));

        let delete = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Approve,
                world_path("home/count"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);

        let after = proc_df(State(state), Method::GET, headers).await;
        let after_body = response_text(after).await;
        assert!(after_body.contains("storage\t0\tunlimited\tunlimited\n"));
        assert!(after_body.contains("worlds\t0\tunlimited\tunlimited\n"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_pool_emits_metrics_with_type_labels() {
        // Warm the cache via a PUT + GET, then assert the metrics
        // body has the right counter / snapshot labels and tracks
        // hits + misses correctly. After a DELETE the
        // `ledger_writer_inits` counter must bump from 0 to 1
        // (lazy-init fired exactly once).
        let (core, dir) = test_core("proc-pool-metrics");
        let headers = HeaderMap::new();

        let put = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"hello"),
                auth::Tier::Write,
                world_path("home/m"),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(put.status(), StatusCode::CREATED);

        // First GET = miss (Phase 3); second GET = hit (Phase 1).
        for _ in 0..2 {
            let get = unwrap_response(
                execute_get(
                    headers.clone(),
                    auth::Tier::Read,
                    world_path("home/m"),
                    &core,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(get.status(), StatusCode::OK);
        }

        let state = Arc::new(core);
        let resp = proc_pool(State(state.clone()), Method::GET, headers.clone()).await;
        let body = response_text(resp).await;

        assert!(body.contains("read_cache_entries 1 snapshot\n"));
        assert!(body.contains("read_cache_tombstones 0 snapshot\n"));
        assert!(body.contains("read_cache_hits 1 counter\n"));
        assert!(body.contains("read_cache_misses 1 counter\n"));
        assert!(body.contains("read_cache_capped 0 counter\n"));
        assert!(body.contains("read_cache_open_fails 0 counter\n"));
        assert!(body.contains("read_cache_max_entries "));
        // No DELETE issued yet -- ledger writer never lazy-inited.
        assert!(body.contains("ledger_writer_inits 0 counter\n"));

        // After a DELETE, the lazy-init fires exactly once
        // (Codex P3: counter not snapshot).
        let _ = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Approve,
                world_path("home/m"),
                &state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        let resp2 = proc_pool(State(state), Method::GET, headers).await;
        let body2 = response_text(resp2).await;
        assert!(
            body2.contains("ledger_writer_inits 1 counter\n"),
            "expected counter to bump to 1 after first DELETE; body=\n{body2}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_pool_requires_read_token_when_enabled() {
        // Codex P3 sub-finding: /proc/pool exposes read-cache and
        // ledger writer internals -- match the auth-deny coverage of
        // /proc/du and /proc/df. With a read token configured, an
        // unauthenticated GET must return 401, not leak metrics.
        let (mut core, dir) = test_core("proc-pool-read-token");
        core.tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let resp = proc_pool(State(state), Method::GET, headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "multi-thread")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_deletes_increment_world_count_exactly_once() {
        // Bug 16 race coverage. Three concurrent DELETEs on a fresh
        // Core (delete_ledger_created starts false). The ledger gets
        // created on the first DELETE that wins the
        // `swap(true, AcqRel)` edge -- exactly one of them sees
        // was_first=true and bumps `durable_world_count`. The other
        // two see the swap-already-true and skip the bump.
        //
        // Setup: PUT three distinct worlds (durable_world_count = 3).
        // Then run three concurrent DELETEs in parallel.
        // Final state: durable_world_count = 3 + 1[ledger creation,
        // exactly once] - 3[three deletes succeed] = 1.
        //
        // Without Bug 16's `swap` ordering, two or all three of the
        // racing DELETEs would each independently observe
        // delete_ledger_created==false (via world_exists_blocking)
        // and each bump the counter, leading to drift. With the
        // atomic swap, only the unique false->true transition bumps.
        let (core, dir) = test_core("concurrent-first-deletes");
        let headers = HeaderMap::new();
        for w in ["home/a", "home/b", "home/c"] {
            let put = unwrap_response(
                execute_put(
                    headers.clone(),
                    Bytes::from_static(b"x"),
                    auth::Tier::Write,
                    world_path(w),
                    &core,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(put.status(), StatusCode::CREATED);
        }
        assert_eq!(core.durable_world_count.load(Ordering::Relaxed), 3);
        assert!(!core.delete_ledger_created.load(Ordering::Relaxed));

        let state = Arc::new(core);
        let s1 = state.clone();
        let s2 = state.clone();
        let s3 = state.clone();
        let h1 = headers.clone();
        let h2 = headers.clone();
        let h3 = headers.clone();
        let trace1 = TraceCtx::disabled();
        let trace2 = TraceCtx::disabled();
        let trace3 = TraceCtx::disabled();
        let (r1, r2, r3) = tokio::join!(
            execute_delete(h1, auth::Tier::Approve, world_path("home/a"), &s1, &trace1),
            execute_delete(h2, auth::Tier::Approve, world_path("home/b"), &s2, &trace2),
            execute_delete(h3, auth::Tier::Approve, world_path("home/c"), &s3, &trace3),
        );
        assert_eq!(unwrap_response(r1).status(), StatusCode::NO_CONTENT);
        assert_eq!(unwrap_response(r2).status(), StatusCode::NO_CONTENT);
        assert_eq!(unwrap_response(r3).status(), StatusCode::NO_CONTENT);

        // 3 (original) + 1 (ledger creation, exactly once) - 3 (three
        // deletes) = 1.
        assert_eq!(state.durable_world_count.load(Ordering::Relaxed), 1);
        assert!(state.delete_ledger_created.load(Ordering::Relaxed));

        let _ = std::fs::remove_dir_all(dir);
    }

    async fn response_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // ── pipeline route-level coverage (PR 4b/4c) ───────────────
    //
    // The white-box tests above call `execute_get` / `execute_head`
    // / `execute_put` / `execute_post` / `execute_delete` directly
    // (renamed mechanically from `handle_*` in PR 4c) -- they cover
    // verb-handler logic in isolation. The tests below call
    // `pipeline::run` with the same Core fixture, exercising the
    // `world_handler -> pipeline::run -> handler::execute` route that
    // every real request now takes. Without these, a bug in the
    // pipeline wiring (path canonicalization, auth threading,
    // dispatch, response construction in the handler) would not be
    // caught by white-box tests; only e2e_blackbox would surface it.

    #[tokio::test]
    async fn pipeline_get_existing_world_returns_200_with_body() {
        let (core, dir) = test_core("pipeline-get-200");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let resp = pipeline::run(
            Method::GET,
            "/home/hello".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            42,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        assert_eq!(response_text(resp).await, "hello world");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_head_existing_world_returns_headers_no_body() {
        let (core, dir) = test_core("pipeline-head-200");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let resp = pipeline::run(
            Method::HEAD,
            "/home/hello".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            43,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("11")
        );
        // HEAD body must be empty even though Content-Length says 11.
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_nonexistent_world_returns_404() {
        let (core, dir) = test_core("pipeline-get-404");
        let core = Arc::new(core);

        let resp = pipeline::run(
            Method::GET,
            "/home/missing".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            44,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_invalid_dot_segment_returns_400() {
        let (core, dir) = test_core("pipeline-get-400");
        let core = Arc::new(core);

        let resp = pipeline::run(
            Method::GET,
            "/home/../etc/secret".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            45,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_with_read_token_required_rejects_anon() {
        let (mut core, dir) = test_core("pipeline-get-401");
        core.tokens.read = auth::NonEmptyBytes::new(b"reader".to_vec());
        core.write_world("home/secret", b"shhh", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let resp = pipeline::run(
            Method::GET,
            "/home/secret".to_string(),
            HeaderMap::new(), // no Authorization header
            Bytes::new(),
            &core,
            46,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// World-handler glue test (1/2): the full extractor chain
    /// (`State` + `Extension<RequestId>` + `Method` + `AxPath` +
    /// `HeaderMap` + `Bytes`) wires up correctly and `world_handler`
    /// routes GET to the pipeline. Goes through `tower::oneshot` so
    /// the `add_core_response_headers` middleware fires too -- that
    /// way we can assert the unified `x-request-id` header lands on
    /// the response.
    #[tokio::test]
    async fn world_handler_get_routes_through_pipeline() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let (core, dir) = test_core("world-handler-get");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let app = Router::new()
            .route("/*world", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                core.clone(),
                add_core_response_headers,
            ))
            .with_state(core.clone());

        let req = HttpRequest::builder()
            .method("GET")
            .uri("/home/hello")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        // Middleware stamps x-request-id; pipeline trace uses the
        // same id (`pipeline::run` reads RequestId from extensions
        // rather than allocating its own). The fact that this
        // header is present on the response is what the unification
        // fix guarantees -- without it, the bug would slip through
        // again silently.
        let req_id_header = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("missing");
        assert!(
            req_id_header.parse::<u64>().is_ok(),
            "x-request-id should be a numeric id, got {req_id_header:?}"
        );
        assert_eq!(response_text(resp).await, "hello world");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// World-handler glue test (2/2): the same extractor chain works
    /// for HEAD. Validates the `if matches!(method, Method::GET |
    /// Method::HEAD)` short-circuit covers HEAD too, not just GET.
    #[tokio::test]
    async fn world_handler_head_routes_through_pipeline() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let (core, dir) = test_core("world-handler-head");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let app = Router::new()
            .route("/*world", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                core.clone(),
                add_core_response_headers,
            ))
            .with_state(core.clone());

        let req = HttpRequest::builder()
            .method("HEAD")
            .uri("/home/hello")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("11"),
        );
        assert!(resp.headers().get("x-request-id").is_some());
        // HEAD body must be empty even though Content-Length says 11.
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 304 path: `If-None-Match: <current-etag>` short-circuits
    /// inside `execute_get` to `hs::not_modified`, returning
    /// `Phase::ExecutedRead(304)`.
    #[tokio::test]
    async fn pipeline_get_if_none_match_returns_304() {
        let (core, dir) = test_core("pipeline-304");
        core.write_world("home/cached", b"cached body", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        // First GET to discover the current etag.
        let first = pipeline::run(
            Method::GET,
            "/home/cached".to_string(),
            HeaderMap::new(),
            Bytes::new(),
            &core,
            100,
        )
        .await;
        let etag = first
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .expect("first GET must return an ETag header")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let resp = pipeline::run(
            Method::GET,
            "/home/cached".to_string(),
            headers,
            Bytes::new(),
            &core,
            101,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        // 304 bodies must be empty.
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 416 path: `Range: bytes=999-` against a 3-byte world is out
    /// of range. `effective_range` returns `Err(())` and
    /// `execute_get` produces `Phase::Error { reason:
    /// RangeNotSatisfiable }`. We assert BOTH the surfaced HTTP
    /// status (via `pipeline::run`) AND the structured reason
    /// variant (via direct `handler::execute`) so the 12th
    /// `ErrorReason` variant is verified to fire on a real
    /// read-path code path. Without the second assertion, a
    /// regression that emits the right status but the wrong reason
    /// would slip through and quietly poison trace / metrics.
    #[tokio::test]
    async fn pipeline_get_out_of_range_returns_416_with_reason() {
        let (core, dir) = test_core("pipeline-416");
        core.write_world("home/short", b"abc", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        // 1) Production path: pipeline::run surfaces 416 to the wire.
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=999-"));
        let resp = pipeline::run(
            Method::GET,
            "/home/short".to_string(),
            headers,
            Bytes::new(),
            &core,
            200,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        // 2) Internal phase: handler::execute returns the explicit
        // Phase::Error{RangeNotSatisfiable} variant.
        let mut headers2 = HeaderMap::new();
        headers2.insert(header::RANGE, HeaderValue::from_static("bytes=999-"));
        let phase = crate::handler::execute(
            Verb::Get,
            headers2,
            Bytes::new(),
            auth::Tier::Anon,
            world_path("home/short"),
            &core,
            &TraceCtx::disabled(),
        )
        .await;
        match phase {
            Phase::Error {
                reason: ErrorReason::RangeNotSatisfiable,
                resp,
            } => {
                assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            }
            _ => panic!("expected Phase::Error{{RangeNotSatisfiable}}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_range_returns_206_with_chunk() {
        let (core, dir) = test_core("pipeline-get-range");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);

        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

        let resp = pipeline::run(
            Method::GET,
            "/home/range".to_string(),
            headers,
            Bytes::new(),
            &core,
            47,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 1-3/6")
        );
        assert_eq!(response_text(resp).await, "bcd");

        let _ = std::fs::remove_dir_all(dir);
    }

    fn test_core(label: &str) -> (Core, PathBuf) {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!(
            "elastik-core-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (
            {
                let (events, _) = broadcast::channel(16);
                Core {
                    data: dir.clone(),
                    tokens: auth::Tokens {
                        read: None,
                        write: None,
                        approve: None,
                    },
                    hmac_key: b"test-key".to_vec(),
                    mem: Arc::new(store::MemoryStore::new()),
                    max_world_bytes: DEFAULT_MAX_WORLD_BYTES,
                    max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                    max_storage_bytes: None,
                    storage_body_bytes: Arc::new(AtomicUsize::new(0)),
                    durable_world_count: Arc::new(AtomicUsize::new(0)),
                    delete_ledger_created: Arc::new(AtomicBool::new(false)),
                    events,
                    listen_slots: Arc::new(Semaphore::new(DEFAULT_MAX_LISTEN_CONNECTIONS)),
                    listen_replay_max: DEFAULT_LISTEN_REPLAY_MAX,
                    event_log: Arc::new(StdMutex::new(VecDeque::with_capacity(
                        DEFAULT_LISTEN_REPLAY_MAX,
                    ))),
                    shutdown: watch::channel(false).1,
                    next_event: crate::state::new_event_counter(),
                    next_request: Arc::new(AtomicUsize::new(0)),
                    world_locks: Arc::new(DashMap::new()),
                    ledger: Arc::new(crate::ledger::LedgerWriter::new()),
                    read_cache: Arc::new(crate::read_cache::ReadCache::new(
                        crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES,
                    )),
                    persist_header_allowlist: Arc::new(
                        crate::http_semantics::HeaderAllowlist::empty(),
                    ),
                    persist_header_user_deny: Arc::new(
                        crate::http_semantics::HeaderAllowlist::empty(),
                    ),
                }
            },
            dir,
        )
    }

    #[tokio::test]
    async fn write_permit_is_bound_to_one_world() {
        struct NoopTrace;
        impl crate::world_ops::WriteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("permit-bound");
        let world = world_path("home/permit-a");
        let permit = crate::world_ops::authorize_write(&world, auth::Tier::Write)
            .expect("write token tier should authorize home writes");
        let req = crate::world_ops::ReplaceRequest {
            body: Bytes::from_static(b"right-door"),
            content_type: "text/plain; charset=utf-8".to_owned(),
            headers: Vec::new(),
            preconditions: et::Preconditions::default(),
        };

        crate::world_ops::replace_write(&core, &permit, req, &NoopTrace)
            .await
            .expect("permit writes only its bound world");

        assert_eq!(
            core.read_world("home/permit-a").unwrap().unwrap().body,
            b"right-door"
        );
        assert!(core.read_world("home/permit-b").unwrap().is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_permit_preserves_path_based_approve_gate() {
        assert!(matches!(
            crate::world_ops::authorize_write(&world_path("etc/config"), auth::Tier::Write),
            Err(crate::world_ops::WriteError::Auth(AuthGate::WriteApprove))
        ));
        assert!(
            crate::world_ops::authorize_write(&world_path("etc/config"), auth::Tier::Approve)
                .is_ok()
        );
        assert!(
            crate::world_ops::authorize_write(&world_path("home/config"), auth::Tier::Write)
                .is_ok()
        );
    }
}
