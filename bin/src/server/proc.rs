//! `/proc/*` introspection endpoints + the `/` root hint.
//!
//! These routes are read-gated, do not enter the HMAC audit chain, do
//! not emit `/listen/*` events, and do not replay user-controlled
//! headers. Durable-state scans run on the blocking pool. Per
//! AGENTS.md "`/proc/*` discipline" — proc endpoints are introspection,
//! not worlds.
//!
//! `root_hint` is here too. It is the `/` handler, not a `/proc/*`
//! endpoint, but it is the same kind of content-free routing courtesy
//! that returns core identity in plain text. Keeping it next to its
//! siblings means the introspection surface lives in one file.
//!
//! Re-exported into the crate root by `main.rs`; existing route table
//! references (`any(root_hint)`, `any(proc_version)`, ...) and the
//! inline tests in main.rs (via `super::*`) keep working without
//! import churn.

use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    engine::{Engine, EngineError},
    engine_introspection::{AuditVerify, PoolSnapshot, WorldUsage},
    engine_types::ValidatedWorldPath,
    server::{
        audit_broken, audit_not_applicable, audit_valid, bad_request, decimal_header_value,
        df_body, du_body, insufficient_storage, method_not_allowed, not_found, options_response,
        path::canonicalize_path, proc_text_response, server_error, storage_temporarily_unavailable,
        to_header_map, unauthorized, world_list_body, ServerState, VERSION,
    },
};

// Allow headers for OPTIONS / 405 responses. `pub(crate)` so the
// inline tests in main.rs (via `super::*`) can assert exact values
// without re-stringifying. Sibling modules don't actually need them
// outside test code.
pub(crate) const ROOT_ALLOW: &str = "GET, HEAD, OPTIONS";
pub(crate) const PROC_ALLOW: &str = "GET, HEAD, OPTIONS";
pub(crate) const AUDIT_VERIFY_ALLOW: &str = "GET, HEAD, OPTIONS";

/// Bare `GET /` — not protocol, not UI. Just a courtesy text/plain
/// signpost so a curious human doesn't white-screen. The protocol
/// surface starts under `/home`, `/tmp`, `/dev`, `/sys`, `/proc`,
/// `/etc`, `/lib`, `/var`. Browser shells are SDK-app territory; core
/// never serves HTML, never sets CSP, never thinks about iframes.
pub(crate) async fn root_hint(method: Method) -> Response {
    let body = format!("elastik-core {VERSION} (rust)\ntry: curl /proc/worlds\n");
    match method {
        Method::GET => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
        Method::HEAD => (
            StatusCode::OK,
            to_header_map(vec![
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (header::CONTENT_LENGTH, decimal_header_value(body.len())),
            ]),
            "",
        )
            .into_response(),
        Method::OPTIONS => options_response(ROOT_ALLOW),
        _ => method_not_allowed(ROOT_ALLOW),
    }
}

// ─── /proc/version ──────────────────────────────────────────────────
pub(crate) async fn proc_version(method: Method) -> Response {
    let body = format!("elastik-core {VERSION} (rust)\n");
    match method {
        Method::GET => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
        Method::HEAD => (
            StatusCode::OK,
            to_header_map(vec![
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (header::CONTENT_LENGTH, decimal_header_value(body.len())),
            ]),
            "",
        )
            .into_response(),
        Method::OPTIONS => options_response(PROC_ALLOW),
        _ => method_not_allowed(PROC_ALLOW),
    }
}

// ─── /proc/worlds ───────────────────────────────────────────────────
pub(crate) async fn proc_worlds(
    State(state): State<ServerState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let tier = state.access_tier_from_headers(&headers);
    let engine = state.engine().clone();
    let names = match run_introspection(engine, "proc worlds", move |engine| {
        engine.list_worlds(tier)
    })
    .await
    {
        Ok(names) => names,
        Err(resp) => return *resp,
    };
    let body = world_list_body_from_paths(&names);
    let mut resp_headers = vec![(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    )];
    if method == Method::HEAD {
        resp_headers.push((header::CONTENT_LENGTH, decimal_header_value(body.len())));
    }
    (
        StatusCode::OK,
        to_header_map(resp_headers),
        if method == Method::HEAD {
            String::new()
        } else {
            body
        },
    )
        .into_response()
}

// /proc/du is read-gated management introspection, intentionally unpaginated
// like Unix du: one line per world. Durable scans run on the blocking pool; use
// /proc/df for cheap polling instead of scraping this as hot-path telemetry.
pub(crate) async fn proc_du(
    State(state): State<ServerState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let tier = state.access_tier_from_headers(&headers);
    let engine = state.engine().clone();
    let sizes = match run_introspection(engine, "proc du", move |engine| engine.du(tier)).await {
        Ok(sizes) => sizes,
        Err(resp) => return *resp,
    };
    let body = du_body_from_usage(&sizes);
    proc_text_response(method, body)
}

pub(crate) async fn proc_df(
    State(state): State<ServerState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let tier = state.access_tier_from_headers(&headers);
    let engine = state.engine().clone();
    let snapshot = match run_introspection(engine, "proc df", move |engine| engine.df(tier)).await {
        Ok(snapshot) => snapshot,
        Err(resp) => return *resp,
    };
    let body = df_body(
        snapshot.storage_used,
        snapshot.storage_quota,
        snapshot.memory_used,
        snapshot.memory_quota,
        snapshot.worlds,
    );
    proc_text_response(method, body)
}

// /proc/pool -- read connection cache + ledger writer metrics.
//
// One line per metric, mirroring /proc/df's text shape. Each line
// has a `counter` or `snapshot` type label so an operator polling
// the endpoint can tell monotonic-from-startup deltas (counter)
// from instantaneous gauges (snapshot). Mirrors Prometheus's
// counter/gauge convention.
//
// The DashMap walk for `read_cache_tombstones` (O(N) in cache size,
// cap=5000 default) and the snapshot of `read_cache_entries` both
// run inside `spawn_blocking`. Atomic counter loads stay on the
// async task -- they don't block. Same pattern as `proc_du` and
// `proc_df`. (Codex P2.)
pub(crate) async fn proc_pool(
    State(state): State<ServerState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let tier = state.access_tier_from_headers(&headers);
    let engine = state.engine().clone();
    let snapshot =
        match run_introspection(engine, "proc pool", move |engine| engine.pool(tier)).await {
            Ok(snapshot) => snapshot,
            Err(resp) => return *resp,
        };
    let body = pool_body(&snapshot);
    proc_text_response(method, body)
}

// /proc/mqtt/metrics -- MQTT adapter counters.
//
// Mirrors /proc/pool's one-line-per-metric shape. Values are protocol-local
// process counters, not Engine worlds, but the endpoint is still read-gated so
// MQTT operational state follows the same visibility policy as /proc/*.
#[cfg(feature = "mqtt")]
pub(crate) async fn proc_mqtt_metrics(
    State(state): State<ServerState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let tier = state.access_tier_from_headers(&headers);
    if !state.engine().allows_read(tier) {
        return unauthorized("read requires read token");
    }
    let Some(metrics) = state.mqtt_metrics() else {
        return not_found();
    };
    let body = mqtt_metrics_body(&metrics.snapshot());
    proc_text_response(method, body)
}

// /proc/audit/{world}/verify
pub(crate) async fn proc_audit_verify(
    State(state): State<ServerState>,
    method: Method,
    AxPath(audit_path): AxPath<String>,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(AUDIT_VERIFY_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(AUDIT_VERIFY_ALLOW);
    }

    let Some(raw_world) = audit_path.strip_suffix("/verify") else {
        return not_found();
    };
    let raw_world = raw_world.trim_end_matches('/');
    if raw_world.is_empty() {
        return bad_request("audit verify requires a world path");
    }
    let world = match ValidatedWorldPath::new(canonicalize_path(raw_world)) {
        Ok(world) => world,
        Err(_) => return bad_request("invalid audit verify world path"),
    };

    let tier = state.access_tier_from_headers(&headers);
    let engine = state.engine().clone();
    let verify_result = match run_introspection(engine, "audit verify", move |engine| {
        engine.verify_audit(&world, tier)
    })
    .await
    {
        Ok(result) => result,
        Err(resp) => return *resp,
    };

    match verify_result {
        AuditVerify::Valid(report) => audit_valid(report),
        AuditVerify::Broken(report) => audit_broken(report),
        AuditVerify::NotApplicable => audit_not_applicable(),
        #[cfg(not(test))]
        _ => server_error("unknown audit verification result".to_string()),
    }
}

pub(crate) async fn proc_reserved(method: Method) -> Response {
    match method {
        Method::OPTIONS => options_response(PROC_ALLOW),
        Method::GET | Method::HEAD => not_found(),
        _ => method_not_allowed(PROC_ALLOW),
    }
}

async fn run_introspection<T, F>(
    engine: Engine,
    scope: &'static str,
    f: F,
) -> Result<T, Box<Response>>
where
    T: Send + 'static,
    F: FnOnce(&Engine) -> Result<T, EngineError> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || f(&engine)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(Box::new(proc_engine_error(scope, err))),
        Err(_) => Err(Box::new(server_error(format!("{scope} worker failed")))),
    }
}

fn proc_engine_error(scope: &'static str, err: EngineError) -> Response {
    match err {
        EngineError::Auth(_) => unauthorized("read requires read token"),
        EngineError::NotFound => not_found(),
        EngineError::TransientStorage { .. } | EngineError::ShuttingDown => {
            storage_temporarily_unavailable()
        }
        EngineError::InsufficientStorage { .. } => insufficient_storage(),
        EngineError::Storage { .. } => server_error(format!("{scope} storage failure")),
        EngineError::InvalidWorldName => bad_request("invalid world path"),
        EngineError::InternalInvariant(message) => {
            server_error(format!("{scope} internal invariant: {message}"))
        }
        EngineError::PayloadTooLarge { .. }
        | EngineError::AppendOnly
        | EngineError::PreconditionFailed { .. }
        | EngineError::QuotaExceeded { .. }
        | EngineError::SubscriptionLimit => {
            server_error(format!("unexpected {scope} engine error"))
        }
        #[cfg(not(test))]
        _ => server_error(format!("unknown {scope} engine error")),
    }
}

fn world_list_body_from_paths(names: &[ValidatedWorldPath]) -> String {
    let names: Vec<String> = names
        .iter()
        .map(|world| world.as_str().to_owned())
        .collect();
    world_list_body(&names)
}

fn du_body_from_usage(sizes: &[WorldUsage]) -> String {
    let sizes: Vec<(String, usize)> = sizes
        .iter()
        .map(|usage| (usage.world.as_str().to_owned(), usage.bytes))
        .collect();
    du_body(&sizes)
}

fn pool_body(snapshot: &PoolSnapshot) -> String {
    format!(
        "read_cache_entries {} snapshot\n\
         read_cache_tombstones {} snapshot\n\
         read_cache_hits {} counter\n\
         read_cache_misses {} counter\n\
         read_cache_capped {} counter\n\
         read_cache_evictions {} counter\n\
         read_cache_open_fails {} counter\n\
         read_cache_max_entries {} snapshot\n\
         ledger_writer_inits {} counter\n",
        snapshot.read_cache_entries,
        snapshot.read_cache_tombstones,
        snapshot.read_cache_hits,
        snapshot.read_cache_misses,
        snapshot.read_cache_capped,
        snapshot.read_cache_evictions,
        snapshot.read_cache_open_fails,
        snapshot.read_cache_max_entries,
        snapshot.ledger_writer_inits
    )
}

#[cfg(feature = "mqtt")]
fn mqtt_metrics_body(snapshot: &crate::server::mqtt::MqttMetricsSnapshot) -> String {
    format!(
        "mqtt_active_connections {} snapshot\n\
         mqtt_total_connections {} counter\n\
         mqtt_auth_failures {} counter\n\
         mqtt_publish_failures {} counter\n\
         mqtt_retained_publishes {} counter\n\
         mqtt_keep_alive_timeouts {} counter\n\
         mqtt_retained_replay_failures {} counter\n\
         mqtt_retained_replay_messages {} counter\n\
         mqtt_retained_replay_worlds_scanned {} counter\n\
         mqtt_preauth_rejections {} counter\n\
         mqtt_client_id_replacements {} counter\n\
         mqtt_fanout_drops {} counter\n\
         mqtt_fanout_read_failures {} counter\n\
         mqtt_qos2_pending_messages {} snapshot\n\
         mqtt_qos2_pending_bytes {} snapshot\n\
         mqtt_qos2_pending_bytes_peak {} snapshot\n",
        snapshot.active_connections,
        snapshot.total_connections,
        snapshot.auth_failures,
        snapshot.publish_failures,
        snapshot.retained_publishes,
        snapshot.keep_alive_timeouts,
        snapshot.retained_replay_failures,
        snapshot.retained_replay_messages,
        snapshot.retained_replay_worlds_scanned,
        snapshot.preauth_rejections,
        snapshot.client_id_replacements,
        snapshot.fanout_drops,
        snapshot.fanout_read_failures,
        snapshot.qos2_pending_messages,
        snapshot.qos2_pending_bytes,
        snapshot.qos2_pending_bytes_peak
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth,
        engine_types::{AccessTier, Preconditions, Representation},
        server::{
            handler::{execute_delete, execute_get, execute_put},
            test_support::{
                server_state_for_engine_for_tests, server_state_for_tests, test_engine_for_server,
                world_db_path_for_server_tests,
            },
            Phase, TraceCtx,
        },
        test_support::{
            test_core, test_core_with_read_cache_max, world_db_path_for_tests,
            write_audited_world_for_tests,
        },
    };
    use axum::body::{to_bytes, Bytes};
    use std::sync::Arc;

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn unwrap_response(phase: Phase) -> Response {
        match phase {
            Phase::ExecutedRead(r) | Phase::CommittedWrite(r) | Phase::Done(r) => r,
            Phase::Error { resp, .. } => resp,
            Phase::Received { .. }
            | Phase::Authenticated { .. }
            | Phase::PathValidated { .. }
            | Phase::Dispatched { .. } => {
                panic!("execute_* returned a non-terminal Phase variant")
            }
        }
    }

    async fn response_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).unwrap()
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
        let (engine, dir) = test_engine_for_server("proc-worlds-http");
        engine
            .replace(
                &world_path("home/a"),
                Representation::new(Bytes::from_static(b"a"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let state = server_state_for_engine_for_tests(engine);
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
        let (engine, dir) = test_engine_for_server("proc-audit-valid");
        let world = world_path("home/audit-ok");
        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from_static(b"hello"),
                    "text/plain",
                    vec![("x-meta-author".to_owned(), "ranger".to_owned())],
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let expected = match engine.verify_audit(&world, AccessTier::Read).unwrap() {
            AuditVerify::Valid(valid) => valid,
            _ => panic!("expected valid audit chain"),
        };
        let state = server_state_for_engine_for_tests(engine);
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
            expected.latest.as_str()
        );
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "0");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_broken_chain_in_headers() {
        let (engine, dir) = test_engine_for_server("proc-audit-broken");
        let world = world_path("home/audit-broken");
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"hello"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let db = world_db_path_for_server_tests(&dir, "home/audit-broken");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let state = server_state_for_engine_for_tests(engine);
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
        write_audited_world_for_tests(&core, "home/audit-escaped", b"hello", "text/plain", &[])
            .unwrap();
        let db = world_db_path_for_tests(&core.data, "home/audit-escaped");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute(
            "UPDATE events SET hmac=? WHERE id=1",
            ["bad\nInjected: yes"],
        )
        .unwrap();

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(server_state_for_tests(state)),
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
            State(server_state_for_tests(state)),
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
        let db = world_db_path_for_tests(&core.data, "home/missing-audit");
        assert!(!db.exists());

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(server_state_for_tests(state)),
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
    async fn proc_du_and_df_report_resource_usage() {
        let (mut core, dir) = test_core("proc-du-df");
        core.max_storage_bytes = Some(10);
        core.write_world("home/hello", b"hello", "text/plain", &[])
            .unwrap();
        core.write_world("tmp/scratch", b"data", "text/plain", &[])
            .unwrap();
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let du = proc_du(
            State(server_state_for_tests(state.clone())),
            Method::GET,
            headers.clone(),
        )
        .await;
        assert_eq!(du.status(), StatusCode::OK);
        let du_body = response_text(du).await;
        assert!(du_body.contains("home/hello\t5\n"));
        assert!(du_body.contains("tmp/scratch\t4\n"));

        let df = proc_df(
            State(server_state_for_tests(state.clone())),
            Method::GET,
            headers.clone(),
        )
        .await;
        assert_eq!(df.status(), StatusCode::OK);
        let df_body = response_text(df).await;
        assert!(df_body.contains("storage\t5\t10\t5\n"));
        assert!(df_body.contains("memory\t4\t268435456\t268435452\n"));
        assert!(df_body.contains("worlds\t2\tunlimited\tunlimited\n"));

        let head = proc_du(State(server_state_for_tests(state)), Method::HEAD, headers).await;
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

        let du = proc_du(
            State(server_state_for_tests(state.clone())),
            Method::GET,
            headers.clone(),
        )
        .await;
        assert_eq!(du.status(), StatusCode::UNAUTHORIZED);

        let df = proc_df(
            State(server_state_for_tests(state.clone())),
            Method::GET,
            headers,
        )
        .await;
        assert_eq!(df.status(), StatusCode::UNAUTHORIZED);

        let mut auth_headers = HeaderMap::new();
        let auth_value =
            HeaderValue::from_str(&format!("{} {}", "Bearer", "reader")).expect("valid test auth");
        auth_headers.insert(header::AUTHORIZATION, auth_value);
        let authorized = proc_df(
            State(server_state_for_tests(state)),
            Method::GET,
            auth_headers,
        )
        .await;
        assert_eq!(authorized.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_df_world_count_tracks_durable_put_and_delete() {
        let (core, dir) = test_core("proc-df-world-count");
        let state = Arc::new(core);
        let server_state = server_state_for_tests(state.clone());
        let headers = HeaderMap::new();

        let put = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"x"),
                auth::Tier::Write,
                world_path("home/count"),
                &server_state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(put.status(), StatusCode::CREATED);

        let before = proc_df(State(server_state.clone()), Method::GET, headers.clone()).await;
        assert!(response_text(before)
            .await
            .contains("worlds\t1\tunlimited\tunlimited\n"));

        let delete = unwrap_response(
            execute_delete(
                headers.clone(),
                auth::Tier::Approve,
                world_path("home/count"),
                &server_state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);

        let after = proc_df(State(server_state), Method::GET, headers).await;
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
        let state = Arc::new(core);
        let server_state = server_state_for_tests(state.clone());
        let headers = HeaderMap::new();

        let put = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"hello"),
                auth::Tier::Write,
                world_path("home/m"),
                &server_state,
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
                    &server_state,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(get.status(), StatusCode::OK);
        }

        let resp = proc_pool(State(server_state.clone()), Method::GET, headers.clone()).await;
        let body = response_text(resp).await;

        assert!(body.contains("read_cache_entries 1 snapshot\n"));
        assert!(body.contains("read_cache_tombstones 0 snapshot\n"));
        assert!(body.contains("read_cache_hits 1 counter\n"));
        assert!(body.contains("read_cache_misses 1 counter\n"));
        assert!(body.contains("read_cache_capped 0 counter\n"));
        assert!(body.contains("read_cache_evictions 0 counter\n"));
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
                &server_state,
                &TraceCtx::disabled(),
            )
            .await,
        );
        let resp2 = proc_pool(State(server_state), Method::GET, headers).await;
        let body2 = response_text(resp2).await;
        assert!(
            body2.contains("ledger_writer_inits 1 counter\n"),
            "expected counter to bump to 1 after first DELETE; body=\n{body2}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_pool_reports_read_cache_eviction_values() {
        let (core, dir) = test_core_with_read_cache_max("proc-pool-eviction-values", 2);
        let state = Arc::new(core);
        let server_state = server_state_for_tests(state);
        let headers = HeaderMap::new();

        for world in ["home/a", "home/b", "home/c"] {
            let put = unwrap_response(
                execute_put(
                    headers.clone(),
                    Bytes::from_static(b"x"),
                    auth::Tier::Write,
                    world_path(world),
                    &server_state,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(put.status(), StatusCode::CREATED);
        }

        for world in ["home/a", "home/b", "home/c"] {
            let get = unwrap_response(
                execute_get(
                    headers.clone(),
                    auth::Tier::Read,
                    world_path(world),
                    &server_state,
                    &TraceCtx::disabled(),
                )
                .await,
            );
            assert_eq!(get.status(), StatusCode::OK);
        }

        let resp = proc_pool(State(server_state), Method::GET, headers).await;
        let body = response_text(resp).await;

        assert!(body.contains("read_cache_entries 2 snapshot\n"));
        assert!(body.contains("read_cache_hits 0 counter\n"));
        assert!(body.contains("read_cache_misses 3 counter\n"));
        assert!(body.contains("read_cache_capped 1 counter\n"));
        assert!(body.contains("read_cache_evictions 1 counter\n"));
        assert!(body.contains("read_cache_open_fails 0 counter\n"));

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

        let resp = proc_pool(State(server_state_for_tests(state)), Method::GET, headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }
}
