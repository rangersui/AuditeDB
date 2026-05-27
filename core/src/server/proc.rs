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
    audit_broken, audit_not_applicable, audit_valid, bad_request, decimal_header_value, df_body,
    du_body,
    engine::{Engine, EngineError},
    engine_introspection::{AuditVerify, PoolSnapshot, WorldUsage},
    engine_types::ValidatedWorldPath,
    insufficient_storage, method_not_allowed, not_found, options_response, proc_text_response,
    server::ServerState,
    server_error, storage_temporarily_unavailable, to_header_map, unauthorized, world_list_body,
    VERSION,
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
    let world = match ValidatedWorldPath::new(crate::canonicalize_path(raw_world)) {
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
fn mqtt_metrics_body(snapshot: &crate::mqtt::MqttMetricsSnapshot) -> String {
    format!(
        "mqtt_active_connections {} snapshot\n\
         mqtt_total_connections {} counter\n\
         mqtt_auth_failures {} counter\n\
         mqtt_retained_publishes {} counter\n\
         mqtt_keep_alive_timeouts {} counter\n\
         mqtt_retained_replay_failures {} counter\n\
         mqtt_retained_replay_messages {} counter\n\
         mqtt_retained_replay_worlds_scanned {} counter\n\
         mqtt_fanout_drops {} counter\n\
         mqtt_qos2_pending_messages {} snapshot\n\
         mqtt_qos2_pending_bytes {} snapshot\n\
         mqtt_qos2_pending_bytes_peak {} snapshot\n",
        snapshot.active_connections,
        snapshot.total_connections,
        snapshot.auth_failures,
        snapshot.retained_publishes,
        snapshot.keep_alive_timeouts,
        snapshot.retained_replay_failures,
        snapshot.retained_replay_messages,
        snapshot.retained_replay_worlds_scanned,
        snapshot.fanout_drops,
        snapshot.qos2_pending_messages,
        snapshot.qos2_pending_bytes,
        snapshot.qos2_pending_bytes_peak
    )
}
