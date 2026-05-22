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

use std::sync::{atomic::Ordering, Arc};

use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    audit, audit_broken, audit_not_applicable, audit_valid, bad_request, can_read,
    canonicalize_path, decimal_header_value, df_body, du_body, method_not_allowed, not_found,
    options_response, proc_text_response, server_error, storage_error, store, to_header_map,
    unauthorized, validate_world_name, world, world_list_body, Core, VERSION,
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
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if !can_read(&core, tier) {
        return unauthorized("read requires read token");
    }
    let data = core.data.clone();
    let mut names = match tokio::task::spawn_blocking(move || world::list(&data)).await {
        Ok(Ok(names)) => names,
        Ok(Err(e)) => return storage_error("proc worlds", e),
        Err(_) => return server_error("proc worlds worker failed".to_string()),
    };
    names.extend(core.mem.list());
    names.sort();
    names.dedup();
    let body = world_list_body(&names);
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
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    if let Err(resp) = require_read(&core, &headers) {
        return *resp;
    }
    let data = core.data.clone();
    let mut sizes = match tokio::task::spawn_blocking(move || world::sizes(&data)).await {
        Ok(Ok(sizes)) => sizes,
        Ok(Err(e)) => return storage_error("proc du", e),
        Err(_) => return server_error("proc du worker failed".to_string()),
    };
    sizes.extend(core.mem.sizes());
    sizes.sort_by(|a, b| a.0.cmp(&b.0));
    sizes.dedup_by(|a, b| a.0 == b.0);
    let body = du_body(&sizes);
    proc_text_response(method, body)
}

pub(crate) async fn proc_df(
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    if let Err(resp) = require_read(&core, &headers) {
        return *resp;
    }
    let mem = core.mem.clone();
    let (memory_used, memory_worlds) =
        match tokio::task::spawn_blocking(move || (mem.total_bytes(), mem.list().len())).await {
            Ok(counts) => counts,
            Err(_) => return server_error("proc df worker failed".to_string()),
        };
    let storage_used = core.storage_body_bytes.load(Ordering::Relaxed);
    let durable_worlds = core
        .durable_world_count
        .load(Ordering::Relaxed)
        .saturating_sub(usize::from(
            core.delete_ledger_created.load(Ordering::Relaxed),
        ));
    let worlds = durable_worlds + memory_worlds;
    let body = df_body(
        storage_used,
        core.max_storage_bytes,
        memory_used,
        core.max_memory_bytes,
        worlds,
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
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    if let Err(resp) = require_read(&core, &headers) {
        return *resp;
    }

    let hits = core
        .read_cache
        .metrics
        .read_cache_hits
        .load(Ordering::Relaxed);
    let misses = core
        .read_cache
        .metrics
        .read_cache_misses
        .load(Ordering::Relaxed);
    let capped = core
        .read_cache
        .metrics
        .read_cache_capped
        .load(Ordering::Relaxed);
    let open_fails = core
        .read_cache
        .metrics
        .read_cache_open_fails
        .load(Ordering::Relaxed);
    let ledger_inits = core.ledger.inits.load(Ordering::Relaxed);
    let max_entries = core.read_cache.max_entries;

    let read_cache = core.read_cache.clone();
    let snapshot = match tokio::task::spawn_blocking(move || {
        let entries = read_cache.snapshot_entries();
        let tombstones = read_cache.snapshot_tombstones();
        (entries, tombstones)
    })
    .await
    {
        Ok(snap) => snap,
        Err(_) => return server_error("proc pool worker failed".to_string()),
    };
    let (entries, tombstones) = snapshot;

    let body = format!(
        "read_cache_entries {entries} snapshot\n\
         read_cache_tombstones {tombstones} snapshot\n\
         read_cache_hits {hits} counter\n\
         read_cache_misses {misses} counter\n\
         read_cache_capped {capped} counter\n\
         read_cache_open_fails {open_fails} counter\n\
         read_cache_max_entries {max_entries} snapshot\n\
         ledger_writer_inits {ledger_inits} counter\n"
    );
    proc_text_response(method, body)
}

// /proc/audit/{world}/verify
pub(crate) async fn proc_audit_verify(
    State(core): State<Arc<Core>>,
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
    let world_name = canonicalize_path(raw_world);
    if let Err(reason) = validate_world_name(&world_name) {
        return bad_request(reason);
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if !can_read(&core, tier) {
        return unauthorized("read requires read token");
    }

    if store::is_memory_world(&world_name) {
        if !core.mem.contains(&world_name) {
            return not_found();
        }
        return audit_not_applicable();
    }

    // Bug 58 fix: route through the read cache so DELETE on the same
    // world drains in-flight verifies via the slot's write guard.
    // The bare `audit::verify_chain(data, world, key)` path is gone
    // -- it opened a fresh fd outside SlotState and would have
    // re-introduced Bug 48 / Bug 54-shape races on this admin endpoint.
    let core_clone = core.clone();
    let verify_result = match tokio::task::spawn_blocking(move || {
        core_clone.cached_verify_chain(&world_name)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => return server_error("audit verify worker failed".to_string()),
    };

    match verify_result {
        Ok(Some(audit::VerifyReport::Valid(report))) => audit_valid(report),
        Ok(Some(audit::VerifyReport::Broken(report))) => audit_broken(report),
        Ok(None) => not_found(),
        Err(e) => storage_error("audit verify", e),
    }
}

pub(crate) async fn proc_reserved(method: Method) -> Response {
    match method {
        Method::OPTIONS => options_response(PROC_ALLOW),
        Method::GET | Method::HEAD => not_found(),
        _ => method_not_allowed(PROC_ALLOW),
    }
}

/// Auth gate shared by `/proc/du` and `/proc/df`. Module-private —
/// only the proc handlers in this file call it. Returns the
/// `Box<Response>` form so the lint `clippy::result_large_err` stays
/// happy without forcing the caller to box at every site.
fn require_read(core: &Core, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if can_read(core, tier) {
        Ok(())
    } else {
        Err(Box::new(unauthorized("read requires read token")))
    }
}
