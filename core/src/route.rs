//! axum router assembly + the world route's thin handler.
//!
//! `build_app(state, max_world_bytes)` returns the fully wired
//! `Router` that `main()` serves. The route table itself is short
//! (root, listen, proc/*, /<world>) and adding a new top-level
//! route happens here. Per-verb logic lives in `crate::handler`;
//! `world_handler` only routes OPTIONS to a static response and
//! every other method into `pipeline::run`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxPath, State},
    http::{HeaderMap, Method},
    middleware::from_fn_with_state,
    response::Response,
    routing::any,
    Router,
};

use crate::{
    listen, options_response, pipeline, proc_audit_verify, proc_df, proc_du, proc_reserved,
    proc_version, proc_worlds, root_hint, Core, WORLD_ALLOW,
};

pub(crate) fn build_app(state: Arc<Core>, max_world_bytes: usize) -> Router {
    Router::new()
        .route("/", any(root_hint))
        .route("/listen/*pattern", any(listen::handler))
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/proc/du", any(proc_du))
        .route("/proc/df", any(proc_df))
        .route("/proc/audit/*audit_path", any(proc_audit_verify))
        .route("/proc", any(proc_reserved))
        .route("/proc/*reserved", any(proc_reserved))
        .route("/*world", any(world_handler))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(max_world_bytes))
        .layer(from_fn_with_state(
            state,
            crate::middleware::add_core_response_headers,
        ))
}

pub(crate) async fn world_handler(
    State(core): State<Arc<Core>>,
    axum::Extension(crate::pipeline::RequestId(req_id)): axum::Extension<
        crate::pipeline::RequestId,
    >,
    method: Method,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // OPTIONS is policy-free — answer it without entering the FSM.
    // Every other method (including unsupported ones, which the
    // dispatch step rejects with MethodNotAllowed) flows through
    // `pipeline::run`. PR 4c retired the GET/HEAD short-circuit and
    // the legacy `handle_*` write handlers; all five real verbs now
    // share the FSM driver and produce trace output under
    // `ELASTIK_TRACE_PIPELINE=1`.
    //
    // `req_id` comes from `add_core_response_headers` middleware via
    // request extensions — same id stamped on `x-request-id` so
    // trace output and response header agree.
    if method == Method::OPTIONS {
        return options_response(WORLD_ALLOW);
    }
    pipeline::run(method, path, headers, body, &core, req_id).await
}
