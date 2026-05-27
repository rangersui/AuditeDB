//! axum router assembly + the world route's thin handler.
//!
//! `build_app(state)` returns the fully wired
//! `Router` that `main()` serves. The route table itself is short
//! (root, listen, proc/*, `/<world>`) and adding a new top-level
//! route happens here. Per-verb logic lives in `crate::handler`;
//! `world_handler` only routes OPTIONS to a static response and
//! every other method into `pipeline::run`.

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
    listen, options_response, pipeline, proc_audit_verify, proc_df, proc_du, proc_pool,
    proc_reserved, proc_version, proc_worlds, root_hint, server::ServerState, WORLD_ALLOW,
};

#[cfg(feature = "mqtt")]
use crate::proc_mqtt_metrics;

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn build_app(state: ServerState) -> Router {
    let app = Router::new()
        .route("/", any(root_hint))
        .route("/listen/*pattern", any(listen::handler))
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/proc/du", any(proc_du))
        .route("/proc/df", any(proc_df))
        .route("/proc/pool", any(proc_pool));
    #[cfg(feature = "mqtt")]
    let app = app.route("/proc/mqtt/metrics", any(proc_mqtt_metrics));
    app.route("/proc/audit/*audit_path", any(proc_audit_verify))
        .route("/proc", any(proc_reserved))
        .route("/proc/*reserved", any(proc_reserved))
        .route("/*world", any(world_handler))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(state.max_world_bytes()))
        .layer(from_fn_with_state(
            state,
            crate::middleware::add_server_response_headers,
        ))
}

pub(crate) async fn world_handler(
    State(state): State<ServerState>,
    axum::Extension(crate::pipeline::RequestId(req_id)): axum::Extension<
        crate::pipeline::RequestId,
    >,
    method: Method,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // OPTIONS is policy-free -- answer it without entering the FSM.
    // Every other method (including unsupported ones, which the
    // dispatch step rejects with MethodNotAllowed) flows through
    // `pipeline::run`. PR 4c retired the GET/HEAD short-circuit and
    // the legacy `handle_*` write handlers; all five real verbs now
    // share the FSM driver and produce trace output under
    // `ELASTIK_TRACE_PIPELINE=1`.
    //
    // `req_id` comes from `add_server_response_headers` middleware via
    // request extensions -- same id stamped on `x-request-id` so
    // trace output and response header agree.
    if method == Method::OPTIONS {
        return options_response(WORLD_ALLOW);
    }
    pipeline::run(method, path, headers, body, &state, req_id).await
}
