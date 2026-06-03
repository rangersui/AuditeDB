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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request as HttpRequest, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::{
        defaults::DEFAULT_MAX_WORLD_BYTES, server::ServerState, test_support::test_core, Core,
    };

    fn server_state_for_tests(core: Arc<Core>) -> ServerState {
        ServerState::from_core_for_tests(core, DEFAULT_MAX_WORLD_BYTES)
    }

    async fn response_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// World-handler glue test (1/2): the full extractor chain
    /// (`State` + `Extension<RequestId>` + `Method` + `AxPath` +
    /// `HeaderMap` + `Bytes`) wires up correctly and `world_handler`
    /// routes GET to the pipeline. Goes through `tower::oneshot` so
    /// the `add_server_response_headers` middleware fires too -- that
    /// way we can assert the unified `x-request-id` header lands on
    /// the response.
    #[tokio::test]
    async fn world_handler_get_routes_through_pipeline() {
        let (core, dir) = test_core("world-handler-get");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);
        let state = server_state_for_tests(core.clone());

        let app = Router::new()
            .route("/*world", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::add_server_response_headers,
            ))
            .with_state(state);

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
        let (core, dir) = test_core("world-handler-head");
        core.write_world("home/hello", b"hello world", "text/plain", &[])
            .unwrap();
        let core = Arc::new(core);
        let state = server_state_for_tests(core.clone());

        let app = Router::new()
            .route("/*world", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::add_server_response_headers,
            ))
            .with_state(state);

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
}
