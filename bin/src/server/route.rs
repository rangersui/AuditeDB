//! axum router assembly + the world route's thin handler.
//!
//! `build_app(state)` returns the fully wired
//! `Router` that `main()` serves. The route table itself is short
//! (root, listen, proc/*, `/<world>`) and adding a new top-level
//! route happens here. Per-verb logic lives in `crate::server::handler`;
//! `world_handler` only routes OPTIONS to a static response and
//! every other method into `pipeline::run`.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxPath, State},
    http::{HeaderMap, Method, Uri},
    middleware::from_fn_with_state,
    response::Response,
    routing::any,
    Router,
};

use crate::server::{
    listen, options_response, pipeline, proc_audit_verify, proc_df, proc_du, proc_pool,
    proc_reserved, proc_version, proc_worlds, root_hint, ServerState,
};

#[cfg(feature = "mqtt")]
use crate::server::proc_mqtt_metrics;

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn build_app(state: ServerState) -> Router {
    let app = Router::new()
        .route("/", any(root_hint))
        .route("/listen/{*pattern}", any(listen::handler))
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/proc/du", any(proc_du))
        .route("/proc/df", any(proc_df))
        .route("/proc/pool", any(proc_pool));
    #[cfg(feature = "mqtt")]
    let app = app.route("/proc/mqtt/metrics", any(proc_mqtt_metrics));
    app.route("/proc/audit/{*audit_path}", any(proc_audit_verify))
        .route("/proc", any(proc_reserved))
        .route("/proc/{*reserved}", any(proc_reserved))
        .route("/{*world}", any(world_handler))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(state.max_world_bytes()))
        .layer(from_fn_with_state(
            state,
            crate::server::middleware::add_server_response_headers,
        ))
}

pub(crate) async fn world_handler(
    State(state): State<ServerState>,
    axum::Extension(crate::server::pipeline::RequestId(req_id)): axum::Extension<
        crate::server::pipeline::RequestId,
    >,
    method: Method,
    uri: Uri,
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
        return options_response(crate::server::WORLD_ALLOW);
    }
    let raw_query = pipeline::RawQuery::from_uri(&uri);
    pipeline::run(method, path, raw_query, headers, body, &state, req_id).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request as HttpRequest, StatusCode},
    };
    use tower::ServiceExt;

    use crate::server::test_support::{
        server_state_for_engine_for_tests, test_engine_for_server, write_text_world_for_tests,
    };

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
        let (engine, dir) = test_engine_for_server("world-handler-get");
        write_text_world_for_tests(&engine, "home/hello", "hello world").await;
        let state = server_state_for_engine_for_tests(engine);

        let app = Router::new()
            .route("/{*world}", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::server::middleware::add_server_response_headers,
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
        let (engine, dir) = test_engine_for_server("world-handler-head");
        write_text_world_for_tests(&engine, "home/hello", "hello world").await;
        let state = server_state_for_engine_for_tests(engine);

        let app = Router::new()
            .route("/{*world}", any(world_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::server::middleware::add_server_response_headers,
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

    #[tokio::test]
    async fn world_handler_options_ignores_malformed_timeline_query() {
        let (engine, dir) = test_engine_for_server("world-handler-options-query");
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        for uri in [
            "/home/hello?timeline%ZZ=1",
            "/home/hello?timeline=1",
            "/home/hello?timeline-generation=abc",
        ] {
            let req = HttpRequest::builder()
                .method("OPTIONS")
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                resp.headers().get(header::ALLOW).unwrap(),
                crate::server::WORLD_ALLOW
            );
            assert_eq!(response_text(resp).await, "");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn world_handler_options_ignores_timeline_and_malformed_query() {
        let (engine, dir) = test_engine_for_server("world-handler-options-valid-timeline");
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);
        let valid_timeline_query = concat!(
            "timeline=1&",
            "timeline-generation=0123456789abcdef0123456789abcdef&",
            "timeline-seq=1&",
            "timeline-body-sha256=",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .replace("timel", "time%6c");
        for query in [valid_timeline_query.as_str(), "timeline%ZZ=1"] {
            let req = HttpRequest::builder()
                .method("OPTIONS")
                .uri(format!("/home/hello?{query}"))
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                resp.headers().get(header::ALLOW).unwrap(),
                crate::server::WORLD_ALLOW
            );
            assert_eq!(response_text(resp).await, "");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn world_handler_rejects_overlong_world_before_storage() {
        let (engine, dir) = test_engine_for_server("world-handler-overlong-path");
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);
        let path = format!("/home/{}", "a".repeat(195));

        let req = HttpRequest::builder()
            .method("PUT")
            .uri(path)
            .body(Body::from("body"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_text(resp).await,
            "bad request: world path is too long\n"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn timeline_path_is_still_an_ordinary_home_world() {
        let (engine, dir) = test_engine_for_server("timeline-path-is-world");
        write_text_world_for_tests(&engine, "home/timeline/foo", "ordinary").await;
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        let req = HttpRequest::builder()
            .method("GET")
            .uri("/timeline/foo")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_text(resp).await, "ordinary");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_head_routes_through_full_app() {
        let (engine, dir) = test_engine_for_server("proc-audit-head-route");
        write_text_world_for_tests(&engine, "home/audit-head-route", "hello").await;
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        let req = HttpRequest::builder()
            .method("HEAD")
            .uri("/proc/audit/home/audit-head-route/head")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-audit-head").unwrap(), "true");
        assert_eq!(
            resp.headers()
                .get("x-audit-generation")
                .and_then(|v| v.to_str().ok())
                .map(str::len),
            Some(32),
        );
        assert_eq!(resp.headers().get("x-audit-seq").unwrap(), "2");
        assert!(resp.headers().get("x-audit-hmac").is_some());
        assert_eq!(response_text(resp).await, "");

        let req = HttpRequest::builder()
            .method("HEAD")
            .uri("/proc/audit/home//audit-head-route/head")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(resp.headers().get("x-audit-head").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn proc_audit_stamp_routes_through_full_app() {
        let (engine, dir) = test_engine_for_server("proc-audit-stamp-route");
        write_text_world_for_tests(&engine, "home/audit-stamp-route", "hello").await;
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        let req = HttpRequest::builder()
            .method("HEAD")
            .uri("/proc/audit/home/audit-stamp-route/stamp/2")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-audit-stamp").unwrap(), "true");
        assert_eq!(
            resp.headers()
                .get("x-audit-generation")
                .and_then(|v| v.to_str().ok())
                .map(str::len),
            Some(32),
        );
        assert_eq!(resp.headers().get("x-audit-seq").unwrap(), "2");
        assert!(resp.headers().get("x-audit-hmac").is_some());
        assert_eq!(response_text(resp).await, "");

        let bad = HttpRequest::builder()
            .method("HEAD")
            .uri("/proc/audit/home/audit-stamp-route/stamp/01")
            .body(Body::empty())
            .unwrap();
        let bad = app.oneshot(bad).await.unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        assert!(bad.headers().get("x-audit-stamp").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn reserved_routes_keep_ownership_ahead_of_world_catchall() {
        let (engine, dir) = test_engine_for_server("reserved-route-ownership");
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        let root = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("GET")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::OK);
        assert!(response_text(root).await.contains("try: curl /proc/worlds"));

        let listen_options = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("OPTIONS")
                    .uri("/listen/home/task/foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listen_options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            listen_options.headers().get(header::ALLOW).unwrap(),
            crate::server::listen::ALLOW
        );

        let proc_version = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("GET")
                    .uri("/proc/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proc_version.status(), StatusCode::OK);
        assert!(response_text(proc_version)
            .await
            .starts_with("elastik-core "));

        let proc_reserved_options = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("OPTIONS")
                    .uri("/proc/not-a-world")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proc_reserved_options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            proc_reserved_options.headers().get(header::ALLOW).unwrap(),
            crate::server::proc::PROC_ALLOW
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_routes_through_full_app() {
        let (engine, dir) = test_engine_for_server("proc-audit-route");
        write_text_world_for_tests(&engine, "home/audit-route", "hello").await;
        let state = server_state_for_engine_for_tests(engine);
        let app = build_app(state);

        let req = HttpRequest::builder()
            .method("GET")
            .uri("/proc/audit/home/audit-route/verify")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "true");
        assert_eq!(resp.headers().get("x-audit-events").unwrap(), "2");
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("0"),
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
