//! axum middleware that runs around every request.
//!
//! `add_server_response_headers` is the single Tower layer the router
//! installs. It does two jobs:
//!
//! 1. Allocates a per-request id from server-owned state and
//!    inserts it into the request extensions as
//!    `crate::pipeline::RequestId`. The FSM driver (`pipeline::run`)
//!    pulls the SAME id out of extensions, so trace output and the
//!    `x-request-id` response header agree. Without this, the
//!    middleware and `pipeline::run` each independently allocated ids.
//! 2. Stamps `x-request-id`, `x-elapsed-us`, `Vary: Authorization`,
//!    and `x-content-type-options: nosniff` onto every response.
//!    These are uniform across all routes; the layer is the only
//!    place they're set.

use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};

use crate::server::ServerState;

pub(crate) async fn add_server_response_headers(
    State(state): State<ServerState>,
    mut req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let request_id = state.next_request_id();
    // Stash on request extensions so the FSM driver
    // (`pipeline::run`) reads the SAME id we'll stamp on the
    // response. Without this, the middleware and `pipeline::run`
    // each call `next_request.fetch_add` and produce off-by-one
    // ids -- trace says `req-43` while the response says `42`.
    req.extensions_mut()
        .insert(crate::pipeline::RequestId(request_id));
    let start = Instant::now();
    let mut response = next.run(req).await;
    stamp_core_response_headers(
        request_id,
        start.elapsed().as_micros(),
        response.headers_mut(),
    );
    response
}

pub(crate) fn stamp_core_response_headers(
    request_id: u64,
    elapsed_us: u128,
    headers: &mut HeaderMap,
) {
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        HeaderName::from_static("x-elapsed-us"),
        HeaderValue::from_str(&elapsed_us.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Authorization"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}
