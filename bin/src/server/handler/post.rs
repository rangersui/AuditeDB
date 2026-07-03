//! POST verb implementation -- append to an existing world.
//!
//! Extracted from `handler.rs` so the four verb implementations
//! (GET / HEAD / PUT / POST) plus the dispatcher fit comfortably
//! inside the 500-line ceiling. POST is structurally similar to
//! PUT (both write under per-world lock, both reserve quota, both
//! notify) but semantically distinct: POST appends rather than
//! replaces, never updates `X-Meta-*` (PUT-only), and 404s when
//! the world is absent. Keeping POST in its own file makes that
//! distinction visible at the module level rather than buried in
//! a long shared file.
//!
//! `pub(crate) use` re-exports `execute_post` from `handler.rs`
//! so callers (`handler::execute(verb=Post, ...)` and the
//! white-box tests in `main.rs`) keep their import path stable.

use axum::{
    body::Bytes,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

use super::{write_error_phase, HttpWriteTrace};
use crate::{
    engine_types::{AccessTier, ValidatedWorldPath},
    server::{http::semantics as hs, Phase, ServerState, TraceCtx},
};

pub(crate) async fn execute_post(
    headers: HeaderMap,
    body: Bytes,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    state: &ServerState,
    trace: &TraceCtx,
) -> Phase {
    let tier = tier.into();
    let outcome = match state
        .engine()
        .append_traced(
            &world,
            body,
            hs::request_preconditions(&headers),
            tier,
            Arc::new(HttpWriteTrace {
                trace: trace.clone(),
            }),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => return write_error_phase(err),
    };
    let resp_headers = [(header::ETAG, hs::etag_header(&outcome.etag))];
    Phase::CommittedWrite((StatusCode::OK, resp_headers, "").into_response())
}
