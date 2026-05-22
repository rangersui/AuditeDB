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

use super::{write_error_phase, HttpWriteTrace};
use crate::{auth, http_semantics as hs, world_ops, Core, Phase, TraceCtx};

pub(crate) async fn execute_post(
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let permit = match world_ops::authorize_write(&world, tier) {
        Ok(permit) => permit,
        Err(err) => return write_error_phase(err),
    };
    let req = world_ops::AppendRequest {
        world,
        body,
        preconditions: hs::request_preconditions(&headers),
    };
    let outcome = match world_ops::append_write(core, &permit, req, &HttpWriteTrace { trace }).await
    {
        Ok(outcome) => outcome,
        Err(err) => return write_error_phase(err),
    };
    let resp_headers = [(header::ETAG, hs::etag_header(&outcome.etag))];
    Phase::CommittedWrite((StatusCode::OK, resp_headers, "").into_response())
}
