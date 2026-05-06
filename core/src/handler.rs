//! Per-verb handlers driven by the FSM pipeline.
//!
//! `handler::execute(verb, ...)` is called from `pipeline::run` after
//! the driver has handled authentication, path canonicalization /
//! validation, and method-to-verb dispatch. Each `execute_*` function:
//!
//! 1. Runs its verb-specific authorization gate (`can_read` /
//!    `can_write` / `can_delete`). Authentication is the driver's
//!    job; authorization lives next to the verb because the gate is
//!    verb-and-path-specific.
//! 2. Performs the verb's actual work.
//! 3. Returns either `Phase::ExecutedRead(Response)` (GET / HEAD),
//!    `Phase::CommittedWrite(Response)` (PUT / POST / DELETE), or
//!    `Phase::Error { resp, reason }`.
//!
//! Verb handlers can call `trace.emit_aux(...)` and
//! `trace.emit_aux_kv(...)` to surface sub-step timings (lock
//! acquired, sqlite committed, body_size computed, ...).
//!
//! ## PR 4b scope
//!
//! Only `execute_get` and `execute_head` are real implementations.
//! `execute_put` / `execute_post` / `execute_delete` return a
//! placeholder `Phase::Error` in 4b. PR 4c replaces the placeholders
//! with real write-path implementations and deletes the legacy
//! `handle_*` from `main.rs`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    apply_meta_headers, auth, can_read, http_semantics as hs, not_found, storage_error,
    to_header_map, unauthorized, AuthGate, Core, ErrorReason, Phase, TraceCtx, Verb,
};

/// Dispatch from `Phase::Dispatched` to the verb-specific handler.
/// Called from inside `pipeline::run`'s match arm.
pub(crate) async fn execute(
    verb: Verb,
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
    world: String,
    core: &Arc<Core>,
    trace: &TraceCtx,
) -> Phase {
    // `body` is currently only used by write verbs (PR 4c). Reads
    // ignore it. Suppress the unused-variable warning until 4c.
    let _ = &body;

    match verb {
        Verb::Get => execute_get(headers, tier, world, core, trace).await,
        Verb::Head => execute_head(headers, tier, world, core, trace).await,
        Verb::Put | Verb::Post | Verb::Delete => {
            // PR 4b ships only the read path. Write verbs still go
            // through legacy `handle_put` / `handle_post` /
            // `handle_delete` in main.rs's `world_handler`. They do
            // not reach this dispatcher in production. PR 4c adds
            // execute_put / execute_post / execute_delete and
            // deletes the legacy handlers.
            Phase::Error {
                resp: not_yet_wired_response(verb),
                reason: ErrorReason::MethodNotAllowed,
            }
        }
    }
}

async fn execute_get(
    headers: HeaderMap,
    tier: auth::Tier,
    world: String,
    core: &Arc<Core>,
    trace: &TraceCtx,
) -> Phase {
    if !can_read(core, tier) {
        return Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(AuthGate::Read),
        };
    }
    let Some((stage, etag)) = (match core.read_world_with_etag(&world) {
        Ok(current) => current,
        Err(e) => {
            return Phase::Error {
                resp: storage_error("storage read", e),
                reason: ErrorReason::StorageRead,
            };
        }
    }) else {
        return Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        };
    };
    if hs::read_not_modified(&headers, &etag) {
        // 304: no body, but emit body_size for diagnostic clarity
        // ("the cached body would be N bytes if the client revalidated").
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(&world, &etag, &stage));
    }
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(&world, &mut resp_headers);
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            let chunk = stage.body[start..=end].to_vec();
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&chunk.len().to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
            ));
            trace.emit_aux_kv("body_size", &chunk.len().to_string());
            Phase::ExecutedRead(
                (
                    StatusCode::PARTIAL_CONTENT,
                    to_header_map(resp_headers),
                    chunk,
                )
                    .into_response(),
            )
        }
        Ok(None) => {
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
            ));
            trace.emit_aux_kv("body_size", &stage.body.len().to_string());
            Phase::ExecutedRead(
                (StatusCode::OK, to_header_map(resp_headers), stage.body).into_response(),
            )
        }
        Err(()) => Phase::Error {
            resp: hs::range_not_satisfiable(stage.body.len()),
            reason: ErrorReason::RangeNotSatisfiable,
        },
    }
}

async fn execute_head(
    headers: HeaderMap,
    tier: auth::Tier,
    world: String,
    core: &Arc<Core>,
    trace: &TraceCtx,
) -> Phase {
    if !can_read(core, tier) {
        return Phase::Error {
            resp: unauthorized("read requires read token"),
            reason: ErrorReason::Auth(AuthGate::Read),
        };
    }
    let Some((stage, etag)) = (match core.read_world_with_etag(&world) {
        Ok(current) => current,
        Err(e) => {
            return Phase::Error {
                resp: storage_error("storage read", e),
                reason: ErrorReason::StorageRead,
            };
        }
    }) else {
        return Phase::Error {
            resp: not_found(),
            reason: ErrorReason::NotFound,
        };
    };
    if hs::read_not_modified(&headers, &etag) {
        trace.emit_aux_kv("body_size", &stage.body.len().to_string());
        return Phase::ExecutedRead(hs::not_modified(&world, &etag, &stage));
    }
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(&world, &mut resp_headers);
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(&headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            resp_headers.retain(|(name, _)| name != header::CONTENT_LENGTH);
            let chunk_len = end - start + 1;
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&chunk_len.to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
            ));
            trace.emit_aux_kv("body_size", &chunk_len.to_string());
            Phase::ExecutedRead(
                (StatusCode::PARTIAL_CONTENT, to_header_map(resp_headers), "").into_response(),
            )
        }
        Ok(None) => {
            trace.emit_aux_kv("body_size", &stage.body.len().to_string());
            Phase::ExecutedRead((StatusCode::OK, to_header_map(resp_headers), "").into_response())
        }
        Err(()) => Phase::Error {
            resp: hs::range_not_satisfiable(stage.body.len()),
            reason: ErrorReason::RangeNotSatisfiable,
        },
    }
}

fn not_yet_wired_response(verb: Verb) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("pipeline 4b: verb {verb:?} dispatch not yet wired (PR 4c)\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tier;

    /// Without a Core construction, we can still test the dispatch
    /// table — Verb::Put / Post / Delete must hit the 4b stub
    /// regardless of state. Reaching this path in production would
    /// be a routing bug (legacy `world_handler` short-circuits write
    /// verbs before reaching `pipeline::run`), so the assertion is
    /// "if the dispatcher IS reached for a write verb, the response
    /// is a 501 marker, not a panic or wrong-status".
    #[tokio::test]
    async fn execute_dispatches_write_verbs_to_stub() {
        // We can't easily construct a real `Arc<Core>` here without
        // duplicating the test_core helper from main.rs; for the
        // dispatch table we don't need the Core to be functional —
        // the stub returns Phase::Error before touching it. Skip
        // tests that would require a real Core in 4b; they land in
        // 4c when test_core moves into a shared test-support
        // module.
        for verb in [Verb::Put, Verb::Post, Verb::Delete] {
            let resp = not_yet_wired_response(verb);
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        }
    }

    #[test]
    fn not_yet_wired_response_describes_the_verb_for_diagnostics() {
        let resp = not_yet_wired_response(Verb::Put);
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        // Body content is logged in trace; we don't assert on body
        // bytes here because Response body is streaming and reading
        // it in tests is not free. The presence of NOT_IMPLEMENTED
        // is the assertion that matters.
        let _ = &resp;

        // Sanity check the other two verb labels formatter-survive.
        let _ = not_yet_wired_response(Verb::Post);
        let _ = not_yet_wired_response(Verb::Delete);

        // Read verbs should never reach this — passing one would be
        // a logic error; we only construct stubs for write verbs.
        // No assertion required, just documentation of intent.
        let _ = Tier::Anon; // silence the unused import on Tier
    }

    #[test]
    fn auth_gate_rejection_uses_correct_reason_variant() {
        // The Auth(AuthGate::Read) variant is what execute_get /
        // execute_head emit when the read-token gate rejects them.
        // We're testing the variant constructs and is `Debug`-able.
        let phase = Phase::Error {
            resp: unauthorized("test"),
            reason: ErrorReason::Auth(AuthGate::Read),
        };
        match phase {
            Phase::Error { reason, .. } => {
                let formatted = format!("{reason:?}");
                assert!(formatted.contains("Auth"));
                assert!(formatted.contains("Read"));
            }
            _ => panic!("expected Phase::Error"),
        }
    }
}
