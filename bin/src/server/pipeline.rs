//! Request lifecycle FSM driver. Five phase nodes, two terminals:
//!
//! ```text
//! Received → Authenticated → PathValidated → Dispatched
//!   ├─ ExecutedRead   → Done    (GET / HEAD; no audit, no notify)
//!   ├─ CommittedWrite → Done    (PUT / POST / DELETE; verb owns audit + notify)
//!   └─ Error          → Done    (any phase can short-circuit)
//! ```
//!
//! ## Authentication vs Authorization
//!
//! - **Driver (this module)** parses the `Authorization` header into an
//!   `AccessTier` and stamps it onto `Phase::Authenticated`. That is
//!   pure authentication — "who is asking".
//! - **Verb handlers** run the gate check (`can_read` / `can_write` /
//!   `can_delete`). That is
//!   authorization — "may this identity do this thing on this
//!   resource". Gates are verb-and-path-specific (PUT to `/home/`
//!   needs Write, PUT to `/etc/` needs Approve, etc), so they live
//!   next to the verb.
//!
//! ## `/listen/*` bypass
//!
//! `/listen/*` is request → infinite SSE stream, not request →
//! response. The Phase enum models the latter. `/listen/*` keeps its
//! own axum handler in `listen.rs` and never enters this driver.
//!
//! ## Trace
//!
//! `ELASTIK_TRACE_PIPELINE=1` enables stderr trace, one line per phase
//! transition, with elapsed time and a `req-N` tag. Default off; one
//! atomic-bool load + branch per emit call when off (~1 ns). Verb
//! handlers can also call `TraceCtx::emit_aux(...)` for indented
//! sub-step lines (lock acquisition, SQLite commit, audit append, ...).
//!
//! ## Routing scope
//!
//! This driver owns regular world routes reached from `server/route.rs`.
//! `/listen/*` and `/proc/*` keep dedicated handlers because their wire
//! shapes are SSE streams and generated introspection responses.

mod context;
mod query;
mod timeline_mode;
#[cfg(test)]
use context::trace_enabled_for_tests;
pub(crate) use context::{init_trace_from_env, RawQuery, RequestId, TraceCtx};
pub(crate) use timeline_mode::TimelineVerb;
#[cfg(test)]
use timeline_mode::TIMELINE_ALLOW;

use axum::{
    body::Bytes,
    http::{HeaderMap, Method},
    response::Response,
};

use crate::{
    engine_types::{AccessTier, ValidatedWorldPath},
    server::{bad_request, method_not_allowed, path::canonicalize_path, ServerState, WORLD_ALLOW},
    timeline::TimelineCoordinate,
    AuthGate,
};

use query::{TimelineQueryError, TimelineRequestMode};
use timeline_mode::classify_timeline_request;

// ─── Phase enum ──────────────────────────────────────────────────

/// FSM state. Five forward nodes plus two terminals (`Done`, `Error`).
/// Each variant carries the data the next transition needs;
/// `headers` and `body` thread through the read-only prefix and are
/// consumed by the verb handler when it lands in 4b/4c.
///
/// `#[allow(dead_code)]` covers the variants and fields that no caller
/// uses yet — `ExecutedRead` / `CommittedWrite` are produced by verb
/// handlers (4b/4c), and `Dispatched`'s fields are read by the same
/// handlers when they extract them. Removing the allow before 4b
/// would force premature wiring; the allow comes off in 4c when
/// every variant has at least one production caller.
#[allow(dead_code)]
pub(crate) enum Phase {
    Received {
        method: Method,
        path: String,
        raw_query: RawQuery,
        headers: HeaderMap,
        body: Bytes,
    },
    Authenticated {
        method: Method,
        path: String,
        raw_query: RawQuery,
        headers: HeaderMap,
        body: Bytes,
        tier: AccessTier,
    },
    PathValidated {
        method: Method,
        raw_query: RawQuery,
        headers: HeaderMap,
        body: Bytes,
        tier: AccessTier,
        world: ValidatedWorldPath,
    },
    Dispatched {
        verb: Verb,
        headers: HeaderMap,
        body: Bytes,
        tier: AccessTier,
        world: ValidatedWorldPath,
    },
    TimelineDispatched {
        verb: TimelineVerb,
        coordinate: TimelineCoordinate,
        tier: AccessTier,
    },
    /// GET / HEAD finished. No audit, no notify.
    ExecutedRead(Response),
    /// PUT / POST / DELETE finished — the verb handler internally
    /// sequenced its audit + notify before reaching here. The FSM
    /// models the request envelope; storage ordering is not its job.
    CommittedWrite(Response),
    Done(Response),
    Error {
        resp: Response,
        reason: ErrorReason,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Verb {
    Get,
    Head,
    Put,
    Post,
    Delete,
}

/// Closed vocabulary of pipeline-level error reasons. Trace, metrics,
/// and SDK error mapping all match against this enum. Strings as
/// reasons turn into log soup; an enum forces a fixed vocabulary.
///
/// PR 4c wires every variant: `execute_put` emits PayloadTooLarge /
/// PreconditionFailed / QuotaExceeded / InsufficientStorage /
/// StorageWriteAudit; `execute_delete` adds AuthGate::Delete;
/// `execute_*` handlers cover the read-side variants the 4b code
/// already used. AuditChainBroken is reserved for the
/// `/proc/audit/verify` path (proc.rs) and not emitted by the
/// pipeline driver itself.
///
/// `#[allow(dead_code)]` on the enum is for the *inner data* of
/// variants like `Auth(AuthGate)` and `PathInvalid(&'static str)`:
/// those fields are read by the `Debug` formatter (`format!("{:?}",
/// reason)` in `trace::emit_error`), which rustc's dead-code
/// analysis intentionally ignores. The variants themselves are all
/// constructed.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ErrorReason {
    Auth(AuthGate),
    /// Path validation rejection. The inner `&'static str` carries
    /// the specific reason from `validate_world_name` (a closed set
    /// of literal strings defined in `path.rs`).
    PathInvalid(&'static str),
    MethodNotAllowed,
    TimelineMethodNotAllowed,
    TimelineRequestTargetTooLong,
    TimelineQuery(TimelineQueryError),
    NotFound,
    PreconditionFailed,
    /// 416 — `Range` header asks for bytes outside the resource.
    /// Read-path only; surfaced from `execute_get` / `execute_head`
    /// when `hs::effective_range` returns `Err(())`. Distinct from
    /// `PreconditionFailed` (412) because the wire status is
    /// different and the operational meaning differs.
    RangeNotSatisfiable,
    PayloadTooLarge,
    QuotaExceeded,
    InsufficientStorage,
    StorageRead,
    TimelineStorageRead,
    TimelineGenMismatch,
    TimelineBodyHashMismatch,
    TimelineNonBodyEvent,
    TimelineMissingRow,
    TimelineUnprovenCoordinate,
    TimelineCorrupt,
    StorageWriteAudit,
    /// 409 — `/proc/audit/verify` discovers an HMAC chain break.
    /// Reserved for the proc-side audit verifier (proc.rs); the
    /// pipeline driver itself never emits it. The verifier handler
    /// runs outside `pipeline::run` (proc routes are direct), so the
    /// variant is currently unused at the FSM layer but kept for
    /// when the proc surface migrates onto the pipeline.
    #[allow(dead_code)]
    AuditChainBroken,
}

fn phase_summary(p: &Phase) -> String {
    match p {
        Phase::Received {
            method, path, body, ..
        } => format!("Received       {method} {path} {}B", body.len()),
        Phase::Authenticated { tier, .. } => format!("Authenticated  tier={tier:?}"),
        Phase::PathValidated { world, .. } => format!("PathValidated  world={world}"),
        Phase::Dispatched { verb, .. } => format!("Dispatched     verb={verb:?}"),
        Phase::TimelineDispatched { verb, .. } => format!("Timeline       verb={verb:?}"),
        Phase::ExecutedRead(resp) => format!("ExecutedRead   status={}", resp.status()),
        Phase::CommittedWrite(resp) => format!("CommittedWrite status={}", resp.status()),
        Phase::Done(resp) => format!("Done           status={}", resp.status()),
        Phase::Error { resp, reason } => {
            format!("Error          status={} reason={reason:?}", resp.status())
        }
    }
}

// ─── Transitions ─────────────────────────────────────────────────

/// `Received → Authenticated`. Pure authentication: parse the
/// Authorization header into a tier. Never emits an Error — Anon is
/// a valid tier; rejecting Anon is the verb handler's authorization
/// step, not the driver's.
fn authenticate(
    method: Method,
    path: String,
    raw_query: RawQuery,
    headers: HeaderMap,
    body: Bytes,
    tier: AccessTier,
) -> Phase {
    Phase::Authenticated {
        method,
        path,
        raw_query,
        headers,
        body,
        tier,
    }
}

/// `Authenticated → PathValidated | Error`. Canonicalize the raw URL
/// path into a world name (`/foo` → `home/foo`, namespace prefix
/// preserved), and reject malformed shapes (empty, dot segments,
/// percent-encoded dot, backslash, control bytes, reserved namespace
/// roots).
fn validate_path(
    method: Method,
    path: String,
    raw_query: RawQuery,
    headers: HeaderMap,
    body: Bytes,
    tier: AccessTier,
) -> Phase {
    let world = canonicalize_path(&path);
    if let Err(reason) = crate::path::validate_world_name(&world) {
        return Phase::Error {
            resp: bad_request(reason),
            reason: ErrorReason::PathInvalid(reason),
        };
    }
    let world = match ValidatedWorldPath::new(world) {
        Ok(world) => world,
        Err(_) => {
            let reason = "world path missing canonical namespace prefix";
            return Phase::Error {
                resp: bad_request(reason),
                reason: ErrorReason::PathInvalid(reason),
            };
        }
    };
    Phase::PathValidated {
        method,
        raw_query,
        headers,
        body,
        tier,
        world,
    }
}

/// `PathValidated → Dispatched | Error`. Map the HTTP `Method` onto
/// the closed `Verb` set the pipeline understands. `PATCH` / `TRACE`
/// / any other method short-circuits to a 405 with `Allow:
/// GET, HEAD, PUT, POST, DELETE, OPTIONS`.
///
/// `OPTIONS` is not a `Verb` here. The world route's OPTIONS reply
/// (a 204 with the Allow header) is policy-free and cheap; the route
/// adapter that wires up in 4b/4c branches on OPTIONS before
/// entering `run()` so it never reaches this point.
fn dispatch(
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    tier: AccessTier,
    world: ValidatedWorldPath,
) -> Phase {
    let verb = match method {
        Method::GET => Verb::Get,
        Method::HEAD => Verb::Head,
        Method::PUT => Verb::Put,
        Method::POST => Verb::Post,
        Method::DELETE => Verb::Delete,
        _ => {
            return Phase::Error {
                resp: method_not_allowed(WORLD_ALLOW),
                reason: ErrorReason::MethodNotAllowed,
            };
        }
    };
    Phase::Dispatched {
        verb,
        headers,
        body,
        tier,
        world,
    }
}

// ─── Driver ──────────────────────────────────────────────────────

/// Run the FSM end-to-end. Constructs a `TraceCtx` from the shared
/// atomic flag, drives the request through phase transitions, and
/// returns the final `Response`.
///
/// `req_id` is the request identifier assigned by the
/// `add_server_response_headers` middleware in `server/middleware.rs` and stamped
/// onto the response as `x-request-id`. The pipeline does NOT
/// allocate its own id — that would diverge from the response
/// header. Tests calling `run` directly pass an explicit id.
pub(crate) async fn run(
    method: Method,
    path: String,
    raw_query: RawQuery,
    headers: HeaderMap,
    body: Bytes,
    state: &ServerState,
    req_id: u64,
) -> Response {
    // Request id allocation is intentionally outside this function; see
    // the RequestId doc comment for the off-by-one history. `state` itself
    // is consumed inside the loop (used for auth and handed to
    // `handler::execute` for the verb).
    let trace = TraceCtx::new(req_id);

    let mut phase = Phase::Received {
        method,
        path,
        raw_query,
        headers,
        body,
    };
    trace.emit_phase(&phase);

    loop {
        phase = match phase {
            Phase::Received {
                method,
                path,
                raw_query,
                headers,
                body,
            } => {
                let tier = state.access_tier_from_headers(&headers);
                authenticate(method, path, raw_query, headers, body, tier)
            }

            Phase::Authenticated {
                method,
                path,
                raw_query,
                headers,
                body,
                tier,
            } => validate_path(method, path, raw_query, headers, body, tier),

            Phase::PathValidated {
                method,
                raw_query,
                headers,
                body,
                tier,
                world,
            } => classify_timeline_request(method, raw_query, headers, body, tier, world),

            Phase::Dispatched {
                verb,
                headers,
                body,
                tier,
                world,
            } => {
                crate::server::handler::execute(verb, headers, body, tier, world, state, &trace)
                    .await
            }

            Phase::TimelineDispatched {
                verb,
                coordinate,
                tier,
            } => {
                crate::server::handler::execute_timeline(
                    coordinate,
                    tier,
                    state,
                    &trace,
                    matches!(verb, TimelineVerb::Head),
                )
                .await
            }

            Phase::ExecutedRead(resp) | Phase::CommittedWrite(resp) => Phase::Done(resp),

            Phase::Done(resp) => {
                trace.emit_done(&resp);
                return resp;
            }

            Phase::Error { resp, reason } => {
                trace.emit_error(&reason, resp.status());
                trace.emit_done(&resp);
                return resp;
            }
        };
        // emit_phase intentionally fires AFTER each transition so
        // the trace shows the state we are now in. Done / Error
        // have their own dedicated emit functions (called above
        // before return), so we skip emit_phase for them to avoid
        // double-printing.
        if !matches!(phase, Phase::Done(_) | Phase::Error { .. }) {
            trace.emit_phase(&phase);
        }
    }
}

// ─── Local response helpers ──────────────────────────────────────
//
// `method_not_allowed` for unsupported verbs uses the canonical helper
// from `response.rs`, parameterized with the crate-root `WORLD_ALLOW`
// constant — one source of truth for the Allow header string.
//
// (4a's `not_yet_wired_response` was relocated to `handler.rs` in 4b
// — it now only fires for write verbs not yet implemented there.)

// ─── Tests ───────────────────────────────────────────────────────
//
// 4a tests cover individual transition functions and the trace API.
// End-to-end driver tests (Phase::Received all the way through to a
// real handler response) come in 4b once `handler::execute` exists
// and an `Engine` can be constructed in a shared test-support module.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        engine_types::{
            Preconditions, Representation, SubscribePattern, SubscriptionResume, ValidatedWorldPath,
        },
        server::test_support::{
            server_state_for_engine_for_tests, test_engine_for_server,
            test_engine_for_server_with_read_token, world_db_path_for_server_tests,
            write_text_world_for_tests,
        },
    };
    use axum::{
        body::to_bytes,
        http::{header, HeaderValue, StatusCode},
    };

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    async fn response_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn header_map_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    fn bearer(token: &str) -> String {
        format!("{} {token}", "Bearer")
    }

    fn raw_query(raw: &str) -> RawQuery {
        RawQuery::from_uri(&format!("/home/query?{raw}").parse().unwrap())
    }

    fn timeline_query(address: &crate::timeline::TimelineAddress) -> String {
        timeline_query_parts(
            address.generation().as_str(),
            address.seq().get(),
            address.body_sha256().as_str(),
        )
    }

    fn encoded_timeline_keys(query: &str) -> String {
        query.replace("timel", "time%6c")
    }

    fn timeline_query_parts(generation: &str, seq: i64, body_sha256: &str) -> String {
        format!(
            "timeline=1&timeline-generation={}&timeline-seq={}&timeline-body-sha256={}",
            generation, seq, body_sha256
        )
    }

    async fn write_body_and_capture_timeline_address_with_tier(
        engine: &crate::engine::Engine,
        world: &str,
        body: &'static [u8],
        headers: Vec<(String, String)>,
        tier: AccessTier,
    ) -> crate::timeline::TimelineAddress {
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new(world),
                tier,
                SubscriptionResume::none(),
            )
            .expect("test subscription should open");
        engine
            .replace(
                &world_path(world),
                Representation::new(Bytes::from_static(body), "text/plain", headers),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .expect("test write should succeed");
        let event = subscription.recv().await.expect("test write event");
        event
            .timeline_address
            .expect("durable write should carry timeline address")
    }

    async fn write_body_and_capture_timeline_address(
        engine: &crate::engine::Engine,
        world: &str,
        body: &'static [u8],
        headers: Vec<(String, String)>,
    ) -> crate::timeline::TimelineAddress {
        write_body_and_capture_timeline_address_with_tier(
            engine,
            world,
            body,
            headers,
            AccessTier::Anon,
        )
        .await
    }

    async fn write_body_and_capture_timeline_query(
        engine: &crate::engine::Engine,
        world: &str,
        body: &'static [u8],
        headers: Vec<(String, String)>,
    ) -> String {
        let address = write_body_and_capture_timeline_address(engine, world, body, headers).await;
        timeline_query(&address)
    }

    fn assert_current_body(engine: &crate::engine::Engine, world: &str, expected: &[u8]) {
        let current = engine
            .read(&world_path(world), AccessTier::Read)
            .unwrap()
            .expect("current body should exist");
        assert_eq!(current.representation.body.as_ref(), expected);
    }

    // ── authenticate ───────────────────────────────────────────

    #[test]
    fn authenticate_no_auth_header_yields_anon_tier() {
        let phase = authenticate(
            Method::GET,
            "/home/foo".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Anon,
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, AccessTier::Anon),
            _ => panic!("expected Authenticated phase"),
        }
    }

    #[test]
    fn authenticate_valid_bearer_yields_write_tier() {
        let phase = authenticate(
            Method::PUT,
            "/home/foo".into(),
            RawQuery::absent(),
            header_map_with_auth(&bearer("writer")),
            Bytes::from_static(b"hi"),
            AccessTier::Write,
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, AccessTier::Write),
            _ => panic!("expected Authenticated phase"),
        }
    }

    #[test]
    fn authenticate_unrecognized_token_falls_back_to_anon() {
        let phase = authenticate(
            Method::PUT,
            "/home/foo".into(),
            RawQuery::absent(),
            header_map_with_auth(&bearer("wrong")),
            Bytes::new(),
            AccessTier::Anon,
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, AccessTier::Anon),
            _ => panic!("expected Authenticated phase"),
        }
    }

    // ── validate_path ──────────────────────────────────────────

    #[test]
    fn validate_path_canonicalizes_bare_to_home_namespace() {
        let phase = validate_path(
            Method::GET,
            "/foo".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Anon,
        );
        match phase {
            Phase::PathValidated { world, .. } => assert_eq!(world.as_str(), "home/foo"),
            _ => panic!("expected PathValidated"),
        }
    }

    #[test]
    fn validate_path_keeps_explicit_namespaces() {
        let phase = validate_path(
            Method::GET,
            "/etc/foo".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Approve,
        );
        match phase {
            Phase::PathValidated { world, .. } => assert_eq!(world.as_str(), "etc/foo"),
            _ => panic!("expected PathValidated"),
        }
    }

    #[test]
    fn validate_path_preserves_raw_query_for_later_classification() {
        let raw_query = RawQuery::from_uri(&"/home/foo?timeline%2dgeneration=abc".parse().unwrap());
        let phase = validate_path(
            Method::GET,
            "/home/foo".into(),
            raw_query,
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Anon,
        );
        match phase {
            Phase::PathValidated { raw_query, .. } => {
                assert_eq!(raw_query.as_deref(), Some("timeline%2dgeneration=abc"));
            }
            _ => panic!("expected PathValidated"),
        }
    }

    #[test]
    fn validate_path_rejects_dot_segments_with_pathinvalid() {
        let phase = validate_path(
            Method::PUT,
            "/home/../etc/secret".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Write,
        );
        match phase {
            Phase::Error {
                reason: ErrorReason::PathInvalid(_),
                resp,
            } => assert_eq!(resp.status(), StatusCode::BAD_REQUEST),
            _ => panic!("expected Error::PathInvalid"),
        }
    }

    #[test]
    fn validate_path_rejects_reserved_namespace_root() {
        let phase = validate_path(
            Method::PUT,
            "/home".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Write,
        );
        match phase {
            Phase::Error {
                reason: ErrorReason::PathInvalid(_),
                ..
            } => {}
            _ => panic!("expected Error::PathInvalid for reserved root"),
        }
    }

    #[test]
    fn validate_path_rejects_percent_encoded_dot_segment() {
        let phase = validate_path(
            Method::GET,
            "/home/%2E%2E/etc/secret".into(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Read,
        );
        assert!(matches!(
            phase,
            Phase::Error {
                reason: ErrorReason::PathInvalid(_),
                ..
            }
        ));
    }

    // ── dispatch ───────────────────────────────────────────────

    #[test]
    fn dispatch_maps_get_to_verb_get() {
        let phase = dispatch(
            Method::GET,
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Anon,
            ValidatedWorldPath::new("home/foo").unwrap(),
        );
        match phase {
            Phase::Dispatched { verb, .. } => assert_eq!(verb, Verb::Get),
            _ => panic!("expected Dispatched"),
        }
    }

    #[test]
    fn dispatch_rejects_patch_with_method_not_allowed() {
        let phase = dispatch(
            Method::PATCH,
            HeaderMap::new(),
            Bytes::new(),
            AccessTier::Write,
            ValidatedWorldPath::new("home/foo").unwrap(),
        );
        match phase {
            Phase::Error {
                reason: ErrorReason::MethodNotAllowed,
                resp,
            } => {
                assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
                let allow = resp
                    .headers()
                    .get(header::ALLOW)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert!(allow.contains("GET"));
                assert!(allow.contains("PUT"));
                assert!(allow.contains("OPTIONS"));
            }
            _ => panic!("expected Error::MethodNotAllowed"),
        }
    }

    #[test]
    fn dispatch_maps_all_five_supported_verbs() {
        let cases = [
            (Method::GET, Verb::Get),
            (Method::HEAD, Verb::Head),
            (Method::PUT, Verb::Put),
            (Method::POST, Verb::Post),
            (Method::DELETE, Verb::Delete),
        ];
        for (method, expected_verb) in cases {
            let display = method.clone();
            let phase = dispatch(
                method,
                HeaderMap::new(),
                Bytes::new(),
                AccessTier::Anon,
                ValidatedWorldPath::new("home/x").unwrap(),
            );
            match phase {
                Phase::Dispatched { verb, .. } => assert_eq!(verb, expected_verb),
                _ => panic!("expected Dispatched for {display}"),
            }
        }
    }

    // ── trace ──────────────────────────────────────────────────

    #[test]
    fn trace_ctx_disabled_emits_nothing() {
        // Sanity: emitting on a disabled context is safe and silent.
        // Test passes iff none of these panic.
        let ctx = TraceCtx::disabled();
        let phase = Phase::Received {
            method: Method::GET,
            path: "/home/foo".into(),
            raw_query: RawQuery::absent(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        ctx.emit_phase(&phase);
        ctx.emit_aux("noop");
        ctx.emit_aux_kv("noop", "key=value");
    }

    #[test]
    fn phase_summary_distinguishes_terminal_variants() {
        // Sanity-check that phase_summary produces distinct prefixes
        // per variant — trace consumers (grep / log filters) rely
        // on these being unique.
        use axum::body::Body;
        let resp_ok = Response::builder().status(200).body(Body::empty()).unwrap();
        let resp_err = Response::builder().status(401).body(Body::empty()).unwrap();

        assert!(phase_summary(&Phase::Done(resp_ok)).starts_with("Done"));
        assert!(phase_summary(&Phase::Error {
            resp: resp_err,
            reason: ErrorReason::Auth(AuthGate::Read),
        })
        .starts_with("Error"));
    }

    // ── init_trace_from_env ────────────────────────────────────

    #[test]
    fn init_trace_from_env_off_by_default() {
        // Snapshot whatever the test runner has, then clear.
        let prior = std::env::var("ELASTIK_TRACE_PIPELINE").ok();
        std::env::remove_var("ELASTIK_TRACE_PIPELINE");
        init_trace_from_env();
        assert!(!trace_enabled_for_tests());
        // Restore.
        if let Some(v) = prior {
            std::env::set_var("ELASTIK_TRACE_PIPELINE", v);
        }
        // Re-init so subsequent tests see the original state.
        init_trace_from_env();
    }

    // ── pipeline route-level coverage (PR 4b/4c) ───────────────
    //
    // The white-box tests above cover individual transition functions.
    // The tests below call `pipeline::run` with the same Engine fixture,
    // exercising the `world_handler -> pipeline::run -> handler::execute`
    // route that every real request now takes. Without these, a bug in
    // pipeline wiring (path canonicalization, auth threading, dispatch,
    // response construction in the handler) would not be caught by
    // transition-only tests; only e2e_blackbox would surface it.

    #[tokio::test]
    async fn options_and_405_advertise_allow_headers() {
        // PR 4c: `handle_world_method` was retired. OPTIONS is now
        // answered directly in `world_handler` (policy-free, never
        // enters the FSM); PATCH and any other unsupported method
        // are rejected by `pipeline::dispatch` with `MethodNotAllowed`.
        let (engine, dir) = test_engine_for_server("allow");
        let state = server_state_for_engine_for_tests(engine);

        let options = crate::server::options_response(WORLD_ALLOW);
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let patch = run(
            Method::PATCH,
            "home/allow".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            0,
        )
        .await;
        assert_eq!(patch.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(patch.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_existing_world_returns_200_with_body() {
        let (engine, dir) = test_engine_for_server("pipeline-get-200");
        write_text_world_for_tests(&engine, "home/hello", "hello world").await;
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::GET,
            "/home/hello".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            42,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        assert_eq!(response_text(resp).await, "hello world");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_head_existing_world_returns_headers_no_body() {
        let (engine, dir) = test_engine_for_server("pipeline-head-200");
        write_text_world_for_tests(&engine, "home/hello", "hello world").await;
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::HEAD,
            "/home/hello".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            43,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("11")
        );
        // HEAD body must be empty even though Content-Length says 11.
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_nonexistent_world_returns_404() {
        let (engine, dir) = test_engine_for_server("pipeline-get-404");
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::GET,
            "/home/missing".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            44,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_invalid_dot_segment_returns_400() {
        let (engine, dir) = test_engine_for_server("pipeline-get-400");
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::GET,
            "/home/../etc/secret".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            45,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_with_read_token_required_rejects_anon() {
        let (engine, dir) =
            test_engine_for_server_with_read_token("pipeline-get-401", b"reader".to_vec());
        write_text_world_for_tests(&engine, "home/secret", "shhh").await;
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::GET,
            "/home/secret".to_string(),
            RawQuery::absent(),
            HeaderMap::new(), // no Authorization header
            Bytes::new(),
            &state,
            46,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 304 path: `If-None-Match: <current-etag>` short-circuits
    /// inside `execute_get` to `hs::not_modified`, returning
    /// `Phase::ExecutedRead(304)`.
    #[tokio::test]
    async fn pipeline_get_if_none_match_returns_304() {
        let (engine, dir) = test_engine_for_server("pipeline-304");
        write_text_world_for_tests(&engine, "home/cached", "cached body").await;
        let state = server_state_for_engine_for_tests(engine);

        // First GET to discover the current etag.
        let first = run(
            Method::GET,
            "/home/cached".to_string(),
            RawQuery::absent(),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            100,
        )
        .await;
        let etag = first
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .expect("first GET must return an ETag header")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let resp = run(
            Method::GET,
            "/home/cached".to_string(),
            RawQuery::absent(),
            headers,
            Bytes::new(),
            &state,
            101,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        // 304 bodies must be empty.
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 416 path: `Range: bytes=999-` against a 3-byte world is out
    /// of range. `effective_range` returns `Err(())` and
    /// `execute_get` produces `Phase::Error { reason:
    /// RangeNotSatisfiable }`. We assert BOTH the surfaced HTTP
    /// status (via `pipeline::run`) AND the structured reason
    /// variant (via direct `handler::execute`) so the 12th
    /// `ErrorReason` variant is verified to fire on a real
    /// read-path code path. Without the second assertion, a
    /// regression that emits the right status but the wrong reason
    /// would slip through and quietly poison trace / metrics.
    #[tokio::test]
    async fn pipeline_get_out_of_range_returns_416_with_reason() {
        let (engine, dir) = test_engine_for_server("pipeline-416");
        write_text_world_for_tests(&engine, "home/short", "abc").await;
        let state = server_state_for_engine_for_tests(engine);

        // 1) Production path: pipeline::run surfaces 416 to the wire.
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=999-"));
        let resp = run(
            Method::GET,
            "/home/short".to_string(),
            RawQuery::absent(),
            headers,
            Bytes::new(),
            &state,
            200,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        // 2) Internal phase: handler::execute returns the explicit
        // Phase::Error{RangeNotSatisfiable} variant.
        let mut headers2 = HeaderMap::new();
        headers2.insert(header::RANGE, HeaderValue::from_static("bytes=999-"));
        let phase = crate::server::handler::execute(
            Verb::Get,
            headers2,
            Bytes::new(),
            AccessTier::Anon,
            world_path("home/short"),
            &state,
            &TraceCtx::disabled(),
        )
        .await;
        match phase {
            Phase::Error {
                reason: ErrorReason::RangeNotSatisfiable,
                resp,
            } => {
                assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            }
            _ => panic!("expected Phase::Error{{RangeNotSatisfiable}}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_get_range_returns_206_with_chunk() {
        let (engine, dir) = test_engine_for_server("pipeline-get-range");
        write_text_world_for_tests(&engine, "home/range", "abcdef").await;
        let state = server_state_for_engine_for_tests(engine);

        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

        let resp = run(
            Method::GET,
            "/home/range".to_string(),
            RawQuery::absent(),
            headers,
            Bytes::new(),
            &state,
            47,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 1-3/6")
        );
        assert_eq!(response_text(resp).await, "bcd");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_get_returns_historical_body_and_proof_headers() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-get");
        let query = write_body_and_capture_timeline_query(
            &engine,
            "home/timeline/http",
            b"old",
            vec![
                ("content-language".to_string(), "en-GB".to_string()),
                ("x-timeline-seq".to_string(), "999".to_string()),
            ],
        )
        .await;
        write_text_world_for_tests(&engine, "home/timeline/http", "new").await;
        let state = server_state_for_engine_for_tests(engine.clone());
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-0"));
        headers.insert(
            header::IF_RANGE,
            HeaderValue::from_static("\"hmac-current\""),
        );
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"hmac-current\""),
        );

        let resp = run(
            Method::GET,
            "/home/timeline/http".to_string(),
            raw_query(&query),
            headers,
            Bytes::new(),
            &state,
            300,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        assert_eq!(resp.headers().get("content-language").unwrap(), "en-GB");
        assert_eq!(
            resp.headers().get("x-timeline-world").unwrap(),
            "home/timeline/http"
        );
        assert_eq!(resp.headers().get("x-timeline-seq").unwrap(), "1");
        assert_eq!(resp.headers().get_all("x-timeline-seq").iter().count(), 1);
        assert!(resp.headers().get(header::ETAG).is_none());
        assert!(resp.headers().get(header::ACCEPT_RANGES).is_none());
        assert!(resp.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(resp.headers().get_all(header::LINK).iter().count(), 0);
        assert_eq!(response_text(resp).await, "old");

        let current = engine
            .read(&world_path("home/timeline/http"), AccessTier::Read)
            .unwrap()
            .expect("current body should exist");
        assert_eq!(current.representation.body.as_ref(), b"new");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_head_returns_headers_without_body() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-head");
        let query = write_body_and_capture_timeline_query(
            &engine,
            "home/timeline/head",
            b"old",
            Vec::new(),
        )
        .await;
        write_text_world_for_tests(&engine, "home/timeline/head", "new").await;
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::HEAD,
            "/home/timeline/head".to_string(),
            raw_query(&query),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            301,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(resp.headers().get("x-timeline-seq").unwrap(), "1");
        assert!(resp.headers().get(header::ETAG).is_none());
        assert_eq!(response_text(resp).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_method_wall_prevents_current_mutation() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-method-wall");
        let query = write_body_and_capture_timeline_query(
            &engine,
            "home/timeline/wall",
            b"old",
            Vec::new(),
        )
        .await;
        write_text_world_for_tests(&engine, "home/timeline/wall", "new").await;
        let state = server_state_for_engine_for_tests(engine.clone());

        for (idx, method) in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH]
            .into_iter()
            .enumerate()
        {
            let request_query = if method == Method::PATCH {
                encoded_timeline_keys(&query)
            } else {
                query.clone()
            };
            let resp = run(
                method,
                "/home/timeline/wall".to_string(),
                raw_query(&request_query),
                HeaderMap::new(),
                Bytes::from_static(b"evil"),
                &state,
                302 + idx as u64,
            )
            .await;

            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(resp.headers().get(header::ALLOW).unwrap(), TIMELINE_ALLOW);
            assert_current_body(&engine, "home/timeline/wall", b"new");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_get_honors_read_token_gate() {
        let (engine, dir) =
            test_engine_for_server_with_read_token("pipeline-timeline-auth", b"reader".to_vec());
        let address = write_body_and_capture_timeline_address_with_tier(
            &engine,
            "home/timeline/auth",
            b"secret",
            Vec::new(),
            AccessTier::Read,
        )
        .await;
        let query = timeline_query(&address);
        let state = server_state_for_engine_for_tests(engine);

        let anon = run(
            Method::GET,
            "/home/timeline/auth".to_string(),
            raw_query(&query),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            306,
        )
        .await;
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

        let bad = run(
            Method::HEAD,
            "/home/timeline/auth".to_string(),
            raw_query(&query),
            header_map_with_auth(&bearer("wrong")),
            Bytes::new(),
            &state,
            307,
        )
        .await;
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_text(bad).await, "");

        let good = run(
            Method::GET,
            "/home/timeline/auth".to_string(),
            raw_query(&query),
            header_map_with_auth(&bearer("reader")),
            Bytes::new(),
            &state,
            308,
        )
        .await;
        assert_eq!(good.status(), StatusCode::OK);
        assert_eq!(response_text(good).await, "secret");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_query_rejects_query_world_identity() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-world-query");
        let address = write_body_and_capture_timeline_address(
            &engine,
            "home/timeline/world-query",
            b"old",
            Vec::new(),
        )
        .await;
        write_text_world_for_tests(&engine, "home/timeline/world-query", "new").await;
        let state = server_state_for_engine_for_tests(engine);
        let query = format!(
            "{}&timeline-world=home/timeline/other",
            timeline_query(&address)
        );

        let resp = run(
            Method::GET,
            "/home/timeline/world-query".to_string(),
            raw_query(&query),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            309,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_text(resp).await,
            "bad request: invalid timeline query: TimelineWorldComesFromPath\n"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_missing_world_is_unproven_not_gone() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-unproven");
        let state = server_state_for_engine_for_tests(engine);

        let resp = run(
            Method::GET,
            "/home/timeline/unproven".to_string(),
            raw_query(
                "timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&\
                 timeline-seq=1&timeline-body-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            319,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_text(resp).await,
            "timeline coordinate not proven\n"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_head_errors_have_no_body() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-head-errors");
        let address = write_body_and_capture_timeline_address(
            &engine,
            "home/timeline/head-errors",
            b"old",
            Vec::new(),
        )
        .await;
        let state = server_state_for_engine_for_tests(engine.clone());

        let missing_row = timeline_query_parts(
            address.generation().as_str(),
            99,
            address.body_sha256().as_str(),
        );
        let missing = run(
            Method::HEAD,
            "/home/timeline/head-errors".to_string(),
            raw_query(&missing_row),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            309,
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_text(missing).await, "");

        let wrong_generation = timeline_query_parts(
            "fedcba9876543210fedcba9876543210",
            address.seq().get(),
            address.body_sha256().as_str(),
        );
        let gen_mismatch = run(
            Method::HEAD,
            "/home/timeline/head-errors".to_string(),
            raw_query(&wrong_generation),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            310,
        )
        .await;
        assert_eq!(gen_mismatch.status(), StatusCode::CONFLICT);
        assert_eq!(response_text(gen_mismatch).await, "");

        let wrong_hash = timeline_query_parts(
            address.generation().as_str(),
            address.seq().get(),
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        );
        let hash_mismatch = run(
            Method::HEAD,
            "/home/timeline/head-errors".to_string(),
            raw_query(&wrong_hash),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            311,
        )
        .await;
        assert_eq!(hash_mismatch.status(), StatusCode::CONFLICT);
        assert_eq!(response_text(hash_mismatch).await, "");

        write_text_world_for_tests(&engine, "home/timeline/deleted", "gone").await;
        engine
            .delete(
                &world_path("home/timeline/deleted"),
                Preconditions::none(),
                AccessTier::Approve,
            )
            .await
            .unwrap();
        let ledger_db = world_db_path_for_server_tests(&dir, "var/log/deletes");
        let conn = rusqlite::Connection::open(ledger_db).unwrap();
        let (ledger_generation, ledger_body_sha256): (String, String) = conn
            .query_row(
                "SELECT (SELECT generation FROM stage_meta WHERE id=1), body_sha256 \
                 FROM events WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(conn);
        let corrupt_query = timeline_query_parts(&ledger_generation, 1, &ledger_body_sha256);

        let get_corrupt = run(
            Method::GET,
            "/var/log/deletes".to_string(),
            raw_query(&corrupt_query),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            312,
        )
        .await;
        assert_eq!(get_corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let corrupt_headers = get_corrupt.headers().clone();
        assert_eq!(response_text(get_corrupt).await, "timeline corruption\n");

        let head_corrupt = run(
            Method::HEAD,
            "/var/log/deletes".to_string(),
            raw_query(&corrupt_query),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            313,
        )
        .await;
        assert_eq!(head_corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(head_corrupt.headers(), &corrupt_headers);
        assert_eq!(response_text(head_corrupt).await, "");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pipeline_timeline_query_errors_are_closed_and_head_empty() {
        let (engine, dir) = test_engine_for_server("pipeline-timeline-query-errors");
        write_text_world_for_tests(&engine, "home/timeline/errors", "current").await;
        let state = server_state_for_engine_for_tests(engine);

        let get = run(
            Method::GET,
            "/home/timeline/errors".to_string(),
            raw_query("timeline-generation=abc"),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            303,
        )
        .await;
        assert_eq!(get.status(), StatusCode::BAD_REQUEST);

        let head = run(
            Method::HEAD,
            "/home/timeline/errors".to_string(),
            raw_query("timeline-generation=abc"),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            304,
        )
        .await;
        assert_eq!(head.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_text(head).await, "");

        let ordinary_field_cases = [
            "timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&\
             timeline-seq=1&timeline-body-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&x=1",
            "x=1&timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&\
             timeline-seq=1&timeline-body-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        for (idx, query) in ordinary_field_cases.into_iter().enumerate() {
            let fallthrough = run(
                Method::GET,
                "/home/timeline/errors".to_string(),
                raw_query(query),
                HeaderMap::new(),
                Bytes::new(),
                &state,
                314 + idx as u64,
            )
            .await;
            assert_eq!(fallthrough.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_text(fallthrough).await,
                "bad request: invalid timeline query: UnsupportedTimelineQueryField\n"
            );
        }

        let memory_engine = state.engine().clone();
        for (idx, prefix) in ["tmp", "dev", "sys"].into_iter().enumerate() {
            let world = format!("{prefix}/timeline/errors");
            write_text_world_for_tests(&memory_engine, &world, "memory-current").await;
            let memory = run(
                Method::GET,
                format!("/{world}"),
                raw_query(
                    "timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&\
                     timeline-seq=1&timeline-body-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ),
                HeaderMap::new(),
                Bytes::new(),
                &state,
                316 + idx as u64,
            )
            .await;
            assert_eq!(memory.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_text(memory).await,
                "bad request: invalid timeline query: InvalidTimelineCoordinate(MemoryWorld)\n"
            );
        }

        let huge = format!("{}x", "a=".repeat(4097));
        let resp = run(
            Method::GET,
            "/home/timeline/errors".to_string(),
            raw_query(&huge),
            HeaderMap::new(),
            Bytes::new(),
            &state,
            305,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::URI_TOO_LONG);

        let _ = std::fs::remove_dir_all(dir);
    }
}
