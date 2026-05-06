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
//!   `auth::Tier` and stamps it onto `Phase::Authenticated`. That is
//!   pure authentication — "who is asking".
//! - **Verb handlers** (lands in PR 4b for read, 4c for write) run the
//!   gate check (`can_read` / `can_write` / `can_delete`). That is
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
//! ## PR 4a scope
//!
//! This is the FSM **skeleton**: Phase enum, ErrorReason vocabulary,
//! TraceCtx, the driver loop, and transition functions through
//! `dispatch`. Verb handler integration (Phase::Dispatched →
//! ExecutedRead / CommittedWrite) lands in PR 4b (read path) and
//! PR 4c (write path). In 4a the Dispatched arm of the driver loop
//! returns a synthetic 501 so the loop terminates; no production
//! route in `main.rs` calls `run()` yet.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{auth, canonicalize_path, validate_world_name, Core};

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
        headers: HeaderMap,
        body: Bytes,
    },
    Authenticated {
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Bytes,
        tier: auth::Tier,
    },
    PathValidated {
        method: Method,
        headers: HeaderMap,
        body: Bytes,
        tier: auth::Tier,
        world: String,
    },
    Dispatched {
        verb: Verb,
        headers: HeaderMap,
        body: Bytes,
        tier: auth::Tier,
        world: String,
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
/// `#[allow(dead_code)]` covers variants that no caller emits yet
/// (4a only constructs `PathInvalid`, `MethodNotAllowed`, and
/// `Auth(AuthGate::Read)` in tests). The allow comes off in 4c when
/// verb handlers cover the rest.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ErrorReason {
    Auth(AuthGate),
    /// Path validation rejection. The inner `&'static str` carries
    /// the specific reason from `validate_world_name` (a closed set
    /// of literal strings defined in `path.rs`).
    PathInvalid(&'static str),
    MethodNotAllowed,
    NotFound,
    PreconditionFailed,
    PayloadTooLarge,
    QuotaExceeded,
    InsufficientStorage,
    StorageRead,
    StorageWriteAudit,
    AuditChainBroken,
}

/// `#[allow(dead_code)]` mirrors `ErrorReason` — only `Read` is
/// constructed in 4a tests; the rest land in 4b/4c verb handlers.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum AuthGate {
    Read,
    Write,
    WriteApprove,
    Delete,
}

// ─── Trace ───────────────────────────────────────────────────────

static PIPELINE_TRACE: AtomicBool = AtomicBool::new(false);

/// Read `ELASTIK_TRACE_PIPELINE` once and freeze the result for the
/// process lifetime. Called from `main()` after env is loaded. The
/// flag is process-global because per-request trace state would add
/// overhead even when the feature is off, and the use case here is
/// "running the binary with trace on for a debug session".
pub(crate) fn init_trace_from_env() {
    let enabled = matches!(
        std::env::var("ELASTIK_TRACE_PIPELINE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    );
    PIPELINE_TRACE.store(enabled, Ordering::Relaxed);
    if enabled {
        eprintln!("elastik-core: pipeline trace ENABLED via ELASTIK_TRACE_PIPELINE");
    }
}

/// Per-request trace context. Construct once at the top of `run()`,
/// pass through to verb handlers (in 4b/4c) so they can emit aux
/// lines for sub-steps. `enabled` is sampled once on construction
/// so a runtime toggle would only take effect for new requests
/// (acceptable for env-var gating; PR 5 adds a runtime-toggleable
/// `/etc/debug` world).
pub(crate) struct TraceCtx {
    req_id: u64,
    started: Instant,
    enabled: bool,
}

impl TraceCtx {
    pub(crate) fn new(req_id: u64, started: Instant) -> Self {
        Self {
            req_id,
            started,
            enabled: PIPELINE_TRACE.load(Ordering::Relaxed),
        }
    }

    /// Test-only no-op trace context. Always disabled. Used as a
    /// stand-in argument when calling `execute_*` handlers from
    /// unit tests in PR 4b/4c.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            req_id: 0,
            started: Instant::now(),
            enabled: false,
        }
    }

    /// Top-level phase transition. Called by the driver after each
    /// transition. Skipped for `Done` / `Error` because those have
    /// dedicated emit_done / emit_error formatters.
    pub(crate) fn emit_phase(&self, phase: &Phase) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[req-{:<3} +{:>7.3}ms] {}",
            self.req_id,
            elapsed_ms,
            phase_summary(phase)
        );
    }

    /// Indented sub-step emitted from inside a verb handler.
    /// Surfaces what is happening between Dispatched and
    /// ExecutedRead/CommittedWrite (lock acquisition, SQLite commits,
    /// audit appends, notify dispatch, quota reservations, ...).
    /// Currently unused — verb handlers wire these up in 4b/4c.
    #[allow(dead_code)]
    pub(crate) fn emit_aux(&self, label: &str) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[req-{:<3} +{:>7.3}ms]   aux            {}",
            self.req_id, elapsed_ms, label
        );
    }

    /// Same as `emit_aux` but with a key=value tail.
    /// Currently unused — verb handlers wire these up in 4b/4c.
    #[allow(dead_code)]
    pub(crate) fn emit_aux_kv(&self, label: &str, kv: &str) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[req-{:<3} +{:>7.3}ms]   aux            {} {}",
            self.req_id, elapsed_ms, label, kv
        );
    }

    /// Terminal Done line with total elapsed.
    fn emit_done(&self, resp: &Response) {
        if !self.enabled {
            return;
        }
        let total_ms = self.started.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[req-{:<3} +{:>7.3}ms] Done           status={} total={:.3}ms",
            self.req_id,
            total_ms,
            resp.status(),
            total_ms
        );
    }

    /// Terminal Error line with status + structured reason.
    fn emit_error(&self, reason: &ErrorReason, status: StatusCode) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[req-{:<3} +{:>7.3}ms] Error          status={} reason={:?}",
            self.req_id, elapsed_ms, status, reason
        );
    }
}

fn phase_summary(p: &Phase) -> String {
    match p {
        Phase::Received {
            method, path, body, ..
        } => format!("Received       {method} {path} {}B", body.len()),
        Phase::Authenticated { tier, .. } => format!("Authenticated  tier={tier:?}"),
        Phase::PathValidated { world, .. } => format!("PathValidated  world={world}"),
        Phase::Dispatched { verb, .. } => format!("Dispatched     verb={verb:?}"),
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
    headers: HeaderMap,
    body: Bytes,
    tokens: &auth::Tokens,
) -> Phase {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = tokens.check(auth_header);
    Phase::Authenticated {
        method,
        path,
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
    headers: HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Phase {
    let world = canonicalize_path(&path);
    if let Err(reason) = validate_world_name(&world) {
        return Phase::Error {
            resp: crate::bad_request(reason),
            reason: ErrorReason::PathInvalid(reason),
        };
    }
    Phase::PathValidated {
        method,
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
    tier: auth::Tier,
    world: String,
) -> Phase {
    let verb = match method {
        Method::GET => Verb::Get,
        Method::HEAD => Verb::Head,
        Method::PUT => Verb::Put,
        Method::POST => Verb::Post,
        Method::DELETE => Verb::Delete,
        _ => {
            return Phase::Error {
                resp: method_not_allowed_response(),
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
/// **PR 4a scope**: the `Phase::Dispatched` arm is a stub that
/// returns a 501. PR 4b replaces it with a call to
/// `handler::execute(verb, ...)` for read verbs; PR 4c covers the
/// write verbs. Until then, no route in `main.rs` calls this
/// function — it exists so that the FSM can be exercised in unit
/// tests.
#[allow(dead_code)]
pub(crate) async fn run(
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    core: &Arc<Core>,
) -> Response {
    let req_id = core.next_request.fetch_add(1, Ordering::Relaxed);
    let trace = TraceCtx::new(req_id, Instant::now());

    let mut phase = Phase::Received {
        method,
        path,
        headers,
        body,
    };
    trace.emit_phase(&phase);

    loop {
        phase = match phase {
            Phase::Received {
                method,
                path,
                headers,
                body,
            } => authenticate(method, path, headers, body, &core.tokens),

            Phase::Authenticated {
                method,
                path,
                headers,
                body,
                tier,
            } => validate_path(method, path, headers, body, tier),

            Phase::PathValidated {
                method,
                headers,
                body,
                tier,
                world,
            } => dispatch(method, headers, body, tier, world),

            Phase::Dispatched { verb, .. } => {
                // PR 4a stub. PR 4b wires read verbs (Get / Head);
                // PR 4c wires write verbs (Put / Post / Delete).
                // Until then this synthetic 501 keeps the loop
                // closed so end-to-end tests for the FSM up to
                // Dispatched can run.
                Phase::Error {
                    resp: not_yet_wired_response(verb),
                    reason: ErrorReason::MethodNotAllowed,
                }
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

fn method_not_allowed_response() -> Response {
    let allow = "GET, HEAD, PUT, POST, DELETE, OPTIONS";
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::ALLOW, allow),
        ],
        "method not allowed\n",
    )
        .into_response()
}

fn not_yet_wired_response(verb: Verb) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("pipeline 4a: verb {verb:?} dispatch not yet wired (PR 4b/4c)\n"),
    )
        .into_response()
}

// ─── Tests ───────────────────────────────────────────────────────
//
// 4a tests cover individual transition functions and the trace API.
// End-to-end driver tests (Phase::Received all the way through to a
// real handler response) come in 4b once `handler::execute` exists
// and `Core` can be constructed in a shared test-support module.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tokens;
    use axum::http::HeaderValue;

    fn empty_tokens() -> Tokens {
        Tokens {
            read: None,
            write: None,
            approve: None,
        }
    }

    fn tokens_with_write(write: &[u8]) -> Tokens {
        Tokens {
            read: None,
            write: Some(write.to_vec()),
            approve: None,
        }
    }

    fn header_map_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    // ── authenticate ───────────────────────────────────────────

    #[test]
    fn authenticate_no_auth_header_yields_anon_tier() {
        let phase = authenticate(
            Method::GET,
            "/home/foo".into(),
            HeaderMap::new(),
            Bytes::new(),
            &empty_tokens(),
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, auth::Tier::Anon),
            _ => panic!("expected Authenticated phase"),
        }
    }

    #[test]
    fn authenticate_valid_bearer_yields_write_tier() {
        let tokens = tokens_with_write(b"writer");
        let phase = authenticate(
            Method::PUT,
            "/home/foo".into(),
            header_map_with_auth("Bearer writer"),
            Bytes::from_static(b"hi"),
            &tokens,
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, auth::Tier::Write),
            _ => panic!("expected Authenticated phase"),
        }
    }

    #[test]
    fn authenticate_unrecognized_token_falls_back_to_anon() {
        let tokens = tokens_with_write(b"writer");
        let phase = authenticate(
            Method::PUT,
            "/home/foo".into(),
            header_map_with_auth("Bearer wrong"),
            Bytes::new(),
            &tokens,
        );
        match phase {
            Phase::Authenticated { tier, .. } => assert_eq!(tier, auth::Tier::Anon),
            _ => panic!("expected Authenticated phase"),
        }
    }

    // ── validate_path ──────────────────────────────────────────

    #[test]
    fn validate_path_canonicalizes_bare_to_home_namespace() {
        let phase = validate_path(
            Method::GET,
            "/foo".into(),
            HeaderMap::new(),
            Bytes::new(),
            auth::Tier::Anon,
        );
        match phase {
            Phase::PathValidated { world, .. } => assert_eq!(world, "home/foo"),
            _ => panic!("expected PathValidated"),
        }
    }

    #[test]
    fn validate_path_keeps_explicit_namespaces() {
        let phase = validate_path(
            Method::GET,
            "/etc/foo".into(),
            HeaderMap::new(),
            Bytes::new(),
            auth::Tier::Approve,
        );
        match phase {
            Phase::PathValidated { world, .. } => assert_eq!(world, "etc/foo"),
            _ => panic!("expected PathValidated"),
        }
    }

    #[test]
    fn validate_path_rejects_dot_segments_with_pathinvalid() {
        let phase = validate_path(
            Method::PUT,
            "/home/../etc/secret".into(),
            HeaderMap::new(),
            Bytes::new(),
            auth::Tier::Write,
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
            HeaderMap::new(),
            Bytes::new(),
            auth::Tier::Write,
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
            HeaderMap::new(),
            Bytes::new(),
            auth::Tier::Read,
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
            auth::Tier::Anon,
            "home/foo".into(),
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
            auth::Tier::Write,
            "home/foo".into(),
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
                auth::Tier::Anon,
                "home/x".into(),
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
        assert!(!PIPELINE_TRACE.load(Ordering::Relaxed));
        // Restore.
        if let Some(v) = prior {
            std::env::set_var("ELASTIK_TRACE_PIPELINE", v);
        }
        // Re-init so subsequent tests see the original state.
        init_trace_from_env();
    }
}
