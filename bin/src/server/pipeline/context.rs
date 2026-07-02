use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use axum::{
    http::{StatusCode, Uri},
    response::Response,
};
use elastik_core::ValidatedWorldPath;

use super::{phase_summary, ErrorReason, Phase};

/// Request ID stamped onto each incoming request by the
/// `add_server_response_headers` middleware in `server/middleware.rs` and threaded
/// through axum's request extensions so the pipeline driver and the
/// `x-request-id` response header are guaranteed to use the same
/// number. Without this, two independent request-id allocations
/// (one in the middleware, one in `pipeline::run`) produced
/// off-by-one ids: trace said `req-43` while the response header
/// said `42`.
#[derive(Clone, Copy)]
pub(crate) struct RequestId(pub(crate) u64);

#[derive(Clone)]
pub(crate) struct RawQuery(Option<String>);

impl RawQuery {
    pub(crate) fn from_uri(uri: &Uri) -> Self {
        Self(uri.query().map(str::to_owned))
    }

    pub(crate) fn classify_timeline_mode(
        &self,
        world: &ValidatedWorldPath,
    ) -> Result<super::query::TimelineRequestMode, super::query::TimelineQueryError> {
        super::query::classify_raw_query(self.0.as_deref(), world)
    }

    #[cfg(test)]
    pub(crate) fn absent() -> Self {
        Self(None)
    }

    #[cfg(test)]
    pub(crate) fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

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

#[cfg(test)]
pub(crate) fn trace_enabled_for_tests() -> bool {
    PIPELINE_TRACE.load(Ordering::Relaxed)
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
    pub(crate) fn new(req_id: u64) -> Self {
        Self {
            req_id,
            started: Instant::now(),
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
    pub(super) fn emit_done(&self, resp: &Response) {
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
    pub(super) fn emit_error(&self, reason: &ErrorReason, status: StatusCode) {
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
