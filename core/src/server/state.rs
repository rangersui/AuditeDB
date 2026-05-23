//! Server-owned adapter state.
//!
//! `ServerState` is the bin/adapter-side handle that axum routes receive.
//! Request ids, HTTP header persistence policy, and the Engine lifecycle live
//! here rather than in storage internals.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[cfg(test)]
use crate::Core;
use crate::{engine::Engine, engine_types::AccessTier, http_semantics::HeaderAllowlist};

const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub(crate) struct ServerState {
    engine: Engine,
    max_world_bytes: usize,
    persist_header_allowlist: Arc<HeaderAllowlist>,
    persist_header_user_deny: Arc<HeaderAllowlist>,
    next_request: Arc<AtomicUsize>,
}

impl ServerState {
    pub(crate) fn new(
        engine: Engine,
        max_world_bytes: usize,
        persist_header_allowlist: HeaderAllowlist,
        persist_header_user_deny: HeaderAllowlist,
    ) -> Self {
        Self {
            engine,
            max_world_bytes,
            persist_header_allowlist: Arc::new(persist_header_allowlist),
            persist_header_user_deny: Arc::new(persist_header_user_deny),
            next_request: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    /// Test-only bypass: wraps a raw `Core` into `ServerState` via
    /// `Engine::from_core_for_tests`. See its doc for bypass details.
    pub(crate) fn from_core_for_tests(core: Arc<Core>, max_world_bytes: usize) -> Self {
        Self::new(
            Engine::from_core_for_tests(core),
            max_world_bytes,
            HeaderAllowlist::empty(),
            HeaderAllowlist::empty(),
        )
    }

    /// Returns the protocol-neutral Engine used by server adapters.
    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    pub(crate) fn max_world_bytes(&self) -> usize {
        self.max_world_bytes
    }

    pub(crate) fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        self.persist_header_allowlist.clone()
    }

    pub(crate) fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        self.persist_header_user_deny.clone()
    }

    pub(crate) fn next_request_id(&self) -> u64 {
        (self.next_request.fetch_add(1, Ordering::Relaxed) + 1) as u64
    }

    pub(crate) fn access_tier_from_headers(&self, headers: &HeaderMap) -> AccessTier {
        let Some(value) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return AccessTier::Anon;
        };
        if value.len() > MAX_AUTHORIZATION_BYTES {
            return AccessTier::Anon;
        }
        let Some((scheme, credentials)) = value.split_once(char::is_whitespace) else {
            return AccessTier::Anon;
        };
        let credentials = credentials.trim();
        if scheme.eq_ignore_ascii_case("Bearer") {
            return self.engine.verify_token(credentials.as_bytes());
        }
        if scheme.eq_ignore_ascii_case("Basic") {
            if let Ok(decoded) = B64.decode(credentials) {
                if let Some(idx) = decoded.iter().position(|&byte| byte == b':') {
                    return self.engine.verify_token(&decoded[idx + 1..]);
                }
            }
        }
        AccessTier::Anon
    }
}
