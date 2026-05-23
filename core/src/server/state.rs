//! Server-owned adapter state.
//!
//! `ServerState` is the bin/adapter-side handle that axum routes receive.
//! During the PR5 transition it can still yield an `Arc<Core>` substate for
//! legacy handlers, but request ids and the Engine lifecycle now live outside
//! storage internals.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    extract::FromRef,
    http::{header, HeaderMap},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{engine::Engine, engine_types::AccessTier, Core};

const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub(crate) struct ServerState {
    engine: Engine,
    max_world_bytes: usize,
    next_request: Arc<AtomicUsize>,
}

impl ServerState {
    pub(crate) fn new(engine: Engine, max_world_bytes: usize) -> Self {
        Self {
            engine,
            max_world_bytes,
            next_request: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    /// Test-only bypass: wraps a raw `Core` into `ServerState` via
    /// `Engine::from_core_for_tests`. See its doc for bypass details.
    pub(crate) fn from_core_for_tests(core: Arc<Core>, max_world_bytes: usize) -> Self {
        Self::new(Engine::from_core_for_tests(core), max_world_bytes)
    }

    /// Returns the protocol-neutral Engine for handlers that have migrated
    /// away from the legacy `Arc<Core>` extraction path.
    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    pub(crate) fn core_arc(&self) -> Arc<Core> {
        self.engine.core_arc()
    }

    pub(crate) fn max_world_bytes(&self) -> usize {
        self.max_world_bytes
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

impl FromRef<ServerState> for Arc<Core> {
    fn from_ref(input: &ServerState) -> Self {
        input.core_arc()
    }
}
