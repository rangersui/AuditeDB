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

use axum::extract::FromRef;

use crate::{engine::Engine, Core};

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
    pub(crate) fn from_core_for_tests(core: Arc<Core>, max_world_bytes: usize) -> Self {
        Self::new(Engine::from_core_for_tests(core), max_world_bytes)
    }

    #[allow(dead_code)]
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
}

impl FromRef<ServerState> for Arc<Core> {
    fn from_ref(input: &ServerState) -> Self {
        input.core_arc()
    }
}
