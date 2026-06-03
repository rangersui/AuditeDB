use std::sync::Arc;

use crate::{
    defaults::DEFAULT_MAX_WORLD_BYTES,
    engine::Engine,
    server::{http::semantics::HeaderAllowlist, ServerState},
    Core,
};

pub(crate) fn server_state_for_tests(core: Arc<Core>) -> ServerState {
    server_state_with_max_world_bytes_for_tests(core, DEFAULT_MAX_WORLD_BYTES)
}

pub(crate) fn server_state_with_max_world_bytes_for_tests(
    core: Arc<Core>,
    max_world_bytes: usize,
) -> ServerState {
    ServerState::new(
        Engine::from_core_for_tests(core),
        max_world_bytes,
        HeaderAllowlist::empty(),
        HeaderAllowlist::empty(),
    )
}
