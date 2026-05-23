//! Protocol-neutral sizing defaults shared by the engine and server adapter.

pub(crate) const DEFAULT_MAX_WORLD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const DEFAULT_LISTEN_REPLAY_MAX: usize = 1024;
pub(crate) const DEFAULT_MAX_LISTEN_CONNECTIONS: usize = 1024;
#[allow(dead_code)]
pub(crate) const DEFAULT_COAP_MAX_IN_FLIGHT: usize = 1024;
pub(crate) const DEFAULT_READ_CACHE_MAX_ENTRIES: usize = 5000;
