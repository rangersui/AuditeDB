//! Protocol-neutral sizing defaults shared by the engine and server adapter.

pub const DEFAULT_MAX_WORLD_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_LISTEN_REPLAY_MAX: usize = 1024;
pub const DEFAULT_MAX_LISTEN_CONNECTIONS: usize = 1024;
pub const DEFAULT_READ_CACHE_MAX_ENTRIES: usize = 5000;
