//! Protocol-neutral sizing defaults shared by the engine and server adapter.

/// Default maximum payload size for one world: 64 MiB.
///
/// Override with [`crate::EngineBuilder::max_world_bytes`]. This limit applies
/// to the stored body bytes of a single world, not to SQLite file size,
/// metadata, WAL bytes, or audit rows.
pub const DEFAULT_MAX_WORLD_BYTES: usize = 64 * 1024 * 1024;

/// Default total in-memory backend quota: 256 MiB.
///
/// Override with [`crate::EngineBuilder::max_memory_bytes`]. This limit charges
/// body bytes plus key, metadata, hash, and fixed entry overhead for transient
/// `tmp/`, `dev/`, and `sys/` worlds.
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Default per-subscription replay ring depth: 1024 events.
///
/// Override with [`crate::EngineBuilder::listen_replay_max`]. A resumed
/// subscription whose `since` value is older than this ring can receive
/// [`crate::SubscriptionRecvError::Lagged`].
pub const DEFAULT_LISTEN_REPLAY_MAX: usize = 1024;

/// Default maximum number of simultaneous subscriptions: 1024.
///
/// Override with [`crate::EngineBuilder::max_listen_connections`]. Each live
/// [`crate::EngineSubscription`] holds one slot until dropped.
pub const DEFAULT_MAX_LISTEN_CONNECTIONS: usize = 1024;

/// Default maximum read-cache entries: 5000 worlds.
///
/// Override with [`crate::EngineBuilder::read_cache_max_entries`]. This caps
/// tracked read-cache slots for durable worlds; it is not a limit on the
/// number of worlds stored on disk.
pub const DEFAULT_READ_CACHE_MAX_ENTRIES: usize = 5000;

/// Default retained historical body snapshots per durable world.
///
/// Override with [`crate::EngineBuilder::retained_body_count`]. This limits
/// retained CAS body blobs only; audit rows remain permanent. Older rows may
/// still dereference when they share identical bytes with a retained newer row.
pub const DEFAULT_RETAINED_BODY_COUNT: usize = 1024;

/// Maximum retained historical body snapshots per durable world.
///
/// This caps verification/startup memory: retained CAS indexes are built in
/// process memory while checking a world's audit chain.
pub const MAX_RETAINED_BODY_COUNT: usize = 65_536;
