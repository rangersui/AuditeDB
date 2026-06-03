use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex as StdMutex};

use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Semaphore};

use crate::{
    auth,
    defaults::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES,
    },
    store, Core,
};

pub(crate) fn test_core(label: &str) -> (Core, PathBuf) {
    test_core_with_read_cache_max(label, crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES)
}

pub(crate) fn test_core_with_read_cache_max(
    label: &str,
    read_cache_max_entries: usize,
) -> (Core, PathBuf) {
    let mut dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.push(format!(
        "elastik-core-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (
        {
            let (events, _) = broadcast::channel(16);
            Core {
                data: dir.clone(),
                tokens: auth::Tokens {
                    read: None,
                    write: None,
                    approve: None,
                },
                hmac_key: b"test-key".to_vec(),
                mem: Arc::new(store::MemoryStore::new()),
                max_world_bytes: DEFAULT_MAX_WORLD_BYTES,
                max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                max_storage_bytes: None,
                storage_body_bytes: Arc::new(AtomicUsize::new(0)),
                durable_world_count: Arc::new(AtomicUsize::new(0)),
                delete_ledger_created: Arc::new(AtomicBool::new(false)),
                events,
                listen_slots: Arc::new(Semaphore::new(DEFAULT_MAX_LISTEN_CONNECTIONS)),
                listen_replay_max: DEFAULT_LISTEN_REPLAY_MAX,
                event_log: Arc::new(StdMutex::new(VecDeque::with_capacity(
                    DEFAULT_LISTEN_REPLAY_MAX,
                ))),
                shutdown: watch::channel(false).1,
                next_event: crate::state::new_event_counter(),
                world_locks: Arc::new(DashMap::new()),
                ledger: Arc::new(crate::ledger::LedgerWriter::new()),
                read_cache: Arc::new(crate::read_cache::ReadCache::new(read_cache_max_entries)),
            }
        },
        dir,
    )
}
