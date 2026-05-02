//! Store routing — one core, one port, prefix decides the backend.
//!
//!     /home/* /etc/* /lib/* /boot/* /usr/*  → SQLite (durable)
//!     /tmp/*  /dev/*  /sys/*                → memory (transient)
//!
//! `MemoryStore` is a small Redis-shaped substrate that keeps the
//! elastik shape: same port, same HTTP, only the path prefix changes
//! the backend. Useful for agent scratchpads, transient queues,
//! latest-state caches, and framebuffers. `/listen/*` reports changes
//! as control-plane events, but the memory backend itself only stores
//! latest bytes and metadata.
//!
//! Audit/HMAC chain only fires on durable writes — memory worlds are
//! by definition not tamper-evident across restarts.

use crate::world::{self, AppendResult, Stage};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub fn is_memory_world(world: &str) -> bool {
    world.starts_with("tmp/") || world.starts_with("dev/") || world.starts_with("sys/")
}

/// True if writes to this world should append a row to the HMAC
/// audit chain. Memory worlds opt out (they don't survive restart).
pub fn is_persistent(world: &str) -> bool {
    !is_memory_world(world)
}

#[derive(Default)]
struct MemEntry {
    body: Vec<u8>,
    content_type: String,
    headers: Vec<(String, String)>,
}

#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, MemEntry>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, world: &str) -> Option<Stage> {
        let map = self.map_guard();
        let e = map.get(world)?;
        Some(Stage {
            body: e.body.clone(),
            content_type: e.content_type.clone(),
            headers: e.headers.clone(),
        })
    }

    pub fn contains(&self, world: &str) -> bool {
        self.map_guard().contains_key(world)
    }

    pub fn write(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) {
        let mut map = self.map_guard();
        let e = map.entry(world.to_string()).or_default();
        e.body = body.to_vec();
        e.content_type = content_type.to_string();
        e.headers = headers.to_vec();
    }

    pub fn append(&self, world: &str, body: &[u8]) -> Option<AppendResult> {
        let mut map = self.map_guard();
        let e = map.get_mut(world)?;
        e.body.extend_from_slice(body);
        let after = world::sha256_hex(&e.body);
        Some(AppendResult {
            body_sha256_after: after,
        })
    }

    pub fn delete(&self, world: &str) -> bool {
        let mut map = self.map_guard();
        map.remove(world).is_some()
    }

    pub fn list(&self) -> Vec<String> {
        let mut out: Vec<String> = self.map_guard().keys().cloned().collect();
        out.sort();
        out
    }

    pub fn total_bytes(&self) -> usize {
        self.map_guard()
            .values()
            .map(|entry| entry.body.len())
            .sum()
    }

    fn map_guard(&self) -> MutexGuard<'_, HashMap<String, MemEntry>> {
        self.map.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Combined view: sqlite + memory. Used by /proc/worlds.
pub fn list_all(data_root: &Path, mem: &MemoryStore) -> Vec<String> {
    let mut out = world::list(data_root);
    out.extend(mem.list());
    out.sort();
    out.dedup();
    out
}
