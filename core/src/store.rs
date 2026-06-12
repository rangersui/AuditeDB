//! Store routing — one core, one port, prefix decides the backend.
//!
//! ```text
//!     /home/* /etc/* /lib/* /boot/* /usr/* /var/*  → SQLite (durable)
//!     /tmp/*  /dev/*  /sys/*                       → memory (transient)
//!
//! ```
//!
//! `MemoryStore` is a small Redis-shaped substrate that keeps the
//! elastik shape: the path prefix selects the backend without changing
//! the higher-level storage model. Useful for agent scratchpads, transient queues,
//! latest-state caches, and framebuffers. `/listen/*` reports changes
//! as control-plane events, but the memory backend itself only stores
//! latest bytes and metadata.
//!
//! Audit/HMAC chain only fires on durable writes — memory worlds are
//! by definition not tamper-evident across restarts.

use crate::world::{self, AppendResult, Stage, WorldMetadata};
use std::collections::HashMap;
#[cfg(test)]
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
    body_hash: String,
    content_type: String,
    headers: Vec<(String, String)>,
}

#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, MemEntry>>,
}

/// Returned by `write_with_quota` / `append_with_quota` when the requested
/// write would push the total memory store size past `max_total_bytes`.
/// The check happens under the same mutex as the write so concurrent
/// writers cannot both pass a stale snapshot and then both commit
/// (durable quota is reserved before SQLite write transactions).
pub struct MemoryQuotaError {
    /// Pre-write total bytes across all memory worlds. Currently the
    /// callers only need `quota` for payload-cap mapping, but `used` and
    /// `projected` are populated for diagnostic clarity.
    #[allow(dead_code)]
    pub used: usize,
    pub quota: usize,
    #[allow(dead_code)]
    pub projected: usize,
}

/// Outcome of a successful `write_with_quota`.
pub struct MemoryWriteOutcome {
    /// True if the world existed before this write.
    pub existed: bool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read body + metadata only, without the body hash. Currently unused
    /// since `read_with_hash` covers all internal callers, but kept as a
    /// convenience wrapper for future external SDK code.
    #[allow(dead_code)]
    pub fn read(&self, world: &str) -> Option<Stage> {
        self.read_with_hash(world).map(|(stage, _)| stage)
    }

    pub fn read_with_hash(&self, world: &str) -> Option<(Stage, String)> {
        let map = self.map_guard();
        let e = map.get(world)?;
        Some((
            Stage {
                body: e.body.clone(),
                content_type: e.content_type.clone(),
                headers: e.headers.clone(),
            },
            e.body_hash.clone(),
        ))
    }

    pub fn metadata(&self, world: &str) -> Option<WorldMetadata> {
        let map = self.map_guard();
        let e = map.get(world)?;
        Some((e.body.len(), e.content_type.clone(), e.headers.clone()))
    }

    pub fn contains(&self, world: &str) -> bool {
        self.map_guard().contains_key(world)
    }

    /// Unconditional write without quota enforcement. Used only by the
    /// test-only `Core::write_world` fixture; production goes through
    /// `write_with_quota`. Kept as `#[allow(dead_code)]` so the test
    /// helper survives future production-only clippy passes.
    #[allow(dead_code)]
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
        e.body_hash = world::sha256_hex(body);
        e.content_type = content_type.to_string();
        e.headers = headers.to_vec();
    }

    /// Append without quota enforcement. Replaced in production by
    /// `append_with_quota`; kept available with `#[allow(dead_code)]`
    /// for future tooling that wants the raw primitive (e.g. tests
    /// asserting growth behavior).
    #[allow(dead_code)]
    pub fn append(&self, world: &str, body: &[u8]) -> Option<AppendResult> {
        let mut map = self.map_guard();
        let e = map.get_mut(world)?;
        e.body.extend_from_slice(body);
        let after = world::sha256_hex(&e.body);
        e.body_hash = after.clone();
        Some(AppendResult {
            body_sha256_after: after,
            cas_body_inserted: false,
        })
    }

    /// Write a memory world with an atomic quota check. The HashMap mutex
    /// is held across "compute current total -> compare against quota ->
    /// insert", so two concurrent writes to different memory worlds
    /// cannot both observe usage below the cap and both commit. Replaces
    /// the old split read/check/write sequence, which was race-prone
    /// after the global write_lock was removed.
    ///
    /// Returns `Ok(outcome)` with `existed` populated for the caller's
    /// 200 vs 201 decision; `Err(MemoryQuotaError)` if accepting the
    /// write would push the total memory store size past
    /// `max_total_bytes`.
    pub fn write_with_quota(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
        max_total_bytes: usize,
    ) -> Result<MemoryWriteOutcome, MemoryQuotaError> {
        let mut map = self.map_guard();
        let used: usize = map.values().map(|entry| entry.body.len()).sum();
        let prev_len = map.get(world).map(|entry| entry.body.len()).unwrap_or(0);
        let projected = used.saturating_sub(prev_len).saturating_add(body.len());
        if projected > max_total_bytes {
            return Err(MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected,
            });
        }
        let existed = map.contains_key(world);
        let e = map.entry(world.to_string()).or_default();
        e.body = body.to_vec();
        e.body_hash = world::sha256_hex(body);
        e.content_type = content_type.to_string();
        e.headers = headers.to_vec();
        Ok(MemoryWriteOutcome { existed })
    }

    /// Append to a memory world with an atomic quota check. Returns
    /// `Ok(None)` if the world does not exist (caller maps to 404).
    /// `Err(MemoryQuotaError)` if accepting the append would push the
    /// total memory store size past `max_total_bytes`. Otherwise
    /// `Ok(Some(result))` with the post-append SHA-256 of the body.
    pub fn append_with_quota(
        &self,
        world: &str,
        body: &[u8],
        max_total_bytes: usize,
    ) -> Result<Option<AppendResult>, MemoryQuotaError> {
        let mut map = self.map_guard();
        let used: usize = map.values().map(|entry| entry.body.len()).sum();
        let projected = used.saturating_add(body.len());
        if projected > max_total_bytes {
            return Err(MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected,
            });
        }
        let Some(entry) = map.get_mut(world) else {
            return Ok(None);
        };
        entry.body.extend_from_slice(body);
        let after = world::sha256_hex(&entry.body);
        entry.body_hash = after.clone();
        Ok(Some(AppendResult {
            body_sha256_after: after,
            cas_body_inserted: false,
        }))
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

    pub fn list_with_prefix(&self, prefix: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .map_guard()
            .keys()
            .filter(|world| world.starts_with(prefix))
            .cloned()
            .collect();
        out.sort();
        out
    }

    pub fn list_with_prefix_bounded(&self, prefix: &str, max: usize) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for world in self
            .map_guard()
            .keys()
            .filter(|world| world.starts_with(prefix))
        {
            if out.len() >= max {
                return None;
            }
            out.push(world.clone());
        }
        out.sort();
        Some(out)
    }

    pub fn total_bytes(&self) -> usize {
        self.map_guard()
            .values()
            .map(|entry| entry.body.len())
            .sum()
    }

    pub fn sizes(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = self
            .map_guard()
            .iter()
            .map(|(world, entry)| (world.clone(), entry.body.len()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn map_guard(&self) -> MutexGuard<'_, HashMap<String, MemEntry>> {
        self.map.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Combined view: sqlite + memory. Used by tests that assert both stores agree.
#[cfg(test)]
pub fn list_all(data_root: &Path, mem: &MemoryStore) -> rusqlite::Result<Vec<String>> {
    let mut out = world::list(data_root)?;
    out.extend(mem.list());
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit, test_support::test_core};

    #[test]
    fn worlds_store_content_type_not_private_extensions() {
        let (core, dir) = test_core("content-type");
        core.write_world("home/pdf", b"%PDF-1.7", "application/pdf", &[])
            .unwrap();

        let stage = core.read_world("home/pdf").unwrap().unwrap();
        assert_eq!(stage.content_type, "application/pdf");
        assert_eq!(stage.body, b"%PDF-1.7");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn storage_prefix_routes_memory_and_disk_modes() {
        assert!(!is_memory_world("home/report"));
        assert!(!is_memory_world("etc/config"));
        assert!(is_memory_world("tmp/scratch"));
        assert!(is_memory_world("dev/fb0"));
        assert!(is_memory_world("sys/status"));
        assert!(is_persistent("home/report"));
        assert!(!is_persistent("tmp/scratch"));
    }

    #[test]
    fn memory_worlds_do_not_create_sqlite_files_or_audit_chain() {
        let (core, dir) = test_core("memory-world");
        core.write_world(
            "tmp/scratch",
            b"draft",
            "text/plain; charset=utf-8",
            &[("x-meta-owner".to_string(), "agent".to_string())],
        )
        .unwrap();

        let stage = core.read_world("tmp/scratch").unwrap().unwrap();
        assert_eq!(stage.body, b"draft");
        assert_eq!(stage.content_type, "text/plain; charset=utf-8");
        assert_eq!(
            stage.headers,
            vec![("x-meta-owner".to_string(), "agent".to_string())]
        );
        assert!(!world::world_db(&core.data, "tmp/scratch").exists());
        assert!(audit::latest_hmac(&core.data, "tmp/scratch").is_none());

        let names = list_all(&core.data, &core.mem);
        assert_eq!(names.unwrap(), vec!["tmp/scratch".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disk_worlds_create_sqlite_files_and_audit_chain_when_using_audit_path() {
        let (core, dir) = test_core("disk-world");
        let h = world::write_with_audit(
            &core.data,
            "home/report",
            b"final",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let stage = core.read_world("home/report").unwrap().unwrap();
        assert_eq!(stage.body, b"final");
        assert!(world::world_db(&core.data, "home/report").exists());
        assert_eq!(audit::latest_hmac(&core.data, "home/report"), Some(h));

        let names = list_all(&core.data, &core.mem);
        assert_eq!(names.unwrap(), vec!["home/report".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }
}
