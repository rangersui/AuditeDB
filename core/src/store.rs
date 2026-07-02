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

use crate::{
    engine_types::{ValidatedWorldPath, ValidatedWorldPrefix},
    world::{self, AppendResult, Stage, WorldMetadata},
};
use std::collections::HashMap;
#[cfg(test)]
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

fn has_memory_prefix(world: &str) -> bool {
    world.starts_with("tmp/") || world.starts_with("dev/") || world.starts_with("sys/")
}

pub(crate) struct MemoryWorldPath<'a>(&'a ValidatedWorldPath);

impl<'a> MemoryWorldPath<'a> {
    pub(crate) fn new(world: &'a ValidatedWorldPath) -> Option<Self> {
        is_memory_world(world).then_some(Self(world))
    }

    fn as_path(&self) -> &ValidatedWorldPath {
        self.0
    }
}

pub fn is_memory_world(world: &ValidatedWorldPath) -> bool {
    has_memory_prefix(world.as_str())
}

/// True if writes to this world should append a row to the HMAC
/// audit chain. Memory worlds opt out (they don't survive restart).
pub fn is_persistent(world: &ValidatedWorldPath) -> bool {
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
    map: Mutex<HashMap<ValidatedWorldPath, MemEntry>>,
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
    /// convenience wrapper for future internal tooling.
    #[allow(dead_code)]
    pub fn read(&self, world: MemoryWorldPath<'_>) -> Option<Stage> {
        self.read_with_hash(world).map(|(stage, _)| stage)
    }

    pub fn read_with_hash(&self, world: MemoryWorldPath<'_>) -> Option<(Stage, String)> {
        let map = self.map_guard();
        let e = map.get(world.as_path())?;
        Some((
            Stage {
                body: e.body.clone(),
                content_type: e.content_type.clone(),
                headers: e.headers.clone(),
            },
            e.body_hash.clone(),
        ))
    }

    pub fn metadata(&self, world: MemoryWorldPath<'_>) -> Option<WorldMetadata> {
        let map = self.map_guard();
        let e = map.get(world.as_path())?;
        Some((e.body.len(), e.content_type.clone(), e.headers.clone()))
    }

    pub fn contains(&self, world: MemoryWorldPath<'_>) -> bool {
        self.map_guard().contains_key(world.as_path())
    }

    /// Unconditional write without quota enforcement. Used only by the
    /// test-only `Core::write_world` fixture; production goes through
    /// `write_with_quota`. Kept as `#[allow(dead_code)]` so the test
    /// helper survives future production-only clippy passes.
    #[allow(dead_code)]
    pub fn write(
        &self,
        world: MemoryWorldPath<'_>,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) {
        let mut map = self.map_guard();
        let e = map.entry(world.as_path().clone()).or_default();
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
    pub fn append(&self, world: MemoryWorldPath<'_>, body: &[u8]) -> Option<AppendResult> {
        let mut map = self.map_guard();
        let e = map.get_mut(world.as_path())?;
        e.body.extend_from_slice(body);
        let after = world::sha256_hex(&e.body);
        e.body_hash = after.clone();
        Some(AppendResult {
            body_sha256_after: after,
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
        world: MemoryWorldPath<'_>,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
        max_total_bytes: usize,
    ) -> Result<MemoryWriteOutcome, MemoryQuotaError> {
        let mut map = self.map_guard();
        let used: usize = map.values().map(|entry| entry.body.len()).sum();
        let prev_len = map
            .get(world.as_path())
            .map(|entry| entry.body.len())
            .unwrap_or(0);
        let projected = used.saturating_sub(prev_len).saturating_add(body.len());
        if projected > max_total_bytes {
            return Err(MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected,
            });
        }
        let existed = map.contains_key(world.as_path());
        let e = map.entry(world.as_path().clone()).or_default();
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
        world: MemoryWorldPath<'_>,
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
        let Some(entry) = map.get_mut(world.as_path()) else {
            return Ok(None);
        };
        entry.body.extend_from_slice(body);
        let after = world::sha256_hex(&entry.body);
        entry.body_hash = after.clone();
        Ok(Some(AppendResult {
            body_sha256_after: after,
        }))
    }

    pub fn delete(&self, world: MemoryWorldPath<'_>) -> bool {
        let mut map = self.map_guard();
        map.remove(world.as_path()).is_some()
    }

    pub fn list(&self) -> Vec<ValidatedWorldPath> {
        let mut out: Vec<ValidatedWorldPath> = self.map_guard().keys().cloned().collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    pub fn list_with_prefix(&self, prefix: &ValidatedWorldPrefix) -> Vec<ValidatedWorldPath> {
        let mut out: Vec<ValidatedWorldPath> = self
            .map_guard()
            .keys()
            .filter(|world| world.as_str().starts_with(prefix.as_str()))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    pub fn list_with_prefix_bounded(
        &self,
        prefix: &ValidatedWorldPrefix,
        max: usize,
    ) -> Option<Vec<ValidatedWorldPath>> {
        let mut out = Vec::new();
        for world in self
            .map_guard()
            .keys()
            .filter(|world| world.as_str().starts_with(prefix.as_str()))
        {
            if out.len() >= max {
                return None;
            }
            out.push(world.clone());
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Some(out)
    }

    pub fn total_bytes(&self) -> usize {
        self.map_guard()
            .values()
            .map(|entry| entry.body.len())
            .sum()
    }

    pub fn sizes(&self) -> Vec<(ValidatedWorldPath, usize)> {
        let mut out: Vec<(ValidatedWorldPath, usize)> = self
            .map_guard()
            .iter()
            .map(|(world, entry)| (world.clone(), entry.body.len()))
            .collect();
        out.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        out
    }

    fn map_guard(&self) -> MutexGuard<'_, HashMap<ValidatedWorldPath, MemEntry>> {
        self.map.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Combined view: sqlite + memory. Used by tests that assert both stores agree.
#[cfg(test)]
pub fn list_all(data_root: &Path, mem: &MemoryStore) -> rusqlite::Result<Vec<String>> {
    let mut out: Vec<String> = world::list(data_root)?
        .into_iter()
        .map(|world| world.as_str().to_owned())
        .collect();
    out.extend(
        mem.list()
            .into_iter()
            .map(|world| world.as_str().to_owned()),
    );
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{audit, engine_types::ValidatedWorldPath, test_support::test_core};

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    #[test]
    fn worlds_store_content_type_not_private_extensions() {
        let (core, dir) = test_core("content-type");
        core.test_only_write_world("home/pdf", b"%PDF-1.7", "application/pdf", &[])
            .unwrap();

        let file_op = core.begin_file_op().unwrap();
        let stage = core
            .read_world(&world_path("home/pdf"), &file_op)
            .unwrap()
            .unwrap();
        assert_eq!(stage.content_type, "application/pdf");
        assert_eq!(stage.body, b"%PDF-1.7");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn storage_prefix_routes_memory_and_disk_modes() {
        assert!(!is_memory_world(&world_path("home/report")));
        assert!(!is_memory_world(&world_path("etc/config")));
        assert!(is_memory_world(&world_path("tmp/scratch")));
        assert!(is_memory_world(&world_path("dev/fb0")));
        assert!(is_memory_world(&world_path("sys/status")));
        assert!(is_persistent(&world_path("home/report")));
        assert!(!is_persistent(&world_path("tmp/scratch")));
        assert!(MemoryWorldPath::new(&world_path("tmp/scratch")).is_some());
        assert!(MemoryWorldPath::new(&world_path("home/report")).is_none());
    }

    #[test]
    fn memory_worlds_do_not_create_sqlite_files_or_audit_chain() {
        let (core, dir) = test_core("memory-world");
        core.test_only_write_world(
            "tmp/scratch",
            b"draft",
            "text/plain; charset=utf-8",
            &[("x-meta-owner".to_string(), "agent".to_string())],
        )
        .unwrap();

        let stage = core
            .read_world(&world_path("tmp/scratch"), &core.begin_file_op().unwrap())
            .unwrap()
            .unwrap();
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
        let world = ValidatedWorldPath::new("home/report").unwrap();
        let h = world::write_with_audit(
            &core.data,
            &world,
            b"final",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let file_op = core.begin_file_op().unwrap();
        let stage = core.read_world(&world, &file_op).unwrap().unwrap();
        assert_eq!(stage.body, b"final");
        assert!(world::world_db(&core.data, "home/report").exists());
        assert_eq!(audit::latest_hmac(&core.data, "home/report"), Some(h));

        let names = list_all(&core.data, &core.mem);
        assert_eq!(names.unwrap(), vec!["home/report".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn list_all_merges_disk_and_memory_worlds_sorted_and_deduped() {
        let (core, dir) = test_core("list-all");
        let disk_b = ValidatedWorldPath::new("home/b").unwrap();
        let disk_tmp = ValidatedWorldPath::new("tmp/dup").unwrap();
        world::write_with_audit(
            &core.data,
            &disk_b,
            b"disk",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit(
            &core.data,
            &disk_tmp,
            b"legacy-disk-tmp",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        core.test_only_write_world("tmp/a", b"mem", "text/plain", &[])
            .unwrap();
        core.test_only_write_world("tmp/dup", b"mem", "text/plain", &[])
            .unwrap();

        assert_eq!(
            list_all(&core.data, &core.mem).unwrap(),
            vec![
                "home/b".to_string(),
                "tmp/a".to_string(),
                "tmp/dup".to_string()
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
