//! Store routing — one core, one port, prefix decides the backend.
//!
//! ```text
//!     /home/* /etc/* /lib/* /boot/* /usr/* /var/*  → SQLite (durable)
//!     /tmp/*  /dev/*  /sys/*                       → memory (transient)
//!
//! ```
//!
//! `MemoryStore` is a small Redis-shaped substrate that keeps the
//! L5 shape: the path prefix selects the backend without changing
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
use dashmap::{mapref::entry::Entry, DashMap};
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

impl MemEntry {
    fn new(body: &[u8], content_type: &str, headers: &[(String, String)]) -> Self {
        Self {
            body: body.to_vec(),
            body_hash: world::sha256_hex(body),
            content_type: content_type.to_owned(),
            headers: headers.to_vec(),
        }
    }
}

const MEMORY_ENTRY_OVERHEAD_BYTES: usize = 128;
const MEMORY_BODY_HASH_HEX_BYTES: usize = 64;

#[derive(Default)]
pub struct MemoryStore {
    map: DashMap<ValidatedWorldPath, MemEntry>,
    /// Short global commit point for the transient-store byte budget.
    /// Body cloning and hashing happen before this lock is acquired.
    accounted_bytes: Mutex<usize>,
}

/// Returned by `write_with_quota` / `append_with_quota` when the requested
/// write would push the total accounted memory store size past
/// `max_total_bytes`.
/// The check and DashMap entry commit happen under the same short quota
/// mutex so concurrent writers cannot both pass a stale snapshot and then
/// both commit. Body cloning and hashing stay outside that mutex.
#[derive(Debug)]
pub struct MemoryQuotaError {
    /// Pre-write total accounted bytes across all memory worlds. Currently
    /// the callers only need `quota` for payload-cap mapping, but `used` and
    /// `projected` are populated for diagnostic clarity.
    #[allow(dead_code)]
    pub used: usize,
    pub quota: usize,
    #[allow(dead_code)]
    pub projected: usize,
}

/// Outcome of a successful `write_with_quota`.
#[derive(Debug)]
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
        let e = self.map.get(world.as_path())?;
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
        let e = self.map.get(world.as_path())?;
        Some((e.body.len(), e.content_type.clone(), e.headers.clone()))
    }

    pub fn contains(&self, world: MemoryWorldPath<'_>) -> bool {
        self.map.contains_key(world.as_path())
    }

    /// Write a memory world with an atomic quota check. The replacement body,
    /// hash, and metadata are prepared before any lock. The DashMap entry guard
    /// then stabilizes this world while the short quota mutex serializes only
    /// "compare global total -> commit entry -> update total". The quota
    /// charges stored body bytes plus key/metadata/hash/accounting overhead, so
    /// empty memory worlds cannot grow the map without consuming quota.
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
        let Some(next_len) =
            accounted_entry_parts_bytes(world.as_path(), body.len(), content_type, headers)
        else {
            return Err(self.accounting_overflow(max_total_bytes));
        };
        let replacement = MemEntry::new(body, content_type, headers);
        let entry = self.map.entry(world.as_path().clone());
        let (existed, previous_len) = match &entry {
            Entry::Occupied(slot) => {
                let Some(previous_len) = accounted_entry_bytes(world.as_path(), slot.get()) else {
                    return Err(self.accounting_overflow(max_total_bytes));
                };
                (true, previous_len)
            }
            Entry::Vacant(_) => (false, 0),
        };
        let mut accounted = self.accounted_guard();
        let used = *accounted;
        let Some(projected) = projected_accounted_bytes(used, previous_len, next_len) else {
            return Err(MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected: usize::MAX,
            });
        };
        if projected > max_total_bytes {
            return Err(MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected,
            });
        }
        let previous = match entry {
            Entry::Occupied(mut slot) => Some(slot.insert(replacement)),
            Entry::Vacant(slot) => {
                drop(slot.insert(replacement));
                None
            }
        };
        *accounted = projected;
        drop(accounted);
        drop(previous);
        Ok(MemoryWriteOutcome { existed })
    }

    /// Append to a memory world with an atomic quota check. Returns
    /// `Ok(None)` if the world does not exist (caller maps to 404).
    /// `Err(MemoryQuotaError)` if accepting the append would push the
    /// total accounted memory store size past `max_total_bytes`. Otherwise
    /// `Ok(Some(result))` with the post-append SHA-256 of the body.
    pub fn append_with_quota(
        &self,
        world: MemoryWorldPath<'_>,
        body: &[u8],
        max_total_bytes: usize,
    ) -> Result<Option<AppendResult>, MemoryQuotaError> {
        let Entry::Occupied(mut entry) = self.map.entry(world.as_path().clone()) else {
            return Ok(None);
        };
        let Some(previous_len) = accounted_entry_bytes(world.as_path(), entry.get()) else {
            return Err(self.accounting_overflow(max_total_bytes));
        };
        let mut next_body = entry.get().body.clone();
        next_body.extend_from_slice(body);
        let after = world::sha256_hex(&next_body);
        let replacement = MemEntry {
            body: next_body,
            body_hash: after.clone(),
            content_type: entry.get().content_type.clone(),
            headers: entry.get().headers.clone(),
        };
        let Some(next_len) = accounted_entry_bytes(world.as_path(), &replacement) else {
            let error = self.accounting_overflow(max_total_bytes);
            drop(entry);
            drop(replacement);
            return Err(error);
        };
        let mut accounted = self.accounted_guard();
        let used = *accounted;
        let Some(projected) = projected_accounted_bytes(used, previous_len, next_len) else {
            let error = MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected: usize::MAX,
            };
            drop(accounted);
            drop(entry);
            drop(replacement);
            return Err(error);
        };
        if projected > max_total_bytes {
            let error = MemoryQuotaError {
                used,
                quota: max_total_bytes,
                projected,
            };
            drop(accounted);
            drop(entry);
            drop(replacement);
            return Err(error);
        }
        let previous = entry.insert(replacement);
        *accounted = projected;
        drop(accounted);
        drop(entry);
        drop(previous);
        Ok(Some(AppendResult {
            body_sha256_after: after,
        }))
    }

    pub fn delete(&self, world: MemoryWorldPath<'_>) -> bool {
        let Entry::Occupied(entry) = self.map.entry(world.as_path().clone()) else {
            return false;
        };
        let Some(removed_len) = accounted_entry_bytes(world.as_path(), entry.get()) else {
            return false;
        };
        let mut accounted = self.accounted_guard();
        let Some(projected) = accounted.checked_sub(removed_len) else {
            return false;
        };
        let removed = entry.remove();
        *accounted = projected;
        drop(accounted);
        drop(removed);
        true
    }

    pub fn list(&self) -> Vec<ValidatedWorldPath> {
        let mut out: Vec<ValidatedWorldPath> =
            self.map.iter().map(|entry| entry.key().clone()).collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    pub fn list_with_prefix(&self, prefix: &ValidatedWorldPrefix) -> Vec<ValidatedWorldPath> {
        let mut out: Vec<ValidatedWorldPath> = self
            .map
            .iter()
            .filter(|entry| entry.key().as_str().starts_with(prefix.as_str()))
            .map(|entry| entry.key().clone())
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
            .map
            .iter()
            .filter(|entry| entry.key().as_str().starts_with(prefix.as_str()))
        {
            if out.len() >= max {
                return None;
            }
            out.push(world.key().clone());
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Some(out)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn total_bytes(&self) -> usize {
        self.map.iter().map(|entry| entry.value().body.len()).sum()
    }

    pub fn accounted_total_bytes(&self) -> usize {
        *self.accounted_guard()
    }

    pub fn sizes(&self) -> Vec<(ValidatedWorldPath, usize)> {
        let mut out: Vec<(ValidatedWorldPath, usize)> = self
            .map
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().body.len()))
            .collect();
        out.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        out
    }

    fn accounted_guard(&self) -> MutexGuard<'_, usize> {
        self.accounted_bytes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn accounting_overflow(&self, quota: usize) -> MemoryQuotaError {
        MemoryQuotaError {
            used: *self.accounted_guard(),
            quota,
            projected: usize::MAX,
        }
    }
}

fn accounted_entry_bytes(world: &ValidatedWorldPath, entry: &MemEntry) -> Option<usize> {
    accounted_entry_parts_bytes(world, entry.body.len(), &entry.content_type, &entry.headers)
}

fn accounted_entry_parts_bytes(
    world: &ValidatedWorldPath,
    body_len: usize,
    content_type: &str,
    headers: &[(String, String)],
) -> Option<usize> {
    MEMORY_ENTRY_OVERHEAD_BYTES
        .checked_add(world.as_str().len())?
        .checked_add(body_len)?
        .checked_add(MEMORY_BODY_HASH_HEX_BYTES)?
        .checked_add(metadata_bytes(content_type, headers)?)
}

fn metadata_bytes(content_type: &str, headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .try_fold(content_type.len(), |total, (name, value)| {
            total.checked_add(name.len())?.checked_add(value.len())
        })
}

fn projected_accounted_bytes(used: usize, previous: usize, next: usize) -> Option<usize> {
    used.checked_sub(previous)?.checked_add(next)
}

/// Combined view: sqlite + memory. Used by tests that assert both stores agree.
#[cfg(test)]
pub fn list_all(data_root: &Path, mem: &MemoryStore) -> rusqlite::Result<Vec<String>> {
    let gate = std::sync::Arc::new(crate::state::FileOpGate::new());
    let file_op = gate
        .begin()
        .ok_or_else(|| rusqlite::Error::ExecuteReturnedResults)?;
    let mut out: Vec<String> = world::list(
        &mut crate::blocking_sqlite::test_only_mint(),
        data_root,
        &file_op,
    )?
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
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn recomputed_accounted_bytes(store: &MemoryStore) -> usize {
        store
            .map
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(accounted_entry_bytes(entry.key(), entry.value())?)
            })
            .unwrap()
    }

    fn expected_accounted_entry_parts_bytes(
        world: &ValidatedWorldPath,
        body_len: usize,
        content_type: &str,
        headers: &[(String, String)],
    ) -> usize {
        accounted_entry_parts_bytes(world, body_len, content_type, headers).unwrap()
    }

    #[test]
    fn worlds_store_content_type_not_private_extensions() {
        let (core, dir) = test_core("content-type");
        core.test_only_write_world("home/pdf", b"%PDF-1.7", "application/pdf", &[])
            .unwrap();

        let file_op = core.begin_file_op().unwrap();
        let stage = core
            .read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/pdf"),
                &file_op,
            )
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
    fn memory_quota_charges_empty_world_key_and_metadata() {
        let store = MemoryStore::new();
        let world = world_path("tmp/empty");
        let headers = vec![("x-meta-owner".to_owned(), "agent".to_owned())];
        let required = expected_accounted_entry_parts_bytes(&world, 0, "text/plain", &headers);

        let err = store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"",
                "text/plain",
                &headers,
                required - 1,
            )
            .unwrap_err();
        assert_eq!(err.quota, required - 1);

        store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"",
                "text/plain",
                &headers,
                required,
            )
            .unwrap();
        assert_eq!(store.total_bytes(), 0);
        assert_eq!(store.accounted_total_bytes(), required);
    }

    #[test]
    fn memory_append_quota_charges_projected_body_without_losing_metadata() {
        let store = MemoryStore::new();
        let world = world_path("tmp/append");
        let headers = vec![("x-meta-kind".to_owned(), "log".to_owned())];
        let initial = expected_accounted_entry_parts_bytes(&world, 1, "text/plain", &headers);

        store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"a",
                "text/plain",
                &headers,
                initial,
            )
            .unwrap();

        assert!(store
            .append_with_quota(MemoryWorldPath::new(&world).unwrap(), b"b", initial)
            .is_err());

        let appended = expected_accounted_entry_parts_bytes(&world, 2, "text/plain", &headers);
        store
            .append_with_quota(MemoryWorldPath::new(&world).unwrap(), b"b", appended)
            .unwrap()
            .unwrap();
        assert_eq!(store.total_bytes(), 2);
        assert_eq!(store.accounted_total_bytes(), appended);
    }

    #[test]
    fn memory_accounting_tracks_replace_append_and_delete() {
        let store = MemoryStore::new();
        let world = world_path("tmp/accounting");
        let initial_headers = vec![("x-meta-owner".to_owned(), "one".to_owned())];
        let initial =
            expected_accounted_entry_parts_bytes(&world, 1, "text/plain", &initial_headers);

        store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"a",
                "text/plain",
                &initial_headers,
                usize::MAX,
            )
            .unwrap();
        assert_eq!(store.accounted_total_bytes(), initial);
        assert_eq!(recomputed_accounted_bytes(&store), initial);

        let replacement_headers = vec![("x-meta-owner".to_owned(), "two".to_owned())];
        let replaced = expected_accounted_entry_parts_bytes(
            &world,
            4,
            "application/octet-stream",
            &replacement_headers,
        );
        store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"body",
                "application/octet-stream",
                &replacement_headers,
                usize::MAX,
            )
            .unwrap();
        assert_eq!(store.accounted_total_bytes(), replaced);
        assert_eq!(recomputed_accounted_bytes(&store), replaced);

        let appended = expected_accounted_entry_parts_bytes(
            &world,
            5,
            "application/octet-stream",
            &replacement_headers,
        );
        store
            .append_with_quota(MemoryWorldPath::new(&world).unwrap(), b"!", usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(store.accounted_total_bytes(), appended);
        assert_eq!(recomputed_accounted_bytes(&store), appended);

        assert!(store.delete(MemoryWorldPath::new(&world).unwrap()));
        assert_eq!(store.accounted_total_bytes(), 0);
        assert_eq!(recomputed_accounted_bytes(&store), 0);
    }

    #[test]
    fn rejected_memory_replace_preserves_entry_and_accounting() {
        let store = MemoryStore::new();
        let world = world_path("tmp/rejected-replace");
        let headers = vec![("x-meta-owner".to_owned(), "original".to_owned())];
        let quota = expected_accounted_entry_parts_bytes(&world, 4, "text/plain", &headers);

        store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"keep",
                "text/plain",
                &headers,
                quota,
            )
            .unwrap();
        let error = store
            .write_with_quota(
                MemoryWorldPath::new(&world).unwrap(),
                b"replacement is too large",
                "text/plain",
                &headers,
                quota,
            )
            .unwrap_err();

        assert_eq!(error.used, quota);
        assert!(error.projected > quota);
        let (stage, body_hash) = store
            .read_with_hash(MemoryWorldPath::new(&world).unwrap())
            .unwrap();
        assert_eq!(stage.body, b"keep");
        assert_eq!(body_hash, world::sha256_hex(b"keep"));
        assert_eq!(store.accounted_total_bytes(), quota);
        assert_eq!(recomputed_accounted_bytes(&store), quota);
    }

    #[test]
    fn concurrent_memory_writes_cannot_oversubscribe_quota() {
        const WRITERS: usize = 16;
        const ALLOWED: usize = 4;

        let store = Arc::new(MemoryStore::new());
        let barrier = Arc::new(Barrier::new(WRITERS));
        let sample = world_path("tmp/concurrent-00");
        let per_entry = expected_accounted_entry_parts_bytes(&sample, 1, "text/plain", &[]);
        let quota = per_entry * ALLOWED;
        let mut writers = Vec::new();

        for index in 0..WRITERS {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            writers.push(thread::spawn(move || {
                let world = world_path(&format!("tmp/concurrent-{index:02}"));
                let body = [index as u8];
                barrier.wait();
                store
                    .write_with_quota(
                        MemoryWorldPath::new(&world).unwrap(),
                        &body,
                        "text/plain",
                        &[],
                        quota,
                    )
                    .is_ok()
            }));
        }

        let accepted = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, ALLOWED);
        assert_eq!(store.list().len(), ALLOWED);
        assert_eq!(store.accounted_total_bytes(), quota);
        assert_eq!(recomputed_accounted_bytes(&store), quota);
    }

    #[test]
    fn memory_accounting_rejects_integer_overflow() {
        let world = world_path("tmp/overflow");

        assert_eq!(
            accounted_entry_parts_bytes(&world, usize::MAX, "text/plain", &[]),
            None
        );
        assert_eq!(projected_accounted_bytes(usize::MAX, 0, 1), None);
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
            .read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("tmp/scratch"),
                &core.begin_file_op().unwrap(),
            )
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
        let stage = core
            .read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world,
                &file_op,
            )
            .unwrap()
            .unwrap();
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
