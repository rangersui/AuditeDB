//! Protocol-neutral Engine introspection surface.
//!
//! This module owns the typed snapshots behind generated `proc/*` surfaces.
//! Engine returns structured data; adapters choose their own rendering.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{fmt, sync::atomic::Ordering};

use crate::{
    auth,
    engine::{Engine, EngineError},
    engine_ops::{log_storage_error, EngineOps},
    engine_types::{AccessTier, ValidatedWorldPath, ValidatedWorldPrefix},
    store, world, AuthGate, StorageFailureClass,
};

/// Validated `/proc/*` introspection endpoint.
///
/// This proves the adapter selected one of the declared proc surfaces before
/// asking Engine for metadata. Reserved or misspelled proc paths stay outside
/// the Engine as adapter rendering concerns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedProcPath {
    endpoint: ProcEndpoint,
    audit_world: Option<ValidatedWorldPath>,
}

/// Returned when a string is not one of Engine's known proc endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidProcPath;

/// Stable proc endpoint identity carried by [`ValidatedProcPath`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcEndpoint {
    /// Engine build version string.
    Version,
    /// Enumerate every world (durable + in-memory).
    Worlds,
    /// Per-world body byte size (`du`-like).
    Du,
    /// Aggregate storage + memory usage and quotas (`df`-like).
    Df,
    /// Read cache + ledger writer pool counters.
    Pool,
    /// Verify a single world's HMAC audit chain.
    AuditVerify,
}

/// One world-size row for engine introspection.
#[non_exhaustive]
pub struct WorldUsage {
    /// Canonical world path.
    pub world: ValidatedWorldPath,
    /// Body byte size for this world.
    pub bytes: usize,
}

/// Aggregate storage/memory snapshot.
///
/// Returned by [`crate::Engine::df`]. Quotas of `0`/`None` mean "unlimited";
/// adapters should render that string for operator-facing output.
#[non_exhaustive]
pub struct DfSnapshot {
    /// Bytes used by durable bodies (SQLite-backed worlds).
    pub storage_used: usize,
    /// Configured durable quota, or `None` if unlimited.
    pub storage_quota: Option<usize>,
    /// Bytes used by in-memory bodies.
    pub memory_used: usize,
    /// Configured memory cap. `0` means unlimited.
    pub memory_quota: usize,
    /// Total live worlds (durable + in-memory).
    pub worlds: usize,
}

/// Read-cache + ledger-writer snapshot.
///
/// Returned by [`crate::Engine::pool`]. All counters are monotonic since
/// process start.
#[non_exhaustive]
pub struct PoolSnapshot {
    /// Active read-cache entries (open SQLite connections currently parked).
    pub read_cache_entries: usize,
    /// Tombstoned entries waiting on in-flight reads to drain.
    pub read_cache_tombstones: usize,
    /// Cache hits since process start.
    ///
    /// A hit means a Phase 1 cached slot returned a definitive answer:
    /// `Some` from a Ready slot, or `None` from Tombstone. Opening and
    /// Evicted retry signals are not hits.
    pub read_cache_hits: usize,
    /// Cache misses since process start.
    ///
    /// Counted at most once per external read, even if internal retry loops run
    /// more than once. Under races, one external read may independently count a
    /// miss and later a hit if another reader installs the target slot first.
    pub read_cache_misses: usize,
    /// Times a read saw the cache at cap after a miss.
    ///
    /// Counted at most once per external read. The read may still evict a
    /// sampled cold slot instead of falling back to a transient slot.
    pub read_cache_capped: usize,
    /// Successful cap-full read-cache evictions since process start. Failed
    /// eviction attempts fall back to transient reads and are not counted.
    pub read_cache_evictions: usize,
    /// Read-cache slot open failures (SQLite open errors).
    pub read_cache_open_fails: usize,
    /// Configured maximum cache entries.
    pub read_cache_max_entries: usize,
    /// Ledger writer (re)initializations since process start.
    pub ledger_writer_inits: usize,
}

/// Successful audit-chain verification details.
#[non_exhaustive]
pub struct AuditValid {
    /// Number of events on the chain.
    pub events: usize,
    /// HMAC of the genesis event.
    pub genesis: String,
    /// HMAC of the most recent event.
    pub latest: String,
}

/// Audit-chain break details.
#[non_exhaustive]
pub struct AuditBroken {
    /// Event id at which verification failed.
    pub break_at: usize,
    /// HMAC the chain expected at that position.
    pub expected: String,
    /// HMAC actually stored at that position.
    pub actual: String,
}

/// Result of [`crate::Engine::verify_audit`].
#[non_exhaustive]
pub enum AuditVerify {
    /// Chain verified end-to-end.
    Valid(AuditValid),
    /// Chain failed verification; see [`AuditBroken`] for the break point.
    Broken(AuditBroken),
    /// World does not have an audit chain (e.g. an in-memory `tmp/` world).
    NotApplicable,
}

/// The audit chain's current head: the number of events currently in the
/// chain and the newest event's chain HMAC. Returned by
/// [`crate::Engine::chain_head`].
///
/// This is the unit of external anchoring. In-file verification proves
/// "nobody tampered with what is here"; it structurally cannot prove
/// "everything that happened is here" — every non-empty prefix of a valid
/// chain is itself a valid chain, and a rolled-back file is
/// self-consistent. A host that remembers a `HeadStamp` (on another machine,
/// a subscriber, an RFC 3161 timestamp) can later **prove** truncation or
/// rollback whenever the observed event count is behind the anchored `seq`.
/// A rolled-back or replaced (deleted-and-recreated) chain that has re-grown
/// past the anchor is not caught by the seq comparison alone; catching that
/// requires comparing the hmac at the anchored seq -- the divergence check,
/// a later PR in this stack.
///
/// When the chain verifies, `seq` equals [`AuditValid::events`] and `hmac`
/// equals [`AuditValid::latest`]. `seq` is not a raw SQLite rowid; rowids are
/// mutable storage detail, not an anchoring contract.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStamp {
    /// Number of events currently on the chain.
    pub seq: i64,
    /// Chain HMAC of the newest event.
    pub hmac: String,
}

struct IntrospectionPermit {
    path: ValidatedProcPath,
}

impl ValidatedProcPath {
    /// Parses a wire-shaped proc path into a sealed endpoint identity.
    ///
    /// Accepts `proc/version`, `proc/worlds`, `proc/du`, `proc/df`,
    /// `proc/pool`, or `proc/audit/<world>/verify`. Leading and trailing
    /// slashes are tolerated. The audit world segment must already be a
    /// canonical Engine path such as `home/foo`; bare names like `foo`, wire
    /// paths like `/home/foo`, and generated `proc/*` worlds are rejected.
    ///
    /// # Errors
    /// Returns [`InvalidProcPath`] if the input is not one of the declared
    /// endpoints, or if the audit-verify world fails canonical-path
    /// validation.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, InvalidProcPath> {
        let raw = raw.as_ref().trim_matches('/');
        match raw {
            "proc/version" => Ok(Self::version()),
            "proc/worlds" => Ok(Self::worlds()),
            "proc/du" => Ok(Self::du()),
            "proc/df" => Ok(Self::df()),
            "proc/pool" => Ok(Self::pool()),
            _ => {
                let Some(world) = raw
                    .strip_prefix("proc/audit/")
                    .and_then(|value| value.strip_suffix("/verify"))
                else {
                    return Err(InvalidProcPath);
                };
                if world.trim_matches('/').is_empty() {
                    return Err(InvalidProcPath);
                }
                let world = world.trim_end_matches('/').to_owned();
                let world =
                    ValidatedWorldPath::from_canonical(world).map_err(|_| InvalidProcPath)?;
                Ok(Self::audit_verify(world))
            }
        }
    }

    /// Returns the proof token for the `version` endpoint.
    pub fn version() -> Self {
        Self {
            endpoint: ProcEndpoint::Version,
            audit_world: None,
        }
    }

    /// Returns the proof token for the `worlds` endpoint.
    pub fn worlds() -> Self {
        Self {
            endpoint: ProcEndpoint::Worlds,
            audit_world: None,
        }
    }

    /// Returns the proof token for the `du` endpoint.
    pub fn du() -> Self {
        Self {
            endpoint: ProcEndpoint::Du,
            audit_world: None,
        }
    }

    /// Returns the proof token for the `df` endpoint.
    pub fn df() -> Self {
        Self {
            endpoint: ProcEndpoint::Df,
            audit_world: None,
        }
    }

    /// Returns the proof token for the `pool` endpoint.
    pub fn pool() -> Self {
        Self {
            endpoint: ProcEndpoint::Pool,
            audit_world: None,
        }
    }

    /// Returns the proof token for an `audit verify` operation against a
    /// specific world.
    pub fn audit_verify(world: ValidatedWorldPath) -> Self {
        Self {
            endpoint: ProcEndpoint::AuditVerify,
            audit_world: Some(world),
        }
    }

    pub(crate) fn endpoint(&self) -> ProcEndpoint {
        self.endpoint
    }

    pub(crate) fn audit_world(&self) -> Option<&ValidatedWorldPath> {
        self.audit_world.as_ref()
    }
}

impl fmt::Display for InvalidProcPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid proc path")
    }
}

impl std::error::Error for InvalidProcPath {}

impl EngineOps<'_> {
    pub(crate) fn list_worlds(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<Vec<ValidatedWorldPath>, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::Worlds)?;
        let mut names = world::list(&self.core().data)
            .map_err(|err| storage_error_to_engine("proc worlds", err, "list_worlds", None))?;
        names.extend(self.core().mem.list());
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(validated_world_from_storage)
            .collect()
    }

    pub(crate) fn list_worlds_with_prefix(
        &self,
        prefix: &ValidatedWorldPrefix,
        tier: auth::Tier,
    ) -> Result<Vec<ValidatedWorldPath>, EngineError> {
        if !crate::can_read(self.core(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        let mut names = world::list_with_prefix(&self.core().data, prefix).map_err(|err| {
            storage_error_to_engine("worlds prefix", err, "list_worlds_with_prefix", None)
        })?;
        names.extend(self.core().mem.list_with_prefix(prefix));
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(validated_world_from_storage)
            .collect()
    }

    pub(crate) fn list_worlds_with_prefix_bounded(
        &self,
        prefix: &ValidatedWorldPrefix,
        tier: auth::Tier,
        max: usize,
    ) -> Result<Option<Vec<ValidatedWorldPath>>, EngineError> {
        if !crate::can_read(self.core(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        let limit = max.saturating_add(1);
        let Some(mut names) = world::list_with_prefix_bounded(&self.core().data, prefix, limit)
            .map_err(|err| {
                storage_error_to_engine("worlds prefix", err, "list_worlds_with_prefix", None)
            })?
        else {
            return Ok(None);
        };
        let Some(mem_names) = self.core().mem.list_with_prefix_bounded(prefix, limit) else {
            return Ok(None);
        };
        names.extend(mem_names);
        names.sort();
        names.dedup();
        if names.len() > max {
            return Ok(None);
        }
        names
            .into_iter()
            .map(validated_world_from_storage)
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    pub(crate) fn du(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<Vec<WorldUsage>, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::Du)?;
        let mut sizes = world::sizes(&self.core().data)
            .map_err(|err| storage_error_to_engine("proc du", err, "du", None))?;
        sizes.extend(self.core().mem.sizes());
        sizes.sort_by(|a, b| a.0.cmp(&b.0));
        sizes.dedup_by(|a, b| a.0 == b.0);
        sizes
            .into_iter()
            .map(|(world, bytes)| {
                Ok(WorldUsage {
                    world: validated_world_from_storage(world)?,
                    bytes,
                })
            })
            .collect()
    }

    pub(crate) fn df(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<DfSnapshot, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::Df)?;
        let memory_used = self.core().mem.total_bytes();
        let memory_worlds = self.core().mem.list().len();
        let storage_used = self.core().storage_body_bytes.load(Ordering::Relaxed);
        let durable_worlds = self
            .core()
            .durable_world_count
            .load(Ordering::Relaxed)
            .saturating_sub(usize::from(
                self.core().delete_ledger_created.load(Ordering::Relaxed),
            ));
        Ok(DfSnapshot {
            storage_used,
            storage_quota: self.core().max_storage_bytes,
            memory_used,
            memory_quota: self.core().max_memory_bytes,
            worlds: durable_worlds + memory_worlds,
        })
    }

    pub(crate) fn pool(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<PoolSnapshot, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::Pool)?;
        Ok(PoolSnapshot {
            read_cache_entries: self.core().read_cache.snapshot_entries(),
            read_cache_tombstones: self.core().read_cache.snapshot_tombstones(),
            read_cache_hits: self
                .core()
                .read_cache
                .metrics
                .read_cache_hits
                .load(Ordering::Relaxed),
            read_cache_misses: self
                .core()
                .read_cache
                .metrics
                .read_cache_misses
                .load(Ordering::Relaxed),
            read_cache_capped: self
                .core()
                .read_cache
                .metrics
                .read_cache_capped
                .load(Ordering::Relaxed),
            read_cache_evictions: self
                .core()
                .read_cache
                .metrics
                .read_cache_evictions
                .load(Ordering::Relaxed),
            read_cache_open_fails: self
                .core()
                .read_cache
                .metrics
                .read_cache_open_fails
                .load(Ordering::Relaxed),
            read_cache_max_entries: self.core().read_cache.max_entries,
            ledger_writer_inits: self.core().ledger.inits.load(Ordering::Relaxed),
        })
    }

    pub(crate) fn verify_audit(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<AuditVerify, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::AuditVerify)?;
        let world = permit
            .path
            .audit_world()
            .ok_or(EngineError::InternalInvariant("audit verify missing world"))?;
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            if !self.core().mem.contains(memory_world) {
                return Err(EngineError::NotFound);
            }
            return Ok(AuditVerify::NotApplicable);
        }
        match self.core().cached_verify_chain(world) {
            Ok(Some(crate::audit::VerifyReport::Valid(report))) => {
                Ok(AuditVerify::Valid(report.into()))
            }
            Ok(Some(crate::audit::VerifyReport::Broken(report))) => {
                Ok(AuditVerify::Broken(report.into()))
            }
            Ok(None) => Err(EngineError::NotFound),
            Err(err) => Err(storage_error_to_engine(
                "audit verify",
                err,
                "verify_audit",
                Some(world.as_str()),
            )),
        }
    }

    pub(crate) fn chain_head(
        &self,
        world: &ValidatedWorldPath,
        tier: auth::Tier,
    ) -> Result<Option<HeadStamp>, EngineError> {
        if !crate::can_read(self.core(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            if !self.core().mem.contains(memory_world) {
                return Err(EngineError::NotFound);
            }
            // Memory worlds have no audit chain: nothing to anchor.
            return Ok(None);
        }
        match self.core().cached_chain_head(world) {
            Ok(Some(Some((seq, hmac)))) => Ok(Some(HeadStamp { seq, hmac })),
            // Existing DB with an empty chain (bootstrap shape): nothing to
            // anchor yet.
            Ok(Some(None)) => Ok(None),
            Ok(None) => Err(EngineError::NotFound),
            Err(err) => Err(storage_error_to_engine(
                "chain head",
                err,
                "chain_head",
                Some(world.as_str()),
            )),
        }
    }

    fn authorize_introspection(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<IntrospectionPermit, EngineError> {
        if !crate::can_read(self.core(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        Ok(IntrospectionPermit { path: path.clone() })
    }
}

impl Engine {
    /// Lists every canonical world (durable + in-memory) in sorted order.
    ///
    /// This is a synchronous API. It may scan durable world names from the
    /// data root and memory world names from the in-process store.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::TransientStorage`] / [`EngineError::Storage`] /
    ///   [`EngineError::InsufficientStorage`] for storage failures.
    pub fn list_worlds(&self, tier: AccessTier) -> Result<Vec<ValidatedWorldPath>, EngineError> {
        EngineOps::new(self.core()).list_worlds(&ValidatedProcPath::worlds(), tier.into())
    }

    /// Lists canonical worlds with the supplied canonical prefix.
    ///
    /// This is a synchronous API and may scan storage on the caller thread.
    ///
    /// This is intended for adapters that need a bounded namespace view (for
    /// example retained replay) without materializing the full proc-worlds
    /// set first. It applies the read gate directly and intentionally bypasses
    /// proc-path authorization; do not expose it directly as a network endpoint.
    ///
    /// # Errors
    /// Same authorization and storage failures as [`Engine::list_worlds`].
    pub fn list_worlds_with_prefix(
        &self,
        prefix: &str,
        tier: AccessTier,
    ) -> Result<Vec<ValidatedWorldPath>, EngineError> {
        let prefix =
            ValidatedWorldPrefix::new(prefix).map_err(|_| EngineError::InvalidWorldName)?;
        EngineOps::new(self.core()).list_worlds_with_prefix(&prefix, tier.into())
    }

    /// Lists canonical worlds with the supplied canonical prefix, returning
    /// `Ok(None)` if more than `max` distinct worlds match.
    ///
    /// This is a synchronous API and may scan storage on the caller thread.
    ///
    /// This is intended for adapter-internal bounded scans. It uses the same
    /// read-tier gate as [`Engine::list_worlds_with_prefix`].
    pub fn list_worlds_with_prefix_bounded(
        &self,
        prefix: &str,
        tier: AccessTier,
        max: usize,
    ) -> Result<Option<Vec<ValidatedWorldPath>>, EngineError> {
        let prefix =
            ValidatedWorldPrefix::new(prefix).map_err(|_| EngineError::InvalidWorldName)?;
        EngineOps::new(self.core()).list_worlds_with_prefix_bounded(&prefix, tier.into(), max)
    }

    /// Returns per-world body byte size, `du`-style.
    ///
    /// This is a synchronous API. Durable sizes are read from storage; memory
    /// sizes are read from the in-process store.
    ///
    /// # Errors
    /// See [`Engine::list_worlds`] for the storage-failure variants. Same
    /// `Read`-tier requirement.
    pub fn du(&self, tier: AccessTier) -> Result<Vec<WorldUsage>, EngineError> {
        EngineOps::new(self.core()).du(&ValidatedProcPath::du(), tier.into())
    }

    /// Returns aggregate storage + memory usage, `df`-style.
    ///
    /// This is a synchronous snapshot of engine counters. It does not walk
    /// every durable world on each call.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    pub fn df(&self, tier: AccessTier) -> Result<DfSnapshot, EngineError> {
        EngineOps::new(self.core()).df(&ValidatedProcPath::df(), tier.into())
    }

    /// Returns the read-cache + ledger-writer counter snapshot.
    ///
    /// This is a synchronous snapshot of in-process counters.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    pub fn pool(&self, tier: AccessTier) -> Result<PoolSnapshot, EngineError> {
        EngineOps::new(self.core()).pool(&ValidatedProcPath::pool(), tier.into())
    }

    /// Verifies a single world's HMAC audit chain.
    ///
    /// This is a synchronous API. It may use the read cache and read the
    /// world's SQLite-backed audit ledger on the caller thread.
    ///
    /// Returns [`AuditVerify::Valid`] / [`AuditVerify::Broken`] /
    /// [`AuditVerify::NotApplicable`] (the latter for in-memory worlds with
    /// no chain).
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::NotFound`] if `world` does not exist.
    /// - [`EngineError::TransientStorage`] / [`EngineError::Storage`] /
    ///   [`EngineError::InsufficientStorage`] for storage failures during
    ///   verification.
    pub fn verify_audit(
        &self,
        world: &ValidatedWorldPath,
        tier: AccessTier,
    ) -> Result<AuditVerify, EngineError> {
        let path = ValidatedProcPath::audit_verify(world.clone());
        EngineOps::new(self.core()).verify_audit(&path, tier.into())
    }

    /// Returns the audit chain's current head for external anchoring.
    ///
    /// This is a synchronous API: it reads the current event count and
    /// newest event HMAC through the cached read path without re-computing
    /// every HMAC. It does **not** verify the chain -- pair it with
    /// [`Engine::verify_audit`] when integrity matters; when the chain
    /// verifies, [`HeadStamp::seq`] equals [`AuditValid::events`] and
    /// [`HeadStamp::hmac`] equals [`AuditValid::latest`].
    ///
    /// Push the returned stamp somewhere — ideally somewhere this machine
    /// cannot rewrite (another host, a subscriber, an RFC 3161 timestamp;
    /// the further from this machine, the stronger the guarantee). A later
    /// head whose `seq` went backwards proves truncation or rollback that
    /// in-file verification cannot detect — and so does a durable world
    /// that previously had a stamp **persistently** returning `Ok(None)`
    /// or [`EngineError::NotFound`] (total truncation or deletion). A
    /// delete in flight also reads as `NotFound`, and a delete that failed
    /// before touching the chain file restores the head — re-poll before
    /// treating a single `NotFound` observation as loss.
    ///
    /// This method applies the read gate directly and intentionally
    /// bypasses proc-path authorization; do not expose it directly as a
    /// network endpoint (the proc endpoint comes in a later PR of this
    /// stack).
    ///
    /// # Returns
    /// - `Ok(Some(HeadStamp))` — the durable world's current chain head.
    /// - `Ok(None)` — the world exists but has no chain head to anchor:
    ///   an in-memory world (no audit chain) or an empty bootstrap-shape
    ///   chain. Note: [`Engine::verify_audit`] reports an existing durable
    ///   world with an empty chain as `Broken` (`no-events`) — `Ok(None)`
    ///   here is not a clean bill of health.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::NotFound`] if `world` does not exist.
    /// - [`EngineError::TransientStorage`] / [`EngineError::Storage`] /
    ///   [`EngineError::InsufficientStorage`] for storage failures.
    pub fn chain_head(
        &self,
        world: &ValidatedWorldPath,
        tier: AccessTier,
    ) -> Result<Option<HeadStamp>, EngineError> {
        EngineOps::new(self.core()).chain_head(world, tier.into())
    }
}

fn storage_error_to_engine(
    scope: &'static str,
    err: rusqlite::Error,
    operation: &'static str,
    world: Option<&str>,
) -> EngineError {
    match crate::classify_storage_failure(&err) {
        StorageFailureClass::InsufficientStorage => {
            log_storage_error(scope, &err, operation, world);
            EngineError::InsufficientStorage
        }
        StorageFailureClass::Transient => {
            log_storage_error(scope, &err, operation, world);
            EngineError::TransientStorage
        }
        StorageFailureClass::Other => {
            log_storage_error(scope, &err, operation, world);
            EngineError::Storage
        }
    }
}

fn validated_world_from_storage(world: String) -> Result<ValidatedWorldPath, EngineError> {
    ValidatedWorldPath::from_canonical(world)
        .map_err(|_| EngineError::InternalInvariant("storage returned invalid world path"))
}

fn ensure_proc_endpoint(
    permit: &IntrospectionPermit,
    expected: ProcEndpoint,
) -> Result<(), EngineError> {
    if permit.path.endpoint() == expected {
        Ok(())
    } else {
        Err(EngineError::InternalInvariant(
            "proc permit endpoint mismatch",
        ))
    }
}

impl From<crate::audit::VerifyOk> for AuditValid {
    fn from(value: crate::audit::VerifyOk) -> Self {
        Self {
            events: value.events,
            genesis: value.genesis,
            latest: value.latest,
        }
    }
}

impl From<crate::audit::VerifyBreak> for AuditBroken {
    fn from(value: crate::audit::VerifyBreak) -> Self {
        Self {
            break_at: value.break_at,
            expected: value.expected,
            actual: value.actual,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::{AuditVerify, ProcEndpoint, ValidatedProcPath};
    use crate::{
        engine::{Engine, EngineError},
        engine_ops::EngineOps,
        engine_types::{
            AccessTier, AuditHmacKey, Preconditions, Representation, ValidatedWorldPath,
        },
        AuthGate,
    };

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "elastik-engine-introspection-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn validated_proc_path_accepts_declared_endpoints_only() {
        assert_eq!(
            ValidatedProcPath::new("/proc/worlds").unwrap().endpoint(),
            ProcEndpoint::Worlds
        );
        assert_eq!(
            ValidatedProcPath::new("proc/du").unwrap().endpoint(),
            ProcEndpoint::Du
        );
        assert_eq!(
            ValidatedProcPath::new("proc/audit/home/foo/verify")
                .unwrap()
                .audit_world()
                .unwrap()
                .as_str(),
            "home/foo"
        );

        assert!(ValidatedProcPath::new("proc").is_err());
        assert!(ValidatedProcPath::new("proc/nope").is_err());
        assert!(ValidatedProcPath::new("proc/audit/foo/verify").is_err());
        assert!(ValidatedProcPath::new("proc/audit//verify").is_err());
        assert!(ValidatedProcPath::new("proc/audit/proc/version/verify").is_err());
    }

    #[tokio::test]
    async fn engine_introspection_returns_typed_snapshots() {
        let root = temp_root("snapshots");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .max_storage_bytes(Some(64))
            .build()
            .unwrap();
        let disk = ValidatedWorldPath::new("home/inspect").unwrap();
        let memory = ValidatedWorldPath::new("tmp/inspect").unwrap();

        assert!(matches!(
            engine.list_worlds(AccessTier::Anon),
            Err(EngineError::Auth(AuthGate::Read))
        ));

        for world in [&disk, &memory] {
            engine
                .replace(
                    world,
                    Representation::new(Bytes::from_static(b"hello"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let worlds = engine.list_worlds(AccessTier::Read).unwrap();
        assert!(worlds.iter().any(|world| world == &disk));
        assert!(worlds.iter().any(|world| world == &memory));

        let usage = engine.du(AccessTier::Read).unwrap();
        assert!(usage
            .iter()
            .any(|row| row.world == disk && row.bytes == b"hello".len() * 2));
        assert!(usage
            .iter()
            .any(|row| row.world == memory && row.bytes == b"hello".len()));

        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, b"hello".len() * 2);
        assert_eq!(df.storage_quota, Some(64));
        assert_eq!(df.memory_used, b"hello".len());
        assert_eq!(df.worlds, 2);

        let pool = engine.pool(AccessTier::Read).unwrap();
        assert_eq!(
            pool.read_cache_max_entries,
            crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES
        );
        assert!(pool.read_cache_entries <= pool.read_cache_max_entries);

        assert!(matches!(
            engine.verify_audit(&disk, AccessTier::Read).unwrap(),
            AuditVerify::Valid(_)
        ));
        assert!(matches!(
            engine.verify_audit(&memory, AccessTier::Read).unwrap(),
            AuditVerify::NotApplicable
        ));

        assert!(matches!(
            EngineOps::new(engine.core())
                .list_worlds(&ValidatedProcPath::du(), AccessTier::Read.into()),
            Err(EngineError::InternalInvariant(
                "proc permit endpoint mismatch"
            ))
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn engine_prefix_listing_validates_prefixes_and_preserves_scan_semantics() {
        let root = temp_root("prefixes");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        let disk_sensor = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        let disk_other = ValidatedWorldPath::new("home/other").unwrap();
        let memory_sensor = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();

        for world in [&disk_sensor, &disk_other, &memory_sensor] {
            engine
                .replace(
                    world,
                    Representation::new(Bytes::from_static(b"v"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let to_names = |worlds: Vec<ValidatedWorldPath>| {
            worlds
                .into_iter()
                .map(|world| world.as_str().to_owned())
                .collect::<Vec<_>>()
        };

        let all = engine.list_worlds(AccessTier::Read).unwrap();
        assert_eq!(
            to_names(
                engine
                    .list_worlds_with_prefix("", AccessTier::Read)
                    .unwrap()
            ),
            to_names(all)
        );

        let home_sensor = engine
            .list_worlds_with_prefix("home/sensor/", AccessTier::Read)
            .unwrap();
        assert_eq!(to_names(home_sensor.clone()), vec!["home/sensor/temp"]);
        assert_eq!(
            engine
                .list_worlds_with_prefix_bounded("home/sensor/", AccessTier::Read, 10)
                .unwrap(),
            Some(home_sensor)
        );

        let tmp_sensor = engine
            .list_worlds_with_prefix("tmp/sensor/", AccessTier::Read)
            .unwrap();
        assert_eq!(to_names(tmp_sensor.clone()), vec!["tmp/sensor/temp"]);
        assert_eq!(
            engine
                .list_worlds_with_prefix_bounded("tmp/sensor/", AccessTier::Read, 10)
                .unwrap(),
            Some(tmp_sensor)
        );

        for prefix in ["home/..", "home/.", "home/.ssh", "/home/", "proc/"] {
            assert!(matches!(
                engine.list_worlds_with_prefix(prefix, AccessTier::Read),
                Err(EngineError::InvalidWorldName)
            ));
            assert!(matches!(
                engine.list_worlds_with_prefix_bounded(prefix, AccessTier::Read, 10),
                Err(EngineError::InvalidWorldName)
            ));
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn chain_head_matches_verify_head_without_trusting_rowid() {
        let root = temp_root("chain-head");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .build()
            .unwrap();
        let disk = ValidatedWorldPath::new("home/anchored").unwrap();
        let memory = ValidatedWorldPath::new("tmp/anchored").unwrap();

        assert!(matches!(
            engine.chain_head(&disk, AccessTier::Anon),
            Err(EngineError::Auth(AuthGate::Read))
        ));
        assert!(matches!(
            engine.chain_head(&disk, AccessTier::Read),
            Err(EngineError::NotFound)
        ));

        for body in [b"one".as_slice(), b"two", b"three"] {
            engine
                .replace(
                    &disk,
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }
        engine
            .replace(
                &memory,
                Representation::new(Bytes::from_static(b"ram"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let head = engine
            .chain_head(&disk, AccessTier::Read)
            .unwrap()
            .expect("durable world has a chain head");
        let AuditVerify::Valid(valid) = engine.verify_audit(&disk, AccessTier::Read).unwrap()
        else {
            panic!("chain must verify");
        };
        // The stamp is the cheap subset of a full verify walk.
        assert_eq!(head.hmac, valid.latest);
        assert_eq!(head.seq, valid.events as i64);
        let max_id: i64 =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, disk.as_str()))
                .unwrap()
                .query_row("SELECT MAX(id) FROM events", [], |row| row.get(0))
                .unwrap();
        assert_eq!(head.seq, max_id);

        // Memory world exists but has no chain to anchor. The auth gate
        // must also hold on the memory path (pins gate-before-branch).
        assert!(matches!(
            engine.chain_head(&memory, AccessTier::Anon),
            Err(EngineError::Auth(AuthGate::Read))
        ));
        assert_eq!(engine.chain_head(&memory, AccessTier::Read).unwrap(), None);
        let missing_memory = ValidatedWorldPath::new("tmp/anchored-missing").unwrap();
        assert!(matches!(
            engine.chain_head(&missing_memory, AccessTier::Read),
            Err(EngineError::NotFound)
        ));

        // Bootstrap-shape durable DB (schema committed, zero events):
        // nothing to anchor — while verify_audit reports the same state
        // as Broken (no-events). The contrast is documented on the
        // chain_head facade.
        drop(crate::world::open(&engine.core().data, "home/anchored-bootstrap").unwrap());
        let bootstrap = ValidatedWorldPath::new("home/anchored-bootstrap").unwrap();
        assert_eq!(
            engine.chain_head(&bootstrap, AccessTier::Read).unwrap(),
            None
        );
        assert!(matches!(
            engine.verify_audit(&bootstrap, AccessTier::Read).unwrap(),
            AuditVerify::Broken(b) if b.actual == "no-events"
        ));

        // The head advances with the chain and never repeats.
        engine
            .replace(
                &disk,
                Representation::new(Bytes::from_static(b"four"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let advanced = engine
            .chain_head(&disk, AccessTier::Read)
            .unwrap()
            .expect("head persists after another write");
        assert_eq!(advanced.seq, head.seq + 1);
        assert_ne!(advanced.hmac, head.hmac);

        // `seq` is the event count, not a mutable SQLite rowid. A truncated
        // but otherwise self-consistent prefix cannot hide rollback by
        // inflating the surviving tail event id.
        let tampered = ValidatedWorldPath::new("home/anchored-rowid-tamper").unwrap();
        for body in [
            Bytes::from_static(b"one"),
            Bytes::from_static(b"two"),
            Bytes::from_static(b"three"),
        ] {
            engine
                .replace(
                    &tampered,
                    Representation::new(body, "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }
        {
            let c = rusqlite::Connection::open(crate::world::world_db(
                &engine.core().data,
                tampered.as_str(),
            ))
            .unwrap();
            let prefix_body: Vec<u8> = c
                .query_row(
                    "SELECT body FROM cas_bodies
                     WHERE body_sha256 = (SELECT body_sha256 FROM events WHERE id=2)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let deleted_body_sha256: String = c
                .query_row("SELECT body_sha256 FROM events WHERE id=3", [], |row| {
                    row.get(0)
                })
                .unwrap();
            c.execute(
                "DELETE FROM events WHERE id = (SELECT MAX(id) FROM events)",
                [],
            )
            .unwrap();
            c.execute(
                "DELETE FROM cas_bodies WHERE body_sha256=?1",
                [&deleted_body_sha256],
            )
            .unwrap();
            c.execute("UPDATE stage_meta SET body=?1 WHERE id=1", [&prefix_body])
                .unwrap();
            c.execute(
                "UPDATE events SET id = 100 WHERE id = (SELECT MAX(id) FROM events)",
                [],
            )
            .unwrap();
            let count: i64 = c
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            let max_id: i64 = c
                .query_row("SELECT MAX(id) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2);
            assert_eq!(max_id, 100);
        }
        let tampered_head = engine
            .chain_head(&tampered, AccessTier::Read)
            .unwrap()
            .expect("tampered prefix still has a head");
        let AuditVerify::Valid(tampered_valid) =
            engine.verify_audit(&tampered, AccessTier::Read).unwrap()
        else {
            panic!("prefix remains HMAC-valid");
        };
        assert_eq!(tampered_head.seq, 2);
        assert_eq!(tampered_head.seq, tampered_valid.events as i64);
        assert_eq!(tampered_head.hmac, tampered_valid.latest);

        engine.core().install_tombstone(&disk).await;
        assert!(matches!(
            engine.chain_head(&disk, AccessTier::Read),
            Err(EngineError::NotFound)
        ));
        engine.core().clear_tombstone(&disk);

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verify_audit_rejects_tampered_live_body() {
        let root = temp_root("verify-live-body");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        let disk = ValidatedWorldPath::new("home/live-body").unwrap();

        engine
            .replace(
                &disk,
                Representation::new(Bytes::from_static(b"good"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let c =
            rusqlite::Connection::open(crate::world::world_db(&engine.core().data, disk.as_str()))
                .unwrap();
        c.execute(
            "UPDATE stage_meta SET body=?1 WHERE id=1",
            [b"bad".as_slice()],
        )
        .unwrap();
        drop(c);

        assert!(matches!(
            engine.verify_audit(&disk, AccessTier::Read).unwrap(),
            AuditVerify::Broken(break_report)
                if break_report.actual.starts_with("live-body-sha256-")
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn verify_audit_rejects_world_db_copied_under_another_name() {
        let root = temp_root("verify-world-target");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        let source = ValidatedWorldPath::new("home/source-world").unwrap();
        let copied = ValidatedWorldPath::new("home/copied-world").unwrap();

        engine
            .replace(
                &source,
                Representation::new(Bytes::from_static(b"same bytes"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let source_dir = crate::world::world_dir(&engine.core().data, source.as_str());
        let copied_dir = crate::world::world_dir(&engine.core().data, copied.as_str());
        std::fs::create_dir_all(&copied_dir).unwrap();
        for entry in std::fs::read_dir(&source_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), copied_dir.join(entry.file_name())).unwrap();
            }
        }

        assert!(matches!(
            engine.verify_audit(&copied, AccessTier::Read).unwrap(),
            AuditVerify::Broken(break_report)
                if break_report.expected == "target-home/copied-world"
                    && break_report.actual == "target-home/source-world"
        ));

        drop(engine);
        let _ = std::fs::remove_dir_all(root);
    }
}
