//! Protocol-neutral Engine introspection surface.
//!
//! This module owns the typed snapshots behind generated `proc/*` surfaces.
//! Engine returns structured data; adapters choose their own rendering.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use std::{fmt, sync::atomic::Ordering};

use crate::{
    auth, blocking_sqlite,
    chain_stamp::{ChainSeq, ChainStampRead},
    engine::{Engine, EngineError},
    engine_ops::{log_storage_error, EngineOps},
    engine_types::{AccessTier, ValidatedWorldPath, ValidatedWorldPrefix},
    state::FileOpPermit,
    store, world,
    world_generation::WorldGeneration,
    AuthGate, StorageFailureClass,
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
    audit_stamp_seq: Option<ChainSeq>,
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
    /// Return a single world's verified audit chain head.
    AuditHead,
    /// Return the verified audit-chain stamp at one chain ordinal.
    AuditStamp,
}

/// One world-size row for engine introspection.
#[non_exhaustive]
pub struct WorldUsage {
    /// Canonical world path.
    pub world: ValidatedWorldPath,
    /// Total accounted body bytes for this world.
    ///
    /// Durable worlds count the current body plus retained historical CAS
    /// bodies. In-memory worlds count only the current body.
    pub bytes: usize,
    /// Current body bytes.
    pub current_body_bytes: usize,
    /// Retained historical CAS body bytes. Always `0` for in-memory worlds.
    pub retained_cas_body_bytes: usize,
    /// Audit chain rows in this world. Always `0` for in-memory worlds.
    pub audit_chain_events: usize,
}

/// Aggregate storage/memory snapshot.
///
/// Returned by [`crate::Engine::df`]. Quotas of `0`/`None` mean "unlimited";
/// adapters should render that string for operator-facing output.
#[non_exhaustive]
pub struct DfSnapshot {
    /// Total accounted durable body bytes.
    ///
    /// This is the quota-bearing sum of current durable bodies and retained
    /// historical CAS bodies. SQLite file/WAL/index overhead is deliberately
    /// not guessed here.
    pub storage_used: usize,
    /// Current durable body bytes.
    pub storage_current_body_bytes: usize,
    /// Retained historical CAS body bytes.
    pub storage_retained_cas_body_bytes: usize,
    /// Durable audit-chain row count across all worlds.
    pub storage_audit_chain_events: usize,
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
/// When the chain verifies, `generation` equals the world's current durable
/// incarnation, `seq` equals [`AuditValid::events`], and `hmac` equals
/// [`AuditValid::latest`]. `seq` is not a raw SQLite rowid; rowids are mutable
/// storage detail, not an anchoring contract.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStamp {
    /// Durable world incarnation that owns this chain head.
    pub generation: WorldGeneration,
    /// Number of events currently on the chain.
    pub seq: i64,
    /// Chain HMAC of the newest event.
    pub hmac: String,
}

struct IntrospectionPermit {
    path: ValidatedProcPath,
    _file_op: FileOpPermit,
}

impl ValidatedProcPath {
    /// Parses a wire-shaped proc path into a sealed endpoint identity.
    ///
    /// Accepts `proc/version`, `proc/worlds`, `proc/du`, `proc/df`,
    /// `proc/pool`, `proc/audit/<world>/verify`, `proc/audit/<world>/head`, or
    /// `proc/audit/<world>/stamp/<seq>`. Leading and trailing slashes are tolerated.
    /// The audit world segment must already be a
    /// canonical Engine path such as `home/foo`; bare names like `foo`, wire
    /// paths like `/home/foo`, and generated `proc/*` worlds are rejected.
    ///
    /// # Errors
    /// Returns [`InvalidProcPath`] if the input is not one of the declared
    /// endpoints, or if the audit world fails canonical-path validation.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, InvalidProcPath> {
        let raw = raw.as_ref().trim_matches('/');
        match raw {
            "proc/version" => Ok(Self::version()),
            "proc/worlds" => Ok(Self::worlds()),
            "proc/du" => Ok(Self::du()),
            "proc/df" => Ok(Self::df()),
            "proc/pool" => Ok(Self::pool()),
            _ => {
                let (world, endpoint, stamp_seq) = if let Some(world) = raw
                    .strip_prefix("proc/audit/")
                    .and_then(|value| value.strip_suffix("/verify"))
                {
                    (world, ProcEndpoint::AuditVerify, None)
                } else if let Some(world) = raw
                    .strip_prefix("proc/audit/")
                    .and_then(|value| value.strip_suffix("/head"))
                {
                    (world, ProcEndpoint::AuditHead, None)
                } else if let Some(value) = raw.strip_prefix("proc/audit/") {
                    let Some((world, raw_seq)) = value.rsplit_once("/stamp/") else {
                        return Err(InvalidProcPath);
                    };
                    let stamp_seq = parse_proc_chain_seq(raw_seq)?;
                    (world, ProcEndpoint::AuditStamp, Some(stamp_seq))
                } else {
                    return Err(InvalidProcPath);
                };
                if world.trim_matches('/').is_empty()
                    || world.starts_with('/')
                    || world.ends_with('/')
                    || world.contains("//")
                {
                    return Err(InvalidProcPath);
                }
                let world = ValidatedWorldPath::from_canonical(world.to_owned())
                    .map_err(|_| InvalidProcPath)?;
                Ok(match endpoint {
                    ProcEndpoint::AuditVerify => Self::audit_verify(world),
                    ProcEndpoint::AuditHead => Self::audit_head(world),
                    ProcEndpoint::AuditStamp => {
                        let stamp_seq = stamp_seq.ok_or(InvalidProcPath)?;
                        Self::audit_stamp(world, stamp_seq)
                    }
                    _ => return Err(InvalidProcPath),
                })
            }
        }
    }

    /// Returns the proof token for the `version` endpoint.
    pub fn version() -> Self {
        Self {
            endpoint: ProcEndpoint::Version,
            audit_world: None,
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for the `worlds` endpoint.
    pub fn worlds() -> Self {
        Self {
            endpoint: ProcEndpoint::Worlds,
            audit_world: None,
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for the `du` endpoint.
    pub fn du() -> Self {
        Self {
            endpoint: ProcEndpoint::Du,
            audit_world: None,
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for the `df` endpoint.
    pub fn df() -> Self {
        Self {
            endpoint: ProcEndpoint::Df,
            audit_world: None,
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for the `pool` endpoint.
    pub fn pool() -> Self {
        Self {
            endpoint: ProcEndpoint::Pool,
            audit_world: None,
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for an `audit verify` operation against a
    /// specific world.
    pub fn audit_verify(world: ValidatedWorldPath) -> Self {
        Self {
            endpoint: ProcEndpoint::AuditVerify,
            audit_world: Some(world),
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for an `audit head` operation against a
    /// specific world.
    pub fn audit_head(world: ValidatedWorldPath) -> Self {
        Self {
            endpoint: ProcEndpoint::AuditHead,
            audit_world: Some(world),
            audit_stamp_seq: None,
        }
    }

    /// Returns the proof token for an `audit stamp` operation against a
    /// specific world and chain ordinal.
    pub fn audit_stamp(world: ValidatedWorldPath, seq: ChainSeq) -> Self {
        Self {
            endpoint: ProcEndpoint::AuditStamp,
            audit_world: Some(world),
            audit_stamp_seq: Some(seq),
        }
    }

    pub(crate) fn endpoint(&self) -> ProcEndpoint {
        self.endpoint
    }

    pub(crate) fn audit_world(&self) -> Option<&ValidatedWorldPath> {
        self.audit_world.as_ref()
    }

    pub(crate) fn audit_stamp_seq(&self) -> Option<ChainSeq> {
        self.audit_stamp_seq
    }
}

fn parse_proc_chain_seq(raw: &str) -> Result<ChainSeq, InvalidProcPath> {
    if raw.is_empty()
        || raw.starts_with('+')
        || raw.starts_with('-')
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InvalidProcPath);
    }
    let seq = raw.parse::<i64>().map_err(|_| InvalidProcPath)?;
    ChainSeq::new(seq).map_err(|_| InvalidProcPath)
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
        sort_dedup_worlds(&mut names);
        Ok(names)
    }

    pub(crate) fn list_worlds_with_prefix(
        &self,
        prefix: &ValidatedWorldPrefix,
        tier: auth::Tier,
    ) -> Result<Vec<ValidatedWorldPath>, EngineError> {
        if !crate::can_read(self.core(), tier) {
            return Err(EngineError::Auth(AuthGate::Read));
        }
        let _file_op = self
            .core()
            .begin_file_op()
            .ok_or(EngineError::ShuttingDown)?;
        let mut names = world::list_with_prefix(&self.core().data, prefix).map_err(|err| {
            storage_error_to_engine("worlds prefix", err, "list_worlds_with_prefix", None)
        })?;
        names.extend(self.core().mem.list_with_prefix(prefix));
        sort_dedup_worlds(&mut names);
        Ok(names)
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
        let _file_op = self
            .core()
            .begin_file_op()
            .ok_or(EngineError::ShuttingDown)?;
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
        sort_dedup_worlds(&mut names);
        if names.len() > max {
            return Ok(None);
        }
        Ok(Some(names))
    }

    pub(crate) fn du(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<Vec<WorldUsage>, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::Du)?;
        let mut sizes = world::usages(&self.core().data, &permit._file_op)
            .map_err(|err| storage_error_to_engine("proc du", err, "du", None))?;
        sizes.extend(self.core().mem.sizes().into_iter().map(|(world, bytes)| {
            (
                world,
                world::StorageUsageSnapshot::from_current_body_bytes(bytes),
            )
        }));
        sizes.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        sizes.dedup_by(|a, b| a.0 == b.0);
        Ok(sizes
            .into_iter()
            .map(|(world, usage)| WorldUsage {
                world,
                bytes: usage.total_body_bytes(),
                current_body_bytes: usage.current_body_bytes(),
                retained_cas_body_bytes: usage.retained_cas_body_bytes(),
                audit_chain_events: usage.audit_chain_events(),
            })
            .collect())
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
        let storage_current_body_bytes = self
            .core()
            .storage_current_body_bytes
            .load(Ordering::Relaxed);
        let storage_retained_cas_body_bytes = self
            .core()
            .storage_retained_cas_body_bytes
            .load(Ordering::Relaxed);
        let storage_audit_chain_events = self
            .core()
            .storage_audit_chain_events
            .load(Ordering::Relaxed);
        let durable_worlds = self
            .core()
            .durable_world_count
            .load(Ordering::Relaxed)
            .saturating_sub(usize::from(
                self.core().delete_ledger_created.load(Ordering::Relaxed),
            ));
        Ok(DfSnapshot {
            storage_used,
            storage_current_body_bytes,
            storage_retained_cas_body_bytes,
            storage_audit_chain_events,
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
        match blocking_sqlite::run_scoped(|proof| {
            self.core()
                .cached_verify_chain(proof, world, &permit._file_op)
        }) {
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
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<Option<HeadStamp>, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::AuditHead)?;
        let world = permit
            .path
            .audit_world()
            .ok_or(EngineError::InternalInvariant("audit head missing world"))?;
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            if !self.core().mem.contains(memory_world) {
                return Err(EngineError::NotFound);
            }
            // Memory worlds have no audit chain: nothing to anchor.
            return Ok(None);
        }
        match blocking_sqlite::run_scoped(|proof| {
            self.core()
                .cached_chain_head(proof, world, &permit._file_op)
        }) {
            Ok(Some(Ok(Some(head)))) => Ok(Some(HeadStamp {
                generation: head.generation().clone(),
                seq: head.seq(),
                hmac: head.hmac().to_owned(),
            })),
            // Existing DB with an empty chain (bootstrap shape): nothing to
            // anchor yet.
            Ok(Some(Ok(None))) => Ok(None),
            Ok(Some(Err(crate::audit::AuditError::ChainBroken(break_report)))) => {
                crate::engine_error::log_audit_chain_error(
                    "chain head",
                    &break_report,
                    "chain_head",
                    Some(world.as_str()),
                );
                Err(EngineError::Storage)
            }
            Ok(Some(Err(crate::audit::AuditError::Storage(err)))) | Err(err) => Err(
                storage_error_to_engine("chain head", err, "chain_head", Some(world.as_str())),
            ),
            Ok(None) => Err(EngineError::NotFound),
        }
    }

    pub(crate) fn chain_stamp(
        &self,
        path: &ValidatedProcPath,
        tier: auth::Tier,
    ) -> Result<Option<ChainStampRead>, EngineError> {
        let permit = self.authorize_introspection(path, tier)?;
        ensure_proc_endpoint(&permit, ProcEndpoint::AuditStamp)?;
        let world = permit
            .path
            .audit_world()
            .ok_or(EngineError::InternalInvariant("audit stamp missing world"))?;
        let seq = permit
            .path
            .audit_stamp_seq()
            .ok_or(EngineError::InternalInvariant("audit stamp missing seq"))?;
        if let Some(memory_world) = store::MemoryWorldPath::new(world) {
            if !self.core().mem.contains(memory_world) {
                return Err(EngineError::NotFound);
            }
            return Ok(None);
        }
        match blocking_sqlite::run_scoped(|proof| {
            self.core()
                .cached_chain_stamp(proof, world, seq, &permit._file_op)
        }) {
            Ok(Some(Ok(stamp))) => Ok(Some(stamp)),
            Ok(Some(Err(crate::audit::AuditError::ChainBroken(break_report)))) => {
                crate::engine_error::log_audit_chain_error(
                    "chain stamp",
                    &break_report,
                    "chain_stamp",
                    Some(world.as_str()),
                );
                Err(EngineError::Storage)
            }
            Ok(Some(Err(crate::audit::AuditError::Storage(err)))) | Err(err) => Err(
                storage_error_to_engine("chain stamp", err, "chain_stamp", Some(world.as_str())),
            ),
            Ok(None) => Err(EngineError::NotFound),
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
        let file_op = self
            .core()
            .begin_file_op()
            .ok_or(EngineError::ShuttingDown)?;
        Ok(IntrospectionPermit {
            path: path.clone(),
            _file_op: file_op,
        })
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
    /// This is a synchronous API: it verifies the chain through the cached
    /// read path, then returns the current event count and newest event HMAC.
    /// [`HeadStamp::generation`] names the current durable incarnation,
    /// [`HeadStamp::seq`] equals [`AuditValid::events`], and
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
    /// This method mints the same proc-path proof used by the HTTP adapter.
    /// Adapter endpoints still perform their own route-level validation and
    /// blocking-boundary discipline before rendering `/proc/audit/<world>/head`.
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
        let path = ValidatedProcPath::audit_head(world.clone());
        EngineOps::new(self.core()).chain_head(&path, tier.into())
    }

    /// Returns the verified audit-chain stamp at a specific chain ordinal.
    ///
    /// This is a synchronous API: it verifies the chain through the cached
    /// read path and captures the requested ordinal's HMAC from that same
    /// verifier walk. It never resolves the stamp by SQLite row id.
    ///
    /// # Returns
    /// - `Ok(Some(ChainStampRead::Found(_)))` if the requested ordinal exists.
    /// - `Ok(Some(ChainStampRead::Missing(_)))` if the durable chain verified
    ///   but is shorter than `seq`.
    /// - `Ok(None)` if the world exists but has no durable audit chain.
    ///
    /// # Errors
    /// - [`EngineError::Auth`] if `tier` is below `Read`.
    /// - [`EngineError::NotFound`] if `world` does not exist.
    /// - [`EngineError::TransientStorage`] / [`EngineError::Storage`] /
    ///   [`EngineError::InsufficientStorage`] for storage failures.
    pub fn chain_stamp(
        &self,
        world: &ValidatedWorldPath,
        seq: ChainSeq,
        tier: AccessTier,
    ) -> Result<Option<ChainStampRead>, EngineError> {
        let path = ValidatedProcPath::audit_stamp(world.clone(), seq);
        EngineOps::new(self.core()).chain_stamp(&path, tier.into())
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

fn sort_dedup_worlds(worlds: &mut Vec<ValidatedWorldPath>) {
    worlds.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    worlds.dedup();
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
        chain_stamp::{ChainSeq, ChainStampRead},
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
            "auditedb-engine-introspection-{name}-{}-{nonce}",
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
        let audit_verify = ValidatedProcPath::new("proc/audit/home/foo/verify").unwrap();
        assert_eq!(audit_verify.endpoint(), ProcEndpoint::AuditVerify);
        assert_eq!(audit_verify.audit_world().unwrap().as_str(), "home/foo");
        let audit_head = ValidatedProcPath::new("proc/audit/home/foo/head").unwrap();
        assert_eq!(audit_head.endpoint(), ProcEndpoint::AuditHead);
        assert_eq!(audit_head.audit_world().unwrap().as_str(), "home/foo");
        let audit_stamp = ValidatedProcPath::new("proc/audit/home/foo/stamp/7").unwrap();
        assert_eq!(audit_stamp.endpoint(), ProcEndpoint::AuditStamp);
        assert_eq!(audit_stamp.audit_world().unwrap().as_str(), "home/foo");
        assert_eq!(audit_stamp.audit_stamp_seq().unwrap().get(), 7);

        assert!(ValidatedProcPath::new("proc").is_err());
        assert!(ValidatedProcPath::new("proc/nope").is_err());
        assert!(ValidatedProcPath::new("proc/audit/foo/verify").is_err());
        assert!(ValidatedProcPath::new("proc/audit//verify").is_err());
        assert!(ValidatedProcPath::new("proc/audit/proc/version/verify").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/0").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/-1").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/+1").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/01").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/1x").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home/foo/stamp/9223372036854775808").is_err());
        assert!(ValidatedProcPath::new("proc/audit/home//foo/stamp/1").is_err());
        assert!(ValidatedProcPath::new("proc/audit/proc/version/stamp/1").is_err());
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
        assert!(usage.iter().any(|row| {
            row.world == disk
                && row.bytes == b"hello".len() * 2
                && row.current_body_bytes == b"hello".len()
                && row.retained_cas_body_bytes == b"hello".len()
                && row.audit_chain_events == 2
        }));
        assert!(usage.iter().any(|row| {
            row.world == memory
                && row.bytes == b"hello".len()
                && row.current_body_bytes == b"hello".len()
                && row.retained_cas_body_bytes == 0
                && row.audit_chain_events == 0
        }));

        let df = engine.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, b"hello".len() * 2);
        assert_eq!(df.storage_current_body_bytes, b"hello".len());
        assert_eq!(df.storage_retained_cas_body_bytes, b"hello".len());
        assert_eq!(df.storage_audit_chain_events, 2);
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
    async fn df_split_counters_are_seeded_from_existing_worlds_on_build() {
        let root = temp_root("df-split-rebuild");
        let world = ValidatedWorldPath::new("home/df-split-rebuild").unwrap();
        {
            let engine = Engine::builder()
                .data_root(root.clone())
                .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
                .retained_body_count(1)
                .build()
                .unwrap();
            for body in [b"old".as_slice(), b"new".as_slice()] {
                engine
                    .replace(
                        &world,
                        Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                        Preconditions::none(),
                        AccessTier::Write,
                    )
                    .await
                    .unwrap();
            }
        }

        let rebuilt = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .retained_body_count(1)
            .build()
            .unwrap();
        let df = rebuilt.df(AccessTier::Read).unwrap();
        assert_eq!(df.storage_used, 6);
        assert_eq!(df.storage_current_body_bytes, 3);
        assert_eq!(df.storage_retained_cas_body_bytes, 3);
        assert_eq!(df.storage_audit_chain_events, 3);

        let usage = rebuilt.du(AccessTier::Read).unwrap();
        assert!(usage.iter().any(|row| {
            row.world == world
                && row.bytes == 6
                && row.current_body_bytes == 3
                && row.retained_cas_body_bytes == 3
                && row.audit_chain_events == 3
        }));

        drop(rebuilt);
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
        let deleted_for_log = ValidatedWorldPath::new("home/deleted-for-log").unwrap();

        for (world, tier) in [
            (&disk_sensor, AccessTier::Write),
            (&disk_other, AccessTier::Write),
            (&memory_sensor, AccessTier::Write),
            (&deleted_for_log, AccessTier::Write),
        ] {
            engine
                .replace(
                    world,
                    Representation::new(Bytes::from_static(b"v"), "text/plain", Vec::new()),
                    Preconditions::none(),
                    tier,
                )
                .await
                .unwrap();
        }
        engine
            .delete(&deleted_for_log, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();

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

        let prefix_cases = [
            (
                "home",
                vec!["home/other".to_string(), "home/sensor/temp".to_string()],
            ),
            (
                "home/",
                vec!["home/other".to_string(), "home/sensor/temp".to_string()],
            ),
            ("tmp", vec!["tmp/sensor/temp".to_string()]),
            ("tmp/", vec!["tmp/sensor/temp".to_string()]),
            ("var/log", vec!["var/log/deletes".to_string()]),
        ];
        for (prefix, expected) in prefix_cases {
            let listed = engine
                .list_worlds_with_prefix(prefix, AccessTier::Read)
                .unwrap();
            assert_eq!(to_names(listed.clone()), expected, "{prefix}");
            assert_eq!(
                engine
                    .list_worlds_with_prefix_bounded(prefix, AccessTier::Read, 10)
                    .unwrap(),
                Some(listed),
                "{prefix}"
            );
        }

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
    async fn engine_world_listing_returns_sorted_unique_durable_and_memory_names() {
        let root = temp_root("world-listing");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        let disk_b = ValidatedWorldPath::new("home/b").unwrap();
        let disk_tmp = ValidatedWorldPath::new("tmp/dup").unwrap();

        crate::world::write_with_audit(
            &engine.core().data,
            &disk_b,
            b"disk",
            "text/plain",
            &[],
            &engine.core().hmac_key,
        )
        .unwrap();
        crate::world::write_with_audit(
            &engine.core().data,
            &disk_tmp,
            b"legacy-disk-tmp",
            "text/plain",
            &[],
            &engine.core().hmac_key,
        )
        .unwrap();
        engine
            .replace(
                &ValidatedWorldPath::new("tmp/a").unwrap(),
                Representation::new(Bytes::from_static(b"mem"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .replace(
                &ValidatedWorldPath::new("tmp/dup").unwrap(),
                Representation::new(Bytes::from_static(b"mem"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let names = engine
            .list_worlds(AccessTier::Read)
            .unwrap()
            .into_iter()
            .map(|world| world.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "home/b".to_string(),
                "tmp/a".to_string(),
                "tmp/dup".to_string()
            ]
        );

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
        let disk_generation = crate::world_schema::generation(
            &rusqlite::Connection::open(crate::world::world_db(&engine.core().data, disk.as_str()))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(head.generation, disk_generation);
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
        assert_eq!(advanced.generation, head.generation);
        assert_eq!(advanced.seq, head.seq + 1);
        assert_ne!(advanced.hmac, head.hmac);

        // Delete + recreate is a new durable incarnation even if the visible
        // chain length returns to the same small number.
        let recreated = ValidatedWorldPath::new("home/anchored-recreated").unwrap();
        engine
            .replace(
                &recreated,
                Representation::new(Bytes::from_static(b"first"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let before_recreate = engine
            .chain_head(&recreated, AccessTier::Read)
            .unwrap()
            .expect("first incarnation has a head");
        engine
            .delete(&recreated, Preconditions::none(), AccessTier::Approve)
            .await
            .unwrap();
        engine
            .replace(
                &recreated,
                Representation::new(Bytes::from_static(b"second"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let after_recreate = engine
            .chain_head(&recreated, AccessTier::Read)
            .unwrap()
            .expect("second incarnation has a head");
        assert_ne!(after_recreate.generation, before_recreate.generation);
        assert_eq!(after_recreate.seq, before_recreate.seq);

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
                     WHERE body_sha256 = (SELECT body_sha256 FROM events WHERE id=3)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let deleted_body_sha256: String = c
                .query_row("SELECT body_sha256 FROM events WHERE id=4", [], |row| {
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
            assert_eq!(count, 3);
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
        assert_eq!(tampered_head.seq, 3);
        assert_eq!(tampered_head.seq, tampered_valid.events as i64);
        assert_eq!(tampered_head.hmac, tampered_valid.latest);
        assert_ne!(tampered_head.generation, head.generation);

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
    async fn chain_stamp_resolves_verified_ordinal_without_trusting_rowid() {
        let root = temp_root("chain-stamp");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .read_token(b"reader".to_vec())
            .build()
            .unwrap();
        let disk = ValidatedWorldPath::new("home/stamped").unwrap();
        let memory = ValidatedWorldPath::new("tmp/stamped").unwrap();

        assert!(matches!(
            engine.chain_stamp(&disk, ChainSeq::new(1).unwrap(), AccessTier::Anon),
            Err(EngineError::Auth(AuthGate::Read))
        ));
        assert!(matches!(
            engine.chain_stamp(&disk, ChainSeq::new(1).unwrap(), AccessTier::Read),
            Err(EngineError::NotFound)
        ));

        engine
            .replace(
                &disk,
                Representation::new(Bytes::from_static(b"one"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        engine
            .replace(
                &disk,
                Representation::new(Bytes::from_static(b"two"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let head_at_two = engine
            .chain_head(&disk, AccessTier::Read)
            .unwrap()
            .expect("second write has a head");

        engine
            .replace(
                &disk,
                Representation::new(Bytes::from_static(b"three"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let current_head = engine
            .chain_head(&disk, AccessTier::Read)
            .unwrap()
            .expect("third write has a head");

        let stamp = engine
            .chain_stamp(
                &disk,
                ChainSeq::new(head_at_two.seq).unwrap(),
                AccessTier::Read,
            )
            .unwrap()
            .expect("durable world has audit chain");
        match stamp {
            ChainStampRead::Found(stamp) => {
                assert_eq!(stamp.generation(), &head_at_two.generation);
                assert_eq!(stamp.seq().get(), head_at_two.seq);
                assert_eq!(stamp.hmac().as_str(), head_at_two.hmac);
            }
            ChainStampRead::Missing(_) => panic!("anchored ordinal should exist"),
        }

        let missing_seq = ChainSeq::new(current_head.seq + 7).unwrap();
        let missing = engine
            .chain_stamp(&disk, missing_seq, AccessTier::Read)
            .unwrap()
            .expect("durable world has audit chain");
        match missing {
            ChainStampRead::Missing(missing) => {
                assert_eq!(missing.generation(), &current_head.generation);
                assert_eq!(missing.requested(), missing_seq);
                assert_eq!(missing.observed().get(), current_head.seq as usize);
            }
            ChainStampRead::Found(_) => panic!("future ordinal should be missing"),
        }

        rusqlite::Connection::open(crate::world::world_db(&engine.core().data, disk.as_str()))
            .unwrap()
            .execute(
                "UPDATE events SET id=100 WHERE id=(SELECT MAX(id) FROM events)",
                [],
            )
            .unwrap();
        let stamp_after_rowid_tamper = engine
            .chain_stamp(
                &disk,
                ChainSeq::new(current_head.seq).unwrap(),
                AccessTier::Read,
            )
            .unwrap()
            .expect("durable world has audit chain");
        match stamp_after_rowid_tamper {
            ChainStampRead::Found(stamp) => {
                assert_eq!(stamp.seq().get(), current_head.seq);
                assert_eq!(stamp.hmac().as_str(), current_head.hmac);
            }
            ChainStampRead::Missing(_) => {
                panic!("latest ordinal should ignore SQLite rowid tamper")
            }
        }
        let rowid_is_not_ordinal = engine
            .chain_stamp(&disk, ChainSeq::new(100).unwrap(), AccessTier::Read)
            .unwrap()
            .expect("durable world has audit chain");
        match rowid_is_not_ordinal {
            ChainStampRead::Missing(missing) => {
                assert_eq!(missing.requested().get(), 100);
                assert_eq!(missing.observed().get(), current_head.seq as usize);
            }
            ChainStampRead::Found(_) => panic!("rowid 100 must not become chain ordinal 100"),
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
        assert_eq!(
            engine
                .chain_stamp(&memory, ChainSeq::new(1).unwrap(), AccessTier::Read)
                .unwrap(),
            None
        );
        let missing_memory = ValidatedWorldPath::new("tmp/stamped-missing").unwrap();
        assert!(matches!(
            engine.chain_stamp(&missing_memory, ChainSeq::new(1).unwrap(), AccessTier::Read),
            Err(EngineError::NotFound)
        ));
    }
    #[tokio::test]
    async fn chain_head_rejects_broken_chain_instead_of_minting_head() {
        let root = temp_root("chain-head-broken");
        let engine = Engine::builder()
            .data_root(root.clone())
            .key(AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap())
            .build()
            .unwrap();
        let world = ValidatedWorldPath::new("home/chain-head-broken").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"hello"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let db = crate::world::world_db(&engine.core().data, world.as_str());
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();
        drop(conn);

        assert!(matches!(
            engine.chain_head(&world, AccessTier::Read),
            Err(EngineError::Storage)
        ));

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
