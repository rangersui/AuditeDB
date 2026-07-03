//! Protocol-neutral world transitions.
//!
//! This module owns disk-side replace / append semantics:
//! auth permits, body caps, per-world locks, tombstone clearing,
//! preconditions, quota reservation, durable+memory writes, audit,
//! and notify. It deliberately returns semantic outcomes instead of wire
//! adapter outputs. Adapters map these outcomes onto their own shape.
//!
//! Not here: adapter operation lifecycles, stream rendering, or delete (which
//! has a distinct intent/commit ledger protocol).

use std::sync::{atomic::Ordering, Arc};

use bytes::Bytes;

use crate::{
    audit, auth, blocking_sqlite,
    engine_types::{ChangeVerb, ValidatedRepresentationMetadata, ValidatedWorldPath},
    etag, event, store,
    subscription_event_id::ChangeTarget,
    timeline::BodySha256,
    world, AuthGate, Core, StorageFailureClass,
};

#[derive(Clone, Debug)]
pub(crate) struct WritePermit {
    world: ValidatedWorldPath,
    gate: AuthGate,
}

#[derive(Debug)]
pub(crate) struct ReplaceRequest {
    pub(crate) body: Bytes,
    metadata: ValidatedRepresentationMetadata,
    pub(crate) preconditions: etag::Preconditions,
}

#[derive(Debug)]
pub(crate) struct AppendRequest {
    pub(crate) body: Bytes,
    pub(crate) preconditions: etag::Preconditions,
}

impl ReplaceRequest {
    pub(crate) fn new(
        body: Bytes,
        content_type: String,
        headers: Vec<(String, String)>,
        preconditions: etag::Preconditions,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            body,
            metadata: ValidatedRepresentationMetadata::new(content_type, headers)?,
            preconditions,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteStatusKind {
    Created,
    Updated,
}

#[derive(Debug)]
pub(crate) struct WriteOutcome {
    pub(crate) status_kind: WriteStatusKind,
    pub(crate) etag: String,
}

#[derive(Debug)]
pub(crate) enum WriteError {
    Auth(AuthGate),
    AppendOnly,
    PayloadTooLarge {
        max: usize,
    },
    PreconditionFailed {
        message: &'static str,
    },
    /// Only `append_write` returns this; replace creates if absent.
    NotFound,
    QuotaExceeded {
        used: usize,
        quota: usize,
        projected: usize,
    },
    TransientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
        #[allow(dead_code)]
        op: StorageOp,
    },
    InsufficientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
        #[allow(dead_code)]
        op: StorageOp,
    },
    StorageRead {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageWriteAudit {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageInvariant(StorageInvariantReason),
    AuditChainBroken {
        #[allow(dead_code)]
        scope: &'static str,
        break_report: audit::VerifyBreak,
    },
    ShuttingDown,
    Internal(&'static str),
}

#[derive(Debug)]
pub(crate) enum StorageInvariantReason {
    CasBodyMismatch(BodySha256),
    CasState(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageOp {
    Read,
    WriteAudit,
}

pub(crate) trait WriteTraceHooks: Send + Sync {
    fn lock_acquired(&self) {}
    fn quota_check(&self, _used: usize, _quota: usize) {}
    fn sqlite_committed(&self, _etag: &str) {}
    fn notify_sent(&self) {}
}

pub(crate) fn authorize_write(
    world: &ValidatedWorldPath,
    tier: auth::Tier,
) -> Result<WritePermit, WriteError> {
    let gate = if needs_write_approve(world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if can_write(world, tier) {
        if is_append_only_world(world) {
            return Err(WriteError::AppendOnly);
        }
        Ok(WritePermit {
            world: world.clone(),
            gate,
        })
    } else {
        Err(WriteError::Auth(gate))
    }
}

fn is_append_only_world(world: &ValidatedWorldPath) -> bool {
    crate::ledger::is_delete_ledger_world(world)
}

fn can_write(world: &ValidatedWorldPath, tier: auth::Tier) -> bool {
    // Harvard gate: children under lib/etc/boot/usr and var/log
    // descendants require approve. home/tmp/dev/sys and non-log var
    // worlds accept the normal token. Anon refused.
    let needs_approve = needs_write_approve(world);
    match tier {
        auth::Tier::Anon => false,
        auth::Tier::Read => false,
        auth::Tier::Write => !needs_approve,
        auth::Tier::Approve => true,
    }
}

fn needs_write_approve(world: &ValidatedWorldPath) -> bool {
    exact_or_child(world, "lib")
        || exact_or_child(world, "etc")
        || exact_or_child(world, "boot")
        || exact_or_child(world, "usr")
        || exact_or_child(world, "var/log")
}

fn exact_or_child(world: &ValidatedWorldPath, prefix: &str) -> bool {
    let world_name = world.as_str();
    world_name == prefix
        || world_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) async fn replace_write(
    core: Arc<Core>,
    permit: WritePermit,
    req: ReplaceRequest,
    hooks: Arc<dyn WriteTraceHooks>,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(&permit)?;
    let world_path = permit.world.clone();
    if req.body.len() > core.max_world_bytes {
        return Err(WriteError::PayloadTooLarge {
            max: core.max_world_bytes,
        });
    }

    let write_guard = core.acquire_world_lock(&world_path).await;
    hooks.lock_acquired();
    crate::blocking_sqlite::run(move |proof| {
        replace_write_blocking(proof, core, permit, req, hooks, write_guard)
    })
    .await
    .map_err(|_| WriteError::Internal("blocking sqlite worker failed"))?
}

fn replace_write_blocking(
    proof: &mut blocking_sqlite::BlockingSqlite,
    core: Arc<Core>,
    permit: WritePermit,
    req: ReplaceRequest,
    hooks: Arc<dyn WriteTraceHooks>,
    _write_guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(&permit)?;
    let world_path = &permit.world;
    let file_op = core.begin_file_op().ok_or(WriteError::ShuttingDown)?;
    core.clear_tombstone(world_path);
    check_write_preconditions(
        core.as_ref(),
        proof,
        world_path,
        &req.preconditions,
        &file_op,
    )?;

    let (existed, etag, target, format_notice, aux) = if store::is_persistent(world_path) {
        let reservation = if let Some(quota) = core.max_storage_bytes {
            let prev_len_opt =
                world::body_len(proof, &core.data, world_path, &file_op).map_err(|err| {
                    classify_write_storage_error("storage metadata", err, StorageOp::Read)
                })?;
            let prev_len = prev_len_opt.unwrap_or(0);
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
            let cas_candidate_len =
                world::cas_body_len_if_missing(proof, &core.data, world_path, &req.body, &file_op)
                    .map_err(|err| {
                        classify_write_storage_error("storage/cas", err, StorageOp::Read)
                    })?;
            let prunable_cas_len = world::prunable_cas_body_len_after_next_write(
                proof,
                &core.data,
                world_path,
                &req.body,
                core.retained_body_count,
                &file_op,
            )
            .map_err(|err| classify_write_storage_error("storage/cas", err, StorageOp::Read))?;
            let reserve_new_len = req.body.len().saturating_add(cas_candidate_len);
            if let Err(quota) =
                core.reserve_storage_after_prune(prev_len, reserve_new_len, prunable_cas_len)
            {
                return Err(WriteError::QuotaExceeded {
                    used: quota.used,
                    quota: quota.quota,
                    projected: quota.projected,
                });
            }
            Some((
                prev_len,
                cas_candidate_len,
                prunable_cas_len,
                reserve_new_len,
            ))
        } else {
            None
        };
        let write_conn = core
            .cached_write_conn(proof, &permit.world, &file_op)
            .map_err(|err| classify_write_storage_error("storage/audit", err, StorageOp::Read))?;
        let mut write_conn = write_conn
            .lock()
            .map_err(|_| WriteError::Internal("writer connection lock poisoned"))?;
        match world::write_with_audit_checked_retaining_on_conn(
            proof,
            &mut write_conn,
            &permit.world,
            &req.body,
            req.metadata.content_type(),
            req.metadata.headers(),
            &core.hmac_key,
            core.retained_body_count,
        ) {
            Ok(result) => {
                let actual_cas_len = if result.cas_body_inserted {
                    req.body.len()
                } else {
                    0
                };
                let prev_len = reservation
                    .as_ref()
                    .map(|(prev_len, _, _, _)| *prev_len)
                    .unwrap_or(result.previous_len);
                let pruned_cas_len = result.pruned_cas.bytes();
                if reservation.is_none() {
                    let _ = core.reserve_storage_after_prune(
                        prev_len,
                        req.body.len().saturating_add(actual_cas_len),
                        pruned_cas_len,
                    );
                }
                core.note_current_body_replaced(prev_len, req.body.len());
                if let Some((_prev_len, cas_candidate_len, prunable_cas_len, _reserve_new_len)) =
                    reservation
                {
                    if !result.cas_body_inserted {
                        core.rollback_storage_reservation(0, cas_candidate_len);
                    } else {
                        core.note_retained_cas_inserted(cas_candidate_len);
                    }
                    core.credit_pruned_storage_after_estimate(result.pruned_cas, prunable_cas_len);
                } else {
                    core.note_retained_cas_inserted(actual_cas_len);
                    core.credit_pruned_storage_after_estimate(result.pruned_cas, pruned_cas_len);
                }
                let audit_event_count = 1 + usize::from(result.format_event.is_some());
                core.note_audit_events_appended(audit_event_count);
                if !result.existed {
                    core.durable_world_count.fetch_add(1, Ordering::Relaxed);
                }
                let etag = etag::hmac_etag(&result.hmac);
                let format_notice = result.format_event.as_ref().map(format_change_event);
                let target = ChangeTarget::from_appended_body_audit_row(&result.body_event);
                let aux = event::ChangeEventAux::default();
                (result.existed, etag, target, format_notice, aux)
            }
            Err(world::WriteAuditError::Audit(err)) => {
                if let Some((prev_len, _cas_candidate_len, prunable_cas_len, reserve_new_len)) =
                    reservation
                {
                    core.rollback_storage_reservation_after_prune(
                        prev_len,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(classify_write_audit_error("storage/audit", err));
            }
            Err(world::WriteAuditError::Sqlite(err)) => {
                if let Some((prev_len, _cas_candidate_len, prunable_cas_len, reserve_new_len)) =
                    reservation
                {
                    core.rollback_storage_reservation_after_prune(
                        prev_len,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
            Err(world::WriteAuditError::CasBodyMismatch { body_sha256 }) => {
                if let Some((prev_len, _cas_candidate_len, prunable_cas_len, reserve_new_len)) =
                    reservation
                {
                    core.rollback_storage_reservation_after_prune(
                        prev_len,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasBodyMismatch(body_sha256),
                ));
            }
            Err(world::WriteAuditError::StorageInvariant(reason)) => {
                if let Some((prev_len, _cas_candidate_len, prunable_cas_len, reserve_new_len)) =
                    reservation
                {
                    core.rollback_storage_reservation_after_prune(
                        prev_len,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasState(reason),
                ));
            }
        }
    } else {
        let memory_world = store::MemoryWorldPath::new(world_path)
            .ok_or(WriteError::Internal("memory world proof mismatch"))?;
        match core.mem.write_with_quota(
            memory_world,
            &req.body,
            req.metadata.content_type(),
            req.metadata.headers(),
            core.max_memory_bytes,
        ) {
            Ok(outcome) => (
                outcome.existed,
                etag::body_etag(&req.body),
                ChangeTarget::Ephemeral(world_path.clone()),
                None,
                event::ChangeEventAux::default(),
            ),
            Err(store::MemoryQuotaError {
                used,
                quota,
                projected,
            }) => {
                return Err(WriteError::QuotaExceeded {
                    used,
                    quota,
                    projected,
                });
            }
        }
    };

    drop(file_op);
    hooks.sqlite_committed(&etag);
    if let Some((format_etag, format_target, format_aux)) = format_notice {
        core.notify_with_aux(ChangeVerb::Format, format_target, &format_etag, format_aux);
    }
    core.notify_with_aux(ChangeVerb::Replace, target, &etag, aux);
    hooks.notify_sent();
    Ok(WriteOutcome {
        status_kind: if existed {
            WriteStatusKind::Updated
        } else {
            WriteStatusKind::Created
        },
        etag,
    })
}

pub(crate) async fn append_write(
    core: Arc<Core>,
    permit: WritePermit,
    req: AppendRequest,
    hooks: Arc<dyn WriteTraceHooks>,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(&permit)?;
    let world_path = permit.world.clone();
    let write_guard = core.acquire_world_lock(&world_path).await;
    hooks.lock_acquired();
    crate::blocking_sqlite::run(move |proof| {
        append_write_blocking(proof, core, permit, req, hooks, write_guard)
    })
    .await
    .map_err(|_| WriteError::Internal("blocking sqlite worker failed"))?
}

fn append_write_blocking(
    proof: &mut blocking_sqlite::BlockingSqlite,
    core: Arc<Core>,
    permit: WritePermit,
    req: AppendRequest,
    hooks: Arc<dyn WriteTraceHooks>,
    _write_guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(&permit)?;
    let world_path = &permit.world;
    let file_op = core.begin_file_op().ok_or(WriteError::ShuttingDown)?;
    core.clear_tombstone(world_path);
    check_write_preconditions(
        core.as_ref(),
        proof,
        world_path,
        &req.preconditions,
        &file_op,
    )?;

    let memory_world = store::MemoryWorldPath::new(world_path);
    let Some((body_len, content_type, stored_headers)) = (if let Some(memory_world) = memory_world {
        core.mem.metadata(memory_world)
    } else {
        world::metadata(proof, &core.data, world_path, &file_op)
            .map_err(|err| classify_write_storage_error("storage metadata", err, StorageOp::Read))?
    }) else {
        return Err(WriteError::NotFound);
    };
    let Some(projected_len) = body_len.checked_add(req.body.len()) else {
        return Err(WriteError::PayloadTooLarge {
            max: core.max_world_bytes,
        });
    };
    if projected_len > core.max_world_bytes {
        return Err(WriteError::PayloadTooLarge {
            max: core.max_world_bytes,
        });
    }

    let (etag, target, format_notice, aux) = if store::is_persistent(world_path) {
        let reservation = if let Some(quota) = core.max_storage_bytes {
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
            let cas_candidate_len = world::append_cas_body_len_if_missing(
                proof, &core.data, world_path, &req.body, &file_op,
            )
            .map_err(|err| classify_write_storage_error("storage/cas", err, StorageOp::Read))?
            .ok_or(WriteError::NotFound)?;
            let prunable_cas_len = world::append_prunable_cas_body_len_after_next_write(
                proof,
                &core.data,
                world_path,
                &req.body,
                core.retained_body_count,
                &file_op,
            )
            .map_err(|err| classify_write_storage_error("storage/cas", err, StorageOp::Read))?
            .ok_or(WriteError::NotFound)?;
            let reserve_new_len = req.body.len().saturating_add(cas_candidate_len);
            if let Err(quota) =
                core.reserve_storage_after_prune(0, reserve_new_len, prunable_cas_len)
            {
                return Err(WriteError::QuotaExceeded {
                    used: quota.used,
                    quota: quota.quota,
                    projected: quota.projected,
                });
            }
            Some((cas_candidate_len, prunable_cas_len, reserve_new_len))
        } else {
            None
        };
        let Some(write_conn) = core
            .cached_existing_write_conn(proof, &permit.world, &file_op)
            .map_err(|err| classify_write_storage_error("storage/audit", err, StorageOp::Read))?
        else {
            if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                core.rollback_storage_reservation_after_prune(0, reserve_new_len, prunable_cas_len);
            }
            return Err(WriteError::NotFound);
        };
        let mut write_conn = write_conn
            .lock()
            .map_err(|_| WriteError::Internal("writer connection lock poisoned"))?;
        match world::append_with_audit_retaining_on_conn(
            proof,
            &mut write_conn,
            &permit.world,
            &req.body,
            &content_type,
            &stored_headers,
            &core.hmac_key,
            core.retained_body_count,
        ) {
            Ok(Some((result, h))) => {
                let actual_cas_len = if result.cas_body_inserted {
                    projected_len
                } else {
                    0
                };
                let pruned_cas_len = result.pruned_cas.bytes();
                if reservation.is_none() {
                    let _ = core.reserve_storage_after_prune(
                        0,
                        req.body.len().saturating_add(actual_cas_len),
                        pruned_cas_len,
                    );
                }
                core.note_current_body_replaced(body_len, projected_len);
                if let Some((cas_candidate_len, prunable_cas_len, _reserve_new_len)) = reservation {
                    if !result.cas_body_inserted {
                        core.rollback_storage_reservation(0, cas_candidate_len);
                    } else {
                        core.note_retained_cas_inserted(cas_candidate_len);
                    }
                    core.credit_pruned_storage_after_estimate(result.pruned_cas, prunable_cas_len);
                } else {
                    core.note_retained_cas_inserted(actual_cas_len);
                    core.credit_pruned_storage_after_estimate(result.pruned_cas, pruned_cas_len);
                }
                let audit_event_count = 1 + usize::from(result.format_event.is_some());
                core.note_audit_events_appended(audit_event_count);
                let target = ChangeTarget::from_appended_body_audit_row(&result.body_event);
                let aux = event::ChangeEventAux::default();
                let format_notice = result.format_event.as_ref().map(format_change_event);
                (etag::hmac_etag(&h), target, format_notice, aux)
            }
            Ok(None) => {
                if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                    core.rollback_storage_reservation_after_prune(
                        0,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(WriteError::NotFound);
            }
            Err(world::WriteAuditError::Audit(err)) => {
                if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                    core.rollback_storage_reservation_after_prune(
                        0,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(classify_write_audit_error("storage/audit", err));
            }
            Err(world::WriteAuditError::Sqlite(err)) => {
                if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                    core.rollback_storage_reservation_after_prune(
                        0,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
            Err(world::WriteAuditError::CasBodyMismatch { body_sha256 }) => {
                if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                    core.rollback_storage_reservation_after_prune(
                        0,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasBodyMismatch(body_sha256),
                ));
            }
            Err(world::WriteAuditError::StorageInvariant(reason)) => {
                if let Some((_cas_candidate_len, prunable_cas_len, reserve_new_len)) = reservation {
                    core.rollback_storage_reservation_after_prune(
                        0,
                        reserve_new_len,
                        prunable_cas_len,
                    );
                }
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasState(reason),
                ));
            }
        }
    } else {
        let memory_world = store::MemoryWorldPath::new(world_path)
            .ok_or(WriteError::Internal("memory world proof mismatch"))?;
        match core
            .mem
            .append_with_quota(memory_world, &req.body, core.max_memory_bytes)
        {
            Ok(Some(result)) => (
                format!("sha256-{}", result.body_sha256_after),
                ChangeTarget::Ephemeral(world_path.clone()),
                None,
                event::ChangeEventAux::default(),
            ),
            Ok(None) => return Err(WriteError::NotFound),
            Err(store::MemoryQuotaError {
                used,
                quota,
                projected,
            }) => {
                return Err(WriteError::QuotaExceeded {
                    used,
                    quota,
                    projected,
                });
            }
        }
    };

    drop(file_op);
    hooks.sqlite_committed(&etag);
    if let Some((format_etag, format_target, format_aux)) = format_notice {
        core.notify_with_aux(ChangeVerb::Format, format_target, &format_etag, format_aux);
    }
    core.notify_with_aux(ChangeVerb::Append, target, &etag, aux);
    hooks.notify_sent();
    Ok(WriteOutcome {
        status_kind: WriteStatusKind::Updated,
        etag,
    })
}

fn ensure_write_permit(permit: &WritePermit) -> Result<(), WriteError> {
    let expected_gate = if needs_write_approve(&permit.world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if permit.gate != expected_gate {
        return Err(WriteError::Internal("write permit gate mismatch"));
    }
    Ok(())
}

fn format_change_event(
    row: &audit::AppendedAuditRow,
) -> (String, ChangeTarget, event::ChangeEventAux) {
    let etag = etag::hmac_etag(row.hmac());
    let target = ChangeTarget::from_appended_audit_row(row);
    (etag, target, event::ChangeEventAux::default())
}

fn check_write_preconditions(
    core: &Core,
    proof: &mut blocking_sqlite::BlockingSqlite,
    world: &ValidatedWorldPath,
    preconditions: &etag::Preconditions,
    file_op: &crate::state::FileOpPermit,
) -> Result<(), WriteError> {
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(proof, world, file_op)
        .map_err(|err| classify_write_audit_error("precondition read", err))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.as_str());
    etag::check_preconditions(preconditions, current_tag)
        .map_err(|message| WriteError::PreconditionFailed { message })
}

fn classify_write_audit_error(scope: &'static str, err: audit::AuditError) -> WriteError {
    match err {
        audit::AuditError::ChainBroken(break_report) => WriteError::AuditChainBroken {
            scope,
            break_report,
        },
        audit::AuditError::Storage(err) => {
            classify_write_storage_error(scope, err, StorageOp::WriteAudit)
        }
    }
}

fn classify_write_storage_error(
    scope: &'static str,
    err: rusqlite::Error,
    op: StorageOp,
) -> WriteError {
    match crate::classify_storage_failure(&err) {
        StorageFailureClass::InsufficientStorage => {
            WriteError::InsufficientStorage { scope, err, op }
        }
        StorageFailureClass::Transient => WriteError::TransientStorage { scope, err, op },
        StorageFailureClass::Other => match op {
            StorageOp::Read => WriteError::StorageRead { scope, err },
            StorageOp::WriteAudit => WriteError::StorageWriteAudit { scope, err },
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::test_core;

    struct NoopTrace;
    impl WriteTraceHooks for NoopTrace {}

    fn test_hooks() -> Arc<dyn WriteTraceHooks> {
        Arc::new(NoopTrace)
    }

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn replace_req(body: &'static [u8], content_type: &str) -> ReplaceRequest {
        ReplaceRequest::new(
            Bytes::from_static(body),
            content_type.to_owned(),
            Vec::new(),
            etag::Preconditions::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn write_permit_is_bound_to_one_world() {
        let (core, dir) = test_core("permit-bound");
        let core = Arc::new(core);
        let world = world_path("home/permit-a");
        let permit = authorize_write(&world, auth::Tier::Write)
            .expect("write token tier should authorize home writes");
        let req = replace_req(b"right-door", "text/plain; charset=utf-8");

        replace_write(Arc::clone(&core), permit, req, test_hooks())
            .await
            .expect("permit writes only its bound world");

        assert_eq!(
            core.read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/permit-a"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .unwrap()
            .body,
            b"right-door"
        );
        assert!(core
            .read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/permit-b"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn durable_quota_counts_retained_cas_bodies() {
        let (mut core, dir) = test_core("quota-counts-cas");
        core.max_storage_bytes = Some(8);
        let core = Arc::new(core);
        let world = world_path("home/quota-cas");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();

        replace_write(
            Arc::clone(&core),
            permit.clone(),
            replace_req(b"aaaa", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);

        replace_write(
            Arc::clone(&core),
            permit.clone(),
            replace_req(b"aaaa", "application/octet-stream"),
            test_hooks(),
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);

        let err = replace_write(
            Arc::clone(&core),
            permit,
            replace_req(b"bbbb", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::QuotaExceeded { projected: 12, .. }
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);
        assert_eq!(
            core.read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/quota-cas"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .unwrap()
            .body,
            b"aaaa"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn replace_cas_mismatch_rolls_back_storage_reservation() {
        let (core, dir) = test_core("replace-cas-mismatch-accounting");
        let core = Arc::new(core);
        let world = world_path("home/replace-cas-mismatch");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            Arc::clone(&core),
            permit.clone(),
            replace_req(b"old", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap();
        let before = core.storage_body_bytes.load(Ordering::Relaxed);
        assert_eq!(before, 6);
        let c = rusqlite::Connection::open(world::world_db(&dir, world.as_str())).unwrap();
        c.execute_batch(
            r#"CREATE TRIGGER corrupt_new_cas_body
               AFTER INSERT ON cas_bodies
               BEGIN
                   UPDATE cas_bodies SET body=x'00' WHERE body_sha256=NEW.body_sha256;
               END"#,
        )
        .unwrap();

        let err = replace_write(
            Arc::clone(&core),
            permit,
            replace_req(b"new", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::StorageInvariant(StorageInvariantReason::CasBodyMismatch(_))
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), before);
        assert_eq!(
            core.read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/replace-cas-mismatch"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .unwrap()
            .body,
            b"old"
        );
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 2);
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn append_cas_mismatch_rolls_back_storage_reservation() {
        let (core, dir) = test_core("append-cas-mismatch-accounting");
        let core = Arc::new(core);
        let world = world_path("home/append-cas-mismatch");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            Arc::clone(&core),
            permit.clone(),
            replace_req(b"one", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap();
        let before = core.storage_body_bytes.load(Ordering::Relaxed);
        assert_eq!(before, 6);
        let c = rusqlite::Connection::open(world::world_db(&dir, world.as_str())).unwrap();
        c.execute_batch(
            r#"CREATE TRIGGER corrupt_appended_cas_body
               AFTER INSERT ON cas_bodies
               BEGIN
                   UPDATE cas_bodies SET body=x'00' WHERE body_sha256=NEW.body_sha256;
               END"#,
        )
        .unwrap();

        let err = append_write(
            Arc::clone(&core),
            permit,
            AppendRequest {
                body: Bytes::from_static(b"two"),
                preconditions: etag::Preconditions::default(),
            },
            test_hooks(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::StorageInvariant(StorageInvariantReason::CasBodyMismatch(_))
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), before);
        assert_eq!(
            core.read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/append-cas-mismatch"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .unwrap()
            .body,
            b"one"
        );
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 2);
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn append_quota_counts_retained_full_body() {
        let (mut core, dir) = test_core("append-quota-counts-retained");
        core.max_storage_bytes = Some(9);
        let core = Arc::new(core);
        let world = world_path("home/append-quota");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            Arc::clone(&core),
            permit.clone(),
            replace_req(b"aa", "text/plain"),
            test_hooks(),
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 4);

        let err = append_write(
            Arc::clone(&core),
            permit,
            AppendRequest {
                body: Bytes::from_static(b"bb"),
                preconditions: etag::Preconditions::default(),
            },
            test_hooks(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::QuotaExceeded {
                quota: 9,
                projected: 10,
                ..
            }
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(
            core.read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &world_path("home/append-quota"),
                &core.begin_file_op().unwrap(),
            )
            .unwrap()
            .unwrap()
            .body,
            b"aa"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_permit_preserves_path_based_approve_gate() {
        for name in ["lib/config", "etc/config", "boot/config", "usr/config"] {
            assert!(matches!(
                authorize_write(&world_path(name), auth::Tier::Write),
                Err(WriteError::Auth(AuthGate::WriteApprove))
            ));
            assert!(authorize_write(&world_path(name), auth::Tier::Approve).is_ok());
        }
        let ledger = world_path("var/log/deletes");
        assert!(matches!(
            authorize_write(&ledger, auth::Tier::Write),
            Err(WriteError::Auth(AuthGate::WriteApprove))
        ));
        assert!(matches!(
            authorize_write(&ledger, auth::Tier::Approve),
            Err(WriteError::AppendOnly)
        ));
        assert!(authorize_write(&world_path("home/config"), auth::Tier::Write).is_ok());
        assert!(authorize_write(&world_path("var/cache/rag"), auth::Tier::Write).is_ok());
        assert!(authorize_write(&world_path("var/logs/deletes"), auth::Tier::Write).is_ok());
    }
}
