//! Protocol-neutral world transitions.
//!
//! This module owns disk-side read / replace / append semantics:
//! auth permits, body caps, per-world locks, tombstone clearing,
//! preconditions, quota reservation, durable+memory writes, audit,
//! and notify. It deliberately returns semantic outcomes instead of
//! HTTP responses or CoAP packets. Adapters map these outcomes onto
//! their own wire shape.
//!
//! Not here: HTTP request lifecycle (`pipeline.rs` / `handler.rs`),
//! CoAP framing (`coap.rs`), SSE rendering (`listen.rs`), and DELETE
//! (which has a distinct intent/commit ledger protocol).

use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::http_semantics as hs;
use crate::{
    auth, can_read, can_write, is_insufficient_storage_error, is_transient_storage_error,
    needs_write_approve, store, world, AuthGate, Core,
};

#[derive(Debug)]
pub(crate) struct ReadPermit {
    world: String,
}

#[derive(Debug)]
pub(crate) struct WritePermit {
    world: String,
    gate: AuthGate,
}

impl WritePermit {
    pub(crate) fn world(&self) -> &str {
        &self.world
    }
}

pub(crate) enum ReadOutcome {
    Found { stage: world::Stage, etag: String },
    Missing,
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Auth(AuthGate),
    TransientStorage {
        scope: &'static str,
        err: rusqlite::Error,
    },
    InsufficientStorage {
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageRead {
        scope: &'static str,
        err: rusqlite::Error,
    },
    PermitWorldMismatch,
}

#[derive(Debug)]
pub(crate) struct ReplaceRequest {
    pub(crate) world: String,
    pub(crate) body: Bytes,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) preconditions: hs::Preconditions,
}

#[derive(Debug)]
pub(crate) struct AppendRequest {
    pub(crate) world: String,
    pub(crate) body: Bytes,
    pub(crate) preconditions: hs::Preconditions,
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
    PayloadTooLarge {
        max: usize,
    },
    PreconditionFailed {
        message: &'static str,
    },
    /// Only `append_write` returns this; replace/PUT creates if absent.
    NotFound,
    QuotaExceeded {
        used: usize,
        quota: usize,
        projected: usize,
    },
    TransientStorage {
        scope: &'static str,
        err: rusqlite::Error,
        op: StorageOp,
    },
    InsufficientStorage {
        scope: &'static str,
        err: rusqlite::Error,
        op: StorageOp,
    },
    StorageRead {
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageWriteAudit {
        scope: &'static str,
        err: rusqlite::Error,
    },
    Internal(&'static str),
    PermitWorldMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageOp {
    Read,
    WriteAudit,
}

pub(crate) trait WriteTraceHooks {
    fn lock_acquired(&self) {}
    fn quota_check(&self, _used: usize, _quota: usize) {}
    fn sqlite_committed(&self, _etag: &str) {}
    fn notify_sent(&self) {}
}

#[cfg(feature = "coap")]
pub(crate) struct NoopWriteTrace;

#[cfg(feature = "coap")]
impl WriteTraceHooks for NoopWriteTrace {}

pub(crate) fn authorize_read(
    core: &Core,
    world: &str,
    tier: auth::Tier,
) -> Result<ReadPermit, ReadError> {
    if can_read(core, tier) {
        Ok(ReadPermit {
            world: world.to_owned(),
        })
    } else {
        Err(ReadError::Auth(AuthGate::Read))
    }
}

pub(crate) fn authorize_write(world: &str, tier: auth::Tier) -> Result<WritePermit, WriteError> {
    let gate = if needs_write_approve(world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if can_write(world, tier) {
        Ok(WritePermit {
            world: world.to_owned(),
            gate,
        })
    } else {
        Err(WriteError::Auth(gate))
    }
}

pub(crate) fn read_world(core: &Core, permit: &ReadPermit) -> Result<ReadOutcome, ReadError> {
    read_world_for(core, permit, &permit.world)
}

pub(crate) fn read_world_for(
    core: &Core,
    permit: &ReadPermit,
    world: &str,
) -> Result<ReadOutcome, ReadError> {
    if permit.world != world {
        return Err(ReadError::PermitWorldMismatch);
    }
    match core.read_world_with_etag(world) {
        Ok(Some((stage, etag))) => Ok(ReadOutcome::Found { stage, etag }),
        Ok(None) => Ok(ReadOutcome::Missing),
        Err(err) => Err(classify_read_error("storage read", err)),
    }
}

pub(crate) async fn replace_write<H: WriteTraceHooks + ?Sized>(
    core: &Core,
    permit: &WritePermit,
    req: ReplaceRequest,
    hooks: &H,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(permit, &req.world)?;
    if req.body.len() > core.max_world_bytes {
        return Err(WriteError::PayloadTooLarge {
            max: core.max_world_bytes,
        });
    }

    let _write_guard = core.acquire_world_lock(&req.world).await;
    hooks.lock_acquired();
    core.clear_tombstone(&req.world);
    check_write_preconditions(core, &req.world, &req.preconditions)?;

    let (existed, etag) = if store::is_persistent(&req.world) {
        let prev_len_opt = world::body_len(&core.data, &req.world).map_err(|err| {
            classify_write_storage_error("storage metadata", err, StorageOp::Read)
        })?;
        let existed = prev_len_opt.is_some();
        let prev_len = prev_len_opt.unwrap_or(0);
        if let Some(quota) = core.max_storage_bytes {
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
        }
        if let Err(quota) = core.reserve_storage(prev_len, req.body.len()) {
            return Err(WriteError::QuotaExceeded {
                used: quota.used,
                quota: quota.quota,
                projected: quota.projected,
            });
        }
        match world::write_with_audit_checked(
            &core.data,
            &req.world,
            &req.body,
            &req.content_type,
            &req.headers,
            &core.hmac_key,
            None,
        ) {
            Ok(result) => {
                if !existed {
                    core.durable_world_count.fetch_add(1, Ordering::Relaxed);
                }
                (existed, hs::hmac_etag(&result.hmac))
            }
            Err(world::WriteAuditError::Quota { .. }) => {
                core.rollback_storage_reservation(prev_len, req.body.len());
                return Err(WriteError::Internal("unexpected quota error"));
            }
            Err(world::WriteAuditError::Sqlite(err)) => {
                core.rollback_storage_reservation(prev_len, req.body.len());
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
        }
    } else {
        match core.mem.write_with_quota(
            &req.world,
            &req.body,
            &req.content_type,
            &req.headers,
            core.max_memory_bytes,
        ) {
            Ok(outcome) => (outcome.existed, hs::body_etag(&req.body)),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify("PUT", &req.world, &etag);
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

pub(crate) async fn append_write<H: WriteTraceHooks + ?Sized>(
    core: &Core,
    permit: &WritePermit,
    req: AppendRequest,
    hooks: &H,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(permit, &req.world)?;
    let _write_guard = core.acquire_world_lock(&req.world).await;
    hooks.lock_acquired();
    core.clear_tombstone(&req.world);
    check_write_preconditions(core, &req.world, &req.preconditions)?;

    let Some((body_len, content_type, stored_headers)) = (if store::is_memory_world(&req.world) {
        core.mem.metadata(&req.world)
    } else {
        world::metadata(&core.data, &req.world)
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

    let etag = if store::is_persistent(&req.world) {
        if let Some(quota) = core.max_storage_bytes {
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
        }
        if let Err(quota) = core.reserve_storage(0, req.body.len()) {
            return Err(WriteError::QuotaExceeded {
                used: quota.used,
                quota: quota.quota,
                projected: quota.projected,
            });
        }
        match world::append_with_audit(
            &core.data,
            &req.world,
            &req.body,
            &content_type,
            &stored_headers,
            &core.hmac_key,
        ) {
            Ok(Some((_result, h))) => hs::hmac_etag(&h),
            Ok(None) => {
                core.rollback_storage_reservation(0, req.body.len());
                return Err(WriteError::NotFound);
            }
            Err(err) => {
                core.rollback_storage_reservation(0, req.body.len());
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
        }
    } else {
        match core
            .mem
            .append_with_quota(&req.world, &req.body, core.max_memory_bytes)
        {
            Ok(Some(result)) => format!("sha256-{}", result.body_sha256_after),
            Ok(None) => return Err(WriteError::NotFound),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify("POST", &req.world, &etag);
    hooks.notify_sent();
    Ok(WriteOutcome {
        status_kind: WriteStatusKind::Updated,
        etag,
    })
}

fn ensure_write_permit(permit: &WritePermit, world: &str) -> Result<(), WriteError> {
    if permit.world != world {
        return Err(WriteError::PermitWorldMismatch);
    }
    let expected_gate = if needs_write_approve(world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if permit.gate != expected_gate {
        return Err(WriteError::Internal("write permit gate mismatch"));
    }
    Ok(())
}

fn check_write_preconditions(
    core: &Core,
    world: &str,
    preconditions: &hs::Preconditions,
) -> Result<(), WriteError> {
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(world)
        .map_err(|err| classify_write_storage_error("precondition read", err, StorageOp::Read))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.as_str());
    hs::check_preconditions(preconditions, current_tag)
        .map_err(|message| WriteError::PreconditionFailed { message })
}

fn classify_read_error(scope: &'static str, err: rusqlite::Error) -> ReadError {
    if is_insufficient_storage_error(&err) {
        ReadError::InsufficientStorage { scope, err }
    } else if is_transient_storage_error(&err) {
        ReadError::TransientStorage { scope, err }
    } else {
        ReadError::StorageRead { scope, err }
    }
}

fn classify_write_storage_error(
    scope: &'static str,
    err: rusqlite::Error,
    op: StorageOp,
) -> WriteError {
    if is_insufficient_storage_error(&err) {
        WriteError::InsufficientStorage { scope, err, op }
    } else if is_transient_storage_error(&err) {
        WriteError::TransientStorage { scope, err, op }
    } else {
        match op {
            StorageOp::Read => WriteError::StorageRead { scope, err },
            StorageOp::WriteAudit => WriteError::StorageWriteAudit { scope, err },
        }
    }
}
