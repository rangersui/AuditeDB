//! Protocol-neutral world transitions.
//!
//! This module owns disk-side read / replace / append semantics:
//! auth permits, body caps, per-world locks, tombstone clearing,
//! preconditions, quota reservation, durable+memory writes, audit,
//! and notify. It deliberately returns semantic outcomes instead of wire
//! adapter outputs. Adapters map these outcomes onto their own shape.
//!
//! Not here: adapter operation lifecycles, stream rendering, or delete (which
//! has a distinct intent/commit ledger protocol).

use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::{
    auth, can_read, can_write,
    engine_types::{ChangeVerb, ValidatedWorldPath},
    etag, is_insufficient_storage_error, is_transient_storage_error, needs_write_approve, store,
    world, AuthGate, Core,
};

#[derive(Debug)]
pub(crate) struct ReadPermit {
    world: ValidatedWorldPath,
}

#[derive(Debug)]
pub(crate) struct WritePermit {
    world: ValidatedWorldPath,
    gate: AuthGate,
}

pub(crate) enum ReadOutcome {
    Found { stage: world::Stage, etag: String },
    Missing,
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Auth(AuthGate),
    TransientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    InsufficientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageRead {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    PermitWorldMismatch,
}

#[derive(Debug)]
pub(crate) struct ReplaceRequest {
    pub(crate) body: Bytes,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) preconditions: etag::Preconditions,
}

#[derive(Debug)]
pub(crate) struct AppendRequest {
    pub(crate) body: Bytes,
    pub(crate) preconditions: etag::Preconditions,
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
    Internal(&'static str),
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

pub(crate) fn authorize_read(
    core: &Core,
    world: &ValidatedWorldPath,
    tier: auth::Tier,
) -> Result<ReadPermit, ReadError> {
    if can_read(core, tier) {
        Ok(ReadPermit {
            world: world.clone(),
        })
    } else {
        Err(ReadError::Auth(AuthGate::Read))
    }
}

pub(crate) fn authorize_write(
    world: &ValidatedWorldPath,
    tier: auth::Tier,
) -> Result<WritePermit, WriteError> {
    let gate = if needs_write_approve(world.as_str()) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if can_write(world.as_str(), tier) {
        Ok(WritePermit {
            world: world.clone(),
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
    world: &ValidatedWorldPath,
) -> Result<ReadOutcome, ReadError> {
    if &permit.world != world {
        return Err(ReadError::PermitWorldMismatch);
    }
    match core.read_world_with_etag(world.as_str()) {
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
    ensure_write_permit(permit)?;
    let world = permit.world.as_str();
    if req.body.len() > core.max_world_bytes {
        return Err(WriteError::PayloadTooLarge {
            max: core.max_world_bytes,
        });
    }

    let _write_guard = core.acquire_world_lock(world).await;
    hooks.lock_acquired();
    core.clear_tombstone(world);
    check_write_preconditions(core, world, &req.preconditions)?;

    let (existed, etag) = if store::is_persistent(world) {
        let prev_len_opt = world::body_len(&core.data, world).map_err(|err| {
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
            world,
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
                (existed, etag::hmac_etag(&result.hmac))
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
            world,
            &req.body,
            &req.content_type,
            &req.headers,
            core.max_memory_bytes,
        ) {
            Ok(outcome) => (outcome.existed, etag::body_etag(&req.body)),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify(ChangeVerb::Replace, &permit.world, &etag);
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
    ensure_write_permit(permit)?;
    let world = permit.world.as_str();
    let _write_guard = core.acquire_world_lock(world).await;
    hooks.lock_acquired();
    core.clear_tombstone(world);
    check_write_preconditions(core, world, &req.preconditions)?;

    let Some((body_len, content_type, stored_headers)) = (if store::is_memory_world(world) {
        core.mem.metadata(world)
    } else {
        world::metadata(&core.data, world)
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

    let etag = if store::is_persistent(world) {
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
            world,
            &req.body,
            &content_type,
            &stored_headers,
            &core.hmac_key,
        ) {
            Ok(Some((_result, h))) => etag::hmac_etag(&h),
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
            .append_with_quota(world, &req.body, core.max_memory_bytes)
        {
            Ok(Some(result)) => format!("sha256-{}", result.body_sha256_after),
            Ok(None) => return Err(WriteError::NotFound),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify(ChangeVerb::Append, &permit.world, &etag);
    hooks.notify_sent();
    Ok(WriteOutcome {
        status_kind: WriteStatusKind::Updated,
        etag,
    })
}

fn ensure_write_permit(permit: &WritePermit) -> Result<(), WriteError> {
    let expected_gate = if needs_write_approve(permit.world.as_str()) {
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
    preconditions: &etag::Preconditions,
) -> Result<(), WriteError> {
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(world)
        .map_err(|err| classify_write_storage_error("precondition read", err, StorageOp::Read))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.as_str());
    etag::check_preconditions(preconditions, current_tag)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_core;

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    #[tokio::test]
    async fn write_permit_is_bound_to_one_world() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("permit-bound");
        let world = world_path("home/permit-a");
        let permit = authorize_write(&world, auth::Tier::Write)
            .expect("write token tier should authorize home writes");
        let req = ReplaceRequest {
            body: Bytes::from_static(b"right-door"),
            content_type: "text/plain; charset=utf-8".to_owned(),
            headers: Vec::new(),
            preconditions: etag::Preconditions::default(),
        };

        replace_write(&core, &permit, req, &NoopTrace)
            .await
            .expect("permit writes only its bound world");

        assert_eq!(
            core.read_world("home/permit-a").unwrap().unwrap().body,
            b"right-door"
        );
        assert!(core.read_world("home/permit-b").unwrap().is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn real_sqlite_lock_maps_to_transient_read_error() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("runtime-lock-classification");
        let world = world_path("home/busy");
        let write_permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            &core,
            &write_permit,
            ReplaceRequest {
                body: Bytes::from_static(b"ok"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap();

        let holder = rusqlite::Connection::open(crate::world::world_db(&dir, world.as_str()))
            .expect("open lock holder");
        holder
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .expect("exclusive locking mode");
        holder
            .execute_batch("BEGIN EXCLUSIVE")
            .expect("hold exclusive transaction");

        let read_permit = authorize_read(&core, &world, auth::Tier::Read).unwrap();
        assert!(
            matches!(
                read_world(&core, &read_permit),
                Err(ReadError::TransientStorage { .. })
            ),
            "real SQLite busy/locked errors must stay classified as transient"
        );

        drop(holder);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_permit_preserves_path_based_approve_gate() {
        assert!(matches!(
            authorize_write(&world_path("etc/config"), auth::Tier::Write),
            Err(WriteError::Auth(AuthGate::WriteApprove))
        ));
        assert!(authorize_write(&world_path("etc/config"), auth::Tier::Approve).is_ok());
        assert!(authorize_write(&world_path("home/config"), auth::Tier::Write).is_ok());
    }
}
