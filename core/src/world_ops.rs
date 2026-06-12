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

use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::{
    audit, auth, can_write,
    engine_types::{ChangeVerb, ValidatedWorldPath},
    etag, needs_write_approve, store,
    timeline::BodySha256,
    world, AuthGate, Core, StorageFailureClass,
};

#[derive(Debug)]
pub(crate) struct WritePermit {
    world: ValidatedWorldPath,
    gate: AuthGate,
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
    StorageInvariant(StorageInvariantReason),
    AuditChainBroken {
        #[allow(dead_code)]
        scope: &'static str,
        break_report: audit::VerifyBreak,
    },
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

pub(crate) trait WriteTraceHooks {
    fn lock_acquired(&self) {}
    fn quota_check(&self, _used: usize, _quota: usize) {}
    fn sqlite_committed(&self, _etag: &str) {}
    fn notify_sent(&self) {}
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

    let (existed, etag, timeline_address) = if store::is_persistent(world) {
        let prev_len_opt = world::body_len(&core.data, world).map_err(|err| {
            classify_write_storage_error("storage metadata", err, StorageOp::Read)
        })?;
        let existed = prev_len_opt.is_some();
        let prev_len = prev_len_opt.unwrap_or(0);
        if let Some(quota) = core.max_storage_bytes {
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
        }
        let cas_candidate_len = world::cas_body_len_if_missing(&core.data, world, &req.body)
            .map_err(|err| classify_write_storage_error("storage/cas", err, StorageOp::Read))?;
        let reserve_new_len = req.body.len().saturating_add(cas_candidate_len);
        if let Err(quota) = core.reserve_storage(prev_len, reserve_new_len) {
            return Err(WriteError::QuotaExceeded {
                used: quota.used,
                quota: quota.quota,
                projected: quota.projected,
            });
        }
        match world::write_with_audit_checked(
            &core.data,
            &permit.world,
            &req.body,
            &req.content_type,
            &req.headers,
            &core.hmac_key,
        ) {
            Ok(result) => {
                if !result.cas_body_inserted {
                    core.rollback_storage_reservation(0, cas_candidate_len);
                }
                if !existed {
                    core.durable_world_count.fetch_add(1, Ordering::Relaxed);
                }
                let etag = etag::hmac_etag(&result.hmac);
                (existed, etag, Some(result.timeline_address))
            }
            Err(world::WriteAuditError::Audit(err)) => {
                core.rollback_storage_reservation(prev_len, reserve_new_len);
                return Err(classify_write_audit_error("storage/audit", err));
            }
            Err(world::WriteAuditError::Sqlite(err)) => {
                core.rollback_storage_reservation(prev_len, reserve_new_len);
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
            Err(world::WriteAuditError::CasBodyMismatch { body_sha256 }) => {
                core.rollback_storage_reservation(prev_len, reserve_new_len);
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasBodyMismatch(body_sha256),
                ));
            }
            Err(world::WriteAuditError::StorageInvariant(reason)) => {
                core.rollback_storage_reservation(prev_len, reserve_new_len);
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasState(reason),
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
            Ok(outcome) => (outcome.existed, etag::body_etag(&req.body), None),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify(ChangeVerb::Replace, &permit.world, &etag, timeline_address);
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

    let (etag, timeline_address) = if store::is_persistent(world) {
        if let Some(quota) = core.max_storage_bytes {
            hooks.quota_check(core.storage_body_bytes.load(Ordering::Relaxed), quota);
        }
        let cas_candidate_len = world::append_cas_body_len_if_missing(&core.data, world, &req.body)
            .map_err(|err| classify_write_storage_error("storage/cas", err, StorageOp::Read))?
            .ok_or(WriteError::NotFound)?;
        let reserve_new_len = req.body.len().saturating_add(cas_candidate_len);
        if let Err(quota) = core.reserve_storage(0, reserve_new_len) {
            return Err(WriteError::QuotaExceeded {
                used: quota.used,
                quota: quota.quota,
                projected: quota.projected,
            });
        }
        match world::append_with_audit(
            &core.data,
            &permit.world,
            &req.body,
            &content_type,
            &stored_headers,
            &core.hmac_key,
        ) {
            Ok(Some((result, h))) => {
                if !result.cas_body_inserted {
                    core.rollback_storage_reservation(0, cas_candidate_len);
                }
                (etag::hmac_etag(&h), result.timeline_address)
            }
            Ok(None) => {
                core.rollback_storage_reservation(0, reserve_new_len);
                return Err(WriteError::NotFound);
            }
            Err(world::WriteAuditError::Audit(err)) => {
                core.rollback_storage_reservation(0, reserve_new_len);
                return Err(classify_write_audit_error("storage/audit", err));
            }
            Err(world::WriteAuditError::Sqlite(err)) => {
                core.rollback_storage_reservation(0, reserve_new_len);
                return Err(classify_write_storage_error(
                    "storage/audit",
                    err,
                    StorageOp::WriteAudit,
                ));
            }
            Err(world::WriteAuditError::CasBodyMismatch { body_sha256 }) => {
                core.rollback_storage_reservation(0, reserve_new_len);
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasBodyMismatch(body_sha256),
                ));
            }
            Err(world::WriteAuditError::StorageInvariant(reason)) => {
                core.rollback_storage_reservation(0, reserve_new_len);
                return Err(WriteError::StorageInvariant(
                    StorageInvariantReason::CasState(reason),
                ));
            }
        }
    } else {
        match core
            .mem
            .append_with_quota(world, &req.body, core.max_memory_bytes)
        {
            Ok(Some(result)) => (format!("sha256-{}", result.body_sha256_after), None),
            Ok(None) => return Err(WriteError::NotFound),
            Err(store::MemoryQuotaError { quota, .. }) => {
                return Err(WriteError::PayloadTooLarge { max: quota });
            }
        }
    };

    hooks.sqlite_committed(&etag);
    core.notify(ChangeVerb::Append, &permit.world, &etag, timeline_address);
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
    async fn durable_quota_counts_retained_cas_bodies() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (mut core, dir) = test_core("quota-counts-cas");
        core.max_storage_bytes = Some(8);
        let world = world_path("home/quota-cas");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();

        replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"aaaa"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);

        replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"aaaa"),
                content_type: "application/octet-stream".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);

        let err = replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"bbbb"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::QuotaExceeded { projected: 12, .. }
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);
        assert_eq!(
            core.read_world("home/quota-cas").unwrap().unwrap().body,
            b"aaaa"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn replace_cas_mismatch_rolls_back_storage_reservation() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("replace-cas-mismatch-accounting");
        let world = world_path("home/replace-cas-mismatch");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"old"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
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
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"new"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::StorageInvariant(StorageInvariantReason::CasBodyMismatch(_))
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), before);
        assert_eq!(
            core.read_world("home/replace-cas-mismatch")
                .unwrap()
                .unwrap()
                .body,
            b"old"
        );
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 1);
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn append_cas_mismatch_rolls_back_storage_reservation() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("append-cas-mismatch-accounting");
        let world = world_path("home/append-cas-mismatch");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"one"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
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
            &core,
            &permit,
            AppendRequest {
                body: Bytes::from_static(b"two"),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            WriteError::StorageInvariant(StorageInvariantReason::CasBodyMismatch(_))
        ));
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), before);
        assert_eq!(
            core.read_world("home/append-cas-mismatch")
                .unwrap()
                .unwrap()
                .body,
            b"one"
        );
        let events: i64 = c
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 1);
        drop(c);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn append_quota_counts_retained_full_body() {
        struct NoopTrace;
        impl WriteTraceHooks for NoopTrace {}

        let (mut core, dir) = test_core("append-quota-counts-retained");
        core.max_storage_bytes = Some(9);
        let world = world_path("home/append-quota");
        let permit = authorize_write(&world, auth::Tier::Write).unwrap();
        replace_write(
            &core,
            &permit,
            ReplaceRequest {
                body: Bytes::from_static(b"aa"),
                content_type: "text/plain".to_owned(),
                headers: Vec::new(),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
        )
        .await
        .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 4);

        let err = append_write(
            &core,
            &permit,
            AppendRequest {
                body: Bytes::from_static(b"bb"),
                preconditions: etag::Preconditions::default(),
            },
            &NoopTrace,
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
            core.read_world("home/append-quota").unwrap().unwrap().body,
            b"aa"
        );
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
