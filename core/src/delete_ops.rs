//! Protocol-neutral DELETE transition.
//!
//! DELETE has a different physical protocol from replace/append: intent,
//! tombstone drain, physical delete, notify, then commit or commit_failed.
//! Keeping it here avoids turning `world_ops` into a grab bag while still
//! letting HTTP route through Engine-owned disk semantics.

use std::sync::atomic::Ordering;

use crate::{
    auth, can_delete,
    engine::EngineError,
    engine_types::{Preconditions, ValidatedWorldPath},
    etag, is_insufficient_storage_error, is_transient_storage_error, store, world, AuditAppendJob,
    AuthGate, BlockingSqliteError, Core,
};

pub(crate) struct DeleteRequest {
    pub(crate) preconditions: Preconditions,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub(crate) struct DeletePermit {
    world: crate::engine_types::ValidatedWorldPath,
}

#[derive(Debug)]
pub(crate) enum DeleteError {
    Auth(AuthGate),
    AppendOnlyLedger,
    PreconditionFailed {
        message: &'static str,
    },
    NotFound,
    TransientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        world: ValidatedWorldPath,
        err: rusqlite::Error,
    },
    InsufficientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        world: ValidatedWorldPath,
        err: rusqlite::Error,
    },
    StorageRead {
        #[allow(dead_code)]
        scope: &'static str,
        world: ValidatedWorldPath,
        err: rusqlite::Error,
    },
    AuditIntent {
        world: crate::engine_types::ValidatedWorldPath,
        err: BlockingSqliteError,
    },
    DeleteFailedAfterIntent,
    AuditCommitFailed,
}

pub(crate) trait DeleteTraceHooks {
    fn lock_acquired(&self, _world: &str) {}
    fn audit_intent(&self) {}
    fn read_cache_drained(&self) {}
    fn physical_deleted(&self) {}
    fn counter_decremented(&self) {}
    fn notify_sent(&self) {}
    fn audit_commit_failed(&self, _err: &BlockingSqliteError) {}
    fn audit_commit_failed_event_logged(&self) {}
    fn audit_commit_failed_event_failed(&self, _err: &BlockingSqliteError) {}
    fn audit_commit(&self) {}
}

#[allow(clippy::result_large_err)]
pub(crate) fn authorize_delete(
    world: &crate::engine_types::ValidatedWorldPath,
    tier: auth::Tier,
) -> Result<DeletePermit, DeleteError> {
    if !can_delete(tier) {
        return Err(DeleteError::Auth(AuthGate::Delete));
    }
    if world.as_str() == "var/log/deletes" {
        return Err(DeleteError::AppendOnlyLedger);
    }
    Ok(DeletePermit {
        world: world.clone(),
    })
}

#[allow(clippy::result_large_err)]
pub(crate) async fn delete<H: DeleteTraceHooks + ?Sized>(
    core: &Core,
    permit: &DeletePermit,
    req: DeleteRequest,
    hooks: &H,
) -> Result<(), DeleteError> {
    let world_name = permit.world.as_str();
    let _write_guard = core.acquire_world_lock(world_name).await;
    hooks.lock_acquired(world_name);
    check_preconditions(core, &permit.world, &req.preconditions.into())?;

    let Some(stage) = core
        .read_world(world_name)
        .map_err(|err| classify_storage_error("storage read", &permit.world, err))?
    else {
        return Err(DeleteError::NotFound);
    };
    let body_sha256_before = world::sha256_hex(&stage.body);

    if let Err(err) = core
        .append_to_ledger(AuditAppendJob {
            ledger_world: "var/log/deletes",
            event_type: "delete_intent",
            target: world_name.to_owned(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: req.content_type.clone(),
            headers: req.headers.clone(),
            key: core.hmac_key.clone(),
        })
        .await
    {
        return Err(DeleteError::AuditIntent {
            world: permit.world.clone(),
            err,
        });
    }
    hooks.audit_intent();

    let was_first = !core.delete_ledger_created.swap(true, Ordering::AcqRel);
    if was_first {
        core.durable_world_count.fetch_add(1, Ordering::Relaxed);
    }

    core.install_tombstone(world_name).await;
    hooks.read_cache_drained();

    let ok = core.delete_world_blocking(world_name).await;
    core.clear_tombstone(world_name);
    if !ok {
        return Err(DeleteError::DeleteFailedAfterIntent);
    }
    hooks.physical_deleted();

    if store::is_persistent(world_name) {
        core.storage_body_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(stage.body.len()))
            })
            .ok();
        core.durable_world_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            })
            .ok();
    }
    hooks.counter_decremented();
    core.notify("DELETE", &permit.world, "");
    hooks.notify_sent();

    if let Err(commit_err) = core
        .append_to_ledger(AuditAppendJob {
            ledger_world: "var/log/deletes",
            event_type: "delete_commit",
            target: world_name.to_owned(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: req.content_type.clone(),
            headers: req.headers.clone(),
            key: core.hmac_key.clone(),
        })
        .await
    {
        crate::engine_ops::log_blocking_storage_error(
            "audit",
            &commit_err,
            "delete_commit",
            Some(world_name),
        );
        hooks.audit_commit_failed(&commit_err);
        match core
            .append_to_ledger(AuditAppendJob {
                ledger_world: "var/log/deletes",
                event_type: "delete_commit_failed",
                target: world_name.to_owned(),
                body_sha256: body_sha256_before,
                size: 0,
                content_type: req.content_type,
                headers: req.headers,
                key: core.hmac_key.clone(),
            })
            .await
        {
            Ok(_) => hooks.audit_commit_failed_event_logged(),
            Err(failed_event_err) => {
                crate::engine_ops::log_blocking_storage_error(
                    "audit",
                    &failed_event_err,
                    "delete_commit_failed_event_failed",
                    Some(world_name),
                );
                hooks.audit_commit_failed_event_failed(&failed_event_err);
            }
        }
        return Err(DeleteError::AuditCommitFailed);
    }
    hooks.audit_commit();
    Ok(())
}

fn check_preconditions(
    core: &Core,
    world: &ValidatedWorldPath,
    preconditions: &etag::Preconditions,
) -> Result<(), DeleteError> {
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(world.as_str())
        .map_err(|err| classify_storage_error("precondition read", world, err))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.as_str());
    etag::check_preconditions(preconditions, current_tag)
        .map_err(|message| DeleteError::PreconditionFailed { message })
}

fn classify_storage_error(
    scope: &'static str,
    world: &ValidatedWorldPath,
    err: rusqlite::Error,
) -> DeleteError {
    if is_insufficient_storage_error(&err) {
        DeleteError::InsufficientStorage {
            scope,
            world: world.clone(),
            err,
        }
    } else if is_transient_storage_error(&err) {
        DeleteError::TransientStorage {
            scope,
            world: world.clone(),
            err,
        }
    } else {
        DeleteError::StorageRead {
            scope,
            world: world.clone(),
            err,
        }
    }
}

fn blocking_error_to_engine(
    world: &crate::engine_types::ValidatedWorldPath,
    err: BlockingSqliteError,
) -> EngineError {
    crate::engine_ops::log_blocking_storage_error(
        "audit",
        &err,
        "delete_intent",
        Some(world.as_str()),
    );
    match err {
        BlockingSqliteError::Sqlite(err) if is_insufficient_storage_error(&err) => {
            EngineError::InsufficientStorage {
                sqlite_code: crate::engine::sqlite_code(&err),
            }
        }
        BlockingSqliteError::Sqlite(err) if is_transient_storage_error(&err) => {
            EngineError::TransientStorage {
                sqlite_code: crate::engine::sqlite_code(&err),
            }
        }
        BlockingSqliteError::Sqlite(err) => EngineError::Storage {
            sqlite_code: crate::engine::sqlite_code(&err),
        },
        BlockingSqliteError::Worker => EngineError::InternalInvariant("sqlite worker failed"),
    }
}

impl From<DeleteError> for EngineError {
    fn from(value: DeleteError) -> Self {
        match value {
            DeleteError::Auth(gate) => Self::Auth(gate),
            DeleteError::AppendOnlyLedger => Self::AppendOnly,
            DeleteError::PreconditionFailed { message } => Self::PreconditionFailed { message },
            DeleteError::NotFound => Self::NotFound,
            DeleteError::TransientStorage { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::TransientStorage {
                    sqlite_code: crate::engine::sqlite_code(&err),
                }
            }
            DeleteError::InsufficientStorage { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::InsufficientStorage {
                    sqlite_code: crate::engine::sqlite_code(&err),
                }
            }
            DeleteError::StorageRead { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::Storage {
                    sqlite_code: crate::engine::sqlite_code(&err),
                }
            }
            DeleteError::AuditIntent { world, err } => blocking_error_to_engine(&world, err),
            DeleteError::DeleteFailedAfterIntent | DeleteError::AuditCommitFailed => {
                Self::Storage { sqlite_code: None }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_types::ValidatedWorldPath;

    #[test]
    fn delete_permit_requires_approve_and_binds_world() {
        let world = ValidatedWorldPath::new("home/delete-me").unwrap();

        assert!(matches!(
            authorize_delete(&world, auth::Tier::Write),
            Err(DeleteError::Auth(AuthGate::Delete))
        ));

        let permit = authorize_delete(&world, auth::Tier::Approve).unwrap();
        assert_eq!(permit.world.as_str(), "home/delete-me");
    }

    #[test]
    fn delete_permit_rejects_append_only_ledger() {
        let world = ValidatedWorldPath::new("var/log/deletes").unwrap();

        assert!(matches!(
            authorize_delete(&world, auth::Tier::Approve),
            Err(DeleteError::AppendOnlyLedger)
        ));
    }
}
