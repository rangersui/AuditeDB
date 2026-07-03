//! Protocol-neutral delete transition.
//!
//! Delete has a different physical protocol from replace/append: intent,
//! tombstone drain, physical delete, notify, then commit or commit_failed.
//! Keeping it here avoids turning `world_ops` into a grab bag while still
//! letting adapters route through Engine-owned disk semantics.

use std::sync::atomic::Ordering;

use crate::{
    audit::{AuditHeaders, VerifiedDeleteSubject},
    auth, blocking_sqlite, can_delete,
    engine::EngineError,
    engine_types::{
        ChangeVerb, Preconditions, ValidatedRepresentationMetadata, ValidatedWorldPath,
    },
    etag,
    event::EventMetadataKind,
    store,
    subscription_event_id::ChangeTarget,
    timeline::BodySha256,
    world, AuditAppendJob, AuthGate, BlockingSqliteError, Core, StorageFailureClass,
};
use rusqlite::ffi;

pub(crate) struct DeleteRequest {
    pub(crate) preconditions: Preconditions,
    content_type: String,
    headers: Vec<(String, String)>,
}

impl DeleteRequest {
    pub(crate) fn new(
        preconditions: Preconditions,
        content_type: String,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            preconditions,
            content_type,
            headers,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DeletePermit {
    world: crate::engine_types::ValidatedWorldPath,
}

#[derive(Debug)]
pub(crate) enum DeleteError {
    Auth(AuthGate),
    AppendOnlyLedger,
    ReservedMetadataHeader,
    InvalidMetadata {
        message: &'static str,
    },
    PreconditionFailed {
        message: &'static str,
    },
    NotFound,
    SubjectAudit {
        world: ValidatedWorldPath,
        err: crate::audit::AuditError,
    },
    AuditRead {
        #[allow(dead_code)]
        scope: &'static str,
        world: ValidatedWorldPath,
        err: crate::audit::AuditError,
    },
    SubjectMissingHead {
        world: ValidatedWorldPath,
    },
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
    InternalInvariant(&'static str),
    ShuttingDown,
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
    if crate::ledger::is_delete_ledger_world(world) {
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
    let DeleteRequest {
        preconditions,
        content_type,
        headers,
    } = req;
    let world_name = permit.world.as_str();
    let _write_guard = core.acquire_world_lock(&permit.world).await;
    hooks.lock_acquired(world_name);
    let _stream_guard = core.delete_ledger_stream_lock.lock().await;
    let file_op = core.begin_file_op().ok_or(DeleteError::ShuttingDown)?;
    blocking_sqlite::run_scoped(|proof| {
        check_preconditions(core, proof, &permit.world, &preconditions.into(), &file_op)
    })?;
    let metadata = ValidatedRepresentationMetadata::new(content_type, headers)
        .map_err(|message| DeleteError::InvalidMetadata { message })?;
    let (content_type, headers) = metadata.into_parts();
    let user_headers =
        AuditHeaders::from_user(headers).map_err(|_| DeleteError::ReservedMetadataHeader)?;

    let Some(stage) =
        blocking_sqlite::run_scoped(|proof| core.read_world(proof, &permit.world, &file_op))
            .map_err(|err| classify_audit_error("storage read", &permit.world, err))?
    else {
        return Err(DeleteError::NotFound);
    };
    let storage_usage_before = if store::is_persistent(&permit.world) {
        match blocking_sqlite::run_scoped(|proof| {
            world::accounted_storage_usage(proof, &core.data, &permit.world, &file_op)
        })
        .map_err(|err| classify_storage_error("storage size", &permit.world, err))?
        {
            Some(proof) => Some(proof),
            None => {
                return Err(classify_storage_error(
                    "storage size",
                    &permit.world,
                    storage_len_missing_error(),
                ));
            }
        }
    } else {
        None
    };
    let subject = capture_delete_subject_proof(core, &permit.world, &file_op)?;
    let body_sha256_before = subject
        .as_ref()
        .map(VerifiedDeleteSubject::body_sha256)
        .unwrap_or_else(|| BodySha256::for_body(&stage.body));
    let ledger_headers = match subject {
        Some(subject) => user_headers.with_delete_subject(subject),
        None => user_headers,
    };

    let intent_event = match append_ledger_event_and_notify(
        core,
        AuditAppendJob {
            event_type: EventMetadataKind::DELETE_INTENT,
            target: permit.world.clone(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: content_type.clone(),
            headers: ledger_headers.clone(),
            key: ledger_hmac_key(core),
        },
        &file_op,
    ) {
        Ok(event) => event,
        Err(err) => {
            return Err(DeleteError::AuditIntent {
                world: permit.world.clone(),
                err,
            });
        }
    };
    hooks.audit_intent();

    let was_first = !core.delete_ledger_created.swap(true, Ordering::AcqRel);
    if was_first {
        core.durable_world_count.fetch_add(1, Ordering::Relaxed);
    }

    core.clear_cached_write_conn(&permit.world, &file_op);
    core.install_tombstone_blocking(&permit.world, &file_op);
    hooks.read_cache_drained();

    let ok =
        blocking_sqlite::run_scoped(|proof| core.delete_world_now(proof, &permit.world, &file_op));
    core.clear_tombstone(&permit.world);
    if !ok {
        return Err(DeleteError::DeleteFailedAfterIntent);
    }
    hooks.physical_deleted();

    if store::is_persistent(&permit.world) {
        if let Some(usage) = storage_usage_before {
            core.subtract_storage_usage(&permit.world, usage)
                .map_err(|_| DeleteError::InternalInvariant("accounted storage proof mismatch"))?;
        }
        core.durable_world_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            })
            .ok();
    }
    hooks.counter_decremented();
    let intent_event = intent_event
        .as_delete_intent()
        .ok_or(DeleteError::InternalInvariant(
            "ledger append returned non-delete-intent event",
        ))?;
    let aux = crate::event::ChangeEventAux::from_appended_delete_intent(intent_event);
    core.notify_with_aux(
        ChangeVerb::Delete,
        ChangeTarget::Ephemeral(permit.world.clone()),
        "",
        aux,
    );
    hooks.notify_sent();

    match append_ledger_event_and_notify(
        core,
        AuditAppendJob {
            event_type: EventMetadataKind::DELETE_COMMIT,
            target: permit.world.clone(),
            body_sha256: body_sha256_before.clone(),
            size: 0,
            content_type: content_type.clone(),
            headers: ledger_headers.clone(),
            key: ledger_hmac_key(core),
        },
        &file_op,
    ) {
        Ok(_commit_event) => {
            hooks.audit_commit();
            Ok(())
        }
        Err(commit_err) => {
            crate::engine_ops::log_blocking_storage_error(
                "audit",
                &commit_err,
                "delete_commit",
                Some(world_name),
            );
            hooks.audit_commit_failed(&commit_err);
            match append_ledger_event_and_notify(
                core,
                AuditAppendJob {
                    event_type: EventMetadataKind::DELETE_COMMIT_FAILED,
                    target: permit.world.clone(),
                    body_sha256: body_sha256_before,
                    size: 0,
                    content_type,
                    headers: ledger_headers,
                    key: ledger_hmac_key(core),
                },
                &file_op,
            ) {
                Ok(_failed_event) => {
                    hooks.audit_commit_failed_event_logged();
                }
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
            Err(DeleteError::AuditCommitFailed)
        }
    }
}

fn append_ledger_event_and_notify(
    core: &Core,
    job: AuditAppendJob,
    file_op: &crate::state::FileOpPermit,
) -> Result<crate::ledger::AppendedLedgerEvent, BlockingSqliteError> {
    let event =
        blocking_sqlite::run_scoped(|proof| core.append_to_ledger_blocking(proof, job, file_op))?;
    core.note_audit_events_appended(1 + usize::from(event.format_event().is_some()));
    notify_ledger_event(core, &event);
    Ok(event)
}

fn notify_ledger_event(core: &Core, event: &crate::ledger::AppendedLedgerEvent) {
    if let Some(format_event) = event.format_event() {
        let format_etag = crate::etag::hmac_etag(format_event.hmac());
        core.notify_with_aux(
            ChangeVerb::Format,
            ChangeTarget::from_appended_audit_row(format_event),
            &format_etag,
            crate::event::ChangeEventAux::default(),
        );
    }

    let etag = crate::etag::hmac_etag(event.hmac());
    let verb = match event.event_type() {
        crate::event::AuditEventKind::DeleteIntent
        | crate::event::AuditEventKind::DeleteCommit
        | crate::event::AuditEventKind::DeleteCommitFailed => ChangeVerb::Delete,
        crate::event::AuditEventKind::Put | crate::event::AuditEventKind::Append => {
            ChangeVerb::Replace
        }
        crate::event::AuditEventKind::Format => ChangeVerb::Format,
    };
    core.notify_with_aux(
        verb,
        ChangeTarget::from_appended_ledger_event(event),
        &etag,
        crate::event::ChangeEventAux::default(),
    );
}

fn ledger_hmac_key(core: &Core) -> crate::engine_types::AuditHmacKey {
    core.hmac_key.clone_secret()
}

fn capture_delete_subject_proof(
    core: &Core,
    world: &ValidatedWorldPath,
    file_op: &crate::state::FileOpPermit,
) -> Result<Option<VerifiedDeleteSubject>, DeleteError> {
    if store::is_memory_world(world) {
        return Ok(None);
    }
    let Some(head) =
        blocking_sqlite::run_scoped(|proof| core.latest_body_head(proof, world, file_op)).map_err(
            |err| DeleteError::SubjectAudit {
                world: world.clone(),
                err,
            },
        )?
    else {
        return Err(DeleteError::SubjectMissingHead {
            world: world.clone(),
        });
    };
    Ok(Some(VerifiedDeleteSubject::from_body_head(head)))
}

fn storage_len_missing_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error {
            code: ffi::ErrorCode::DatabaseCorrupt,
            extended_code: ffi::SQLITE_CORRUPT,
        },
        Some("persistent world vanished while computing storage_len".to_owned()),
    )
}

fn subject_head_missing_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error {
            code: ffi::ErrorCode::DatabaseCorrupt,
            extended_code: ffi::SQLITE_CORRUPT,
        },
        Some("persistent world has no audited body head".to_owned()),
    )
}

fn check_preconditions(
    core: &Core,
    proof: &mut blocking_sqlite::BlockingSqlite,
    world: &ValidatedWorldPath,
    preconditions: &etag::Preconditions,
    file_op: &crate::state::FileOpPermit,
) -> Result<(), DeleteError> {
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(proof, world, file_op)
        .map_err(|err| classify_audit_error("precondition read", world, err))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.as_str());
    etag::check_preconditions(preconditions, current_tag)
        .map_err(|message| DeleteError::PreconditionFailed { message })
}

fn classify_storage_error(
    scope: &'static str,
    world: &ValidatedWorldPath,
    err: rusqlite::Error,
) -> DeleteError {
    match crate::classify_storage_failure(&err) {
        StorageFailureClass::InsufficientStorage => DeleteError::InsufficientStorage {
            scope,
            world: world.clone(),
            err,
        },
        StorageFailureClass::Transient => DeleteError::TransientStorage {
            scope,
            world: world.clone(),
            err,
        },
        StorageFailureClass::Other => DeleteError::StorageRead {
            scope,
            world: world.clone(),
            err,
        },
    }
}

fn classify_audit_error(
    scope: &'static str,
    world: &ValidatedWorldPath,
    err: crate::audit::AuditError,
) -> DeleteError {
    match err {
        crate::audit::AuditError::ChainBroken(_) => DeleteError::AuditRead {
            scope,
            world: world.clone(),
            err,
        },
        crate::audit::AuditError::Storage(err) => classify_storage_error(scope, world, err),
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
        BlockingSqliteError::Audit(crate::audit::AuditError::ChainBroken(_)) => {
            EngineError::Storage
        }
        BlockingSqliteError::Audit(crate::audit::AuditError::Storage(err)) => {
            match crate::classify_storage_failure(&err) {
                StorageFailureClass::InsufficientStorage => EngineError::InsufficientStorage,
                StorageFailureClass::Transient => EngineError::TransientStorage,
                StorageFailureClass::Other => EngineError::Storage,
            }
        }
        BlockingSqliteError::Sqlite(err) => match crate::classify_storage_failure(&err) {
            StorageFailureClass::InsufficientStorage => EngineError::InsufficientStorage,
            StorageFailureClass::Transient => EngineError::TransientStorage,
            StorageFailureClass::Other => EngineError::Storage,
        },
        BlockingSqliteError::Worker => EngineError::InternalInvariant("sqlite worker failed"),
    }
}

impl From<DeleteError> for EngineError {
    fn from(value: DeleteError) -> Self {
        match value {
            DeleteError::Auth(gate) => Self::Auth(gate),
            DeleteError::AppendOnlyLedger => Self::AppendOnly,
            DeleteError::ReservedMetadataHeader => Self::InvalidMetadata {
                message: "reserved-delete-subject-header",
            },
            DeleteError::InvalidMetadata { message } => Self::InvalidMetadata { message },
            DeleteError::PreconditionFailed { message } => Self::PreconditionFailed { message },
            DeleteError::NotFound => Self::NotFound,
            DeleteError::SubjectAudit { world, err } => subject_audit_error_to_engine(&world, err),
            DeleteError::AuditRead { scope, world, err } => {
                audit_error_to_engine(scope, "delete", &world, err)
            }
            DeleteError::SubjectMissingHead { world } => {
                crate::engine_ops::log_storage_error(
                    "subject audit",
                    &subject_head_missing_error(),
                    "delete",
                    Some(world.as_str()),
                );
                Self::Storage
            }
            DeleteError::TransientStorage { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::TransientStorage
            }
            DeleteError::InsufficientStorage { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::InsufficientStorage
            }
            DeleteError::StorageRead { scope, world, err } => {
                crate::engine_ops::log_storage_error(scope, &err, "delete", Some(world.as_str()));
                Self::Storage
            }
            DeleteError::AuditIntent { world, err } => blocking_error_to_engine(&world, err),
            DeleteError::InternalInvariant(message) => Self::InternalInvariant(message),
            DeleteError::ShuttingDown => Self::ShuttingDown,
            DeleteError::DeleteFailedAfterIntent | DeleteError::AuditCommitFailed => Self::Storage,
        }
    }
}

fn subject_audit_error_to_engine(
    world: &crate::engine_types::ValidatedWorldPath,
    err: crate::audit::AuditError,
) -> EngineError {
    audit_error_to_engine("subject audit", "delete", world, err)
}

fn audit_error_to_engine(
    scope: &'static str,
    action: &'static str,
    world: &crate::engine_types::ValidatedWorldPath,
    err: crate::audit::AuditError,
) -> EngineError {
    match err {
        crate::audit::AuditError::ChainBroken(break_report) => {
            crate::engine_error::log_audit_chain_error(
                scope,
                &break_report,
                action,
                Some(world.as_str()),
            );
            EngineError::Storage
        }
        crate::audit::AuditError::Storage(err) => {
            crate::engine_ops::log_storage_error(scope, &err, action, Some(world.as_str()));
            match crate::classify_storage_failure(&err) {
                StorageFailureClass::InsufficientStorage => EngineError::InsufficientStorage,
                StorageFailureClass::Transient => EngineError::TransientStorage,
                StorageFailureClass::Other => EngineError::Storage,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::engine_types::ValidatedWorldPath;
    use crate::test_support::test_core;
    use crate::world_schema;
    use rusqlite::Connection;

    fn delete_req(content_type: &str, headers: Vec<(String, String)>) -> DeleteRequest {
        DeleteRequest::new(Preconditions::none(), content_type.to_owned(), headers)
    }

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

    #[tokio::test]
    async fn delete_ledger_metadata_events_do_not_retain_cas_bodies() {
        struct NoopTrace;
        impl DeleteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("delete-ledger-no-cas");
        let subject = ValidatedWorldPath::new("home/delete-ledger-no-cas").unwrap();
        core.test_only_write_world(subject.as_str(), b"body", "text/plain", &[])
            .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);
        core.test_only_write_world(subject.as_str(), b"body", "application/octet-stream", &[])
            .unwrap();
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 8);

        let permit = authorize_delete(&subject, auth::Tier::Approve).unwrap();
        delete(
            &core,
            &permit,
            delete_req("application/octet-stream", Vec::new()),
            &NoopTrace,
        )
        .await
        .unwrap();

        let c =
            rusqlite::Connection::open(crate::world::world_db(&dir, "var/log/deletes")).unwrap();
        let cas_rows: i64 = c
            .query_row("SELECT COUNT(*) FROM cas_bodies", [], |r| r.get(0))
            .unwrap();
        let first_retained_seq: Option<i64> = c
            .query_row(
                "SELECT first_retained_seq FROM cas_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(cas_rows, 0);
        assert_eq!(first_retained_seq, None);
        assert_eq!(core.storage_body_bytes.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_ledger_records_subject_final_address() {
        struct NoopTrace;
        impl DeleteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("delete-ledger-subject-address");
        let subject = ValidatedWorldPath::new("home/delete-ledger-subject-address").unwrap();
        core.test_only_write_world(subject.as_str(), b"old", "text/plain", &[])
            .unwrap();
        core.test_only_write_world(subject.as_str(), b"final", "text/plain", &[])
            .unwrap();

        let subject_conn =
            Connection::open(crate::world::world_db(&dir, subject.as_str())).unwrap();
        let subject_generation = world_schema::generation(&subject_conn).unwrap();
        let (subject_seq, subject_hmac): (i64, String) = subject_conn
            .query_row(
                "SELECT id, hmac FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(subject_conn);

        let permit = authorize_delete(&subject, auth::Tier::Approve).unwrap();
        delete(
            &core,
            &permit,
            delete_req(
                "text/plain",
                vec![("x-meta-operator".to_owned(), "alice".to_owned())],
            ),
            &NoopTrace,
        )
        .await
        .unwrap();

        let ledger = Connection::open(crate::world::world_db(&dir, "var/log/deletes")).unwrap();
        let events: Vec<(i64, String)> = {
            let mut stmt = ledger
                .prepare("SELECT id, event_type FROM events ORDER BY id")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(
            events,
            vec![
                (1, "format".to_owned()),
                (2, "delete_intent".to_owned()),
                (3, "delete_commit".to_owned())
            ]
        );

        let expected = [
            (
                crate::audit::DELETE_SUBJECT_WORLD,
                subject.as_str().to_owned(),
            ),
            (
                crate::audit::DELETE_SUBJECT_GENERATION,
                subject_generation.as_str().to_owned(),
            ),
            (crate::audit::DELETE_SUBJECT_SEQ, subject_seq.to_string()),
            (
                crate::audit::DELETE_SUBJECT_BODY_SHA256,
                BodySha256::for_body(b"final").as_str().to_owned(),
            ),
            (
                crate::audit::DELETE_SUBJECT_HMAC,
                format!("hmac-{subject_hmac}"),
            ),
        ];
        for event_id in [2_i64, 3] {
            for (name, value) in expected.iter() {
                let stored: String = ledger
                    .query_row(
                        "SELECT value FROM event_headers WHERE event_id=?1 AND name=?2",
                        rusqlite::params![event_id, name],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(stored, *value);
            }
            let operator: String = ledger
                .query_row(
                    "SELECT value FROM event_headers WHERE event_id=?1 AND name='x-meta-operator'",
                    [event_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(operator, "alice");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_rejects_reserved_subject_metadata_headers() {
        struct NoopTrace;
        impl DeleteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("delete-ledger-reserved-subject-header");
        let subject =
            ValidatedWorldPath::new("home/delete-ledger-reserved-subject-header").unwrap();
        core.test_only_write_world(subject.as_str(), b"body", "text/plain", &[])
            .unwrap();

        let permit = authorize_delete(&subject, auth::Tier::Approve).unwrap();
        let err = delete(
            &core,
            &permit,
            delete_req(
                "text/plain",
                vec![("AuditeDB-Delete-Subject-Seq".to_owned(), "fake".to_owned())],
            ),
            &NoopTrace,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, DeleteError::ReservedMetadataHeader));
        let file_op = core.begin_file_op().unwrap();
        assert!(core
            .read_world(
                &mut crate::blocking_sqlite::test_only_mint(),
                &subject,
                &file_op,
            )
            .unwrap()
            .is_some());
        assert!(!crate::world::world_db(&dir, "var/log/deletes").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_ledger_subject_generation_distinguishes_recreated_world() {
        struct NoopTrace;
        impl DeleteTraceHooks for NoopTrace {}

        let (core, dir) = test_core("delete-ledger-recreate-generation");
        let subject = ValidatedWorldPath::new("home/delete-ledger-recreate-generation").unwrap();
        core.test_only_write_world(subject.as_str(), b"first", "text/plain", &[])
            .unwrap();
        let first_conn = Connection::open(crate::world::world_db(&dir, subject.as_str())).unwrap();
        let first_generation = world_schema::generation(&first_conn).unwrap();
        drop(first_conn);

        let permit = authorize_delete(&subject, auth::Tier::Approve).unwrap();
        delete(
            &core,
            &permit,
            delete_req("text/plain", Vec::new()),
            &NoopTrace,
        )
        .await
        .unwrap();

        core.test_only_write_world(subject.as_str(), b"second", "text/plain", &[])
            .unwrap();
        let second_conn = Connection::open(crate::world::world_db(&dir, subject.as_str())).unwrap();
        let second_generation = world_schema::generation(&second_conn).unwrap();
        drop(second_conn);
        assert_ne!(first_generation, second_generation);

        let ledger = Connection::open(crate::world::world_db(&dir, "var/log/deletes")).unwrap();
        let stored_generation: String = ledger
            .query_row(
                "SELECT value FROM event_headers
                 WHERE event_id=2 AND name=?1",
                [crate::audit::DELETE_SUBJECT_GENERATION],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(stored_generation, first_generation.as_str());
        assert_ne!(stored_generation, second_generation.as_str());
        let _ = std::fs::remove_dir_all(dir);
    }
}
