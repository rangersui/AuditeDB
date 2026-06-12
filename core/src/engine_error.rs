//! Engine error conversion and diagnostics.

use crate::{
    engine::{self, EngineError},
    world_ops, world_read_ops, BlockingSqliteError,
};

fn storage_op_label(op: world_ops::StorageOp) -> &'static str {
    match op {
        world_ops::StorageOp::Read => "read",
        world_ops::StorageOp::WriteAudit => "write_audit",
    }
}

pub(crate) fn read_error_to_engine(
    value: world_read_ops::ReadError,
    world: Option<&str>,
) -> EngineError {
    match value {
        world_read_ops::ReadError::Auth(gate) => EngineError::Auth(gate),
        world_read_ops::ReadError::TransientStorage { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::TransientStorage
        }
        world_read_ops::ReadError::InsufficientStorage { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::InsufficientStorage
        }
        world_read_ops::ReadError::StorageRead { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::Storage
        }
        world_read_ops::ReadError::AuditChainBroken {
            scope,
            break_report,
        } => {
            log_audit_chain_error(scope, &break_report, "read", world);
            EngineError::Storage
        }
        world_read_ops::ReadError::PermitWorldMismatch => {
            EngineError::InternalInvariant("read permit world mismatch")
        }
    }
}

pub(crate) fn write_error_to_engine(
    value: world_ops::WriteError,
    world: Option<&str>,
) -> EngineError {
    match value {
        world_ops::WriteError::Auth(gate) => EngineError::Auth(gate),
        world_ops::WriteError::PayloadTooLarge { max } => EngineError::PayloadTooLarge { max },
        world_ops::WriteError::PreconditionFailed { message } => {
            EngineError::PreconditionFailed { message }
        }
        world_ops::WriteError::NotFound => EngineError::NotFound,
        world_ops::WriteError::QuotaExceeded {
            used,
            quota,
            projected,
        } => EngineError::QuotaExceeded {
            used,
            quota,
            projected,
        },
        world_ops::WriteError::TransientStorage { scope, err, op } => {
            log_storage_error(scope, &err, storage_op_label(op), world);
            EngineError::TransientStorage
        }
        world_ops::WriteError::InsufficientStorage { scope, err, op } => {
            log_storage_error(scope, &err, storage_op_label(op), world);
            EngineError::InsufficientStorage
        }
        world_ops::WriteError::StorageRead { scope, err } => {
            log_storage_error(scope, &err, "read", world);
            EngineError::Storage
        }
        world_ops::WriteError::StorageWriteAudit { scope, err } => {
            log_storage_error(scope, &err, "write_audit", world);
            EngineError::Storage
        }
        world_ops::WriteError::StorageInvariant(reason) => {
            log_storage_invariant("storage/cas", &reason, "write_audit", world);
            EngineError::Storage
        }
        world_ops::WriteError::AuditChainBroken {
            scope,
            break_report,
        } => {
            log_audit_chain_error(scope, &break_report, "write_audit", world);
            EngineError::Storage
        }
        world_ops::WriteError::Internal(message) => EngineError::InternalInvariant(message),
    }
}

fn log_storage_invariant(
    scope: &'static str,
    reason: &world_ops::StorageInvariantReason,
    operation: &'static str,
    world: Option<&str>,
) {
    let reason_text = match reason {
        world_ops::StorageInvariantReason::CasBodyMismatch(body_sha256) => {
            format!(
                "cas body hash row contains different bytes: {}",
                body_sha256.as_str()
            )
        }
        world_ops::StorageInvariantReason::CasState(reason) => (*reason).to_owned(),
    };

    #[cfg(feature = "unstable-engine")]
    tracing::error!(
        scope,
        operation,
        world = world.unwrap_or(""),
        reason = reason_text.as_str(),
        "engine storage invariant violation"
    );

    #[cfg(not(feature = "unstable-engine"))]
    match world {
        Some(world) => {
            eprintln!("elastik-core internal {scope} ({operation}) world={world}: {reason_text}");
        }
        None => eprintln!("elastik-core internal {scope} ({operation}): {reason_text}"),
    }
}

impl From<world_read_ops::ReadError> for EngineError {
    fn from(value: world_read_ops::ReadError) -> Self {
        read_error_to_engine(value, None)
    }
}

impl From<world_ops::WriteError> for EngineError {
    fn from(value: world_ops::WriteError) -> Self {
        write_error_to_engine(value, None)
    }
}

pub(crate) fn log_storage_error(
    scope: &'static str,
    err: &rusqlite::Error,
    operation: &'static str,
    world: Option<&str>,
) {
    #[cfg(feature = "unstable-engine")]
    tracing::error!(
        scope,
        operation,
        world = world.unwrap_or(""),
        sqlite_code = ?engine::sqlite_code(err),
        error = %err,
        "engine storage error"
    );

    #[cfg(not(feature = "unstable-engine"))]
    match world {
        Some(world) => {
            eprintln!("elastik-core internal {scope} ({operation}) world={world}: {err}");
        }
        None => eprintln!("elastik-core internal {scope} ({operation}): {err}"),
    }
}

pub(crate) fn log_audit_chain_error(
    scope: &'static str,
    break_report: &crate::audit::VerifyBreak,
    operation: &'static str,
    world: Option<&str>,
) {
    #[cfg(feature = "unstable-engine")]
    tracing::error!(
        scope,
        operation,
        world = world.unwrap_or(""),
        break_at = break_report.break_at,
        expected = %break_report.expected,
        actual = %break_report.actual,
        "engine audit chain broken"
    );

    #[cfg(not(feature = "unstable-engine"))]
    match world {
        Some(world) => eprintln!(
            "elastik-core internal {scope} ({operation}) world={world}: audit chain broken at event {}: expected {}, actual {}",
            break_report.break_at, break_report.expected, break_report.actual
        ),
        None => eprintln!(
            "elastik-core internal {scope} ({operation}): audit chain broken at event {}: expected {}, actual {}",
            break_report.break_at, break_report.expected, break_report.actual
        ),
    }
}

pub(crate) fn log_blocking_storage_error(
    scope: &'static str,
    err: &BlockingSqliteError,
    operation: &'static str,
    world: Option<&str>,
) {
    match err {
        BlockingSqliteError::Audit(crate::audit::AuditError::ChainBroken(break_report)) => {
            log_audit_chain_error(scope, break_report, operation, world)
        }
        BlockingSqliteError::Audit(crate::audit::AuditError::Storage(err)) => {
            log_storage_error(scope, err, operation, world)
        }
        BlockingSqliteError::Sqlite(err) => log_storage_error(scope, err, operation, world),
        BlockingSqliteError::Worker => {
            #[cfg(feature = "unstable-engine")]
            tracing::error!(
                scope,
                operation,
                world = world.unwrap_or(""),
                "engine storage worker failed"
            );

            #[cfg(not(feature = "unstable-engine"))]
            match world {
                Some(world) => {
                    eprintln!(
                        "elastik-core internal {scope} ({operation}) world={world}: sqlite worker failed"
                    );
                }
                None => {
                    eprintln!("elastik-core internal {scope} ({operation}): sqlite worker failed");
                }
            }
        }
    }
}
