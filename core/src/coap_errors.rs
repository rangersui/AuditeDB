//! CoAP response-code mapping for protocol-neutral world operation errors.

use crate::world_ops;

pub(crate) fn read_error_to_coap(err: &world_ops::ReadError) -> u8 {
    match err {
        world_ops::ReadError::Auth(_) => 129,
        world_ops::ReadError::InsufficientStorage { .. } => 167,
        world_ops::ReadError::TransientStorage { .. } => 163,
        world_ops::ReadError::StorageRead { .. } | world_ops::ReadError::PermitWorldMismatch => 160,
    }
}

pub(crate) fn read_error_body(err: &world_ops::ReadError) -> &'static [u8] {
    match err {
        world_ops::ReadError::Auth(_) => b"unauthorized\n",
        world_ops::ReadError::InsufficientStorage { .. } => b"insufficient storage\n",
        world_ops::ReadError::TransientStorage { .. } => b"storage busy\n",
        world_ops::ReadError::StorageRead { .. } | world_ops::ReadError::PermitWorldMismatch => {
            b"storage error\n"
        }
    }
}

pub(crate) fn write_error_to_coap(err: &world_ops::WriteError) -> u8 {
    match err {
        world_ops::WriteError::Auth(_) => 129,
        world_ops::WriteError::PayloadTooLarge { .. } => 141,
        world_ops::WriteError::PreconditionFailed { .. } => 140,
        world_ops::WriteError::NotFound => 132,
        world_ops::WriteError::QuotaExceeded { .. }
        | world_ops::WriteError::InsufficientStorage { .. } => 167,
        world_ops::WriteError::TransientStorage { .. } => 163,
        world_ops::WriteError::StorageRead { .. }
        | world_ops::WriteError::StorageWriteAudit { .. }
        | world_ops::WriteError::Internal(_)
        | world_ops::WriteError::PermitWorldMismatch => 160,
    }
}
