//! CoAP response-code mapping for protocol-neutral engine operation errors.

use crate::engine::EngineError;

pub(crate) fn read_error_to_coap(err: &EngineError) -> u8 {
    match err {
        EngineError::Auth(_) => 129,
        EngineError::InvalidMetadata { .. } => 128,
        EngineError::InsufficientStorage => 167,
        EngineError::TransientStorage
        | EngineError::ShuttingDown
        | EngineError::SubscriptionLimit => 163,
        EngineError::Storage | EngineError::InternalInvariant(_) => 160,
        EngineError::InvalidWorldName
        | EngineError::NotFound
        | EngineError::AppendOnly
        | EngineError::PayloadTooLarge { .. }
        | EngineError::PreconditionFailed { .. }
        | EngineError::QuotaExceeded { .. } => 160,
        _ => 160,
    }
}

pub(crate) fn read_error_body(err: &EngineError) -> &'static [u8] {
    match err {
        EngineError::Auth(_) => b"unauthorized\n",
        EngineError::InvalidMetadata { .. } => b"invalid metadata\n",
        EngineError::InsufficientStorage => b"insufficient storage\n",
        EngineError::TransientStorage
        | EngineError::ShuttingDown
        | EngineError::SubscriptionLimit => b"storage busy\n",
        _ => b"storage error\n",
    }
}

pub(crate) fn write_error_to_coap(err: &EngineError) -> u8 {
    match err {
        EngineError::Auth(_) => 129,
        EngineError::PayloadTooLarge { .. } => 141,
        EngineError::PreconditionFailed { .. } => 140,
        EngineError::InvalidMetadata { .. } => 128,
        EngineError::NotFound => 132,
        EngineError::QuotaExceeded { .. } | EngineError::InsufficientStorage => 167,
        EngineError::TransientStorage
        | EngineError::ShuttingDown
        | EngineError::SubscriptionLimit => 163,
        EngineError::AppendOnly => 131,
        EngineError::Storage
        | EngineError::InternalInvariant(_)
        | EngineError::InvalidWorldName => 160,
        _ => 160,
    }
}
