//! SQLite error classification shared by protocol adapters and world ops.
//!
//! These helpers classify storage failures without deciding the wire response.
//! HTTP maps them to status codes in `response.rs`; CoAP maps them in
//! `coap.rs`; `world_ops.rs` uses them to keep transient and permanent storage
//! failures distinct.

pub(crate) fn is_transient_storage_error(err: &rusqlite::Error) -> bool {
    if matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked)
    ) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("database is locked") || msg.contains("database table is locked")
}

pub(crate) fn is_insufficient_storage_error(err: &rusqlite::Error) -> bool {
    if matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DiskFull)
    ) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("database or disk is full")
        || msg.contains("disk is full")
        || msg.contains("no space left")
        || msg.contains("not enough space")
}
