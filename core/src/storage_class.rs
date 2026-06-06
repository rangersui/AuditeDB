//! SQLite error classification shared by protocol adapters and world ops.
//!
//! These helpers classify storage failures without deciding adapter output.
//! Adapters map them to protocol-specific outcomes; `world_ops.rs` uses them
//! to keep transient and permanent storage failures distinct.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorageFailureClass {
    Transient,
    InsufficientStorage,
    Other,
}

pub(crate) fn classify_storage_failure(err: &rusqlite::Error) -> StorageFailureClass {
    if is_insufficient_storage_error_impl(err) {
        StorageFailureClass::InsufficientStorage
    } else if is_transient_storage_error_impl(err) {
        StorageFailureClass::Transient
    } else {
        StorageFailureClass::Other
    }
}

fn is_transient_storage_error_impl(err: &rusqlite::Error) -> bool {
    if matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked)
    ) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("database is locked") || msg.contains("database table is locked")
}

fn is_insufficient_storage_error_impl(err: &rusqlite::Error) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_full_is_insufficient_storage() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert_eq!(
            classify_storage_failure(&err),
            StorageFailureClass::InsufficientStorage
        );
    }

    #[test]
    fn busy_and_locked_are_transient_storage() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            let err = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert_eq!(
                classify_storage_failure(&err),
                StorageFailureClass::Transient
            );
        }
    }

    #[test]
    fn corrupt_is_not_quota_or_transient_storage() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            None,
        );
        assert_eq!(classify_storage_failure(&err), StorageFailureClass::Other);
    }
}
