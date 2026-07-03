//! Filesystem operations for world directories.

use percent_encoding::percent_decode_str;
use rusqlite::{ffi, Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

use crate::{
    blocking_sqlite::BlockingSqlite,
    engine_types::{ValidatedWorldPath, ValidatedWorldPrefix},
    world_schema,
};

use super::{create_dir_error, disk_name, validated_world_db, validated_world_dir};

pub(crate) fn delete(
    proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> bool {
    let dir = validated_world_dir(data_root, world);
    if !dir.exists() {
        return false;
    }

    // Windows + SQLite WAL: -wal / -shm files stay locked briefly after
    // the connection drops. Naive remove_dir_all may return Ok while
    // leaving stragglers, or fail outright. Flush WAL via checkpoint,
    // then retry the remove.
    release_wal_files(proof, data_root, world);

    let mut delay = Duration::from_millis(30);
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                if !dir.exists() {
                    return true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => {}
        }
        if attempt == 19 {
            break;
        }
        std::thread::sleep(delay);
        delay = std::cmp::min(delay * 2, Duration::from_millis(500));
    }
    !dir.exists()
}

/// List all sqlite-backed world keys by scanning the data dir.
/// Returns decoded names as validated world-path proofs.
pub fn list(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
) -> rusqlite::Result<Vec<ValidatedWorldPath>> {
    list_matching(data_root, |_| true)
}

/// List sqlite-backed world keys with a canonical prefix.
pub fn list_with_prefix(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    prefix: &ValidatedWorldPrefix,
) -> rusqlite::Result<Vec<ValidatedWorldPath>> {
    list_matching(data_root, |world| {
        world.as_str().starts_with(prefix.as_str())
    })
}

/// List sqlite-backed world keys with a canonical prefix, returning `None`
/// before materializing more than `max` matches.
pub fn list_with_prefix_bounded(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    prefix: &ValidatedWorldPrefix,
    max: usize,
) -> rusqlite::Result<Option<Vec<ValidatedWorldPath>>> {
    list_matching_bounded(
        data_root,
        |world| world.as_str().starts_with(prefix.as_str()),
        max,
    )
}

fn release_wal_files(proof: &mut BlockingSqlite, data_root: &Path, world: &ValidatedWorldPath) {
    match open_checkpoint_conn_validated(proof, data_root, world) {
        Ok(Some(c)) => {
            if let Err(err) = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                log_wal_release_error(world.as_str(), "checkpoint", &err);
            }
            drop(c);
        }
        Ok(None) => {}
        Err(err) => log_wal_release_error(world.as_str(), "open", &err),
    }
    let dir = validated_world_dir(data_root, world);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("universe.db{suffix}")));
    }
    std::thread::sleep(Duration::from_millis(10));
}

#[cfg(test)]
pub(super) fn open_checkpoint_conn(
    data_root: &Path,
    world: &str,
) -> rusqlite::Result<Option<Connection>> {
    let path = super::world_db(data_root, world);
    open_checkpoint_conn_path(&path)
}

fn open_checkpoint_conn_validated(
    _proof: &mut BlockingSqlite,
    data_root: &Path,
    world: &ValidatedWorldPath,
) -> rusqlite::Result<Option<Connection>> {
    let path = validated_world_db(data_root, world);
    open_checkpoint_conn_path(&path)
}

fn open_checkpoint_conn_path(path: &Path) -> rusqlite::Result<Option<Connection>> {
    if !path.exists() {
        return Ok(None);
    }
    let c = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE) {
        Ok(c) => c,
        Err(e) => {
            if !path.exists() {
                return Ok(None);
            }
            return Err(e);
        }
    };
    c.busy_timeout(Duration::from_millis(5000))?;
    world_schema::verify(&c)?;
    Ok(Some(c))
}

fn log_wal_release_error(world: &str, phase: &str, err: &rusqlite::Error) {
    #[cfg(feature = "unstable-engine")]
    tracing::warn!(
        world,
        phase,
        error = %err,
        "delete skipped wal checkpoint before physical remove"
    );

    #[cfg(not(feature = "unstable-engine"))]
    eprintln!("l5 internal delete wal checkpoint {phase} failed for {world}: {err}");
}

fn list_matching(
    data_root: &Path,
    mut keep: impl FnMut(&ValidatedWorldPath) -> bool,
) -> rusqlite::Result<Vec<ValidatedWorldPath>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(data_root).map_err(create_dir_error)?;
    for entry in rd {
        let entry = entry.map_err(create_dir_error)?;
        if !entry.path().join("universe.db").exists() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| corrupt_disk_world_name("<non-unicode>", "disk name is not Unicode"))?;
        let world = decode_disk_world_name(&name)?;
        if keep(&world) {
            out.push(world);
        }
    }
    out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(out)
}

fn list_matching_bounded(
    data_root: &Path,
    mut keep: impl FnMut(&ValidatedWorldPath) -> bool,
    max: usize,
) -> rusqlite::Result<Option<Vec<ValidatedWorldPath>>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(data_root).map_err(create_dir_error)?;
    for entry in rd {
        let entry = entry.map_err(create_dir_error)?;
        if !entry.path().join("universe.db").exists() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| corrupt_disk_world_name("<non-unicode>", "disk name is not Unicode"))?;
        let world = decode_disk_world_name(&name)?;
        if keep(&world) {
            if out.len() >= max {
                return Ok(None);
            }
            out.push(world);
        }
    }
    out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(Some(out))
}

fn decode_disk_world_name(name: &str) -> rusqlite::Result<ValidatedWorldPath> {
    let decoded = percent_decode_str(name)
        .decode_utf8()
        .map_err(|err| corrupt_disk_world_name(name, format!("invalid percent UTF-8: {err}")))?
        .into_owned();
    let world = ValidatedWorldPath::new(decoded)
        .map_err(|_| corrupt_disk_world_name(name, "decoded world path failed validation"))?;
    let canonical = disk_name(world.as_str());
    if canonical != name {
        return Err(corrupt_disk_world_name(
            name,
            format!("non-canonical disk name for {}", world.as_str()),
        ));
    }
    Ok(world)
}

fn corrupt_disk_world_name(name: &str, detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_CORRUPT),
        Some(format!(
            "invalid world directory {name:?}: {}",
            detail.into()
        )),
    )
}
