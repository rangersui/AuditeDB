//! Filesystem operations for world directories.

use percent_encoding::percent_decode_str;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

use crate::{engine_types::ValidatedWorldPath, world_schema};

use super::{create_dir_error, disk_name, world_db, world_dir};

pub(crate) fn delete(data_root: &Path, world: &ValidatedWorldPath) -> bool {
    let world = world.as_str();
    let dir = world_dir(data_root, world);
    if !dir.exists() {
        return false;
    }

    // Windows + SQLite WAL: -wal / -shm files stay locked briefly after
    // the connection drops. Naive remove_dir_all may return Ok while
    // leaving stragglers, or fail outright. Flush WAL via checkpoint,
    // then retry the remove.
    release_wal_files(data_root, world);

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
/// Returns canonical (decoded) names.
pub fn list(data_root: &Path) -> rusqlite::Result<Vec<String>> {
    list_matching(data_root, |_| true)
}

/// List sqlite-backed world keys with a canonical prefix.
pub fn list_with_prefix(data_root: &Path, prefix: &str) -> rusqlite::Result<Vec<String>> {
    list_matching(data_root, |world| world.starts_with(prefix))
}

/// List sqlite-backed world keys with a canonical prefix, returning `None`
/// before materializing more than `max` matches.
pub fn list_with_prefix_bounded(
    data_root: &Path,
    prefix: &str,
    max: usize,
) -> rusqlite::Result<Option<Vec<String>>> {
    list_matching_bounded(data_root, |world| world.starts_with(prefix), max)
}

fn release_wal_files(data_root: &Path, world: &str) {
    match open_checkpoint_conn(data_root, world) {
        Ok(Some(c)) => {
            if let Err(err) = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                log_wal_release_error(world, "checkpoint", &err);
            }
            drop(c);
        }
        Ok(None) => {}
        Err(err) => log_wal_release_error(world, "open", &err),
    }
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(
            data_root
                .join(disk_name(world))
                .join(format!("universe.db{suffix}")),
        );
    }
    std::thread::sleep(Duration::from_millis(10));
}

pub(super) fn open_checkpoint_conn(
    data_root: &Path,
    world: &str,
) -> rusqlite::Result<Option<Connection>> {
    let path = world_db(data_root, world);
    if !path.exists() {
        return Ok(None);
    }
    let c = match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE) {
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
    eprintln!("elastik-core internal delete wal checkpoint {phase} failed for {world}: {err}");
}

fn list_matching(
    data_root: &Path,
    mut keep: impl FnMut(&str) -> bool,
) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(data_root).map_err(create_dir_error)?;
    for entry in rd {
        let entry = entry.map_err(create_dir_error)?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().join("universe.db").exists() {
            continue;
        }
        let decoded = percent_decode_str(&name).decode_utf8_lossy().into_owned();
        if keep(&decoded) {
            out.push(decoded);
        }
    }
    out.sort();
    Ok(out)
}

fn list_matching_bounded(
    data_root: &Path,
    mut keep: impl FnMut(&str) -> bool,
    max: usize,
) -> rusqlite::Result<Option<Vec<String>>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(data_root).map_err(create_dir_error)?;
    for entry in rd {
        let entry = entry.map_err(create_dir_error)?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().join("universe.db").exists() {
            continue;
        }
        let decoded = percent_decode_str(&name).decode_utf8_lossy().into_owned();
        if keep(&decoded) {
            if out.len() >= max {
                return Ok(None);
            }
            out.push(decoded);
        }
    }
    out.sort();
    Ok(Some(out))
}
