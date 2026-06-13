//! Protocol-neutral world read transitions.
//!
//! This module owns read permits and read-side storage/audit error
//! classification. Write transitions stay in `world_ops`.

#![cfg_attr(not(feature = "unstable-engine"), allow(dead_code))]

use crate::{
    audit, auth, can_read,
    engine_types::ValidatedWorldPath,
    timeline::{TimelineAddress, TimelineCoordinate, TimelineRead},
    world, AuthGate, Core, StorageFailureClass,
};

#[derive(Debug)]
pub(crate) struct ReadPermit {
    world: ValidatedWorldPath,
}

impl ReadPermit {
    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }
}

pub(crate) enum ReadOutcome {
    Found { stage: world::Stage, etag: String },
    Missing,
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Auth(AuthGate),
    TransientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    InsufficientStorage {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    StorageRead {
        #[allow(dead_code)]
        scope: &'static str,
        err: rusqlite::Error,
    },
    AuditChainBroken {
        #[allow(dead_code)]
        scope: &'static str,
        break_report: audit::VerifyBreak,
    },
    PermitWorldMismatch,
}

pub(crate) fn authorize_read(
    core: &Core,
    world: &ValidatedWorldPath,
    tier: auth::Tier,
) -> Result<ReadPermit, ReadError> {
    if can_read(core, tier) {
        Ok(ReadPermit {
            world: world.clone(),
        })
    } else {
        Err(ReadError::Auth(AuthGate::Read))
    }
}

pub(crate) fn read_world(core: &Core, permit: &ReadPermit) -> Result<ReadOutcome, ReadError> {
    read_world_for(core, permit, &permit.world)
}

pub(crate) fn read_timeline_body(
    core: &Core,
    permit: &ReadPermit,
    address: &TimelineAddress,
) -> Result<TimelineRead, ReadError> {
    if permit.world != *address.world() {
        return Err(ReadError::PermitWorldMismatch);
    }
    match core.read_timeline_body(address) {
        Ok(Some(read)) => Ok(read),
        Ok(None) => Ok(TimelineRead::Gone {
            address: address.clone(),
        }),
        Err(err) => Err(classify_read_audit_error("timeline read", err)),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn dereference_timeline_coordinate(
    core: &Core,
    permit: &ReadPermit,
    coordinate: &TimelineCoordinate,
) -> Result<audit::timeline_dereference::TimelineDereference, ReadError> {
    if permit.world != *coordinate.world() {
        return Err(ReadError::PermitWorldMismatch);
    }
    let read = core
        .read_cache
        .cached_dereference_timeline_coordinate(&core.data, permit, coordinate, &core.hmac_key)
        .map_err(audit::AuditError::from)
        .map_err(|err| classify_read_audit_error("timeline dereference", err))?;
    match read {
        Some(result) => {
            result.map_err(|err| classify_read_audit_error("timeline dereference", err))
        }
        None => Ok(
            audit::timeline_dereference::TimelineDereference::UnprovenCoordinate(
                coordinate.clone(),
            ),
        ),
    }
}

pub(crate) fn read_world_for(
    core: &Core,
    permit: &ReadPermit,
    world: &ValidatedWorldPath,
) -> Result<ReadOutcome, ReadError> {
    if &permit.world != world {
        return Err(ReadError::PermitWorldMismatch);
    }
    match core.read_world_with_etag(world.as_str()) {
        Ok(Some((stage, etag))) => Ok(ReadOutcome::Found { stage, etag }),
        Ok(None) => Ok(ReadOutcome::Missing),
        Err(err) => Err(classify_read_error("storage read", err)),
    }
}

fn classify_read_error(scope: &'static str, err: rusqlite::Error) -> ReadError {
    match crate::classify_storage_failure(&err) {
        StorageFailureClass::InsufficientStorage => ReadError::InsufficientStorage { scope, err },
        StorageFailureClass::Transient => ReadError::TransientStorage { scope, err },
        StorageFailureClass::Other => ReadError::StorageRead { scope, err },
    }
}

fn classify_read_audit_error(scope: &'static str, err: audit::AuditError) -> ReadError {
    match err {
        audit::AuditError::ChainBroken(break_report) => ReadError::AuditChainBroken {
            scope,
            break_report,
        },
        audit::AuditError::Storage(err) => classify_read_error(scope, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine_types::AuditHmacKey,
        test_support::test_core,
        timeline::{BodySha256, TimelineAddress, TimelineCoordinate, TimelineSeq},
        world,
        world_generation::WorldGeneration,
    };

    fn world_path(world: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(world).unwrap()
    }

    fn timeline_address(world: ValidatedWorldPath) -> TimelineAddress {
        TimelineAddress::test_only_new(
            world,
            WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap(),
            TimelineSeq::new(1).unwrap(),
            BodySha256::for_body(b"value"),
        )
    }

    fn timeline_coordinate(world: &str) -> TimelineCoordinate {
        TimelineCoordinate::from_wire_parts(
            world,
            "0123456789abcdef0123456789abcdef",
            1,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap()
    }

    #[test]
    fn timeline_read_permit_is_bound_to_address_world() {
        let (core, dir) = test_core("timeline-permit-bound");
        let permit_world = world_path("home/right");
        let permit = authorize_read(&core, &permit_world, auth::Tier::Read).unwrap();
        let address = timeline_address(world_path("home/wrong"));

        assert!(matches!(
            read_timeline_body(&core, &permit, &address),
            Err(ReadError::PermitWorldMismatch)
        ));

        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn timeline_dereference_permit_is_bound_to_coordinate_world() {
        let (core, dir) = test_core("timeline-coordinate-permit-bound");
        let permit_world = world_path("home/right");
        let permit = authorize_read(&core, &permit_world, auth::Tier::Read).unwrap();
        let coordinate = timeline_coordinate("home/wrong");

        assert!(matches!(
            dereference_timeline_coordinate(&core, &permit, &coordinate),
            Err(ReadError::PermitWorldMismatch)
        ));

        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn timeline_dereference_missing_world_is_unproven_coordinate() {
        let (core, dir) = test_core("timeline-coordinate-missing-world");
        let coordinate = timeline_coordinate("home/missing");
        let permit = authorize_read(&core, coordinate.world(), auth::Tier::Read).unwrap();

        match dereference_timeline_coordinate(&core, &permit, &coordinate).unwrap() {
            audit::timeline_dereference::TimelineDereference::UnprovenCoordinate(got) => {
                assert_eq!(got, coordinate)
            }
            _ => panic!("missing subject DB must not prove a timeline state"),
        }

        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn real_sqlite_lock_maps_to_transient_read_error() {
        let (core, dir) = test_core("read-runtime-lock-classification");
        let world = world_path("home/busy");
        world::write_with_audit_checked(
            &core.data,
            &world,
            b"ok",
            "text/plain",
            &[],
            &AuditHmacKey::try_from_slice(crate::test_support::TEST_HMAC_KEY).unwrap(),
        )
        .unwrap();

        let holder = rusqlite::Connection::open(crate::world::world_db(&dir, world.as_str()))
            .expect("open lock holder");
        holder
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .expect("exclusive locking mode");
        holder
            .execute_batch("BEGIN EXCLUSIVE")
            .expect("hold exclusive transaction");

        let read_permit = authorize_read(&core, &world, auth::Tier::Read).unwrap();
        assert!(
            matches!(
                read_world(&core, &read_permit),
                Err(ReadError::TransientStorage { .. })
            ),
            "real SQLite busy/locked errors must stay classified as transient"
        );

        drop(holder);
        let _ = std::fs::remove_dir_all(dir);
    }
}
