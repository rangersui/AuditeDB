use crate::world;

use super::ReadCache;

#[cfg_attr(not(test), allow(dead_code))]
type TimelineReadResult = crate::audit::AuditResult<crate::timeline::TimelineRead>;

impl ReadCache {
    /// Read body + meta + latest hmac via the cached read path.
    /// Thin wrapper over the generic `with_tracked_conn` machinery.
    pub(crate) fn cached_read_with_hmac(
        &self,
        data: &std::path::Path,
        world: &str,
    ) -> rusqlite::Result<Option<(world::Stage, Option<String>)>> {
        self.with_tracked_conn(data, world, world::read_with_hmac_via_conn)
    }

    /// O(1) chain-head read through the cached read path. Same
    /// SlotState protocol as `cached_verify_chain` -- delete drains
    /// in-flight head reads via the slot's write guard. Outer `None`
    /// means the world's DB is missing; inner `None` means the chain
    /// is empty (bootstrap shape).
    pub(crate) fn cached_chain_head(
        &self,
        data: &std::path::Path,
        world: &str,
    ) -> rusqlite::Result<Option<Option<(i64, String)>>> {
        self.with_tracked_conn(data, world, crate::audit::chain_head_via_conn)
    }

    /// Verify the audit chain through the cached read path (Bug 58).
    /// Same SlotState protocol as `cached_read_with_hmac` -- delete
    /// drains in-flight verifies via the slot's write guard. Closes
    /// the v10 type-gate gap on the admin
    /// `/proc/audit/{world}/verify` endpoint.
    pub(crate) fn cached_verify_chain(
        &self,
        data: &std::path::Path,
        world: &str,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<crate::audit::VerifyReport>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            crate::audit::verify_chain_via_conn(conn, world, &key)
        })
    }

    /// Historical body read through the cached read path. Same SlotState
    /// protocol as ordinary cached reads: delete drains in-flight timeline
    /// reads before unlinking the world database, and a tombstone produces
    /// `Ok(None)` rather than opening a new fd.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cached_read_timeline_body(
        &self,
        data: &std::path::Path,
        address: &crate::timeline::TimelineAddress,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<TimelineReadResult>> {
        let world = address.world().as_str();
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::read_timeline_body_via_conn(
                conn, address, &key,
            ))
        })
    }

    /// Delete-side subject anchoring. Reads the latest body-bearing audit row
    /// through the same SlotState protocol as ordinary reads, so delete's
    /// later tombstone drain cannot race a bare fd.
    pub(crate) fn cached_latest_body_head(
        &self,
        data: &std::path::Path,
        world: &crate::engine_types::ValidatedWorldPath,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<crate::audit::AuditResult<Option<crate::audit::VerifiedBodyHead>>>>
    {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world.as_str(), move |conn| {
            Ok(crate::audit::verified_latest_body_head_via_conn(
                conn, world, &key,
            ))
        })
    }
}
