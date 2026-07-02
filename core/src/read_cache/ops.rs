use crate::{engine_types::ValidatedWorldPath, world};

use super::ReadCache;

#[cfg_attr(not(test), allow(dead_code))]
type TimelineReadResult = crate::audit::AuditResult<crate::timeline::TimelineRead>;
#[cfg_attr(not(test), allow(dead_code))]
type TimelineDereferenceResult =
    crate::audit::AuditResult<crate::audit::timeline_dereference::TimelineDereference>;
#[cfg_attr(not(test), allow(dead_code))]
type TimelineReplayAfterResult = crate::audit::AuditResult<crate::audit::VerifiedReplayAfter>;
type ChainHeadResult = crate::audit::AuditResult<Option<crate::audit::VerifiedChainHead>>;
type ChainStampResult = crate::audit::AuditResult<crate::chain_stamp::ChainStampRead>;
type CurrentReadResult = crate::audit::AuditResult<(world::Stage, Option<String>)>;

impl ReadCache {
    /// Read body + meta + latest hmac via the cached read path.
    /// Thin wrapper over the generic `with_tracked_conn` machinery.
    pub(crate) fn cached_read_with_hmac(
        &self,
        data: &std::path::Path,
        world_path: &ValidatedWorldPath,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<CurrentReadResult>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world_path, move |conn| {
            Ok(world::read_with_hmac_via_conn(conn, world_path, &key))
        })
    }

    /// Verified chain-head read through the cached read path. Same
    /// SlotState protocol as `cached_verify_chain` -- delete drains
    /// in-flight head reads via the slot's write guard. Outer `None`
    /// means the world's DB is missing; inner `None` means the chain
    /// is empty (bootstrap shape).
    pub(crate) fn cached_chain_head(
        &self,
        data: &std::path::Path,
        world: &ValidatedWorldPath,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<ChainHeadResult>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::chain_head_via_conn(conn, world, &key))
        })
    }

    /// Verified chain-stamp lookup through the cached read path. Same SlotState
    /// protocol as `cached_chain_head`: delete drains in-flight stamp lookups
    /// via the slot guard, and the stamp is captured by the verifier walk.
    pub(crate) fn cached_chain_stamp(
        &self,
        data: &std::path::Path,
        world: &ValidatedWorldPath,
        seq: crate::chain_stamp::ChainSeq,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<ChainStampResult>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::chain_stamp_via_conn(conn, world, seq, &key))
        })
    }

    /// Verify the audit chain through the cached read path (Bug 58).
    /// Same SlotState protocol as `cached_read_with_hmac` -- delete
    /// drains in-flight verifies via the slot's write guard. Closes
    /// the v10 type-gate gap on the admin
    /// `/proc/audit/{world}/verify` endpoint.
    pub(crate) fn cached_verify_chain(
        &self,
        data: &std::path::Path,
        world: &ValidatedWorldPath,
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
        let world = address.world();
        let key = key.clone_secret();
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::read_timeline_body_via_conn(
                conn, address, &key,
            ))
        })
    }

    /// Coordinate dereference through the cached read path. The resolver runs
    /// inside one tracked read transaction so audit verification, row proof,
    /// and retained-CAS lookup share one SQLite snapshot.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cached_dereference_timeline_coordinate(
        &self,
        data: &std::path::Path,
        // Deliberately require the read permit here so cache helpers cannot
        // turn raw coordinate syntax into a proof outside the read gate.
        permit: &crate::world_read_ops::ReadPermit,
        coordinate: &crate::timeline::TimelineCoordinate,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<TimelineDereferenceResult>> {
        if permit.world() != coordinate.world() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let key = key.clone_secret();
        self.with_tracked_conn(data, coordinate.world(), move |conn| {
            Ok(
                crate::audit::timeline_dereference::dereference_timeline_coordinate_via_conn(
                    conn, coordinate, &key,
                ),
            )
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
        self.with_tracked_conn(data, world, move |conn| {
            Ok(crate::audit::verified_latest_body_head_via_conn(
                conn, world, &key,
            ))
        })
    }

    /// Durable subscription replay scan through the cached read path.
    /// Verification, marker lookup, and replay-row extraction share one
    /// tracked SQLite transaction, so delete cannot unlink the database while
    /// a replay scan owns the fd.
    pub(crate) fn cached_replay_chain_events_after(
        &self,
        data: &std::path::Path,
        event_id: &crate::subscription_event_id::SubscriptionEventId,
        limit: usize,
        key: &crate::engine_types::AuditHmacKey,
    ) -> rusqlite::Result<Option<TimelineReplayAfterResult>> {
        let key = key.clone_secret();
        self.with_tracked_conn(data, event_id.world(), move |conn| {
            Ok(crate::audit::verified_replay_events_after_via_conn(
                conn,
                event_id.world(),
                event_id.generation(),
                event_id.seq(),
                limit,
                &key,
            ))
        })
    }
}
