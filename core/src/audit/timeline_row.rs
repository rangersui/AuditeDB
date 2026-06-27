//! Sealed SQLite row snapshots for timeline reads.
//!
//! Raw `events` columns are allowed to exist only inside this module. Callers
//! get methods that expose typed or checked facts, so timeline resolvers cannot
//! accidentally carry unparsed SQL strings past the row-loading boundary.

use bytes::Bytes;
use rusqlite::{ffi, params, OptionalExtension, Transaction};

use crate::{
    engine_types::{Representation, ValidatedWorldPath},
    event::AuditEventKind,
    timeline::{BodySha256, InvalidBodySha256, TimelineSeq},
};

pub(super) struct TimelineEventIdentity {
    event_type: String,
    target: String,
    body_sha256: String,
}

pub(super) struct TimelineEventSnapshot {
    identity: TimelineEventIdentity,
    size: i64,
    content_type: String,
    headers: Vec<(String, String)>,
}

pub(super) struct MatchedTimelineBodyRow {
    snapshot: TimelineEventSnapshot,
    body_sha256: BodySha256,
}

pub(super) struct TimelineBodyHeadSnapshot {
    seq: TimelineSeq,
    event: TimelineEventIdentity,
    hmac_label: String,
}

pub(super) enum TimelineBodyRowMatch {
    Body(MatchedTimelineBodyRow),
    NonBody,
    TargetMismatch,
    InvalidEventKind,
    InvalidBodySha256(InvalidBodySha256),
    BodyHashMismatch(BodySha256),
}

impl TimelineEventIdentity {
    pub(super) fn kind(&self) -> Option<AuditEventKind> {
        AuditEventKind::from_storage(&self.event_type)
    }

    pub(super) fn kind_or_corrupt(&self) -> rusqlite::Result<AuditEventKind> {
        self.kind()
            .ok_or_else(|| corrupt("events.event_type is not a known audit event"))
    }

    pub(super) fn target_matches(&self, world: &ValidatedWorldPath) -> bool {
        self.target == world.as_str()
    }

    pub(super) fn target(&self) -> &str {
        &self.target
    }

    pub(super) fn body_sha256_or_corrupt(&self) -> rusqlite::Result<BodySha256> {
        BodySha256::new(self.body_sha256.clone())
            .map_err(|err| corrupt(&format!("events.body_sha256 is invalid: {err:?}")))
    }
}

impl TimelineEventSnapshot {
    pub(super) fn match_body_row(
        self,
        world: &ValidatedWorldPath,
        expected_body_sha256: &BodySha256,
    ) -> TimelineBodyRowMatch {
        self.match_body_row_inner(
            world,
            expected_body_sha256,
            TargetCheckOrder::AfterBodyClass,
        )
    }

    pub(super) fn match_body_row_target_first(
        self,
        world: &ValidatedWorldPath,
        expected_body_sha256: &BodySha256,
    ) -> TimelineBodyRowMatch {
        self.match_body_row_inner(
            world,
            expected_body_sha256,
            TargetCheckOrder::BeforeBodyClass,
        )
    }

    fn match_body_row_inner(
        self,
        world: &ValidatedWorldPath,
        expected_body_sha256: &BodySha256,
        target_check_order: TargetCheckOrder,
    ) -> TimelineBodyRowMatch {
        let Some(kind) = self.identity.kind() else {
            return TimelineBodyRowMatch::InvalidEventKind;
        };
        let target_mismatch = !self.identity.target_matches(world);
        if matches!(target_check_order, TargetCheckOrder::BeforeBodyClass) && target_mismatch {
            return TimelineBodyRowMatch::TargetMismatch;
        }
        if !kind.class().body_bearing {
            return TimelineBodyRowMatch::NonBody;
        }
        if target_mismatch {
            return TimelineBodyRowMatch::TargetMismatch;
        }
        let body_sha256 = match BodySha256::new(self.identity.body_sha256.clone()) {
            Ok(body_sha256) => body_sha256,
            Err(err) => return TimelineBodyRowMatch::InvalidBodySha256(err),
        };
        if &body_sha256 != expected_body_sha256 {
            return TimelineBodyRowMatch::BodyHashMismatch(body_sha256);
        }
        TimelineBodyRowMatch::Body(MatchedTimelineBodyRow {
            snapshot: self,
            body_sha256,
        })
    }
}

#[derive(Clone, Copy)]
enum TargetCheckOrder {
    BeforeBodyClass,
    AfterBodyClass,
}

impl MatchedTimelineBodyRow {
    pub(super) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }

    pub(super) fn into_representation(self, body: Vec<u8>) -> Option<Representation> {
        if i64::try_from(body.len()).ok() != Some(self.snapshot.size) {
            return None;
        }
        Some(Representation::new(
            Bytes::from(body),
            self.snapshot.content_type,
            self.snapshot.headers,
        ))
    }
}

impl TimelineBodyHeadSnapshot {
    pub(super) fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(super) fn event(&self) -> &TimelineEventIdentity {
        &self.event
    }

    pub(super) fn hmac_label(&self) -> &str {
        &self.hmac_label
    }
}

pub(super) fn load_event_identity(
    tx: &Transaction<'_>,
    seq: TimelineSeq,
) -> rusqlite::Result<Option<TimelineEventIdentity>> {
    tx.query_row(
        "SELECT event_type, target, body_sha256 FROM events WHERE id=?1",
        params![seq.get()],
        |r| {
            Ok(TimelineEventIdentity {
                event_type: r.get(0)?,
                target: r.get(1)?,
                body_sha256: r.get(2)?,
            })
        },
    )
    .optional()
}

pub(super) fn load_event_snapshot(
    tx: &Transaction<'_>,
    seq: TimelineSeq,
) -> rusqlite::Result<Option<TimelineEventSnapshot>> {
    let Some((identity, size, content_type)) = tx
        .query_row(
            "SELECT event_type, target, body_sha256, size, content_type FROM events WHERE id=?1",
            params![seq.get()],
            |r| {
                Ok((
                    TimelineEventIdentity {
                        event_type: r.get(0)?,
                        target: r.get(1)?,
                        body_sha256: r.get(2)?,
                    },
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let mut headers = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT name, value FROM event_headers WHERE event_id=?1 ORDER BY name, value",
        )?;
        let rows = stmt.query_map(params![seq.get()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for pair in rows {
            headers.push(pair?);
        }
    }

    Ok(Some(TimelineEventSnapshot {
        identity,
        size,
        content_type,
        headers,
    }))
}

pub(super) fn load_latest_body_head(
    tx: &Transaction<'_>,
) -> rusqlite::Result<Option<TimelineBodyHeadSnapshot>> {
    let Some((raw_seq, event, hmac)) = tx
        .query_row(
            "SELECT id, event_type, target, body_sha256, hmac
             FROM events
             WHERE event_type IN ('put', 'append')
             ORDER BY id DESC
             LIMIT 1",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    TimelineEventIdentity {
                        event_type: r.get(1)?,
                        target: r.get(2)?,
                        body_sha256: r.get(3)?,
                    },
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let seq = TimelineSeq::new(raw_seq).map_err(|_| corrupt("events.id is not positive"))?;
    let hmac_label = super::hmac_label(&hmac);
    Ok(Some(TimelineBodyHeadSnapshot {
        seq,
        event,
        hmac_label,
    }))
}

pub(super) fn corrupt(message: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_CORRUPT),
        Some(message.to_owned()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn snapshot(body_sha256: &str) -> TimelineEventSnapshot {
        TimelineEventSnapshot {
            identity: TimelineEventIdentity {
                event_type: AuditEventKind::Put.as_str().to_owned(),
                target: "home/a".to_owned(),
                body_sha256: body_sha256.to_owned(),
            },
            size: 0,
            content_type: "application/octet-stream".to_owned(),
            headers: Vec::new(),
        }
    }

    fn world() -> ValidatedWorldPath {
        ValidatedWorldPath::new("home/a").unwrap()
    }

    fn expected_body_sha256() -> BodySha256 {
        BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn timeline_body_row_match_carries_invalid_body_hash_reason() {
        match snapshot("abc").match_body_row(&world(), &expected_body_sha256()) {
            TimelineBodyRowMatch::InvalidBodySha256(reason) => {
                assert_eq!(reason, InvalidBodySha256::WrongLength);
            }
            _ => panic!("expected wrong length body hash"),
        }

        match snapshot("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF")
            .match_body_row(&world(), &expected_body_sha256())
        {
            TimelineBodyRowMatch::InvalidBodySha256(reason) => {
                assert_eq!(reason, InvalidBodySha256::NotLowerHex);
            }
            _ => panic!("expected non-lowerhex body hash"),
        }
    }
}
