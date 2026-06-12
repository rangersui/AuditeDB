//! CAS retained-body verification for the audit chain.

use rusqlite::{ffi, Connection, OptionalExtension};
use std::collections::HashMap;

use crate::{
    event::AuditEventKind,
    timeline::{BodySha256, TimelineSeq},
};

use super::{EventRow, VerifyAccumulator, VerifyBreak};

pub(super) struct CasRetentionState {
    first_retained_seq: Option<TimelineSeq>,
    bodies: HashMap<String, RetainedCasBodyInfo>,
}

impl CasRetentionState {
    pub(super) fn floor_is_unset(&self) -> bool {
        self.first_retained_seq.is_none()
    }
}

struct RetainedCasBodyInfo {
    len: i64,
}

pub(super) fn load(c: &Connection) -> rusqlite::Result<CasRetentionState> {
    let first_retained_seq = c
        .query_row(
            "SELECT first_retained_seq FROM cas_state WHERE id=1",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )?
        .map(|seq| TimelineSeq::new(seq).map_err(|_| corrupt_error("invalid first_retained_seq")))
        .transpose()?;
    let mut bodies = HashMap::new();
    {
        let mut stmt = c.prepare("SELECT body_sha256, body FROM cas_bodies")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (body_sha256, body) = row?;
            let computed = BodySha256::for_body(&body);
            if computed.as_str() != body_sha256 {
                return Err(corrupt_error("cas_bodies.body does not match body_sha256"));
            }
            let len = i64::try_from(body.len())
                .map_err(|_| corrupt_error("cas_bodies.body length does not fit i64"))?;
            bodies.insert(body_sha256, RetainedCasBodyInfo { len });
        }
    }
    if first_retained_seq.is_none() && !bodies.is_empty() {
        return Err(corrupt_error(
            "cas_bodies rows exist before first_retained_seq is set",
        ));
    }
    if first_retained_seq.is_none() && has_body_bearing_events(c)? {
        return Err(corrupt_error(
            "body-bearing events exist before first_retained_seq is set",
        ));
    }
    Ok(CasRetentionState {
        first_retained_seq,
        bodies,
    })
}

pub(super) fn verify_completion(
    state: &VerifyAccumulator,
    retention: &CasRetentionState,
) -> Option<VerifyBreak> {
    if !state.saw_retention_floor {
        let Some(first_retained_seq) = retention.first_retained_seq else {
            return Some(VerifyBreak {
                break_at: state.events,
                expected: "retention floor".to_owned(),
                actual: "unset-retention-floor".to_owned(),
            });
        };
        return Some(VerifyBreak {
            break_at: state.events,
            expected: format!(
                "body-bearing event at first_retained_seq {}",
                first_retained_seq.get()
            ),
            actual: "missing-retention-floor-event".to_owned(),
        });
    }
    if state.referenced_retained_bodies.len() != retention.bodies.len() {
        return Some(VerifyBreak {
            break_at: state.events,
            expected: "all CAS bodies referenced by retained events".to_owned(),
            actual: "unreferenced-cas-body".to_owned(),
        });
    }
    None
}

pub(super) fn verify_retained_body(
    row: &EventRow,
    idx: usize,
    retention: &CasRetentionState,
    state: &mut VerifyAccumulator,
) -> Option<VerifyBreak> {
    let floor = retention.first_retained_seq?;
    let is_body_event = is_body_bearing_event_type(&row.event_type);
    if is_body_event && state.first_body_event.is_none() {
        let first_body_event = match TimelineSeq::new(row.id) {
            Ok(seq) => seq,
            Err(_) => {
                return Some(VerifyBreak {
                    break_at: idx,
                    expected: "positive body-bearing event id".to_owned(),
                    actual: format!("event-id-{}", row.id),
                });
            }
        };
        state.first_body_event = Some(first_body_event);
        if first_body_event != floor {
            return Some(VerifyBreak {
                break_at: idx,
                expected: format!("first_retained_seq-{}", first_body_event.get()),
                actual: format!("first_retained_seq-{}", floor.get()),
            });
        }
    }
    if row.id == floor.get() && !is_body_event {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("body-bearing event at first_retained_seq {}", floor.get()),
            actual: row.event_type.clone(),
        });
    }
    if row.id < floor.get() || !is_body_event {
        return None;
    }
    if BodySha256::new(row.body_sha256.clone()).is_err() {
        return Some(VerifyBreak {
            break_at: idx,
            expected: "valid body_sha256".to_owned(),
            actual: format!("body-sha256-{}", row.body_sha256),
        });
    }
    let Some(retained) = retention.bodies.get(&row.body_sha256) else {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("cas-body-{}", row.body_sha256),
            actual: "missing-cas-body".to_owned(),
        });
    };
    if retained.len != row.size {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("cas-body-size-{}", row.size),
            actual: format!("cas-body-size-{}", retained.len),
        });
    }
    if row.id == floor.get() {
        state.saw_retention_floor = true;
    }
    state
        .referenced_retained_bodies
        .insert(row.body_sha256.clone());
    None
}

fn has_body_bearing_events(c: &Connection) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT 1 FROM events WHERE event_type IN (?1, ?2) LIMIT 1",
        rusqlite::params![
            AuditEventKind::Put.as_str(),
            AuditEventKind::Append.as_str()
        ],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
}

fn is_body_bearing_event_type(event_type: &str) -> bool {
    event_type == AuditEventKind::Put.as_str() || event_type == AuditEventKind::Append.as_str()
}

fn corrupt_error(reason: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error {
            code: ffi::ErrorCode::DatabaseCorrupt,
            extended_code: ffi::SQLITE_CORRUPT,
        },
        Some(reason.to_owned()),
    )
}
