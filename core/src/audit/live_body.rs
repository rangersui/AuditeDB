//! Live body head verification for one world DB.

use rusqlite::{OptionalExtension, Transaction};

use crate::{event::AuditEventKind, timeline::BodySha256};

use super::VerifyBreak;

pub(super) fn verify_tx(tx: &Transaction<'_>) -> rusqlite::Result<Option<VerifyBreak>> {
    if !has_stage_meta_tx(tx)? {
        return Ok(None);
    }
    let live_body = tx.query_row("SELECT body FROM stage_meta WHERE id=1", [], |r| {
        r.get::<_, Vec<u8>>(0)
    })?;
    let latest = latest_body_event_tx(tx)?;
    let event_count = event_count_tx(tx)?;
    Ok(live_body_head_break(live_body, latest, event_count))
}

fn live_body_head_break(
    live_body: Vec<u8>,
    latest: Option<(i64, String, i64)>,
    event_count: usize,
) -> Option<VerifyBreak> {
    let live_hash = BodySha256::for_body(&live_body);
    let live_size = i64::try_from(live_body.len()).unwrap_or(i64::MAX);
    let break_at = event_count.saturating_sub(1);
    let Some((_id, body_sha256, size)) = latest else {
        if live_body.is_empty() {
            return None;
        }
        return Some(VerifyBreak {
            break_at,
            expected: "latest body-bearing event".to_owned(),
            actual: format!("live-body-sha256-{}", live_hash.as_str()),
        });
    };
    if body_sha256 != live_hash.as_str() {
        return Some(VerifyBreak {
            break_at,
            expected: format!("live-body-sha256-{body_sha256}"),
            actual: format!("live-body-sha256-{}", live_hash.as_str()),
        });
    }
    if size != live_size {
        return Some(VerifyBreak {
            break_at,
            expected: format!("live-body-size-{size}"),
            actual: format!("live-body-size-{live_size}"),
        });
    }
    None
}

fn has_stage_meta_tx(tx: &Transaction<'_>) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='stage_meta' LIMIT 1",
        [],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
}

fn latest_body_event_tx(tx: &Transaction<'_>) -> rusqlite::Result<Option<(i64, String, i64)>> {
    tx.query_row(
        "SELECT id, body_sha256, size FROM events WHERE event_type IN (?1, ?2) ORDER BY id DESC LIMIT 1",
        rusqlite::params![AuditEventKind::Put.as_str(), AuditEventKind::Append.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
}

fn event_count_tx(tx: &Transaction<'_>) -> rusqlite::Result<usize> {
    let count = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))?;
    Ok(count.max(0) as usize)
}
