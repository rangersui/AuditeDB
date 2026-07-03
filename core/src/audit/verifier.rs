use std::collections::HashSet;

use super::*;

pub(crate) struct VerifiedChainHead {
    stamp: ChainStamp,
}

/// Verifier-only mint token for audit-chain head proof values.
///
/// Only this verifier module can construct it; `chain_stamp` can only consume it.
pub(crate) struct VerifiedChainHeadParts {
    generation: WorldGeneration,
    event_count: usize,
    latest_hmac: String,
}

/// Verifier-only mint token for a stamp captured at a requested chain ordinal.
///
/// Only this verifier module can construct it; `chain_stamp` can only consume it.
pub(crate) struct VerifiedChainStampParts {
    generation: WorldGeneration,
    seq: ChainSeq,
    hmac: String,
}

/// Verifier-only mint token for a missing chain-stamp proof.
///
/// Only this verifier module can construct it; `chain_stamp` can only consume it.
pub(crate) struct VerifiedChainStampMissingParts {
    generation: WorldGeneration,
    requested: ChainSeq,
    observed: usize,
}

impl VerifiedChainHead {
    fn new(generation: WorldGeneration, event_count: usize, hmac: String) -> Option<Self> {
        let parts = VerifiedChainHeadParts::new(generation, event_count, hmac);
        Some(Self {
            stamp: ChainStamp::from_verified_head_parts(parts)?,
        })
    }

    pub(crate) fn generation(&self) -> &WorldGeneration {
        self.stamp.generation()
    }

    pub(crate) fn seq(&self) -> i64 {
        self.stamp.seq().get()
    }

    pub(crate) fn hmac(&self) -> &str {
        self.stamp.hmac().as_str()
    }
}

impl VerifiedChainHeadParts {
    fn new(generation: WorldGeneration, event_count: usize, latest_hmac: String) -> Self {
        Self {
            generation,
            event_count,
            latest_hmac,
        }
    }

    pub(crate) fn into_chain_stamp_parts(self) -> (WorldGeneration, usize, String) {
        (self.generation, self.event_count, self.latest_hmac)
    }
}

impl VerifiedChainStampParts {
    fn new(generation: WorldGeneration, seq: ChainSeq, hmac: String) -> Self {
        Self {
            generation,
            seq,
            hmac,
        }
    }

    pub(crate) fn into_chain_stamp_parts(self) -> (WorldGeneration, ChainSeq, String) {
        (self.generation, self.seq, self.hmac)
    }
}

impl VerifiedChainStampMissingParts {
    fn new(generation: WorldGeneration, requested: ChainSeq, observed: usize) -> Self {
        Self {
            generation,
            requested,
            observed,
        }
    }

    pub(crate) fn into_chain_stamp_missing_parts(self) -> (WorldGeneration, ChainSeq, usize) {
        (self.generation, self.requested, self.observed)
    }
}

struct CapturedStampCandidate {
    generation: WorldGeneration,
    seq: ChainSeq,
    hmac: String,
}

pub(super) struct VerifyAccumulator {
    pub(super) prev: String,
    pub(super) genesis: String,
    pub(super) events: usize,
    pub(super) first_body_event: Option<TimelineSeq>,
    pub(super) saw_retention_floor: bool,
    pub(super) referenced_retained_bodies: HashSet<BodySha256>,
    capture_stamp_at: Option<ChainSeq>,
    captured_stamp: Option<CapturedStampCandidate>,
}

pub(super) enum VerifyCapturedReport {
    Valid {
        ok: VerifyOk,
        head: Option<VerifiedChainHead>,
        stamp: Option<ChainStampRead>,
    },
    Broken(VerifyBreak),
}

pub(super) fn verify_statement_capture(
    stmt: &mut Statement<'_>,
    key: &AuditHmacKey,
    allow_empty: bool,
    retention: &retention::CasRetentionState,
    chain_world: &ValidatedWorldPath,
    generation: &WorldGeneration,
    capture_stamp_at: Option<ChainSeq>,
) -> rusqlite::Result<VerifyCapturedReport> {
    let mut state = VerifyAccumulator {
        prev: String::new(),
        genesis: String::new(),
        events: 0,
        first_body_event: None,
        saw_retention_floor: retention.floor_is_unset(),
        referenced_retained_bodies: HashSet::new(),
        capture_stamp_at,
        captured_stamp: None,
    };
    let mut rows = stmt.query([])?;
    let mut current: Option<EventRow> = None;
    let mut headers = Vec::new();

    while let Some(r) = rows.next()? {
        let row = EventRow {
            id: r.get(0)?,
            timestamp: r.get(1)?,
            event_type: r.get(2)?,
            target: r.get(3)?,
            body_sha256: r.get(4)?,
            size: r.get(5)?,
            content_type: r.get(6)?,
            meta_sha256: r.get(7)?,
            hmac: r.get(8)?,
            prev_hmac: r.get(9)?,
        };
        if current.as_ref().is_some_and(|event| event.id != row.id) {
            // Invariant: the guard above already proved `current` is Some.
            #[allow(clippy::expect_used)]
            let event = current.take().expect("current event");
            if let Some(break_report) = verify_event(
                &event,
                &headers,
                key,
                retention,
                &mut state,
                chain_world,
                generation,
            ) {
                return Ok(VerifyCapturedReport::Broken(break_report));
            }
            headers = Vec::new();
        }
        if current.is_none() {
            current = Some(row);
        }
        let header_name: Option<String> = r.get(10)?;
        let header_value: Option<String> = r.get(11)?;
        if let (Some(name), Some(value)) = (header_name, header_value) {
            headers.push((name, value));
        }
    }

    if let Some(event) = current {
        if let Some(break_report) = verify_event(
            &event,
            &headers,
            key,
            retention,
            &mut state,
            chain_world,
            generation,
        ) {
            return Ok(VerifyCapturedReport::Broken(break_report));
        }
    }

    if let Some(break_report) = retention::verify_completion(&state, retention) {
        return Ok(VerifyCapturedReport::Broken(break_report));
    }

    let ok = if state.events == 0 {
        if allow_empty {
            VerifyOk {
                events: 0,
                genesis: hmac_label(""),
                latest: hmac_label(""),
            }
        } else {
            return Ok(VerifyCapturedReport::Broken(VerifyBreak {
                break_at: 0,
                expected: "at-least-one-event".to_owned(),
                actual: "no-events".to_owned(),
            }));
        }
    } else {
        VerifyOk {
            events: state.events,
            genesis: hmac_label(&state.genesis),
            latest: hmac_label(&state.prev),
        }
    };

    let head = verified_head_from_ok(generation, &ok)?;
    let stamp = verified_stamp_from_completed_walk(generation, capture_stamp_at, state);

    Ok(VerifyCapturedReport::Valid { ok, head, stamp })
}

pub(super) fn verify_tail_event(
    row: &EventRow,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    chain_world: &ValidatedWorldPath,
    generation: &WorldGeneration,
    prev_hmac: String,
    event_count: usize,
) -> Option<VerifyBreak> {
    let retention = retention::CasRetentionState::tail_unchecked();
    let mut state = VerifyAccumulator {
        prev: prev_hmac,
        genesis: String::new(),
        events: event_count.saturating_sub(1),
        first_body_event: None,
        saw_retention_floor: retention.floor_is_unset(),
        referenced_retained_bodies: HashSet::new(),
        capture_stamp_at: None,
        captured_stamp: None,
    };
    verify_event(
        row,
        headers,
        key,
        &retention,
        &mut state,
        chain_world,
        generation,
    )
}

fn verified_head_from_ok(
    generation: &WorldGeneration,
    ok: &VerifyOk,
) -> rusqlite::Result<Option<VerifiedChainHead>> {
    if ok.events == 0 {
        return Ok(None);
    }
    VerifiedChainHead::new(generation.clone(), ok.events, ok.latest.clone())
        .map(Some)
        .ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(
                "verified audit chain event count exceeds supported range".to_owned(),
            )
        })
}

fn verified_stamp_from_completed_walk(
    generation: &WorldGeneration,
    requested: Option<ChainSeq>,
    state: VerifyAccumulator,
) -> Option<ChainStampRead> {
    requested.map(|seq| {
        if let Some(candidate) = state.captured_stamp {
            ChainStampRead::found(VerifiedChainStampParts::new(
                candidate.generation,
                candidate.seq,
                candidate.hmac,
            ))
        } else {
            ChainStampRead::missing_from_verified_parts(VerifiedChainStampMissingParts::new(
                generation.clone(),
                seq,
                state.events,
            ))
        }
    })
}

fn verify_event(
    row: &EventRow,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    retention: &retention::CasRetentionState,
    state: &mut VerifyAccumulator,
    chain_world: &ValidatedWorldPath,
    generation: &WorldGeneration,
) -> Option<VerifyBreak> {
    let idx = state.events;
    let Some(event_type) = AuditEventKind::from_storage(row.event_type.as_str()) else {
        return Some(VerifyBreak {
            break_at: idx,
            expected: "known-event-type".to_owned(),
            actual: format!("event-type-{}", row.event_type),
        });
    };
    let target_bound_to_world =
        event_type.class().body_bearing || matches!(event_type, AuditEventKind::Format);
    if target_bound_to_world && chain_world.as_str() != row.target {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("target-{}", chain_world.as_str()),
            actual: format!("target-{}", row.target),
        });
    }
    if !crate::auth::ct_eq(row.prev_hmac.as_bytes(), state.prev.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: hmac_label(&state.prev),
            actual: hmac_label(&row.prev_hmac),
        });
    }
    if matches!(event_type, AuditEventKind::Format) {
        let expected_version = crate::world_schema::CURRENT_WORLD_FORMAT_VERSION.to_string();
        let has_version = headers
            .iter()
            .any(|(name, value)| name == WORLD_FORMAT_VERSION_HEADER && value == &expected_version);
        if !has_version {
            return Some(VerifyBreak {
                break_at: idx,
                expected: format!("{WORLD_FORMAT_VERSION_HEADER}-{expected_version}"),
                actual: "missing-world-format-version".to_owned(),
            });
        }
    }
    if let Some(break_report) = verify_delete_subject_proof(row, headers, event_type, idx) {
        return Some(break_report);
    }
    let expected_meta = meta_sha256_canonical(&row.content_type, headers);
    if !crate::auth::ct_eq(expected_meta.as_bytes(), row.meta_sha256.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: format!("meta-sha256-{expected_meta}"),
            actual: format!("meta-sha256-{}", row.meta_sha256),
        });
    }
    let timestamp = match AuditTimestamp::from_storage(row.timestamp.clone()) {
        Ok(timestamp) => timestamp,
        Err(actual) => {
            return Some(VerifyBreak {
                break_at: idx,
                expected: "timestamp-sqlite-utc-ms".to_owned(),
                actual: format!("timestamp-{actual}"),
            });
        }
    };
    let expected_hmac = event_hmac(
        key,
        EventHmacInput {
            prev: &state.prev,
            world: chain_world,
            timestamp: &timestamp,
            event_type: &row.event_type,
            target: &row.target,
            generation,
            body_sha256: &row.body_sha256,
            size: row.size,
            content_type: &row.content_type,
            meta_sha256: &row.meta_sha256,
        },
    );
    if !crate::auth::ct_eq(expected_hmac.as_bytes(), row.hmac.as_bytes()) {
        return Some(VerifyBreak {
            break_at: idx,
            expected: hmac_label(&expected_hmac),
            actual: hmac_label(&row.hmac),
        });
    }
    if let Some(break_report) =
        retention::verify_retained_body(row, event_type, idx, retention, state)
    {
        return Some(break_report);
    }
    let next_ordinal = state.events + 1;
    if let Some(seq) = state.capture_stamp_at {
        if usize::try_from(seq.get()).ok() == Some(next_ordinal) {
            state.captured_stamp = Some(CapturedStampCandidate {
                generation: generation.clone(),
                seq,
                hmac: hmac_label(&row.hmac),
            });
        }
    }
    if idx == 0 {
        state.genesis = row.hmac.clone();
    }
    state.prev = row.hmac.clone();
    state.events += 1;
    None
}
