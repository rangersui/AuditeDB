//! Audit-row append helpers.

use rusqlite::{Connection, OptionalExtension};

use crate::{
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::{AuditEventKind, BodyEventKind, EventMetadataKind},
    timeline::{BodySha256, TimelineAddress, TimelineSeq},
    world,
    world_generation::WorldGeneration,
};

use super::{
    canonical_headers, event_hmac, AuditResult, EmptyChain, EventHmacInput, VerifiedAuditTx,
};

pub(crate) struct AppendedAuditRow {
    id: TimelineSeq,
    hmac: String,
    generation: WorldGeneration,
}

impl AppendedAuditRow {
    pub(crate) fn id(&self) -> TimelineSeq {
        self.id
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }
}

pub(crate) struct AppendedBodyEvent {
    target: ValidatedWorldPath,
    generation: WorldGeneration,
    seq: TimelineSeq,
    body_sha256: BodySha256,
}

impl AppendedBodyEvent {
    fn new(
        target: ValidatedWorldPath,
        generation: WorldGeneration,
        seq: TimelineSeq,
        body_sha256: BodySha256,
    ) -> Self {
        Self {
            target,
            generation,
            seq,
            body_sha256,
        }
    }

    pub(crate) fn target(&self) -> &ValidatedWorldPath {
        &self.target
    }

    pub(crate) fn generation(&self) -> &WorldGeneration {
        &self.generation
    }

    pub(crate) fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }
}

pub(crate) struct AppendedBodyAuditRow {
    row: AppendedAuditRow,
    timeline_address: TimelineAddress,
}

impl AppendedBodyAuditRow {
    pub(crate) fn id(&self) -> TimelineSeq {
        self.row.id()
    }

    pub(crate) fn hmac(&self) -> &str {
        self.row.hmac()
    }

    pub(crate) fn timeline_address(&self) -> &TimelineAddress {
        &self.timeline_address
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_with_conn_existing(
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
) -> AuditResult<String> {
    append_with_conn_verified(
        conn,
        event_type,
        ledger_world,
        target,
        body_sha256,
        size,
        content_type,
        headers,
        key,
        EmptyChain::Reject,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_with_conn_genesis(
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
) -> AuditResult<String> {
    append_with_conn_verified(
        conn,
        event_type,
        ledger_world,
        target,
        body_sha256,
        size,
        content_type,
        headers,
        key,
        EmptyChain::Allow,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_with_conn_verified(
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<String> {
    let tx = conn.transaction()?;
    let audit_tx = super::verify_appendable_tx(&tx, ledger_world, key, empty_chain)?;
    let headers = headers.to_storage_pairs();
    let row = append_tx_inner(
        &audit_tx,
        event_type.kind(),
        target,
        body_sha256,
        size,
        content_type,
        &headers,
    )?;
    tx.commit()?;
    Ok(row.hmac().to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_retained_body_tx_row(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: BodyEventKind,
    retained: &world::RetainedCasBody,
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<AppendedBodyAuditRow> {
    let row = append_tx_inner(
        audit_tx,
        event_type.kind(),
        retained.target().as_str(),
        retained.body_sha256(),
        retained.size(),
        content_type,
        headers,
    )?;
    let event = AppendedBodyEvent::new(
        retained.target().clone(),
        row.generation.clone(),
        row.id(),
        retained.body_sha256().clone(),
    );
    Ok(AppendedBodyAuditRow {
        row,
        timeline_address: TimelineAddress::from_appended_body_event(event),
    })
}

#[allow(clippy::too_many_arguments)]
fn append_tx_inner(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: AuditEventKind,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<AppendedAuditRow> {
    let tx = audit_tx.tx;
    let class = event_type.class();
    debug_assert!(class.notifies, "audit rows are timeline-visible events");
    debug_assert_eq!(class.body_bearing, class.retention_slot);
    debug_assert_eq!(
        class.body_bearing,
        matches!(class.payload_home, crate::event::AuditPayloadHome::Cas)
    );
    let canonical = canonical_headers(headers);
    let meta_sha256 = super::meta_sha256_canonical(content_type, &canonical);
    let generation = crate::world_schema::generation(tx)?;
    let prev = tx
        .query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default();
    let h = event_hmac(
        audit_tx.key,
        EventHmacInput {
            prev: &prev,
            event_type: event_type.as_str(),
            target,
            generation: &generation,
            body_sha256: body_sha256.as_str(),
            size,
            content_type,
            meta_sha256: &meta_sha256,
        },
    );
    tx.execute(
        r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                              content_type, meta_sha256, hmac, prev_hmac)
           VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)"#,
        rusqlite::params![
            event_type.as_str(),
            target,
            body_sha256.as_str(),
            size,
            content_type,
            meta_sha256,
            h,
            prev
        ],
    )?;
    let event_id = tx.last_insert_rowid();
    let mut stmt =
        tx.prepare("INSERT INTO event_headers(event_id, name, value) VALUES(?, ?, ?)")?;
    for (name, value) in canonical {
        stmt.execute(rusqlite::params![event_id, name, value])?;
    }
    let id = TimelineSeq::new(event_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(AppendedAuditRow {
        id,
        hmac: h,
        generation,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_only_append_tx_inner(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: AuditEventKind,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<AppendedAuditRow> {
    append_tx_inner(
        audit_tx,
        event_type,
        target,
        body_sha256,
        size,
        content_type,
        headers,
    )
}
