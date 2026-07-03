//! Audit-row append helpers.

use rusqlite::{Connection, OptionalExtension};

use crate::{
    blocking_sqlite::BlockingSqlite,
    engine_types::{AuditHmacKey, ValidatedWorldPath},
    event::{AuditEventKind, BodyEventKind, EventMetadataKind},
    timeline::{BodySha256, TimelineAddress, TimelineSeq},
    world,
    world_generation::WorldGeneration,
};

use super::{
    canonical_headers, event_hmac, AuditResult, AuditTimestamp, EmptyChain, EventHmacInput,
    VerifiedAuditTx,
};

pub(crate) struct AppendedAuditRow {
    world: ValidatedWorldPath,
    id: TimelineSeq,
    hmac: String,
    generation: WorldGeneration,
    event_type: AuditEventKind,
    target: ValidatedWorldPath,
    body_sha256: BodySha256,
    size: i64,
    content_type: String,
}

impl AppendedAuditRow {
    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    pub(crate) fn id(&self) -> TimelineSeq {
        self.id
    }

    pub(crate) fn hmac(&self) -> &str {
        &self.hmac
    }

    pub(crate) fn generation(&self) -> &WorldGeneration {
        &self.generation
    }

    pub(crate) fn event_type(&self) -> AuditEventKind {
        self.event_type
    }

    pub(crate) fn target(&self) -> &ValidatedWorldPath {
        &self.target
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }

    pub(crate) fn size(&self) -> i64 {
        self.size
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
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

    pub(crate) fn event_type(&self) -> AuditEventKind {
        self.row.event_type()
    }

    pub(crate) fn target(&self) -> &ValidatedWorldPath {
        self.row.target()
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        self.row.body_sha256()
    }

    pub(crate) fn size(&self) -> i64 {
        self.row.size()
    }

    pub(crate) fn content_type(&self) -> &str {
        self.row.content_type()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_with_conn_existing_row(
    proof: &mut BlockingSqlite,
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &ValidatedWorldPath,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
) -> AuditResult<AppendedAuditRow> {
    append_with_conn_verified(
        proof,
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
pub(crate) fn append_with_conn_genesis_row(
    proof: &mut BlockingSqlite,
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &ValidatedWorldPath,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
) -> AuditResult<(AppendedAuditRow, AppendedAuditRow)> {
    let tx = conn.transaction()?;
    let audit_tx = super::verify_appendable_tx(proof, &tx, ledger_world, key, EmptyChain::Allow)?;
    let format_row = append_format_tx_row(&audit_tx)?;
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
    Ok((format_row, row))
}

#[allow(clippy::too_many_arguments)]
fn append_with_conn_verified(
    proof: &mut BlockingSqlite,
    conn: &mut Connection,
    event_type: EventMetadataKind,
    ledger_world: &ValidatedWorldPath,
    target: &ValidatedWorldPath,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &super::AuditHeaders,
    key: &AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<AppendedAuditRow> {
    let tx = conn.transaction()?;
    let audit_tx = super::verify_appendable_tx(proof, &tx, ledger_world, key, empty_chain)?;
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
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_retained_body_tx_row<'tx, 'conn, 'key>(
    audit_tx: &VerifiedAuditTx<'tx, 'conn, 'key>,
    event_type: BodyEventKind,
    retained: &world::RetainedCasBody<'tx, 'conn>,
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<AppendedBodyAuditRow> {
    if !retained.was_retained_in(audit_tx.tx) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if retained.target() != audit_tx.world() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let row = append_tx_inner(
        audit_tx,
        event_type.kind(),
        retained.target(),
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

pub(crate) fn append_format_tx_row(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
) -> rusqlite::Result<AppendedAuditRow> {
    let version = crate::world_schema::CURRENT_WORLD_FORMAT_VERSION.to_string();
    let headers = [(super::WORLD_FORMAT_VERSION_HEADER.to_owned(), version)];
    append_tx_inner(
        audit_tx,
        AuditEventKind::Format,
        audit_tx.world(),
        &BodySha256::for_body(b""),
        0,
        "",
        &headers,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_tx_inner(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: AuditEventKind,
    target: &ValidatedWorldPath,
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
    let timestamp = AuditTimestamp::now_tx(tx)?;
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
            world: audit_tx.world(),
            timestamp: &timestamp,
            event_type: event_type.as_str(),
            target: target.as_str(),
            generation: audit_tx.generation(),
            body_sha256: body_sha256.as_str(),
            size,
            content_type,
            meta_sha256: &meta_sha256,
        },
    );
    tx.execute(
        r#"INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                              content_type, meta_sha256, hmac, prev_hmac)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        rusqlite::params![
            timestamp.as_str(),
            event_type.as_str(),
            target.as_str(),
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
        world: audit_tx.world().clone(),
        id,
        hmac: h,
        generation: audit_tx.generation().clone(),
        event_type,
        target: target.clone(),
        body_sha256: body_sha256.clone(),
        size,
        content_type: content_type.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_only_append_tx_inner(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: AuditEventKind,
    target: &ValidatedWorldPath,
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
