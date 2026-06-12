//! Audit-row append helpers.

use rusqlite::{Connection, OptionalExtension};

use crate::{
    engine_types::AuditHmacKey,
    event::{AuditEventKind, BodyEventKind, EventMetadataKind},
    timeline::BodySha256,
};

use super::{
    canonical_headers, event_hmac, AuditResult, EmptyChain, EventHmacInput, VerifiedAuditTx,
};

/// Append a single row to the audit chain, reusing an already-open
/// `Connection`. Cached writers (the ledger writer
/// `Mutex<Option<Connection>>` on `Core`) call this directly so the
/// hot delete path doesn't re-open `var/log/deletes` 2-3 times per
/// operation. Per-write paths that don't cache a connection compose
/// `world::open` + the explicit existing/genesis append entrypoint.
#[allow(clippy::too_many_arguments)]
pub(crate) fn append_with_conn_existing(
    conn: &mut Connection,
    event_type: EventMetadataKind,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
) -> AuditResult<String> {
    append_with_conn_verified(
        conn,
        event_type,
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
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
) -> AuditResult<String> {
    append_with_conn_verified(
        conn,
        event_type,
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
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
    key: &AuditHmacKey,
    empty_chain: EmptyChain,
) -> AuditResult<String> {
    let tx = conn.transaction()?;
    let audit_tx = super::verify_appendable_tx(&tx, key, empty_chain)?;
    let h = append_tx_inner(
        &audit_tx,
        event_type.kind(),
        target,
        body_sha256,
        size,
        content_type,
        headers,
    )?;
    tx.commit()?;
    Ok(h)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_body_tx_row(
    audit_tx: &VerifiedAuditTx<'_, '_, '_>,
    event_type: BodyEventKind,
    target: &str,
    body_sha256: &BodySha256,
    size: i64,
    content_type: &str,
    headers: &[(String, String)],
) -> rusqlite::Result<String> {
    append_tx_inner(
        audit_tx,
        event_type.kind(),
        target,
        body_sha256,
        size,
        content_type,
        headers,
    )
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
) -> rusqlite::Result<String> {
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
    let prev = tx
        .query_row(
            "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default();
    let h = event_hmac(
        audit_tx.key.as_slice(),
        EventHmacInput {
            prev: &prev,
            event_type: event_type.as_str(),
            target,
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
    Ok(h)
}
