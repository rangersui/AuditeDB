//! Protocol-neutral event helpers.
//!
//! The engine owns event ids, replay matching, and the live broadcast stream;
//! adapters choose how to render those events.

use crate::engine_types::{ChangeVerb, ValidatedWorldPath};
use crate::subscription_cursor::{SubscribePattern, SubscriptionEpoch};
use crate::subscription_event_id::{ChangeEventIdentity, ChangeTarget, SubscriptionEventId};
use crate::timeline::{BodySha256, DeleteSubjectProof, TimelineAddress};

/// Audit-chain event kinds the engine may append.
///
/// SQLite stores these as strings, but production append paths use this enum so
/// a new audit row cannot be minted with an ad-hoc event name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditEventKind {
    Put,
    Append,
    DeleteIntent,
    DeleteCommit,
    DeleteCommitFailed,
    Format,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditPayloadHome {
    Cas,
    EventMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventMetadataKind(AuditEventKind);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyEventKind(AuditEventKind);

#[derive(Clone, Debug)]
pub(crate) struct AuditEventPayload {
    kind: AuditEventKind,
    target: ValidatedWorldPath,
    body_sha256: BodySha256,
    size: i64,
    content_type: String,
    delete_subject: Option<DeleteSubjectProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditEventClass {
    pub(crate) body_bearing: bool,
    pub(crate) retention_slot: bool,
    pub(crate) notifies: bool,
    pub(crate) payload_home: AuditPayloadHome,
}

impl AuditEventKind {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_storage(raw: &str) -> Option<Self> {
        match raw {
            "put" => Some(Self::Put),
            "append" => Some(Self::Append),
            "delete_intent" => Some(Self::DeleteIntent),
            "delete_commit" => Some(Self::DeleteCommit),
            "delete_commit_failed" => Some(Self::DeleteCommitFailed),
            "format" => Some(Self::Format),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Append => "append",
            Self::DeleteIntent => "delete_intent",
            Self::DeleteCommit => "delete_commit",
            Self::DeleteCommitFailed => "delete_commit_failed",
            Self::Format => "format",
        }
    }

    pub(crate) const fn class(self) -> AuditEventClass {
        match self {
            Self::Put | Self::Append => AuditEventClass {
                body_bearing: true,
                retention_slot: true,
                notifies: true,
                payload_home: AuditPayloadHome::Cas,
            },
            Self::DeleteIntent | Self::DeleteCommit | Self::DeleteCommitFailed | Self::Format => {
                AuditEventClass {
                    body_bearing: false,
                    retention_slot: false,
                    notifies: true,
                    payload_home: AuditPayloadHome::EventMetadata,
                }
            }
        }
    }
}

impl EventMetadataKind {
    pub(crate) const DELETE_INTENT: Self = Self(AuditEventKind::DeleteIntent);
    pub(crate) const DELETE_COMMIT: Self = Self(AuditEventKind::DeleteCommit);
    pub(crate) const DELETE_COMMIT_FAILED: Self = Self(AuditEventKind::DeleteCommitFailed);
    pub(crate) const fn from_kind(kind: AuditEventKind) -> Option<Self> {
        match kind {
            AuditEventKind::DeleteIntent
            | AuditEventKind::DeleteCommit
            | AuditEventKind::DeleteCommitFailed
            | AuditEventKind::Format => Some(Self(kind)),
            AuditEventKind::Put | AuditEventKind::Append => None,
        }
    }

    pub(crate) const fn kind(self) -> AuditEventKind {
        self.0
    }
}

impl AuditEventPayload {
    fn new(
        kind: AuditEventKind,
        target: ValidatedWorldPath,
        body_sha256: BodySha256,
        size: i64,
        content_type: String,
        delete_subject: Option<DeleteSubjectProof>,
    ) -> Self {
        Self {
            kind,
            target,
            body_sha256,
            size,
            content_type,
            delete_subject,
        }
    }

    pub(crate) fn from_appended_audit_row(row: &crate::audit::AppendedAuditRow) -> Self {
        Self::new(
            row.event_type(),
            row.target().clone(),
            row.body_sha256().clone(),
            row.size(),
            row.content_type().to_owned(),
            None,
        )
    }

    pub(crate) fn from_appended_body_audit_row(row: &crate::audit::AppendedBodyAuditRow) -> Self {
        Self::new(
            row.event_type(),
            row.target().clone(),
            row.body_sha256().clone(),
            row.size(),
            row.content_type().to_owned(),
            None,
        )
    }

    pub(crate) fn from_appended_ledger_event(event: &crate::ledger::AppendedLedgerEvent) -> Self {
        Self::new(
            event.event_type(),
            event.target().clone(),
            event.body_sha256().clone(),
            event.size(),
            event.content_type().to_owned(),
            event.delete_subject().cloned(),
        )
    }

    pub(crate) fn from_verified_replay_body_event(
        event: &crate::audit::VerifiedReplayBodyEvent,
    ) -> Self {
        Self::new(
            event.kind(),
            event.world().clone(),
            event.body_sha256().clone(),
            event.size(),
            event.content_type().to_owned(),
            None,
        )
    }

    pub(crate) fn from_verified_replay_non_body_event(
        event: &crate::audit::VerifiedReplayNonBodyEvent,
    ) -> Self {
        Self::new(
            event.kind(),
            event.event_target().clone(),
            event.body_sha256().clone(),
            event.size(),
            event.content_type().to_owned(),
            event.delete_subject().cloned(),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_only(
        kind: AuditEventKind,
        target: ValidatedWorldPath,
        body_sha256: BodySha256,
        size: i64,
        content_type: impl Into<String>,
    ) -> Self {
        Self::new(kind, target, body_sha256, size, content_type.into(), None)
    }

    pub(crate) fn kind(&self) -> AuditEventKind {
        self.kind
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

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject.as_ref()
    }
}

impl BodyEventKind {
    pub(crate) const PUT: Self = Self(AuditEventKind::Put);
    pub(crate) const APPEND: Self = Self(AuditEventKind::Append);

    pub(crate) const fn kind(self) -> AuditEventKind {
        self.0
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChangeEvent {
    id: ChangeDeliveryId,
    listen_epoch: SubscriptionEpoch,
    verb: ChangeVerb,
    target: ChangeTarget,
    etag: String,
    aux: ChangeEventAux,
}

/// Process-local live-delivery coordinate.
///
/// This is not a durable resume cursor and must stay out of audit/timeline
/// identity decisions. Wire and FFI boundaries may render it as a diagnostic
/// `u64`; internal replay fences keep the domain type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ChangeDeliveryId(u64);

/// Optional protocol-neutral metadata attached to a change event.
///
/// This is not payload data. It carries event-coordinate facts such as the
/// delete-ledger intent row for an id-less subject-world delete ping. Durable
/// audit-row payloads are carried by `ChangeTarget::Chain` instead, so chain
/// identity and signed payload cannot be separated.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChangeEventAux {
    delete_ledger_event_id: Option<SubscriptionEventId>,
    delete_subject: Option<DeleteSubjectProof>,
}

impl ChangeEvent {
    #[cfg(test)]
    pub(crate) fn new(
        id: ChangeDeliveryId,
        listen_epoch: SubscriptionEpoch,
        verb: ChangeVerb,
        target: ChangeTarget,
        etag: String,
    ) -> Self {
        Self::new_with_aux(
            id,
            listen_epoch,
            verb,
            target,
            etag,
            ChangeEventAux::default(),
        )
    }

    pub(crate) fn new_with_aux(
        id: ChangeDeliveryId,
        listen_epoch: SubscriptionEpoch,
        verb: ChangeVerb,
        target: ChangeTarget,
        etag: String,
        aux: ChangeEventAux,
    ) -> Self {
        Self {
            id,
            listen_epoch,
            verb,
            target,
            etag,
            aux,
        }
    }

    pub(crate) fn id(&self) -> ChangeDeliveryId {
        self.id
    }

    pub(crate) fn path(&self) -> &ValidatedWorldPath {
        self.target.world()
    }

    pub(crate) fn identity(&self) -> ChangeEventIdentity {
        self.target.identity()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ChangeDeliveryId,
        SubscriptionEpoch,
        ChangeVerb,
        ValidatedWorldPath,
        String,
        Option<TimelineAddress>,
        ChangeEventIdentity,
        Option<AuditEventPayload>,
        ChangeEventAux,
    ) {
        let (path, timeline_address, identity, audit_payload) = self.target.into_timeline_parts();
        (
            self.id,
            self.listen_epoch,
            self.verb,
            path,
            self.etag,
            timeline_address,
            identity,
            audit_payload,
            self.aux,
        )
    }
}

impl ChangeDeliveryId {
    pub(crate) const MIN: Self = Self(0);

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    #[cfg(test)]
    pub(crate) const fn saturating_sub(self, rhs: Self) -> u64 {
        self.0.saturating_sub(rhs.0)
    }
}

impl ChangeEventAux {
    pub(crate) fn from_appended_delete_intent(
        event: crate::ledger::AppendedDeleteIntentEvent<'_>,
    ) -> Self {
        Self {
            delete_ledger_event_id: Some(event.event_id().clone()),
            delete_subject: event.delete_subject().cloned(),
        }
    }

    pub(crate) fn delete_ledger_event_id(&self) -> Option<&SubscriptionEventId> {
        self.delete_ledger_event_id.as_ref()
    }

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject.as_ref()
    }
}

pub(crate) fn pattern(raw: &str) -> String {
    let p = raw.trim();
    if p == "*" || p == "/*" || p == "/" || p.is_empty() {
        "*".to_owned()
    } else if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    }
}

#[cfg(test)]
pub(crate) fn matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

pub(crate) fn matches_world(pattern: &SubscribePattern, path: &ValidatedWorldPath) -> bool {
    let pattern = pattern.as_str();
    if pattern == "*" {
        return true;
    }
    let path = path.as_str();
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix.strip_prefix('/').unwrap_or(prefix))
    } else {
        path == pattern.strip_prefix('/').unwrap_or(pattern)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_prefix_or_exact() {
        assert_eq!(pattern("*"), "*");
        assert_eq!(pattern("/"), "*");
        assert_eq!(pattern("home/task/*"), "/home/task/*");
        assert_eq!(pattern("home/销售/*"), "/home/销售/*");
        assert!(matches("*", "/home/task/a"));
        assert!(matches("/home/task/*", "/home/task/a"));
        assert!(!matches("/home/task/*", "/home/other/a"));
        assert!(matches("/home/销售/*", "/home/销售/报告"));
        assert!(matches("/home/task/a", "/home/task/a"));
        assert!(!matches("/home/task/a", "/home/task/ab"));
    }

    #[test]
    fn patterns_match_validated_world_paths() {
        let path = ValidatedWorldPath::new("home/task/a").unwrap();
        let catch_all = SubscribePattern::new("*");
        let home_tasks = SubscribePattern::new("/home/task/*");
        let exact = SubscribePattern::new("/home/task/a");
        let near_miss = SubscribePattern::new("/home/task/ab");
        let other = SubscribePattern::new("/home/other/*");

        assert!(matches_world(&catch_all, &path));
        assert!(matches_world(&home_tasks, &path));
        assert!(matches_world(&exact, &path));
        assert!(!matches_world(&near_miss, &path));
        assert!(!matches_world(&other, &path));
    }

    #[test]
    fn audit_event_classifier_matches_timeline_plan() {
        for kind in [AuditEventKind::Put, AuditEventKind::Append] {
            let class = kind.class();
            assert!(class.body_bearing);
            assert!(class.retention_slot);
            assert!(class.notifies);
            assert_eq!(class.payload_home, AuditPayloadHome::Cas);
        }

        for kind in [
            AuditEventKind::DeleteIntent,
            AuditEventKind::DeleteCommit,
            AuditEventKind::DeleteCommitFailed,
            AuditEventKind::Format,
        ] {
            let class = kind.class();
            assert!(!class.body_bearing);
            assert!(!class.retention_slot);
            assert!(class.notifies);
            assert_eq!(class.payload_home, AuditPayloadHome::EventMetadata);
        }
    }

    #[test]
    fn audit_event_kind_renders_storage_strings() {
        assert_eq!(AuditEventKind::Put.as_str(), "put");
        assert_eq!(AuditEventKind::Append.as_str(), "append");
        assert_eq!(AuditEventKind::DeleteIntent.as_str(), "delete_intent");
        assert_eq!(AuditEventKind::DeleteCommit.as_str(), "delete_commit");
        assert_eq!(
            AuditEventKind::DeleteCommitFailed.as_str(),
            "delete_commit_failed"
        );
        assert_eq!(AuditEventKind::Format.as_str(), "format");
    }

    #[test]
    fn audit_event_kind_parses_storage_strings() {
        for kind in [
            AuditEventKind::Put,
            AuditEventKind::Append,
            AuditEventKind::DeleteIntent,
            AuditEventKind::DeleteCommit,
            AuditEventKind::DeleteCommitFailed,
            AuditEventKind::Format,
        ] {
            assert_eq!(AuditEventKind::from_storage(kind.as_str()), Some(kind));
        }
        assert_eq!(AuditEventKind::from_storage("custom"), None);
    }
}
