//! Protocol-neutral event helpers.
//!
//! The engine owns event ids, replay matching, and the live broadcast stream;
//! adapters choose how to render those events.

use crate::engine_types::ChangeVerb;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditPayloadHome {
    Cas,
    EventMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditEventClass {
    pub(crate) body_bearing: bool,
    pub(crate) retention_slot: bool,
    pub(crate) notifies: bool,
    pub(crate) payload_home: AuditPayloadHome,
}

impl AuditEventKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Append => "append",
            Self::DeleteIntent => "delete_intent",
            Self::DeleteCommit => "delete_commit",
            Self::DeleteCommitFailed => "delete_commit_failed",
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
            Self::DeleteIntent | Self::DeleteCommit | Self::DeleteCommitFailed => AuditEventClass {
                body_bearing: false,
                retention_slot: false,
                notifies: true,
                payload_home: AuditPayloadHome::EventMetadata,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChangeEvent {
    pub(crate) id: u64,
    pub(crate) verb: ChangeVerb,
    pub(crate) path: String,
    pub(crate) etag: String,
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

#[cfg(test)]
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
    }
}
