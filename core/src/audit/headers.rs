use crate::timeline::{BodySha256, TimelineAddress};

use super::VerifiedBodyHead;

pub(crate) const DELETE_SUBJECT_WORLD: &str = "auditedb-delete-subject-world";
pub(crate) const DELETE_SUBJECT_GENERATION: &str = "auditedb-delete-subject-generation";
pub(crate) const DELETE_SUBJECT_SEQ: &str = "auditedb-delete-subject-seq";
pub(crate) const DELETE_SUBJECT_BODY_SHA256: &str = "auditedb-delete-subject-body-sha256";
pub(crate) const DELETE_SUBJECT_HMAC: &str = "auditedb-delete-subject-hmac";
const DELETE_SUBJECT_RESERVED_PREFIX: &str = "auditedb-delete-subject-";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservedAuditHeader;

#[derive(Clone)]
pub(crate) struct VerifiedDeleteSubject {
    address: TimelineAddress,
    hmac: String,
}

impl VerifiedDeleteSubject {
    pub(crate) fn from_body_head(head: VerifiedBodyHead) -> Self {
        Self {
            address: head.address().clone(),
            hmac: head.hmac().to_owned(),
        }
    }

    fn headers(&self) -> [(String, String); 5] {
        [
            (
                DELETE_SUBJECT_WORLD.to_owned(),
                self.address.world().as_str().to_owned(),
            ),
            (
                DELETE_SUBJECT_GENERATION.to_owned(),
                self.address.generation().as_str().to_owned(),
            ),
            (
                DELETE_SUBJECT_SEQ.to_owned(),
                self.address.seq().get().to_string(),
            ),
            (
                DELETE_SUBJECT_BODY_SHA256.to_owned(),
                self.address.body_sha256().as_str().to_owned(),
            ),
            (DELETE_SUBJECT_HMAC.to_owned(), self.hmac.clone()),
        ]
    }

    pub(crate) fn body_sha256(&self) -> BodySha256 {
        self.address.body_sha256().clone()
    }
}

#[derive(Clone)]
pub(crate) struct AuditHeaders {
    user: Vec<(String, String)>,
    delete_subject: Option<VerifiedDeleteSubject>,
}

impl AuditHeaders {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            user: Vec::new(),
            delete_subject: None,
        }
    }

    pub(crate) fn from_user(headers: Vec<(String, String)>) -> Result<Self, ReservedAuditHeader> {
        if headers
            .iter()
            .any(|(name, _)| is_reserved_audit_header(name))
        {
            return Err(ReservedAuditHeader);
        }
        Ok(Self {
            user: headers,
            delete_subject: None,
        })
    }

    pub(crate) fn with_delete_subject(mut self, subject: VerifiedDeleteSubject) -> Self {
        self.delete_subject = Some(subject);
        self
    }

    pub(super) fn to_storage_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = self.user.clone();
        if let Some(subject) = &self.delete_subject {
            pairs.extend(subject.headers());
        }
        pairs
    }
}

fn is_reserved_audit_header(name: &str) -> bool {
    name.to_ascii_lowercase()
        .starts_with(DELETE_SUBJECT_RESERVED_PREFIX)
}
