use crate::{
    engine_types::ValidatedWorldPath,
    timeline::{BodySha256, DeleteSubjectProof, TimelineSeq},
    world_generation::WorldGeneration,
};

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
    proof: DeleteSubjectProof,
}

impl VerifiedDeleteSubject {
    pub(crate) fn from_body_head(head: VerifiedBodyHead) -> Self {
        Self {
            proof: DeleteSubjectProof::new(head.address().clone(), head.hmac().to_owned()),
        }
    }

    fn headers(&self) -> [(String, String); 5] {
        [
            (
                DELETE_SUBJECT_WORLD.to_owned(),
                self.proof.address().world().as_str().to_owned(),
            ),
            (
                DELETE_SUBJECT_GENERATION.to_owned(),
                self.proof.address().generation().as_str().to_owned(),
            ),
            (
                DELETE_SUBJECT_SEQ.to_owned(),
                self.proof.address().seq().get().to_string(),
            ),
            (
                DELETE_SUBJECT_BODY_SHA256.to_owned(),
                self.proof.address().body_sha256().as_str().to_owned(),
            ),
            (DELETE_SUBJECT_HMAC.to_owned(), self.proof.hmac().to_owned()),
        ]
    }

    pub(crate) fn body_sha256(&self) -> BodySha256 {
        self.proof.address().body_sha256().clone()
    }

    pub(crate) fn proof(&self) -> &DeleteSubjectProof {
        &self.proof
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeleteSubjectProofError {
    Missing(&'static str),
    Duplicated(&'static str),
    Invalid(&'static str),
    WorldMismatch,
    BodyHashMismatch,
}

pub(crate) fn delete_subject_proof_from_headers(
    target: &ValidatedWorldPath,
    expected_body_sha256: &BodySha256,
    headers: &[(String, String)],
) -> Result<Option<DeleteSubjectProof>, DeleteSubjectProofError> {
    let has_any = headers
        .iter()
        .any(|(name, _)| is_reserved_audit_header(name));
    if !has_any && crate::store::is_memory_world(target) {
        return Ok(None);
    }

    let world = parse_world(one_header(headers, DELETE_SUBJECT_WORLD)?)?;
    if &world != target {
        return Err(DeleteSubjectProofError::WorldMismatch);
    }
    let generation =
        WorldGeneration::new(one_header(headers, DELETE_SUBJECT_GENERATION)?.to_owned())
            .map_err(|_| DeleteSubjectProofError::Invalid(DELETE_SUBJECT_GENERATION))?;
    let raw_seq = one_header(headers, DELETE_SUBJECT_SEQ)?;
    let parsed_seq = raw_seq
        .parse::<i64>()
        .map_err(|_| DeleteSubjectProofError::Invalid(DELETE_SUBJECT_SEQ))?;
    if parsed_seq.to_string() != raw_seq {
        return Err(DeleteSubjectProofError::Invalid(DELETE_SUBJECT_SEQ));
    }
    let seq = TimelineSeq::new(parsed_seq)
        .map_err(|_| DeleteSubjectProofError::Invalid(DELETE_SUBJECT_SEQ))?;
    let body_sha256 = BodySha256::new(one_header(headers, DELETE_SUBJECT_BODY_SHA256)?.to_owned())
        .map_err(|_| DeleteSubjectProofError::Invalid(DELETE_SUBJECT_BODY_SHA256))?;
    let hmac = one_header(headers, DELETE_SUBJECT_HMAC)?;
    if !is_hmac_label(hmac) {
        return Err(DeleteSubjectProofError::Invalid(DELETE_SUBJECT_HMAC));
    }

    let proof =
        DeleteSubjectProof::from_parts(world, generation, seq, body_sha256, hmac.to_owned());
    if !proof.address().body_sha256().ct_eq(expected_body_sha256) {
        return Err(DeleteSubjectProofError::BodyHashMismatch);
    }
    Ok(Some(proof))
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

    pub(crate) fn delete_subject(&self) -> Option<&DeleteSubjectProof> {
        self.delete_subject
            .as_ref()
            .map(VerifiedDeleteSubject::proof)
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

fn one_header<'a>(
    headers: &'a [(String, String)],
    name: &'static str,
) -> Result<&'a str, DeleteSubjectProofError> {
    let mut values = headers
        .iter()
        .filter_map(|(header_name, value)| (header_name == name).then_some(value.as_str()));
    let first = values
        .next()
        .ok_or(DeleteSubjectProofError::Missing(name))?;
    if values.next().is_some() {
        return Err(DeleteSubjectProofError::Duplicated(name));
    }
    Ok(first)
}

fn parse_world(raw: &str) -> Result<ValidatedWorldPath, DeleteSubjectProofError> {
    ValidatedWorldPath::from_canonical(raw.to_owned())
        .map_err(|_| DeleteSubjectProofError::Invalid(DELETE_SUBJECT_WORLD))
}

fn is_lower_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_hmac_label(value: &str) -> bool {
    value
        .strip_prefix("hmac-")
        .is_some_and(|raw| is_lower_hex_len(raw, 64))
}
