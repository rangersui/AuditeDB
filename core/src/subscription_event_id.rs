//! Durable subscription event-id and identity types.
//!
//! This module owns the boundary between live process-local subscription
//! cursors and durable audit-chain row coordinates. Raw SSE id strings are
//! parsed only here; internal code carries sealed values. The parsed `seq` is
//! the current `TimelineSeq`/`events.id` replay coordinate, not the verified
//! `ChainSeq` ordinal used by chain-stamp anchoring.

use std::fmt;

use crate::{
    audit::{AppendedAuditRow, AppendedBodyAuditRow},
    engine_types::ValidatedWorldPath,
    event::AuditEventPayload,
    timeline::{TimelineAddress, TimelineSeq},
    world_generation::{InvalidWorldGeneration, WorldGeneration},
};

/// Durable chain-row event id for subscription protocols.
///
/// Rendered as `<percent-encoded-world>@<generation>=<timeline-seq>`. This names
/// the current durable audit-row replay coordinate rather than a process-local
/// broadcast id or a chain-stamp ordinal. It is still a coordinate, not an audit
/// proof: callers use timeline dereference APIs to prove the row exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionEventId {
    world: ValidatedWorldPath,
    generation: WorldGeneration,
    seq: TimelineSeq,
}

/// Returned when a durable subscription event id is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSubscriptionEventId {
    /// The id did not contain the `=<seq>` delimiter.
    MissingSeqDelimiter,
    /// The id did not contain the `@<generation>` delimiter.
    MissingGenerationDelimiter,
    /// The world component could not be decoded as UTF-8.
    InvalidWorldUtf8,
    /// The decoded world path was not canonical.
    WorldPath(&'static str),
    /// The world path names a memory namespace, which has no durable timeline.
    MemoryWorld,
    /// The generation was not 32 characters long.
    GenerationWrongLength,
    /// The generation was not lowercase hexadecimal.
    GenerationNotLowerHex,
    /// The sequence field was not a signed integer.
    SeqNotInteger,
    /// The sequence field was an integer outside the supported range.
    SeqOutOfRange,
    /// The sequence number was not positive.
    SeqNonPositive,
    /// The wire spelling was not the canonical percent-encoded form.
    NonCanonical,
}

/// Subscription event identity.
///
/// Chain-row events have a durable id. Ephemeral signals are live-only and
/// must not advance a protocol cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeEventIdentity {
    /// Replayable audit-chain event.
    Chain(SubscriptionEventId),
    /// Live-only signal with no durable cursor.
    Ephemeral,
}

/// Sealed event target for subscription events.
#[derive(Clone, Debug)]
pub(crate) enum ChangeTarget {
    Chain(Box<MatchedChainEvent>),
    Ephemeral(ValidatedWorldPath),
}

/// Chain event proven to bind durable identity, optional body address, and
/// signed audit-row payload for the same change event.
#[derive(Clone, Debug)]
pub(crate) struct MatchedChainEvent {
    id: SubscriptionEventId,
    timeline_address: Option<TimelineAddress>,
    audit_payload: AuditEventPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct TimelineAddressWorldMismatch;

impl ChangeTarget {
    pub(crate) fn from_appended_body_audit_row(row: &AppendedBodyAuditRow) -> Self {
        Self::Chain(Box::new(MatchedChainEvent::from_appended_body_audit_row(
            row,
        )))
    }

    pub(crate) fn from_verified_replay_body_event(
        event: &crate::audit::VerifiedReplayBodyEvent,
    ) -> Self {
        Self::Chain(Box::new(
            MatchedChainEvent::from_verified_replay_body_event(event),
        ))
    }

    pub(crate) fn from_appended_ledger_event(event: &crate::ledger::AppendedLedgerEvent) -> Self {
        Self::Chain(Box::new(MatchedChainEvent::from_event_id(
            event.event_id().clone(),
            AuditEventPayload::from_appended_ledger_event(event),
        )))
    }

    pub(crate) fn from_appended_audit_row(row: &AppendedAuditRow) -> Self {
        Self::Chain(Box::new(MatchedChainEvent::from_event_id(
            SubscriptionEventId::from_appended_audit_row(row),
            AuditEventPayload::from_appended_audit_row(row),
        )))
    }

    pub(crate) fn from_verified_non_body_replay_event(
        event: &crate::audit::VerifiedReplayNonBodyEvent,
    ) -> Self {
        Self::Chain(Box::new(MatchedChainEvent::from_event_id(
            SubscriptionEventId::from_verified_non_body_replay_event(event),
            AuditEventPayload::from_verified_replay_non_body_event(event),
        )))
    }

    #[cfg(test)]
    pub(crate) fn from_matched_timeline_address(
        world: &ValidatedWorldPath,
        address: TimelineAddress,
        payload: AuditEventPayload,
    ) -> Result<Self, TimelineAddressWorldMismatch> {
        if address.world() == world
            && payload.target() == world
            && payload.body_sha256() == address.body_sha256()
            && payload.kind().class().body_bearing
        {
            Ok(Self::Chain(Box::new(MatchedChainEvent::from_body_parts(
                address, payload,
            ))))
        } else {
            Err(TimelineAddressWorldMismatch)
        }
    }

    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        match self {
            Self::Chain(event) => event.id.world(),
            Self::Ephemeral(world) => world,
        }
    }

    pub(crate) fn identity(&self) -> ChangeEventIdentity {
        match self {
            Self::Chain(event) => ChangeEventIdentity::Chain(event.id.clone()),
            Self::Ephemeral(_) => ChangeEventIdentity::Ephemeral,
        }
    }

    pub(crate) fn into_timeline_parts(
        self,
    ) -> (
        ValidatedWorldPath,
        Option<TimelineAddress>,
        ChangeEventIdentity,
        Option<AuditEventPayload>,
    ) {
        match self {
            Self::Chain(event) => {
                let event = *event;
                let identity = ChangeEventIdentity::Chain(event.id.clone());
                (
                    event.id.world().clone(),
                    event.timeline_address,
                    identity,
                    Some(event.audit_payload),
                )
            }
            Self::Ephemeral(world) => (world, None, ChangeEventIdentity::Ephemeral, None),
        }
    }
}

impl MatchedChainEvent {
    fn from_appended_body_audit_row(row: &AppendedBodyAuditRow) -> Self {
        Self::from_body_parts(
            row.timeline_address().clone(),
            AuditEventPayload::from_appended_body_audit_row(row),
        )
    }

    fn from_verified_replay_body_event(event: &crate::audit::VerifiedReplayBodyEvent) -> Self {
        Self::from_body_parts(
            event.timeline_address().clone(),
            AuditEventPayload::from_verified_replay_body_event(event),
        )
    }

    fn from_event_id(id: SubscriptionEventId, audit_payload: AuditEventPayload) -> Self {
        Self {
            id,
            timeline_address: None,
            audit_payload,
        }
    }

    fn from_body_parts(address: TimelineAddress, audit_payload: AuditEventPayload) -> Self {
        let id = SubscriptionEventId::from_timeline_address(&address);
        Self {
            id,
            timeline_address: Some(address),
            audit_payload,
        }
    }
}

impl SubscriptionEventId {
    pub(crate) fn from_timeline_address(address: &TimelineAddress) -> Self {
        Self {
            world: address.world().clone(),
            generation: address.generation().clone(),
            seq: address.seq(),
        }
    }

    pub(crate) fn from_appended_audit_row(row: &AppendedAuditRow) -> Self {
        Self {
            world: row.world().clone(),
            generation: row.generation().clone(),
            seq: row.id(),
        }
    }

    pub(crate) fn from_verified_replay_event(event: &crate::audit::VerifiedReplayEvent) -> Self {
        Self {
            world: event.world().clone(),
            generation: event.gen().clone(),
            seq: event.seq(),
        }
    }

    pub(crate) fn from_verified_non_body_replay_event(
        event: &crate::audit::VerifiedReplayNonBodyEvent,
    ) -> Self {
        Self {
            world: event.world().clone(),
            generation: event.gen().clone(),
            seq: event.seq(),
        }
    }

    /// Parses a durable subscription event id.
    ///
    /// # Errors
    /// Returns [`InvalidSubscriptionEventId`] unless `raw` is the canonical
    /// `<percent-encoded-world>@<generation>=<positive timeline-seq>` form.
    pub fn from_sse_id(raw: impl AsRef<str>) -> Result<Self, InvalidSubscriptionEventId> {
        let raw = raw.as_ref();
        let Some((left, seq)) = raw.rsplit_once('=') else {
            return Err(InvalidSubscriptionEventId::MissingSeqDelimiter);
        };
        let Some((world, generation)) = left.rsplit_once('@') else {
            return Err(InvalidSubscriptionEventId::MissingGenerationDelimiter);
        };
        let world = percent_encoding::percent_decode_str(world)
            .decode_utf8()
            .map_err(|_| InvalidSubscriptionEventId::InvalidWorldUtf8)?;
        let world = ValidatedWorldPath::from_canonical(world.into_owned())
            .map_err(InvalidSubscriptionEventId::WorldPath)?;
        if crate::store::is_memory_world(&world) {
            return Err(InvalidSubscriptionEventId::MemoryWorld);
        }
        let generation = WorldGeneration::new(generation.to_owned()).map_err(|err| match err {
            InvalidWorldGeneration::WrongLength => {
                InvalidSubscriptionEventId::GenerationWrongLength
            }
            InvalidWorldGeneration::NotLowerHex => {
                InvalidSubscriptionEventId::GenerationNotLowerHex
            }
        })?;
        if seq.is_empty() {
            return Err(InvalidSubscriptionEventId::SeqNotInteger);
        }
        let seq = if seq.bytes().all(|byte| byte.is_ascii_digit())
            || seq
                .strip_prefix('-')
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        {
            seq.parse::<i64>()
                .map_err(|_| InvalidSubscriptionEventId::SeqOutOfRange)?
        } else {
            return Err(InvalidSubscriptionEventId::SeqNotInteger);
        };
        let seq = TimelineSeq::new(seq).map_err(|_| InvalidSubscriptionEventId::SeqNonPositive)?;
        let parsed = Self {
            world,
            generation,
            seq,
        };
        if raw != parsed.to_string() {
            return Err(InvalidSubscriptionEventId::NonCanonical);
        }
        Ok(parsed)
    }

    /// Returns the canonical world path this event id names.
    pub fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    /// Returns the durable-world generation this event id names.
    pub fn generation(&self) -> &WorldGeneration {
        &self.generation
    }

    /// Returns the current `TimelineSeq`/`events.id` coordinate this event id names.
    pub fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(crate) fn same_chain_at_or_before(&self, fence: &Self) -> bool {
        self.world == fence.world && self.generation == fence.generation && self.seq <= fence.seq
    }
}

impl fmt::Display for SubscriptionEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_event_id_world(self.world.as_str()))?;
        write!(f, "@{}={}", self.generation.as_str(), self.seq.get())
    }
}

impl fmt::Display for InvalidSubscriptionEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MissingSeqDelimiter => "subscription event id is missing seq delimiter",
            Self::MissingGenerationDelimiter => {
                "subscription event id is missing generation delimiter"
            }
            Self::InvalidWorldUtf8 => "subscription event id world is not valid UTF-8",
            Self::WorldPath(reason) => reason,
            Self::MemoryWorld => "subscription event id world is not durable",
            Self::GenerationWrongLength => "subscription event id generation has wrong length",
            Self::GenerationNotLowerHex => "subscription event id generation is not lower hex",
            Self::SeqNotInteger => "subscription event id sequence is not an integer",
            Self::SeqOutOfRange => "subscription event id sequence is out of range",
            Self::SeqNonPositive => "subscription event id sequence is not positive",
            Self::NonCanonical => "subscription event id is not canonical",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for InvalidSubscriptionEventId {}

fn encode_event_id_world(world: &str) -> String {
    let mut out = String::with_capacity(world.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in world.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b'~' | b'-') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::timeline::{BodySha256, TimelineAddress};

    fn generation() -> WorldGeneration {
        WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn address(world: &str, seq: i64) -> TimelineAddress {
        TimelineAddress::test_only_new(
            ValidatedWorldPath::new(world).unwrap(),
            generation(),
            TimelineSeq::new(seq).unwrap(),
            BodySha256::for_body(b"value"),
        )
    }

    #[test]
    fn durable_subscription_event_id_round_trips_chain_coordinate() {
        let world = ValidatedWorldPath::new("home/events/key with spaces").unwrap();
        let address = address(world.as_str(), 7);

        let event_id = SubscriptionEventId::from_timeline_address(&address);
        assert_eq!(
            event_id.to_string(),
            "home/events/key%20with%20spaces@0123456789abcdef0123456789abcdef=7"
        );

        let parsed = SubscriptionEventId::from_sse_id(event_id.to_string()).unwrap();
        assert_eq!(parsed.world(), &world);
        assert_eq!(parsed.generation(), &generation());
        assert_eq!(parsed.seq().get(), 7);
    }

    #[test]
    fn durable_subscription_event_id_encodes_reserved_delimiters_in_world() {
        let world = ValidatedWorldPath::new("home/events/key@v=1").unwrap();
        let address = address(world.as_str(), 7);

        let event_id = SubscriptionEventId::from_timeline_address(&address);
        assert_eq!(
            event_id.to_string(),
            "home/events/key%40v%3D1@0123456789abcdef0123456789abcdef=7"
        );

        let parsed = SubscriptionEventId::from_sse_id(event_id.to_string()).unwrap();
        assert_eq!(parsed.world(), &world);
        assert_eq!(parsed.seq().get(), 7);
    }

    #[test]
    fn durable_subscription_event_id_rejects_exact_malformed_reasons() {
        let good_gen = "0123456789abcdef0123456789abcdef";
        let cases = [
            (
                "home/a@0123456789abcdef0123456789abcdef",
                InvalidSubscriptionEventId::MissingSeqDelimiter,
            ),
            (
                "home/a=1",
                InvalidSubscriptionEventId::MissingGenerationDelimiter,
            ),
            (
                "home/a@0123456789abcdef0123456789abcdeF=1",
                InvalidSubscriptionEventId::GenerationNotLowerHex,
            ),
            (
                "home/a@0123456789abcdef0123456789abcdef=x",
                InvalidSubscriptionEventId::SeqNotInteger,
            ),
            (
                "home/a@0123456789abcdef0123456789abcdef=9223372036854775808",
                InvalidSubscriptionEventId::SeqOutOfRange,
            ),
            (
                "home/a@0123456789abcdef0123456789abcdef=0",
                InvalidSubscriptionEventId::SeqNonPositive,
            ),
            (
                "tmp/a@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::MemoryWorld,
            ),
            (
                "%FF@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::InvalidWorldUtf8,
            ),
            (
                "home/@@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::NonCanonical,
            ),
            (
                "home/a%2Fb@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::NonCanonical,
            ),
            (
                "home/a b@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::NonCanonical,
            ),
            (
                "home/a%@0123456789abcdef0123456789abcdef=1",
                InvalidSubscriptionEventId::NonCanonical,
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(
                SubscriptionEventId::from_sse_id(value).unwrap_err(),
                expected,
                "{value}"
            );
        }

        assert_eq!(
            SubscriptionEventId::from_sse_id(format!("home//@{good_gen}=1")).unwrap_err(),
            InvalidSubscriptionEventId::WorldPath("world path has empty segment")
        );
    }

    #[test]
    fn test_only_chain_target_binds_address_to_event_world() {
        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        assert!(ChangeTarget::from_matched_timeline_address(
            &world,
            address("home/events/a", 1),
            payload(&world),
        )
        .is_ok());
        assert!(ChangeTarget::from_matched_timeline_address(
            &world,
            address("home/events/b", 1),
            payload(&world),
        )
        .is_err());
        assert!(ChangeTarget::from_matched_timeline_address(
            &world,
            address("home/events/a", 1),
            payload_with_body(&world, b"other"),
        )
        .is_err());
    }

    fn payload(world: &ValidatedWorldPath) -> AuditEventPayload {
        payload_with_body(world, b"value")
    }

    fn payload_with_body(world: &ValidatedWorldPath, body: &[u8]) -> AuditEventPayload {
        AuditEventPayload::test_only(
            crate::event::AuditEventKind::Put,
            world.clone(),
            crate::timeline::BodySha256::for_body(body),
            body.len() as i64,
            "text/plain",
        )
    }

    #[test]
    fn change_target_derives_path_and_identity_from_one_value() {
        let world = ValidatedWorldPath::new("home/events/a").unwrap();
        let chain = ChangeTarget::from_matched_timeline_address(
            &world,
            address("home/events/a", 1),
            payload(&world),
        )
        .unwrap();
        assert_eq!(chain.world(), &world);
        let (path, timeline_address, identity, audit_payload) = chain.into_timeline_parts();
        assert_eq!(path, world);
        assert!(timeline_address.is_some());
        assert!(audit_payload.is_some());
        assert!(matches!(identity, ChangeEventIdentity::Chain(_)));

        let other = ValidatedWorldPath::new("home/events/b").unwrap();
        let wrong = ChangeTarget::from_matched_timeline_address(
            &other,
            address("home/events/a", 1),
            payload(&other),
        );
        assert!(wrong.is_err());
    }

    #[test]
    fn chain_event_without_body_address_still_carries_durable_identity() {
        let id = SubscriptionEventId {
            world: ValidatedWorldPath::new("var/log/deletes").unwrap(),
            generation: generation(),
            seq: TimelineSeq::new(2).unwrap(),
        };
        let target = ChangeTarget::Chain(Box::new(MatchedChainEvent::from_event_id(
            id.clone(),
            payload(id.world()),
        )));

        assert_eq!(target.world(), id.world());
        let (path, timeline_address, identity, audit_payload) = target.into_timeline_parts();

        assert_eq!(path, *id.world());
        assert!(timeline_address.is_none());
        assert!(audit_payload.is_some());
        assert_eq!(identity, ChangeEventIdentity::Chain(id));
    }
}
