//! Sealed audit-chain stamp proof values.
//!
//! `TimelineSeq` names a SQLite row coordinate. The types in this module name
//! verified audit-chain facts: an ordinal reached by a verifier walk, the
//! number of verified events observed, and the HMAC captured from that walk.
//! Raw integers and strings are accepted only at parser/render boundaries.

use std::{fmt, num::NonZeroI64};

use crate::world_generation::WorldGeneration;

/// Returned when a raw chain sequence is not a positive chain ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidChainSeq {
    /// Chain ordinals start at 1; zero and negative values are invalid.
    NonPositive,
}

/// Positive ordinal inside a verified audit chain.
///
/// This is not SQLite `events.id`. It is the one-based position reached while
/// walking the chain in order and validating every previous HMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainSeq(NonZeroI64);

/// Number of events observed during a verified audit-chain walk.
///
/// Unlike [`ChainSeq`], this value may be zero for an empty bootstrap-shape
/// durable database. It is minted internally from verifier state; callers can
/// inspect it but cannot construct one from a naked integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainEventCount(usize);

/// HMAC value captured from a verified audit-chain walk.
///
/// The value is already labelled for public rendering, matching the existing
/// audit introspection shape such as `hmac-<hex>`. There is intentionally no
/// public constructor: an adapter must not turn an arbitrary header string into
/// a proof-bearing HMAC.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedChainHmac(String);

/// Verified audit-chain stamp for a durable world generation and chain ordinal.
///
/// A `ChainStamp` is minted only after the verifier reaches `seq` in the named
/// generation and captures that row's HMAC from the same walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStamp {
    generation: WorldGeneration,
    seq: ChainSeq,
    hmac: VerifiedChainHmac,
}

/// Result of looking up a chain stamp at a requested ordinal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainStampRead {
    /// The verifier reached the requested ordinal and captured its HMAC.
    Found(ChainStamp),
    /// The chain verified, but it has fewer events than requested.
    Missing(ChainStampMissing),
}

/// Verified absence details for a requested chain stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStampMissing {
    generation: WorldGeneration,
    requested: ChainSeq,
    observed: ChainEventCount,
}

impl ChainSeq {
    /// Parses a positive chain ordinal from a boundary integer.
    ///
    /// This constructor validates shape only. It does not prove that the
    /// ordinal exists in any world; proof comes from [`ChainStamp`].
    ///
    /// # Errors
    /// Returns [`InvalidChainSeq::NonPositive`] for zero or negative values.
    pub fn new(raw: i64) -> Result<Self, InvalidChainSeq> {
        if raw <= 0 {
            return Err(InvalidChainSeq::NonPositive);
        }
        match NonZeroI64::new(raw) {
            Some(seq) => Ok(Self(seq)),
            None => Err(InvalidChainSeq::NonPositive),
        }
    }

    fn from_verified_count(count: usize) -> Option<Self> {
        let raw = i64::try_from(count).ok()?;
        Self::new(raw).ok()
    }

    /// Returns the chain ordinal as a positive integer.
    pub fn get(self) -> i64 {
        self.0.get()
    }
}

impl ChainEventCount {
    fn from_verified_count(count: usize) -> Self {
        Self(count)
    }

    pub(crate) fn latest_seq(self) -> Option<ChainSeq> {
        ChainSeq::from_verified_count(self.0)
    }

    /// Returns the verified event count.
    pub fn get(self) -> usize {
        self.0
    }
}

impl VerifiedChainHmac {
    fn from_verified_label(label: String) -> Self {
        Self(label)
    }

    /// Returns the verified HMAC label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ChainStamp {
    fn from_verified_parts(
        generation: WorldGeneration,
        seq: ChainSeq,
        hmac: VerifiedChainHmac,
    ) -> Self {
        Self {
            generation,
            seq,
            hmac,
        }
    }

    pub(crate) fn from_verified_head_parts(
        parts: crate::audit::VerifiedChainHeadParts,
    ) -> Option<Self> {
        let (generation, event_count, latest_hmac) = parts.into_chain_stamp_parts();
        let event_count = ChainEventCount::from_verified_count(event_count);
        let seq = event_count.latest_seq()?;
        let hmac = VerifiedChainHmac::from_verified_label(latest_hmac);
        Some(Self::from_verified_parts(generation, seq, hmac))
    }

    pub(crate) fn from_verified_stamp_parts(parts: crate::audit::VerifiedChainStampParts) -> Self {
        let (generation, seq, hmac) = parts.into_chain_stamp_parts();
        let hmac = VerifiedChainHmac::from_verified_label(hmac);
        Self::from_verified_parts(generation, seq, hmac)
    }

    /// Returns the durable world generation that owns this stamp.
    pub fn generation(&self) -> &WorldGeneration {
        &self.generation
    }

    /// Returns the verified chain ordinal.
    pub fn seq(&self) -> ChainSeq {
        self.seq
    }

    /// Returns the verified HMAC captured at [`ChainStamp::seq`].
    pub fn hmac(&self) -> &VerifiedChainHmac {
        &self.hmac
    }
}

impl ChainStampRead {
    pub(crate) fn found(parts: crate::audit::VerifiedChainStampParts) -> Self {
        Self::Found(ChainStamp::from_verified_stamp_parts(parts))
    }

    pub(crate) fn missing_from_verified_parts(
        parts: crate::audit::VerifiedChainStampMissingParts,
    ) -> Self {
        let (generation, requested, observed) = parts.into_chain_stamp_missing_parts();
        Self::Missing(ChainStampMissing::from_verified_parts(
            generation, requested, observed,
        ))
    }
}

impl ChainStampMissing {
    fn from_verified_parts(
        generation: WorldGeneration,
        requested: ChainSeq,
        observed: usize,
    ) -> Self {
        Self {
            generation,
            requested,
            observed: ChainEventCount::from_verified_count(observed),
        }
    }

    /// Returns the durable world generation that was verified.
    pub fn generation(&self) -> &WorldGeneration {
        &self.generation
    }

    /// Returns the requested chain ordinal.
    pub fn requested(&self) -> ChainSeq {
        self.requested
    }

    /// Returns the verified event count observed while looking up the stamp.
    pub fn observed(&self) -> ChainEventCount {
        self.observed
    }
}

impl fmt::Display for InvalidChainSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositive => f.write_str("chain sequence must be positive"),
        }
    }
}

impl std::error::Error for InvalidChainSeq {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn generation() -> WorldGeneration {
        WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn chain_seq_rejects_non_positive_values() {
        assert_eq!(ChainSeq::new(0), Err(InvalidChainSeq::NonPositive));
        assert_eq!(ChainSeq::new(-1), Err(InvalidChainSeq::NonPositive));
        assert_eq!(ChainSeq::new(1).unwrap().get(), 1);
    }

    #[test]
    fn event_count_can_name_empty_chain_or_latest_ordinal() {
        let empty = ChainEventCount::from_verified_count(0);
        assert_eq!(empty.get(), 0);
        assert_eq!(empty.latest_seq(), None);

        let non_empty = ChainEventCount::from_verified_count(2);
        assert_eq!(non_empty.get(), 2);
        assert_eq!(non_empty.latest_seq().unwrap().get(), 2);
    }

    #[test]
    fn chain_stamp_carries_only_verified_parts() {
        let hmac = VerifiedChainHmac::from_verified_label(format!("hmac-{}", "a".repeat(64)));
        let stamp = ChainStamp::from_verified_parts(generation(), ChainSeq::new(3).unwrap(), hmac);

        assert_eq!(
            stamp.generation().as_str(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(stamp.seq().get(), 3);
        assert_eq!(stamp.hmac().as_str(), format!("hmac-{}", "a".repeat(64)));
    }

    #[test]
    fn missing_stamp_carries_generation_requested_and_observed_count() {
        let missing = ChainStampRead::Missing(ChainStampMissing::from_verified_parts(
            generation(),
            ChainSeq::new(7).unwrap(),
            3,
        ));
        let ChainStampRead::Missing(missing) = missing else {
            panic!("expected missing stamp");
        };

        assert_eq!(
            missing.generation().as_str(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(missing.requested().get(), 7);
        assert_eq!(missing.observed().get(), 3);
    }
}
