//! Coordinate dereference result contract for timeline reads.
//!
//! A [`TimelineCoordinate`] is wire syntax. This module names the later result
//! states for the resolver that verifies a subject world's audit chain before
//! it returns either a historical body or a proof-bearing negative fact.

#![cfg_attr(not(test), allow(dead_code))]

use crate::timeline::{BodySha256, TimelineBody, TimelineCoordinate, TimelineCorruption};
use crate::world_generation::WorldGeneration;

/// Verified generation mismatch for coordinate-based timeline dereference.
///
/// This is a proof value, not a plain error bag. Callers can inspect it, but
/// cannot construct one without going through this module's resolver path after
/// it verifies the subject world's audit chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGenerationMismatch {
    requested: TimelineCoordinate,
    actual: WorldGeneration,
}

/// Verified body-hash mismatch for coordinate-based timeline dereference.
///
/// The event row exists and has been verified at the requested world,
/// generation, and sequence, but the row's body hash differs from the untrusted
/// coordinate supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBodyHashMismatch {
    requested: TimelineCoordinate,
    actual_body_sha256: BodySha256,
}

/// Verified non-body event for coordinate-based timeline dereference.
///
/// The requested world/generation/sequence exists in an intact audit chain, but
/// that event does not carry a historical body. The requested body hash remains
/// caller-supplied syntax, not a proven row fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNonBodyEvent {
    requested: TimelineCoordinate,
}

/// Verified row absence for coordinate-based timeline dereference.
///
/// The subject world exists, its generation matches the coordinate, and its
/// audit chain is intact, but no row exists at the requested sequence. The
/// requested body hash remains caller-supplied syntax, not a proven row fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMissingRow {
    requested: TimelineCoordinate,
}

/// Result of dereferencing an untrusted [`TimelineCoordinate`].
///
/// This is intentionally separate from [`crate::TimelineRead`].
/// [`crate::TimelineRead`] is for already proof-bearing timeline addresses and
/// can report address-bearing states such as `Gone` or `Expired`. Coordinate
/// dereference starts before that proof exists, so every verified historical
/// negative outcome carries a sealed proof value and unproven absence stays
/// distinct.
///
/// Public callers cannot mint verified negative outcomes with raw constructors:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_generation: elastik_core::WorldGeneration = todo!();
///
/// let _ = elastik_core::VerifiedGenerationMismatch::new(requested, actual_generation);
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_hash: elastik_core::BodySha256 = todo!();
///
/// let _ = elastik_core::VerifiedBodyHashMismatch::new(requested, actual_hash);
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedNonBodyEvent::new(requested.clone());
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedMissingRow::new(requested);
/// # }
/// ```
///
/// Nor can they construct proofs with struct literals:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_generation: elastik_core::WorldGeneration = todo!();
///
/// let _ = elastik_core::VerifiedGenerationMismatch {
///     requested,
///     actual: actual_generation,
/// };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
/// let actual_hash: elastik_core::BodySha256 = todo!();
///
/// let _ = elastik_core::VerifiedBodyHashMismatch {
///     requested,
///     actual_body_sha256: actual_hash,
/// };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedNonBodyEvent { requested };
/// # }
/// ```
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::VerifiedMissingRow { requested };
/// # }
/// ```
///
/// A raw coordinate also cannot stand in for a verified proof:
///
/// ```compile_fail
/// # #[cfg(feature = "unstable-engine")]
/// # fn run() {
/// let requested: elastik_core::TimelineCoordinate = todo!();
///
/// let _ = elastik_core::TimelineDereference::MissingRow(requested);
/// # }
/// ```
#[non_exhaustive]
pub enum TimelineDereference {
    /// The addressed historical body was found.
    Body(TimelineBody),
    /// The subject world exists and verified, but belongs to a different
    /// generation than the coordinate requested.
    GenMismatch(VerifiedGenerationMismatch),
    /// The event row exists and verified, but promised a different body hash.
    BodyHashMismatch(VerifiedBodyHashMismatch),
    /// The event row exists and verified, but it is metadata-only.
    NonBodyEvent(VerifiedNonBodyEvent),
    /// The subject world exists and verified, but the sequence row is absent.
    MissingRow(VerifiedMissingRow),
    /// No bounded proof source can currently prove the requested coordinate.
    UnprovenCoordinate(TimelineCoordinate),
    /// Integrity failure while resolving the coordinate.
    Corrupt {
        /// Coordinate being resolved when corruption was detected.
        coordinate: TimelineCoordinate,
        /// Integrity failure category.
        reason: TimelineCorruption,
    },
}

impl VerifiedGenerationMismatch {
    fn new(requested: TimelineCoordinate, actual: WorldGeneration) -> Option<Self> {
        if requested.generation() == &actual {
            return None;
        }
        Some(Self { requested, actual })
    }

    /// Returns the untrusted coordinate after the resolver proved the mismatch.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }

    /// Returns the actual generation stored in the subject world.
    pub fn actual(&self) -> &WorldGeneration {
        &self.actual
    }
}

impl VerifiedBodyHashMismatch {
    fn new(requested: TimelineCoordinate, actual_body_sha256: BodySha256) -> Option<Self> {
        if requested.body_sha256() == &actual_body_sha256 {
            return None;
        }
        Some(Self {
            requested,
            actual_body_sha256,
        })
    }

    /// Returns the untrusted coordinate after the resolver proved the mismatch.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }

    /// Returns the body digest found in the verified event row.
    pub fn actual_body_sha256(&self) -> &BodySha256 {
        &self.actual_body_sha256
    }
}

impl VerifiedNonBodyEvent {
    fn new(requested: TimelineCoordinate) -> Self {
        Self { requested }
    }

    /// Returns the requested coordinate after the resolver proved the row is
    /// non-body-bearing.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }
}

impl VerifiedMissingRow {
    fn new(requested: TimelineCoordinate) -> Self {
        Self { requested }
    }

    /// Returns the requested coordinate after the resolver proved the row is
    /// absent.
    pub fn requested(&self) -> &TimelineCoordinate {
        &self.requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinate_with_hash(seq: i64, hash: &str) -> TimelineCoordinate {
        TimelineCoordinate::from_wire_parts(
            "home/timeline",
            "0123456789abcdef0123456789abcdef",
            seq,
            hash,
        )
        .unwrap()
    }

    fn coordinate(seq: i64) -> TimelineCoordinate {
        coordinate_with_hash(
            seq,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    fn other_body_hash() -> BodySha256 {
        BodySha256::new("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").unwrap()
    }

    #[test]
    fn timeline_dereference_negative_outcomes_carry_verified_proofs() {
        let requested = coordinate(42);
        let actual_gen = WorldGeneration::new("fedcba9876543210fedcba9876543210").unwrap();
        let actual_hash = other_body_hash();

        let gen_mismatch =
            VerifiedGenerationMismatch::new(requested.clone(), actual_gen.clone()).unwrap();
        assert_eq!(gen_mismatch.requested(), &requested);
        assert_eq!(gen_mismatch.actual(), &actual_gen);

        let body_hash_mismatch =
            VerifiedBodyHashMismatch::new(requested.clone(), actual_hash.clone()).unwrap();
        assert_eq!(body_hash_mismatch.requested(), &requested);
        assert_eq!(body_hash_mismatch.actual_body_sha256(), &actual_hash);

        let non_body = VerifiedNonBodyEvent::new(requested.clone());
        assert_eq!(non_body.requested(), &requested);

        let missing = VerifiedMissingRow::new(requested.clone());
        assert_eq!(missing.requested(), &requested);

        let results = [
            TimelineDereference::GenMismatch(gen_mismatch),
            TimelineDereference::BodyHashMismatch(body_hash_mismatch),
            TimelineDereference::NonBodyEvent(non_body),
            TimelineDereference::MissingRow(missing),
            TimelineDereference::UnprovenCoordinate(requested.clone()),
        ];

        for result in results {
            match result {
                TimelineDereference::GenMismatch(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::BodyHashMismatch(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::NonBodyEvent(proof) => {
                    assert_eq!(proof.requested(), &requested)
                }
                TimelineDereference::MissingRow(proof) => assert_eq!(proof.requested(), &requested),
                TimelineDereference::UnprovenCoordinate(coord) => assert_eq!(coord, requested),
                TimelineDereference::Body(_) | TimelineDereference::Corrupt { .. } => {
                    panic!("unexpected dereference state")
                }
            }
        }
    }

    #[test]
    fn mismatch_proofs_reject_non_mismatches() {
        let requested = coordinate(42);
        assert!(
            VerifiedGenerationMismatch::new(requested.clone(), requested.generation().clone())
                .is_none()
        );
        assert!(
            VerifiedBodyHashMismatch::new(requested.clone(), requested.body_sha256().clone())
                .is_none()
        );
    }
}
