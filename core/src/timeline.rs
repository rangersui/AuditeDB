//! Core timeline address contract for Path 3.
//!
//! A timeline address names one durable body event in one durable world
//! generation. It is not just a row number: the address also carries the world
//! path and the SHA-256 of the body the audit row promised.
//!
//! Public callers may inspect timeline addresses and read outcomes, but they
//! cannot mint addresses directly. Production addresses are created only after
//! audit verification proves that an event row belongs to the requested world
//! and generation.

#![cfg_attr(not(test), allow(dead_code))]

use crate::engine_types::{Representation, ValidatedWorldPath};
use crate::world_generation::{MintedWorldGeneration, WorldGeneration};
use std::num::NonZeroI64;

/// FIPS 180-4 defines SHA-256 output as 256 bits; hex renders 4 bits per char.
const BODY_SHA256_HEX_LEN: usize = 64;

/// Opaque address of one audited body value.
///
/// The fields are private on purpose. A caller can receive, clone, compare, and
/// inspect a `TimelineAddress`, but cannot construct or recombine the
/// `{ world, generation, seq, body_sha256 }` coordinate outside verified audit
/// minting.
///
/// ```compile_fail
/// fn recombine(address: elastik_core::TimelineAddress) -> elastik_core::TimelineAddress {
///     let world = address.world().clone();
///     let generation = address.generation().clone();
///     let seq = address.seq();
///     let body_sha256 = address.body_sha256().clone();
///
///     elastik_core::TimelineAddress::new(world, generation, seq, body_sha256)
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineAddress {
    world: ValidatedWorldPath,
    gen: WorldGeneration,
    seq: TimelineSeq,
    body_sha256: BodySha256,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MintedTimelineAddress {
    world: ValidatedWorldPath,
    gen: MintedWorldGeneration,
    seq: TimelineSeq,
    body_sha256: BodySha256,
}

/// Positive audit-event sequence number inside one durable world generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimelineSeq(NonZeroI64);

/// SHA-256 digest of a body value, rendered as 64 lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodySha256(String);

/// Body value resolved from a timeline address.
pub struct TimelineBody {
    address: TimelineAddress,
    representation: Representation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvalidTimelineSeq {
    NonPositive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvalidBodySha256 {
    WrongLength,
    NotLowerHex,
}

/// Corruption detected while resolving a timeline address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimelineCorruption {
    /// A body event row exists but its retained CAS body is missing in a state
    /// where retention metadata said it should still exist.
    MissingBodyForPresentRow,
    /// The returned bytes did not hash to the address's promised SHA-256.
    BodyHashMismatch,
    /// The event row shape is not a valid body event for this address.
    InvalidEventShape,
}

/// Result of resolving a timeline address.
///
/// `Body` is the only successful byte-bearing outcome. The other variants tell
/// callers why the exact historical value is not available without falling back
/// to the current live body.
#[non_exhaustive]
pub enum TimelineRead {
    /// The addressed historical body was found.
    Body(TimelineBody),
    /// The audit row exists, but the body is before the CAS retention floor.
    ///
    /// This is not a pruning claim. It means the storage state does not claim
    /// this body was ever retained as dereferenceable CAS bytes.
    NeverRetained {
        /// Address that could not be materialized.
        address: TimelineAddress,
    },
    /// The audit row exists, and pruning metadata proves the retained CAS body
    /// has aged out.
    Expired {
        /// Address that could not be materialized.
        address: TimelineAddress,
    },
    /// Delete-ledger proof says the addressed durable world was physically
    /// deleted.
    Gone {
        /// Address that could not be materialized.
        address: TimelineAddress,
    },
    /// The path was deleted and recreated; the address belongs to an older
    /// generation than the current world.
    GenMismatch {
        /// Address requested by the caller.
        requested: TimelineAddress,
        /// Current generation stored in the world's SQLite file.
        actual: WorldGeneration,
    },
    /// No event row with the address's sequence exists in this generation.
    MissingRow {
        /// Address that could not be materialized.
        address: TimelineAddress,
    },
    /// The event row exists, but it names a different body hash than the
    /// requested address.
    AddressMismatch {
        /// Address requested by the caller.
        requested: TimelineAddress,
        /// Body hash carried by the verified audit row.
        actual: BodySha256,
    },
    /// Available storage could not prove whether the address is gone,
    /// retained elsewhere, or permanently unavailable.
    Unproven {
        /// Address that could not be materialized.
        address: TimelineAddress,
    },
    /// The addressed row or retained body failed integrity checks.
    Corrupt {
        /// Address that failed verification.
        address: TimelineAddress,
        /// Integrity failure category.
        reason: TimelineCorruption,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TimelineAddressLookup {
    Body(TimelineAddress),
    MissingRow,
    NoBody,
}

impl TimelineBody {
    /// Returns the address that produced this historical body.
    pub fn address(&self) -> &TimelineAddress {
        &self.address
    }

    /// Returns the body bytes, content type, and metadata snapshot.
    pub fn representation(&self) -> &Representation {
        &self.representation
    }
}

impl TimelineRead {
    pub(crate) fn body(address: TimelineAddress, representation: Representation) -> Self {
        let actual = crate::world::sha256_hex(&representation.body);
        if !crate::auth::ct_eq(actual.as_bytes(), address.body_sha256().as_str().as_bytes()) {
            return Self::Corrupt {
                address,
                reason: TimelineCorruption::BodyHashMismatch,
            };
        }

        Self::Body(TimelineBody {
            address,
            representation,
        })
    }
}

impl TimelineAddress {
    fn new(
        world: ValidatedWorldPath,
        gen: WorldGeneration,
        seq: TimelineSeq,
        body_sha256: BodySha256,
    ) -> Self {
        Self {
            world,
            gen,
            seq,
            body_sha256,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_new(
        world: ValidatedWorldPath,
        gen: WorldGeneration,
        seq: TimelineSeq,
        body_sha256: BodySha256,
    ) -> Self {
        Self::new(world, gen, seq, body_sha256)
    }

    pub(crate) fn from_verified_body_event(event: crate::audit::VerifiedBodyEvent) -> Self {
        Self::new(
            event.world().clone(),
            event.gen().clone(),
            event.seq(),
            event.body_sha256().clone(),
        )
    }

    /// Returns the canonical world path this address belongs to.
    pub fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    /// Returns the durable-world generation this address belongs to.
    pub fn generation(&self) -> &WorldGeneration {
        &self.gen
    }

    pub(crate) fn gen(&self) -> &WorldGeneration {
        &self.gen
    }

    /// Returns the audited event sequence number inside this generation.
    pub fn seq(&self) -> TimelineSeq {
        self.seq
    }

    /// Returns the body digest promised by the audited event row.
    pub fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }
}

impl MintedTimelineAddress {
    pub(crate) fn new(
        world: ValidatedWorldPath,
        gen: MintedWorldGeneration,
        seq: TimelineSeq,
        body_sha256: BodySha256,
    ) -> Self {
        Self {
            world,
            gen,
            seq,
            body_sha256,
        }
    }

    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    pub(crate) fn gen(&self) -> &MintedWorldGeneration {
        &self.gen
    }

    pub(crate) fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
        &self.body_sha256
    }
}

impl TimelineSeq {
    /// Internal SQLite `events.id` coordinate only. This is not an SSE `id`,
    /// not `Last-Event-ID`, and not a durable external cursor by itself.
    pub(crate) fn new(raw: i64) -> Result<Self, InvalidTimelineSeq> {
        NonZeroI64::new(raw)
            .filter(|seq| seq.get() > 0)
            .map(Self)
            .ok_or(InvalidTimelineSeq::NonPositive)
    }

    /// Returns the positive SQLite row id used as the timeline sequence.
    pub fn get(self) -> i64 {
        self.0.get()
    }
}

impl BodySha256 {
    pub(crate) fn for_body(body: &[u8]) -> Self {
        Self(crate::world::sha256_hex(body))
    }

    pub(crate) fn new(raw: impl Into<String>) -> Result<Self, InvalidBodySha256> {
        let raw = raw.into();
        if raw.len() != BODY_SHA256_HEX_LEN {
            return Err(InvalidBodySha256::WrongLength);
        }
        if !is_lower_hex(&raw) {
            return Err(InvalidBodySha256::NotLowerHex);
        }
        Ok(Self(raw))
    }

    /// Returns the 64-character lowercase hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn world() -> ValidatedWorldPath {
        ValidatedWorldPath::new("home/timeline").unwrap()
    }

    fn gen() -> WorldGeneration {
        WorldGeneration::new("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn body_hash() -> BodySha256 {
        BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
    }

    fn address(seq: i64) -> TimelineAddress {
        TimelineAddress::new(world(), gen(), TimelineSeq::new(seq).unwrap(), body_hash())
    }

    fn address_for_body(seq: i64, body: &[u8]) -> TimelineAddress {
        TimelineAddress::new(
            world(),
            gen(),
            TimelineSeq::new(seq).unwrap(),
            BodySha256::new(crate::world::sha256_hex(body)).unwrap(),
        )
    }

    #[test]
    fn timeline_address_carries_full_coordinate() {
        let address =
            TimelineAddress::new(world(), gen(), TimelineSeq::new(42).unwrap(), body_hash());

        assert_eq!(address.world().as_str(), "home/timeline");
        assert_eq!(address.gen(), &gen());
        assert_eq!(address.seq().get(), 42);
        assert_eq!(
            address.body_sha256().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn minted_timeline_address_consumes_minted_generation() {
        let entropy = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let minted = MintedWorldGeneration::test_only_from_entropy_bytes(entropy);
        let expected = MintedWorldGeneration::test_only_from_entropy_bytes(entropy);

        let address =
            MintedTimelineAddress::new(world(), minted, TimelineSeq::new(7).unwrap(), body_hash());

        assert_eq!(address.world().as_str(), "home/timeline");
        assert_eq!(address.gen(), &expected);
        assert_eq!(address.seq().get(), 7);
        assert_eq!(
            address.body_sha256().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn timeline_seq_is_positive_sqlite_rowid() {
        assert_eq!(TimelineSeq::new(1).unwrap().get(), 1);
        assert_eq!(
            TimelineSeq::new(0).unwrap_err(),
            InvalidTimelineSeq::NonPositive
        );
        assert_eq!(
            TimelineSeq::new(-1).unwrap_err(),
            InvalidTimelineSeq::NonPositive
        );
    }

    #[test]
    fn body_sha256_is_256_bit_lower_hex() {
        assert!(BodySha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
        assert_eq!(
            BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
                .unwrap_err(),
            InvalidBodySha256::WrongLength
        );
        assert_eq!(
            BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")
                .unwrap_err(),
            InvalidBodySha256::WrongLength
        );
        assert_eq!(
            BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF")
                .unwrap_err(),
            InvalidBodySha256::NotLowerHex
        );
        assert_eq!(
            BodySha256::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")
                .unwrap_err(),
            InvalidBodySha256::NotLowerHex
        );
    }

    #[test]
    fn timeline_read_body_carries_representation() {
        let address = address_for_body(1, b"value");
        let representation =
            Representation::new(Bytes::from_static(b"value"), "text/plain", Vec::new());

        let result = TimelineRead::body(address.clone(), representation);

        match result {
            TimelineRead::Body(body) => {
                assert_eq!(body.address(), &address);
                assert_eq!(body.representation().body, Bytes::from_static(b"value"));
                assert_eq!(body.representation().content_type, "text/plain");
                assert!(body.representation().headers.is_empty());
            }
            _ => panic!("expected body read"),
        }
    }

    #[test]
    fn timeline_read_body_rejects_hash_mismatch() {
        let address = address_for_body(1, b"expected");
        let representation =
            Representation::new(Bytes::from_static(b"actual"), "text/plain", Vec::new());

        let result = TimelineRead::body(address.clone(), representation);

        match result {
            TimelineRead::Corrupt {
                address: got,
                reason,
            } => {
                assert_eq!(got, address);
                assert_eq!(reason, TimelineCorruption::BodyHashMismatch);
            }
            _ => panic!("expected corrupt read"),
        }
    }

    #[test]
    fn timeline_read_enumerates_absence_and_mismatch_modes() {
        let actual = WorldGeneration::new("fedcba9876543210fedcba9876543210").unwrap();

        let reads = [
            TimelineRead::NeverRetained {
                address: address(1),
            },
            TimelineRead::Expired {
                address: address(2),
            },
            TimelineRead::Gone {
                address: address(3),
            },
            TimelineRead::MissingRow {
                address: address(4),
            },
            TimelineRead::GenMismatch {
                requested: address(5),
                actual: actual.clone(),
            },
            TimelineRead::AddressMismatch {
                requested: address(6),
                actual: BodySha256::for_body(b"actual"),
            },
            TimelineRead::Unproven {
                address: address(7),
            },
        ];

        for read in reads {
            match read {
                TimelineRead::NeverRetained { address } => assert_eq!(address.seq().get(), 1),
                TimelineRead::Expired { address } => assert_eq!(address.seq().get(), 2),
                TimelineRead::Gone { address } => assert_eq!(address.seq().get(), 3),
                TimelineRead::MissingRow { address } => assert_eq!(address.seq().get(), 4),
                TimelineRead::GenMismatch {
                    requested,
                    actual: got,
                } => {
                    assert_eq!(requested.seq().get(), 5);
                    assert_eq!(got, actual);
                }
                TimelineRead::AddressMismatch { requested, actual } => {
                    assert_eq!(requested.seq().get(), 6);
                    assert_eq!(actual, BodySha256::for_body(b"actual"));
                }
                TimelineRead::Unproven { address } => assert_eq!(address.seq().get(), 7),
                TimelineRead::Body(_) | TimelineRead::Corrupt { .. } => {
                    panic!("unexpected read mode")
                }
            }
        }
    }

    #[test]
    fn timeline_address_lookup_distinguishes_missing_and_non_body_events() {
        match TimelineAddressLookup::Body(address(8)) {
            TimelineAddressLookup::Body(address) => assert_eq!(address.seq().get(), 8),
            TimelineAddressLookup::MissingRow | TimelineAddressLookup::NoBody => {
                panic!("expected body address")
            }
        }

        assert!(matches!(
            TimelineAddressLookup::MissingRow,
            TimelineAddressLookup::MissingRow
        ));
        assert!(matches!(
            TimelineAddressLookup::NoBody,
            TimelineAddressLookup::NoBody
        ));
    }

    #[test]
    fn timeline_corruption_reasons_are_part_of_the_contract() {
        let reasons = [
            TimelineCorruption::MissingBodyForPresentRow,
            TimelineCorruption::BodyHashMismatch,
            TimelineCorruption::InvalidEventShape,
        ];

        for (idx, reason) in reasons.into_iter().enumerate() {
            let result = TimelineRead::Corrupt {
                address: address((idx + 10) as i64),
                reason: reason.clone(),
            };

            match result {
                TimelineRead::Corrupt {
                    address,
                    reason: got,
                } => {
                    assert_eq!(address.seq().get(), (idx + 10) as i64);
                    assert_eq!(got, reason);
                }
                _ => panic!("expected corrupt read"),
            }
        }
    }
}
