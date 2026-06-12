//! Core timeline address contract for Path 3.
//!
//! This module intentionally defines only the typed contract. It does not read
//! SQLite, retain CAS bodies, render HTTP, expose FFI, or implement migration.
//! Later layers wire storage into these types.

#![cfg_attr(not(test), allow(dead_code))]

use crate::engine_types::{Representation, ValidatedWorldPath};
use crate::world_generation::{MintedWorldGeneration, WorldGeneration};
use std::num::NonZeroI64;

/// FIPS 180-4 defines SHA-256 output as 256 bits; hex renders 4 bits per char.
const BODY_SHA256_HEX_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TimelineAddress {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TimelineSeq(NonZeroI64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BodySha256(String);

pub(crate) struct TimelineBody {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TimelineCorruption {
    MissingBodyForPresentRow,
    BodyHashMismatch,
    InvalidEventShape,
}

pub(crate) enum TimelineRead {
    Body(TimelineBody),
    Expired {
        address: TimelineAddress,
    },
    Gone {
        address: TimelineAddress,
    },
    GenMismatch {
        requested: TimelineAddress,
        actual: WorldGeneration,
    },
    MissingRow {
        address: TimelineAddress,
    },
    Corrupt {
        address: TimelineAddress,
        reason: TimelineCorruption,
    },
}

impl TimelineBody {
    pub(crate) fn address(&self) -> &TimelineAddress {
        &self.address
    }

    pub(crate) fn representation(&self) -> &Representation {
        &self.representation
    }
}

impl TimelineRead {
    pub(crate) fn body(address: TimelineAddress, representation: Representation) -> Self {
        let actual = crate::world::sha256_hex(&representation.body);
        if actual != address.body_sha256().as_str() {
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

    pub(crate) fn world(&self) -> &ValidatedWorldPath {
        &self.world
    }

    pub(crate) fn gen(&self) -> &WorldGeneration {
        &self.gen
    }

    pub(crate) fn seq(&self) -> TimelineSeq {
        self.seq
    }

    pub(crate) fn body_sha256(&self) -> &BodySha256 {
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
    pub(crate) fn new(raw: i64) -> Result<Self, InvalidTimelineSeq> {
        NonZeroI64::new(raw)
            .filter(|seq| seq.get() > 0)
            .map(Self)
            .ok_or(InvalidTimelineSeq::NonPositive)
    }

    pub(crate) fn get(self) -> i64 {
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

    pub(crate) fn as_str(&self) -> &str {
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
        assert_eq!(address.gen().as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(address.seq().get(), 42);
        assert_eq!(
            address.body_sha256().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn minted_timeline_address_consumes_minted_generation() {
        let minted = MintedWorldGeneration::test_only_from_entropy_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);

        let address =
            MintedTimelineAddress::new(world(), minted, TimelineSeq::new(7).unwrap(), body_hash());

        assert_eq!(address.world().as_str(), "home/timeline");
        assert_eq!(address.gen().as_str(), "000102030405060708090a0b0c0d0e0f");
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
        ];

        for read in reads {
            match read {
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
                TimelineRead::Body(_) | TimelineRead::Corrupt { .. } => {
                    panic!("unexpected read mode")
                }
            }
        }
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
