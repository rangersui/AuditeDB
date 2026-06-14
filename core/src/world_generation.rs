//! World incarnation identity for storage addressing.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use rusqlite::types::{ToSql, ToSqlOutput};

/// Local Path 3 invariant: a world generation is a 128-bit identity rendered as
/// 32 lowercase hexadecimal characters.
const WORLD_GEN_HEX_LEN: usize = 32;

/// Durable-world incarnation identity.
///
/// A world generation changes when a durable world is physically deleted and
/// later recreated at the same path. Timeline addresses include the generation
/// so an old address cannot silently resolve against the new world's audit
/// rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldGeneration(String);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MintedWorldGeneration(WorldGeneration);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvalidWorldGeneration {
    WrongLength,
    NotLowerHex,
}

#[derive(Debug)]
pub(crate) enum MintWorldGenerationError {
    Entropy(getrandom::Error),
}

impl WorldGeneration {
    pub(crate) fn mint() -> Result<MintedWorldGeneration, MintWorldGenerationError> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(MintWorldGenerationError::Entropy)?;
        Ok(MintedWorldGeneration(Self(hex::encode(bytes))))
    }

    pub(crate) fn new(raw: impl Into<String>) -> Result<Self, InvalidWorldGeneration> {
        let raw = raw.into();
        if raw.len() != WORLD_GEN_HEX_LEN {
            return Err(InvalidWorldGeneration::WrongLength);
        }
        if !is_lower_hex(&raw) {
            return Err(InvalidWorldGeneration::NotLowerHex);
        }
        Ok(Self(raw))
    }

    /// Returns the lowercase hexadecimal generation identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl MintedWorldGeneration {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[cfg(test)]
    // Deterministic minting bypass for stable assertions only.
    pub(crate) fn test_only_from_entropy_bytes(bytes: [u8; 16]) -> Self {
        Self(WorldGeneration(hex::encode(bytes)))
    }
}

impl ToSql for MintedWorldGeneration {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

impl fmt::Display for MintWorldGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(err) => write!(f, "world generation entropy failed: {err:?}"),
        }
    }
}

impl std::error::Error for MintWorldGenerationError {}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_128_bit_lower_hex() {
        assert!(WorldGeneration::new("0123456789abcdef0123456789abcdef").is_ok());
        assert_eq!(
            WorldGeneration::new("0123456789abcdef0123456789abcde").unwrap_err(),
            InvalidWorldGeneration::WrongLength
        );
        assert_eq!(
            WorldGeneration::new("0123456789abcdef0123456789abcdef0").unwrap_err(),
            InvalidWorldGeneration::WrongLength
        );
        assert_eq!(
            WorldGeneration::new("0123456789abcdef0123456789abcdeF").unwrap_err(),
            InvalidWorldGeneration::NotLowerHex
        );
        assert_eq!(
            WorldGeneration::new("0123456789abcdef0123456789abcdeg").unwrap_err(),
            InvalidWorldGeneration::NotLowerHex
        );
    }

    #[test]
    fn generation_from_entropy_bytes_renders_lower_hex() {
        let minted = MintedWorldGeneration::test_only_from_entropy_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);

        assert_eq!(minted.as_str(), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn mint_generation_preserves_contract_shape() {
        let minted = WorldGeneration::mint().unwrap();

        assert!(WorldGeneration::new(minted.as_str()).is_ok());
    }
}
