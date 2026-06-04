//! Raw token-byte auth check. Three optional configured token values map to
//! read, write, and approve tiers; adapters decide how bytes arrive on their
//! wire surface.
//!
//! Token comparison uses a small local byte loop that avoids early exit
//! once lengths match. UTF-8 bytes on both sides — non-ASCII passwords
//! don't crash, and the core does not depend on any SDK/runtime language
//! to make auth decisions.

use std::{
    fmt,
    hint::black_box,
    ptr,
    sync::atomic::{fence, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Anon,
    Read,
    Write,
    Approve,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthGate {
    Read,
    Write,
    WriteApprove,
    Delete,
}

#[derive(Clone)]
pub struct Tokens {
    pub(crate) read: Option<NonEmptyBytes>,
    pub(crate) write: Option<NonEmptyBytes>,
    pub(crate) approve: Option<NonEmptyBytes>,
}

/// Byte credential proof: empty and whitespace-only values cannot exist.
///
/// The constructor is the only way to mint this type. Callers can compare or
/// transfer the bytes, but cannot construct a value with a struct literal.
#[derive(Clone)]
pub(crate) struct NonEmptyBytes(Vec<u8>);

impl NonEmptyBytes {
    pub(crate) fn new(bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        Self::is_valid(&bytes).then_some(Self(bytes))
    }

    pub(crate) fn is_valid(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && std::str::from_utf8(bytes)
                .map(|value| !value.trim().is_empty())
                .unwrap_or(true)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Returns true when raw token bytes can represent a configured or candidate
/// Engine token.
///
/// Empty and UTF-8 whitespace-only values are invalid. Non-UTF-8 bytes are
/// allowed so language runtimes can pass opaque credential bytes without
/// losing information.
pub fn is_valid_token(bytes: &[u8]) -> bool {
    NonEmptyBytes::is_valid(bytes)
}

impl Drop for NonEmptyBytes {
    fn drop(&mut self) {
        wipe_vec_allocation(&mut self.0);
    }
}

impl fmt::Debug for NonEmptyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NonEmptyBytes(..)")
    }
}

fn wipe_vec_allocation(bytes: &mut Vec<u8>) {
    // These bytes are credentials. Wipe the full allocation, not only len(),
    // because callers can hand us a Vec whose spare capacity still contains
    // prior credential bytes after truncate/reuse. Volatile writes plus a
    // fence make the best-effort wipe physically observable before free.
    let ptr = bytes.as_mut_ptr();
    for index in 0..bytes.capacity() {
        unsafe {
            ptr::write_volatile(ptr.add(index), 0);
        }
    }
    fence(Ordering::SeqCst);
}

impl Tokens {
    pub fn read_required(&self) -> bool {
        self.read.is_some()
    }

    pub(crate) fn check_token_bytes(&self, candidate: &[u8]) -> Tier {
        // Candidate credentials go through the same byte validity gate as
        // configured tokens. Invalid values are physically unable to match.
        if !NonEmptyBytes::is_valid(candidate) {
            return Tier::Anon;
        }
        // Approve first — wins ties because it's the wider tier.
        if let Some(t) = &self.approve {
            if ct_eq(candidate, t.as_slice()) {
                return Tier::Approve;
            }
        }
        if let Some(t) = &self.write {
            if ct_eq(candidate, t.as_slice()) {
                return Tier::Write;
            }
        }
        if let Some(t) = &self.read {
            if ct_eq(candidate, t.as_slice()) {
                return Tier::Read;
            }
        }
        Tier::Anon
    }
}

/// Equal-length byte comparison without early exit.
///
/// `auth.rs` deliberately keeps credential parsing, validation, comparison,
/// and wipe-on-drop on `std` primitives only. `subtle` is already present
/// through RustCrypto, but this small auth boundary stays locally auditable:
/// length mismatches return early, and equal-length token bytes are compared
/// by XOR accumulation without per-byte early return. The final `black_box`
/// keeps the result comparison visibly tied to the accumulated byte work.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{can_delete, can_read, can_write, test_support::test_core};

    fn token(bytes: &[u8]) -> NonEmptyBytes {
        NonEmptyBytes::new(bytes.to_vec()).unwrap()
    }

    #[test]
    fn invalid_token_candidates_never_match() {
        let tokens = Tokens {
            read: Some(token(b"reader")),
            write: Some(token(b"writer")),
            approve: Some(token(b"approve")),
        };

        assert_eq!(tokens.check_token_bytes(b""), Tier::Anon);
        assert_eq!(tokens.check_token_bytes(b" \t\r\n"), Tier::Anon);
        assert_eq!(tokens.check_token_bytes("\u{2003}".as_bytes()), Tier::Anon);
    }

    #[test]
    fn var_log_requires_approve_token() {
        assert!(!can_write("var/log", Tier::Anon));
        assert!(!can_write("var/log", Tier::Read));
        assert!(!can_write("var/log", Tier::Write));
        assert!(can_write("var/log", Tier::Approve));
        assert!(!can_write("var/log/deletes", Tier::Anon));
        assert!(!can_write("var/log/deletes", Tier::Read));
        assert!(!can_write("var/log/deletes", Tier::Write));
        assert!(can_write("var/log/deletes", Tier::Approve));
    }

    #[test]
    fn delete_requires_approve_token() {
        assert!(!can_delete(Tier::Anon));
        assert!(!can_delete(Tier::Read));
        assert!(!can_delete(Tier::Write));
        assert!(can_delete(Tier::Approve));
    }

    #[test]
    fn system_namespace_roots_require_approve_even_if_called_directly() {
        for name in ["lib", "etc", "boot", "usr"] {
            assert!(!can_write(name, Tier::Anon), "{name}");
            assert!(!can_write(name, Tier::Read), "{name}");
            assert!(!can_write(name, Tier::Write), "{name}");
            assert!(can_write(name, Tier::Approve), "{name}");
        }
    }

    #[test]
    fn non_log_var_still_accepts_auth_token() {
        assert!(!can_write("var/cache/rag", Tier::Anon));
        assert!(!can_write("var/cache/rag", Tier::Read));
        assert!(can_write("var/cache/rag", Tier::Write));
        assert!(can_write("var/cache/rag", Tier::Approve));
    }

    #[test]
    fn read_token_is_optional_but_gates_reads_when_set() {
        let (mut core, dir) = test_core("read-token");
        assert!(can_read(&core, Tier::Anon));

        core.tokens.read = NonEmptyBytes::new(b"reader".to_vec());
        assert!(!can_read(&core, Tier::Anon));
        assert!(can_read(&core, Tier::Read));
        assert!(can_read(&core, Tier::Write));
        assert!(can_read(&core, Tier::Approve));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn public_token_validity_matches_core_token_gate() {
        assert!(is_valid_token(b"reader"));
        assert!(is_valid_token(&[0xff, 0xfe]));
        assert!(!is_valid_token(b""));
        assert!(!is_valid_token(b" \t\r\n"));
    }

    #[test]
    fn wipe_vec_allocation_clears_spare_capacity() {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(b"key");
        let ptr = bytes.as_mut_ptr();
        let cap = bytes.capacity();
        unsafe {
            for index in bytes.len()..cap {
                ptr.add(index).write(b'x');
            }
        }

        wipe_vec_allocation(&mut bytes);

        unsafe {
            bytes.set_len(cap);
        }
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn nonempty_raw_tokens_still_authenticate() {
        let tokens = Tokens {
            read: Some(token(b"reader")),
            write: Some(token(b"writer")),
            approve: Some(token(b"approve")),
        };

        assert_eq!(tokens.check_token_bytes(b"reader"), Tier::Read);
        assert_eq!(tokens.check_token_bytes(b"writer"), Tier::Write);
        assert_eq!(tokens.check_token_bytes(b"approve"), Tier::Approve);
        assert_eq!(tokens.check_token_bytes(b"missing"), Tier::Anon);
    }
}
