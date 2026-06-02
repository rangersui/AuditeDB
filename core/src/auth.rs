//! Bearer + Basic auth check. Three tokens, three tiers:
//!   ELASTIK_READ_TOKEN     -> tier "read"    (T1: reads when enabled)
//!   ELASTIK_WRITE_TOKEN    -> tier "write"   (T2: writes /home/*)
//!   ELASTIK_APPROVE_TOKEN  -> tier "approve" (T3: writes /lib/, /etc/)
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

#[cfg(test)]
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[cfg(test)]
const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;

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
    /// Read tokens from env. Empty / whitespace-only values are
    /// treated as **unset** — never as "the empty token is valid."
    /// A `.env` with `ELASTIK_WRITE_TOKEN=` (placeholder unfilled) must not
    /// silently grant T2 to anyone sending `Authorization: Bearer `.
    #[cfg(test)]
    pub fn from_env() -> Self {
        Self {
            read: nonempty_env("ELASTIK_READ_TOKEN"),
            write: nonempty_env("ELASTIK_WRITE_TOKEN").or_else(|| nonempty_env("ELASTIK_TOKEN")),
            approve: nonempty_env("ELASTIK_APPROVE_TOKEN"),
        }
    }

    pub fn read_required(&self) -> bool {
        self.read.is_some()
    }

    /// Resolve the request's tier from an Authorization header.
    /// Empty / missing / unrecognized → Anon. Loopback callers may
    /// short-circuit to Anon and let the protocol layer rule.
    #[cfg(test)]
    pub fn check(&self, authorization: Option<&str>) -> Tier {
        let Some(value) = authorization else {
            return Tier::Anon;
        };
        if value.len() > MAX_AUTHORIZATION_BYTES {
            return Tier::Anon;
        }
        let Some((scheme, credentials)) = value.split_once(char::is_whitespace) else {
            return Tier::Anon;
        };
        let credentials = credentials.trim();
        if scheme.eq_ignore_ascii_case("Bearer") {
            return self.check_token_bytes(credentials.as_bytes());
        }
        if scheme.eq_ignore_ascii_case("Basic") {
            if let Ok(decoded) = B64.decode(credentials) {
                if let Some(idx) = decoded.iter().position(|&b| b == b':') {
                    return self.check_token_bytes(&decoded[idx + 1..]);
                }
            }
        }
        Tier::Anon
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

#[cfg(test)]
fn nonempty_env(name: &str) -> Option<NonEmptyBytes> {
    match std::env::var(name) {
        Ok(s) => NonEmptyBytes::new(s.into_bytes()),
        _ => None,
    }
}

/// True if `name` is set in the environment but holds an empty or
/// whitespace-only string. Used by main.rs to print a startup warning
/// — the user almost certainly meant "disabled," and we treated it as
/// such, but they should know their `.env` placeholder is still bare.
#[cfg(test)]
pub fn env_set_but_empty(name: &str) -> bool {
    match std::env::var(name) {
        Ok(s) => s.trim().is_empty(),
        Err(_) => false,
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
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn bearer(token: &str) -> String {
        format!("{} {token}", "Bearer")
    }

    fn token(bytes: &[u8]) -> NonEmptyBytes {
        NonEmptyBytes::new(bytes.to_vec()).unwrap()
    }

    struct EnvGuard {
        read: Option<String>,
        write: Option<String>,
        legacy_write: Option<String>,
        approve: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                read: std::env::var("ELASTIK_READ_TOKEN").ok(),
                write: std::env::var("ELASTIK_WRITE_TOKEN").ok(),
                legacy_write: std::env::var("ELASTIK_TOKEN").ok(),
                approve: std::env::var("ELASTIK_APPROVE_TOKEN").ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.read {
                Some(v) => std::env::set_var("ELASTIK_READ_TOKEN", v),
                None => std::env::remove_var("ELASTIK_READ_TOKEN"),
            }
            match &self.write {
                Some(v) => std::env::set_var("ELASTIK_WRITE_TOKEN", v),
                None => std::env::remove_var("ELASTIK_WRITE_TOKEN"),
            }
            match &self.legacy_write {
                Some(v) => std::env::set_var("ELASTIK_TOKEN", v),
                None => std::env::remove_var("ELASTIK_TOKEN"),
            }
            match &self.approve {
                Some(v) => std::env::set_var("ELASTIK_APPROVE_TOKEN", v),
                None => std::env::remove_var("ELASTIK_APPROVE_TOKEN"),
            }
        }
    }

    #[test]
    fn from_env_treats_empty_tokens_as_disabled() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvGuard::capture();
        std::env::set_var("ELASTIK_READ_TOKEN", " ");
        std::env::set_var("ELASTIK_WRITE_TOKEN", "");
        std::env::remove_var("ELASTIK_TOKEN");
        std::env::set_var("ELASTIK_APPROVE_TOKEN", "\u{2003}\n");

        let tokens = Tokens::from_env();

        assert!(tokens.read.is_none());
        assert!(tokens.write.is_none());
        assert!(tokens.approve.is_none());
        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
        assert_eq!(tokens.check(Some("Basic Og==")), Tier::Anon);
        assert!(env_set_but_empty("ELASTIK_READ_TOKEN"));
        assert!(env_set_but_empty("ELASTIK_WRITE_TOKEN"));
        assert!(env_set_but_empty("ELASTIK_APPROVE_TOKEN"));
    }

    #[test]
    fn legacy_elastik_token_is_a_write_token_fallback() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvGuard::capture();
        std::env::remove_var("ELASTIK_WRITE_TOKEN");
        std::env::set_var("ELASTIK_TOKEN", "legacy-writer");

        let tokens = Tokens::from_env();

        assert_eq!(tokens.check(Some(&bearer("legacy-writer"))), Tier::Write);
    }

    #[test]
    fn invalid_authorization_candidates_never_match() {
        let tokens = Tokens {
            read: Some(token(b"reader")),
            write: Some(token(b"writer")),
            approve: Some(token(b"approve")),
        };

        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
        assert_eq!(tokens.check(Some("Bearer \t\r\n")), Tier::Anon);
        assert_eq!(tokens.check(Some(&bearer("\u{2003}"))), Tier::Anon);
        assert_eq!(tokens.check(Some("Basic Og==")), Tier::Anon);
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
    fn oversized_authorization_header_is_anon() {
        let tokens = Tokens {
            read: Some(token(b"reader")),
            write: Some(token(b"writer")),
            approve: Some(token(b"approve")),
        };
        let header = format!("Bearer {}", "x".repeat(MAX_AUTHORIZATION_BYTES));

        assert_eq!(tokens.check(Some(&header)), Tier::Anon);
    }

    #[test]
    fn nonempty_tokens_still_authenticate() {
        let tokens = Tokens {
            read: Some(token(b"reader")),
            write: Some(token(b"writer")),
            approve: Some(token(b"approve")),
        };
        let basic_writer = B64.encode("user:writer");

        assert_eq!(tokens.check(Some(&bearer("reader"))), Tier::Read);
        assert_eq!(tokens.check(Some("bearer reader")), Tier::Read);
        assert_eq!(tokens.check(Some(&bearer("writer"))), Tier::Write);
        assert_eq!(
            tokens.check(Some(&format!("Basic {basic_writer}"))),
            Tier::Write
        );
        assert_eq!(
            tokens.check(Some(&format!("basic {basic_writer}"))),
            Tier::Write
        );
        assert_eq!(tokens.check(Some(&bearer("approve"))), Tier::Approve);
        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
    }
}
