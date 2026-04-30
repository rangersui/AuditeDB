//! Bearer + Basic auth check. Three tokens, three tiers:
//!   ELASTIK_READ_TOKEN     -> tier "read"    (T1: reads when enabled)
//!   ELASTIK_TOKEN          → tier "auth"    (T2: writes /home/*)
//!   ELASTIK_APPROVE_TOKEN  → tier "approve" (T3: writes /lib/, /etc/)
//!
//! Constant-time comparison via hmac::digest::CtOutput. UTF-8 bytes on
//! both sides — non-ASCII passwords don't crash, and the core does not
//! depend on any SDK/runtime language to make auth decisions.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Anon,
    Read,
    Auth,
    Approve,
}

#[derive(Clone)]
pub struct Tokens {
    pub read: Option<Vec<u8>>,
    pub auth: Option<Vec<u8>>,
    pub approve: Option<Vec<u8>>,
}

impl Tokens {
    /// Read tokens from env. Empty / whitespace-only values are
    /// treated as **unset** — never as "the empty token is valid."
    /// A `.env` with `ELASTIK_TOKEN=` (placeholder unfilled) must not
    /// silently grant T2 to anyone sending `Authorization: Bearer `.
    pub fn from_env() -> Self {
        Self {
            read: nonempty_env("ELASTIK_READ_TOKEN"),
            auth: nonempty_env("ELASTIK_TOKEN"),
            approve: nonempty_env("ELASTIK_APPROVE_TOKEN"),
        }
    }

    pub fn read_required(&self) -> bool {
        self.read.is_some()
    }

    /// Resolve the request's tier from an Authorization header.
    /// Empty / missing / unrecognized → Anon. Loopback callers may
    /// short-circuit to Anon and let the protocol layer rule.
    pub fn check(&self, authorization: Option<&str>) -> Tier {
        let Some(value) = authorization else {
            return Tier::Anon;
        };
        if let Some(rest) = value.strip_prefix("Bearer ") {
            return self.check_token(rest.as_bytes());
        }
        if let Some(rest) = value.strip_prefix("Basic ") {
            if let Ok(decoded) = B64.decode(rest.trim()) {
                if let Some(idx) = decoded.iter().position(|&b| b == b':') {
                    return self.check_token(&decoded[idx + 1..]);
                }
            }
        }
        Tier::Anon
    }

    fn check_token(&self, candidate: &[u8]) -> Tier {
        // Defense in depth: even if a configured token is somehow
        // empty (config drift, test fixture, future cap-token bug),
        // never let a zero-length candidate match. The empty string
        // is not a credential.
        if candidate.is_empty() {
            return Tier::Anon;
        }
        // Approve first — wins ties because it's the wider tier.
        if let Some(t) = &self.approve {
            if ct_eq(candidate, t) {
                return Tier::Approve;
            }
        }
        if let Some(t) = &self.auth {
            if ct_eq(candidate, t) {
                return Tier::Auth;
            }
        }
        if let Some(t) = &self.read {
            if ct_eq(candidate, t) {
                return Tier::Read;
            }
        }
        Tier::Anon
    }
}

fn nonempty_env(name: &str) -> Option<Vec<u8>> {
    match std::env::var(name) {
        Ok(s) if !s.trim().is_empty() => Some(s.into_bytes()),
        _ => None,
    }
}

/// True if `name` is set in the environment but holds an empty or
/// whitespace-only string. Used by main.rs to print a startup warning
/// — the user almost certainly meant "disabled," and we treated it as
/// such, but they should know their `.env` placeholder is still bare.
pub fn env_set_but_empty(name: &str) -> bool {
    match std::env::var(name) {
        Ok(s) => s.trim().is_empty(),
        Err(_) => false,
    }
}

/// Constant-time byte equality. Manual loop — avoids pulling `subtle`
/// for one operation. Length differences leak via early-return, which
/// is fine for token compare (the length space is public).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        read: Option<String>,
        token: Option<String>,
        approve: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                read: std::env::var("ELASTIK_READ_TOKEN").ok(),
                token: std::env::var("ELASTIK_TOKEN").ok(),
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
            match &self.token {
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
        std::env::set_var("ELASTIK_TOKEN", "");
        std::env::set_var("ELASTIK_APPROVE_TOKEN", "   ");

        let tokens = Tokens::from_env();

        assert_eq!(tokens.read, None);
        assert_eq!(tokens.auth, None);
        assert_eq!(tokens.approve, None);
        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
        assert_eq!(tokens.check(Some("Basic Og==")), Tier::Anon);
        assert!(env_set_but_empty("ELASTIK_READ_TOKEN"));
        assert!(env_set_but_empty("ELASTIK_TOKEN"));
        assert!(env_set_but_empty("ELASTIK_APPROVE_TOKEN"));
    }

    #[test]
    fn empty_authorization_candidate_never_matches() {
        let tokens = Tokens {
            read: Some(Vec::new()),
            auth: Some(Vec::new()),
            approve: Some(Vec::new()),
        };

        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
        assert_eq!(tokens.check(Some("Basic Og==")), Tier::Anon);
    }

    #[test]
    fn nonempty_tokens_still_authenticate() {
        let tokens = Tokens {
            read: Some(b"reader".to_vec()),
            auth: Some(b"writer".to_vec()),
            approve: Some(b"approve".to_vec()),
        };
        let basic_writer = B64.encode("user:writer");

        assert_eq!(tokens.check(Some("Bearer reader")), Tier::Read);
        assert_eq!(tokens.check(Some("Bearer writer")), Tier::Auth);
        assert_eq!(
            tokens.check(Some(&format!("Basic {basic_writer}"))),
            Tier::Auth
        );
        assert_eq!(tokens.check(Some("Bearer approve")), Tier::Approve);
        assert_eq!(tokens.check(Some("Bearer ")), Tier::Anon);
    }
}
