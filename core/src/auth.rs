//! Bearer + Basic auth check. Two tokens, two tiers:
//!   ELASTIK_TOKEN          → tier "auth"    (T2: writes /home/*)
//!   ELASTIK_APPROVE_TOKEN  → tier "approve" (T3: writes /lib/, /etc/)
//!
//! Constant-time comparison via hmac::digest::CtOutput. UTF-8 bytes on
//! both sides — non-ASCII passwords don't crash here, unlike the Python
//! reference's earlier hmac.compare_digest(str, str) bug.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Anon,
    Auth,
    Approve,
}

#[derive(Clone)]
pub struct Tokens {
    pub auth: Option<Vec<u8>>,
    pub approve: Option<Vec<u8>>,
}

impl Tokens {
    pub fn from_env() -> Self {
        Self {
            auth: std::env::var("ELASTIK_TOKEN").ok().map(Into::into),
            approve: std::env::var("ELASTIK_APPROVE_TOKEN").ok().map(Into::into),
        }
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
        Tier::Anon
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
