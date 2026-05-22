//! Process configuration: env-var parsing, default constants,
//! and the small helpers `main()` uses to compose them.
//!
//! Everything here is invoked from `main()` exactly once, at
//! startup. None of these helpers are called per-request -- if a
//! handler ever needs them at request time, that's a code smell
//! (env should be latched into `Core` at startup, not re-read).

use std::net::{IpAddr, SocketAddr};

use crate::auth;

pub(crate) const DEFAULT_MAX_WORLD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const DEFAULT_LISTEN_REPLAY_MAX: usize = 1024;
pub(crate) const DEFAULT_MAX_LISTEN_CONNECTIONS: usize = 1024;
#[cfg(feature = "coap")]
pub(crate) const DEFAULT_COAP_MAX_IN_FLIGHT: usize = 1024;

pub(crate) fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

pub(crate) fn env_optional_usize(name: &str) -> Option<usize> {
    let Ok(raw) = std::env::var(name) else {
        return None;
    };
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    let parsed = value
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{name} must be a non-negative integer byte count"));
    (parsed > 0).then_some(parsed)
}

pub(crate) fn env_nonzero_usize(name: &str, default: usize) -> usize {
    match env_usize(name, default) {
        0 => default,
        value => value,
    }
}

/// Parse `ELASTIK_PERSIST_HEADERS` into the user-configured
/// allowlist (Layer 3 of the persist policy). Comma-separated;
/// trailing `*` = prefix match. See
/// `crate::http_semantics::HeaderAllowlist` for the matching
/// semantics. An unset, empty, or all-whitespace value yields
/// `HeaderAllowlist::empty()`, which means "no custom headers
/// beyond the built-in default-allow set."
pub(crate) fn header_allowlist_from_env() -> crate::http_semantics::HeaderAllowlist {
    let raw = std::env::var("ELASTIK_PERSIST_HEADERS").unwrap_or_default();
    crate::http_semantics::HeaderAllowlist::parse(&raw)
}

/// Parse `ELASTIK_DENY_HEADERS` into the user-configured deny set
/// (Layer 1.5 of the persist policy). Same matcher shape as
/// `header_allowlist_from_env`; lets the operator subtract a
/// header from the built-in `DEFAULT_PERSIST_HEADERS` allow set
/// (e.g. "this deployment doesn't want `cache-control` round-tripping").
/// L1 hard-deny still wins over this; this beats L2 default and L3 allow.
pub(crate) fn header_user_deny_from_env() -> crate::http_semantics::HeaderAllowlist {
    let raw = std::env::var("ELASTIK_DENY_HEADERS").unwrap_or_default();
    crate::http_semantics::HeaderAllowlist::parse(&raw)
}

#[cfg(feature = "coap")]
pub(crate) fn coap_bind_from_env() -> Option<(String, u16)> {
    let raw = std::env::var("ELASTIK_COAP_PORT").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let port: u16 = match raw.parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("  warning: invalid ELASTIK_COAP_PORT={raw:?}; SCoAP/UDP surface disabled.");
            return None;
        }
    };
    let host = std::env::var("ELASTIK_COAP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    Some((host, port))
}

pub(crate) fn should_warn_public_read(bind_ip: IpAddr, tokens: &auth::Tokens) -> bool {
    !bind_ip.is_loopback() && !tokens.read_required()
}

pub(crate) fn listen_addr(host: &str, port: u16) -> String {
    host.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .unwrap_or_else(|_| format!("{host}:{port}"))
}

pub(crate) fn hmac_key_from_env_value(value: Option<String>) -> Option<Vec<u8>> {
    value
        .filter(|s| !s.trim().is_empty())
        .map(String::into_bytes)
}
