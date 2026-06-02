//! Process configuration: env-var parsing, default constants,
//! and the small helpers `main()` uses to compose them.
//!
//! Everything here is invoked from `main()` exactly once, at
//! startup. None of these helpers are called per-request -- if a
//! handler ever needs them at request time, that's a code smell
//! (env should be latched into `Core` at startup, not re-read).

use std::net::{IpAddr, SocketAddr};

#[cfg(all(not(test), feature = "coap"))]
pub(crate) use crate::defaults::DEFAULT_COAP_MAX_IN_FLIGHT;
#[cfg(not(test))]
pub(crate) use crate::defaults::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
};
#[cfg(all(not(test), feature = "mqtt"))]
pub(crate) use crate::defaults::{
    DEFAULT_MQTT_CONNECT_TIMEOUT_MS, DEFAULT_MQTT_MAX_CONNECTIONS,
    DEFAULT_MQTT_MAX_PENDING_QOS2_BYTES, DEFAULT_MQTT_MAX_PREAUTH_PER_IP,
};

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

#[cfg(feature = "mqtt")]
pub(crate) fn mqtt_max_packet_default(max_world_bytes: usize) -> usize {
    max_world_bytes.saturating_add(1024)
}

/// Parse `ELASTIK_PERSIST_HEADERS` into the user-configured
/// allowlist (Layer 3 of the persist policy). Comma-separated;
/// trailing `*` = prefix match. See
/// `crate::server::http::semantics::HeaderAllowlist` for the matching
/// semantics. An unset, empty, or all-whitespace value yields
/// `HeaderAllowlist::empty()`, which means "no custom headers
/// beyond the built-in default-allow set."
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn header_allowlist_from_env() -> crate::server::http::semantics::HeaderAllowlist {
    let raw = std::env::var("ELASTIK_PERSIST_HEADERS").unwrap_or_default();
    crate::server::http::semantics::HeaderAllowlist::parse(&raw)
}

/// Parse `ELASTIK_DENY_HEADERS` into the user-configured deny set
/// (Layer 1.5 of the persist policy). Same matcher shape as
/// `header_allowlist_from_env`; lets the operator subtract a
/// header from the built-in `DEFAULT_PERSIST_HEADERS` allow set
/// (e.g. "this deployment doesn't want `cache-control` round-tripping").
/// L1 hard-deny still wins over this; this beats L2 default and L3 allow.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn header_user_deny_from_env() -> crate::server::http::semantics::HeaderAllowlist {
    let raw = std::env::var("ELASTIK_DENY_HEADERS").unwrap_or_default();
    crate::server::http::semantics::HeaderAllowlist::parse(&raw)
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

#[cfg(feature = "mqtt")]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mqtt_bind_from_env(default_host: &str) -> Option<(String, u16)> {
    let raw = std::env::var("ELASTIK_MQTT_PORT").unwrap_or_else(|_| "1883".into());
    let raw = raw.trim();
    if raw.is_empty() || raw == "0" {
        return None;
    }
    let port: u16 = match raw.parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("  warning: invalid ELASTIK_MQTT_PORT={raw:?}; MQTT surface disabled.");
            return None;
        }
    };
    let host = std::env::var("ELASTIK_MQTT_HOST").unwrap_or_else(|_| default_host.to_owned());
    Some((host, port))
}

pub(crate) fn should_warn_public_read(bind_ip: IpAddr, read_required: bool) -> bool {
    !bind_ip.is_loopback() && !read_required
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
