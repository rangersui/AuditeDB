//! Process configuration: env-var parsing, default constants,
//! and the small helpers `main()` uses to compose them.
//!
//! Everything here is invoked from `main()` exactly once, at
//! startup. None of these helpers are called per-request -- if a
//! handler ever needs them at request time, that's a code smell
//! (env should be latched into `Core` at startup, not re-read).

use std::net::{IpAddr, SocketAddr};
use std::num::IntErrorKind;

use crate::engine_types::{AuditHmacKey, InvalidHmacKey};

#[cfg(not(test))]
pub(crate) use crate::defaults::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
};

pub(crate) fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    let raw = match std::env::var(name) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{name} must be valid Unicode"));
        }
    };
    parse_usize_env_value(name, &raw, "non-negative integer")
}

pub(crate) fn env_optional_usize(name: &str) -> Result<Option<usize>, String> {
    let raw = match std::env::var(name) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{name} must be valid Unicode"));
        }
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = parse_usize_env_value(name, value, "non-negative integer byte count")?;
    Ok((parsed > 0).then_some(parsed))
}

pub(crate) fn env_nonzero_usize(name: &str, default: usize) -> Result<usize, String> {
    match env_usize(name, default)? {
        0 => Ok(default),
        value => Ok(value),
    }
}

fn parse_usize_env_value(name: &str, raw: &str, expected: &str) -> Result<usize, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("{name} must be a {expected}"));
    }
    match value.parse::<usize>() {
        Ok(value) => Ok(value),
        Err(err) => match err.kind() {
            IntErrorKind::PosOverflow => {
                Err(format!("{name} is too large for usize on this platform"))
            }
            IntErrorKind::Empty
            | IntErrorKind::InvalidDigit
            | IntErrorKind::NegOverflow
            | IntErrorKind::Zero => Err(format!("{name} must be a {expected}")),
            _ => Err(format!("{name} is invalid: {err}")),
        },
    }
}

pub(crate) fn should_warn_public_read(bind_ip: IpAddr, read_required: bool) -> bool {
    !bind_ip.is_loopback() && !read_required
}

pub(crate) fn listen_addr(host: &str, port: u16) -> String {
    host.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .unwrap_or_else(|_| format!("{host}:{port}"))
}

pub(crate) fn hmac_key_from_env_value(
    value: Option<String>,
) -> Result<Option<AuditHmacKey>, InvalidHmacKey> {
    value.map(|s| AuditHmacKey::new(s.into_bytes())).transpose()
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::{Mutex as TestMutex, OnceLock};

    fn env_lock() -> &'static TestMutex<()> {
        static LOCK: OnceLock<TestMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TestMutex::new(()))
    }

    #[test]
    fn hmac_key_requires_nonempty_semantic_content() {
        assert!(matches!(hmac_key_from_env_value(None), Ok(None)));
        assert!(matches!(
            hmac_key_from_env_value(Some(String::new())),
            Err(InvalidHmacKey::Empty(_))
        ));
        assert!(matches!(
            hmac_key_from_env_value(Some(" \t\n".to_string())),
            Err(InvalidHmacKey::Empty(_))
        ));
        assert!(matches!(
            hmac_key_from_env_value(Some("short".to_string())),
            Err(InvalidHmacKey::TooShort { actual: 5, .. })
        ));
        assert!(matches!(
            hmac_key_from_env_value(Some("0123456789abcdef0123456789abcdef".to_string())),
            Ok(Some(_))
        ));
    }

    #[test]
    fn resource_cap_env_zero_falls_back_to_default() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("AUDITEDB_TEST_ZERO_CAP_{}", std::process::id());
        std::env::set_var(&key, "0");
        assert_eq!(env_nonzero_usize(&key, 7), Ok(7));
        std::env::set_var(&key, "9");
        assert_eq!(env_nonzero_usize(&key, 7), Ok(9));
        std::env::remove_var(&key);
    }

    #[test]
    fn resource_cap_env_invalid_values_fail_loud() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("AUDITEDB_TEST_INVALID_CAP_{}", std::process::id());
        std::env::remove_var(&key);
        assert_eq!(env_usize(&key, 7), Ok(7));
        std::env::set_var(&key, "11");
        assert_eq!(env_usize(&key, 7), Ok(11));
        std::env::set_var(&key, "");
        assert_eq!(
            env_usize(&key, 7),
            Err(format!("{key} must be a non-negative integer"))
        );
        std::env::set_var(&key, "10GB");
        assert_eq!(
            env_nonzero_usize(&key, 7),
            Err(format!("{key} must be a non-negative integer"))
        );
        std::env::set_var(&key, "18446744073709551616");
        assert_eq!(
            env_usize(&key, 7),
            Err(format!("{key} is too large for usize on this platform"))
        );
        std::env::remove_var(&key);
    }

    #[test]
    fn optional_storage_quota_zero_is_unlimited() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("AUDITEDB_TEST_STORAGE_CAP_{}", std::process::id());
        std::env::remove_var(&key);
        assert_eq!(env_optional_usize(&key), Ok(None));
        std::env::set_var(&key, "");
        assert_eq!(env_optional_usize(&key), Ok(None));
        std::env::set_var(&key, " \t ");
        assert_eq!(env_optional_usize(&key), Ok(None));
        std::env::set_var(&key, "0");
        assert_eq!(env_optional_usize(&key), Ok(None));
        std::env::set_var(&key, "11");
        assert_eq!(env_optional_usize(&key), Ok(Some(11)));
        std::env::set_var(&key, "10GB");
        assert_eq!(
            env_optional_usize(&key),
            Err(format!("{key} must be a non-negative integer byte count"))
        );
        std::env::set_var(&key, "18446744073709551616");
        assert_eq!(
            env_optional_usize(&key),
            Err(format!("{key} is too large for usize on this platform"))
        );
        std::env::remove_var(&key);
    }

    #[test]
    fn listen_addr_brackets_ipv6_hosts() {
        assert_eq!(listen_addr("127.0.0.1", 3105), "127.0.0.1:3105");
        assert_eq!(listen_addr("0.0.0.0", 3105), "0.0.0.0:3105");
        assert_eq!(listen_addr("::1", 3105), "[::1]:3105");
        assert_eq!(listen_addr("localhost", 3105), "localhost:3105");
    }

    #[test]
    fn non_loopback_public_read_gets_warning_flag() {
        assert!(!should_warn_public_read(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            false
        ));
        assert!(should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            false
        ));

        assert!(!should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            true
        ));
    }
}
