//! Process configuration: env-var parsing, default constants,
//! and the small helpers `main()` uses to compose them.
//!
//! Everything here is invoked from `main()` exactly once, at
//! startup. None of these helpers are called per-request -- if a
//! handler ever needs them at request time, that's a code smell
//! (env should be latched into `Core` at startup, not re-read).

use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "coap")]
pub(crate) const DEFAULT_COAP_MAX_IN_FLIGHT: usize = 1024;
#[cfg(not(test))]
pub(crate) use crate::defaults::{
    DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
};
#[cfg(feature = "mqtt")]
pub(crate) const DEFAULT_MQTT_MAX_CONNECTIONS: usize = 1024;
#[cfg(feature = "mqtt")]
pub(crate) const DEFAULT_MQTT_MAX_PENDING_QOS2_BYTES: usize = 1024 * 1024;
#[cfg(feature = "mqtt")]
pub(crate) const DEFAULT_MQTT_CONNECT_TIMEOUT_MS: usize = 3000;
#[cfg(feature = "mqtt")]
pub(crate) const DEFAULT_MQTT_MAX_PREAUTH_PER_IP: usize = 32;

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
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as TestMutex, OnceLock};

    fn env_lock() -> &'static TestMutex<()> {
        static LOCK: OnceLock<TestMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TestMutex::new(()))
    }

    #[cfg(feature = "coap")]
    struct CoapEnvGuard {
        host: Option<String>,
        port: Option<String>,
    }

    #[cfg(feature = "mqtt")]
    struct MqttEnvGuard {
        host: Option<String>,
        port: Option<String>,
    }

    #[cfg(feature = "coap")]
    impl CoapEnvGuard {
        fn capture() -> Self {
            Self {
                host: std::env::var("ELASTIK_COAP_HOST").ok(),
                port: std::env::var("ELASTIK_COAP_PORT").ok(),
            }
        }
    }

    #[cfg(feature = "coap")]
    impl Drop for CoapEnvGuard {
        fn drop(&mut self) {
            match &self.host {
                Some(v) => std::env::set_var("ELASTIK_COAP_HOST", v),
                None => std::env::remove_var("ELASTIK_COAP_HOST"),
            }
            match &self.port {
                Some(v) => std::env::set_var("ELASTIK_COAP_PORT", v),
                None => std::env::remove_var("ELASTIK_COAP_PORT"),
            }
        }
    }

    #[cfg(feature = "mqtt")]
    impl MqttEnvGuard {
        fn capture() -> Self {
            Self {
                host: std::env::var("ELASTIK_MQTT_HOST").ok(),
                port: std::env::var("ELASTIK_MQTT_PORT").ok(),
            }
        }
    }

    #[cfg(feature = "mqtt")]
    impl Drop for MqttEnvGuard {
        fn drop(&mut self) {
            match &self.host {
                Some(v) => std::env::set_var("ELASTIK_MQTT_HOST", v),
                None => std::env::remove_var("ELASTIK_MQTT_HOST"),
            }
            match &self.port {
                Some(v) => std::env::set_var("ELASTIK_MQTT_PORT", v),
                None => std::env::remove_var("ELASTIK_MQTT_PORT"),
            }
        }
    }

    #[test]
    fn hmac_key_requires_nonempty_semantic_content() {
        assert!(hmac_key_from_env_value(None).is_none());
        assert!(hmac_key_from_env_value(Some(String::new())).is_none());
        assert!(hmac_key_from_env_value(Some(" \t\n".to_string())).is_none());
        assert_eq!(
            hmac_key_from_env_value(Some(" secret ".to_string())).unwrap(),
            b" secret ".to_vec()
        );
    }

    #[test]
    fn resource_cap_env_zero_falls_back_to_default() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("ELASTIK_TEST_ZERO_CAP_{}", std::process::id());
        std::env::set_var(&key, "0");
        assert_eq!(env_nonzero_usize(&key, 7), 7);
        std::env::set_var(&key, "9");
        assert_eq!(env_nonzero_usize(&key, 7), 9);
        std::env::remove_var(&key);
    }

    #[test]
    fn optional_storage_quota_zero_is_unlimited() {
        let _guard = env_lock().lock().unwrap();
        let key = format!("ELASTIK_TEST_STORAGE_CAP_{}", std::process::id());
        std::env::remove_var(&key);
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, " \t ");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "0");
        assert_eq!(env_optional_usize(&key), None);
        std::env::set_var(&key, "11");
        assert_eq!(env_optional_usize(&key), Some(11));
        std::env::set_var(&key, "10GB");
        assert!(std::panic::catch_unwind(|| env_optional_usize(&key)).is_err());
        std::env::remove_var(&key);
    }

    #[test]
    fn listen_addr_brackets_ipv6_hosts() {
        assert_eq!(listen_addr("127.0.0.1", 3105), "127.0.0.1:3105");
        assert_eq!(listen_addr("0.0.0.0", 3105), "0.0.0.0:3105");
        assert_eq!(listen_addr("::1", 3105), "[::1]:3105");
        assert_eq!(listen_addr("localhost", 3105), "localhost:3105");
    }

    #[cfg(feature = "coap")]
    #[test]
    fn coap_bind_is_opt_in_by_port_env() {
        let _lock = env_lock().lock().unwrap();
        let _guard = CoapEnvGuard::capture();
        std::env::remove_var("ELASTIK_COAP_HOST");
        std::env::remove_var("ELASTIK_COAP_PORT");

        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_HOST", "0.0.0.0");
        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_PORT", "5683");
        assert_eq!(coap_bind_from_env(), Some(("0.0.0.0".to_owned(), 5683)));

        std::env::set_var("ELASTIK_COAP_HOST", "127.0.0.1");
        std::env::set_var("ELASTIK_COAP_PORT", " ");
        assert_eq!(coap_bind_from_env(), None);

        std::env::set_var("ELASTIK_COAP_PORT", "not-a-port");
        assert_eq!(coap_bind_from_env(), None);
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn mqtt_bind_defaults_to_port_1883_and_can_be_disabled() {
        let _lock = env_lock().lock().unwrap();
        let _guard = MqttEnvGuard::capture();
        std::env::remove_var("ELASTIK_MQTT_HOST");
        std::env::remove_var("ELASTIK_MQTT_PORT");

        assert_eq!(
            mqtt_bind_from_env("127.0.0.1"),
            Some(("127.0.0.1".to_owned(), 1883))
        );

        std::env::set_var("ELASTIK_MQTT_HOST", "0.0.0.0");
        std::env::set_var("ELASTIK_MQTT_PORT", "1884");
        assert_eq!(
            mqtt_bind_from_env("127.0.0.1"),
            Some(("0.0.0.0".to_owned(), 1884))
        );

        std::env::set_var("ELASTIK_MQTT_PORT", "0");
        assert_eq!(mqtt_bind_from_env("127.0.0.1"), None);

        std::env::set_var("ELASTIK_MQTT_PORT", "not-a-port");
        assert_eq!(mqtt_bind_from_env("127.0.0.1"), None);
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn mqtt_packet_default_tracks_runtime_world_limit() {
        assert_eq!(mqtt_max_packet_default(4096), 5120);
        assert_eq!(mqtt_max_packet_default(usize::MAX), usize::MAX);
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
