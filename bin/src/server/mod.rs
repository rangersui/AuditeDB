//! Binary/server runtime assembly.
//!
//! Startup constructs the protocol-neutral `Engine` first and keeps HTTP
//! adapter state beside it in `ServerState`.

#[cfg(feature = "coap")]
pub(crate) mod coap;
#[cfg(feature = "coap")]
pub(crate) mod coap_errors;
pub(crate) mod config;
pub(crate) mod handler;
pub(crate) mod http;
pub(crate) mod listen;
pub(crate) mod middleware;
#[cfg(feature = "mqtt")]
pub(crate) mod mqtt;
pub(crate) mod path;
pub(crate) mod pipeline;
pub(crate) mod proc;
pub(crate) mod response;
pub(crate) mod route;
mod state;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_support;
pub(crate) use pipeline::{ErrorReason, Phase, TraceCtx, Verb};
#[cfg(feature = "mqtt")]
pub(crate) use proc::proc_mqtt_metrics;
pub(crate) use proc::{
    proc_audit_verify, proc_df, proc_du, proc_pool, proc_reserved, proc_version, proc_worlds,
    root_hint,
};
pub(crate) use response::*;
pub(crate) use state::ServerState;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const WORLD_ALLOW: &str = "GET, HEAD, PUT, POST, DELETE, OPTIONS";

#[cfg(not(test))]
use std::net::IpAddr;
#[cfg(not(test))]
use std::path::PathBuf;
#[cfg(all(not(test), feature = "mqtt"))]
use std::time::Duration;

#[cfg(not(test))]
use crate::{
    engine::{Engine, EngineBuilder},
    engine_types::AuditHmacKey,
};
#[cfg(all(not(test), feature = "coap"))]
use config::{coap_bind_from_env, DEFAULT_COAP_MAX_IN_FLIGHT};
#[cfg(not(test))]
use config::{
    env_nonzero_usize, env_optional_usize, env_usize, hmac_key_from_env_value, listen_addr,
    should_warn_public_read, DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS,
    DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
};
#[cfg(all(not(test), feature = "mqtt"))]
use config::{
    mqtt_bind_from_env, mqtt_max_packet_default, DEFAULT_MQTT_CONNECT_TIMEOUT_MS,
    DEFAULT_MQTT_MAX_CONNECTIONS, DEFAULT_MQTT_MAX_PENDING_QOS2_BYTES,
    DEFAULT_MQTT_MAX_PREAUTH_PER_IP,
};
#[cfg(not(test))]
use http::semantics::{header_allowlist_from_env, header_user_deny_from_env};

#[cfg(not(test))]
pub(crate) async fn run_from_env() -> Result<(), String> {
    pipeline::init_trace_from_env();

    let host = std::env::var("ELASTIK_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = match std::env::var("ELASTIK_PORT") {
        Ok(raw) => raw
            .parse()
            .map_err(|_| format!("ELASTIK_PORT must be a TCP port number; got {raw:?}"))?,
        Err(std::env::VarError::NotPresent) => 3105,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("ELASTIK_PORT must be valid Unicode".into());
        }
    };
    #[cfg(feature = "coap")]
    let coap_bind = coap_bind_from_env();
    #[cfg(feature = "mqtt")]
    let mqtt_bind = mqtt_bind_from_env(&host);
    #[cfg(feature = "mqtt")]
    let mqtt_metrics = mqtt_bind.as_ref().map(|_| mqtt::MqttMetrics::shared());
    let data = PathBuf::from(std::env::var("ELASTIK_DATA").unwrap_or_else(|_| "./data".into()));
    let max_world_bytes = env_usize("ELASTIK_MAX_WORLD_BYTES", DEFAULT_MAX_WORLD_BYTES)?;
    let max_memory_bytes = env_usize("ELASTIK_MAX_MEMORY_BYTES", DEFAULT_MAX_MEMORY_BYTES)?;
    let max_storage_bytes = env_optional_usize("ELASTIK_MAX_STORAGE_BYTES")?;
    let max_listen_connections = env_nonzero_usize(
        "ELASTIK_MAX_LISTEN_CONNECTIONS",
        DEFAULT_MAX_LISTEN_CONNECTIONS,
    )?;
    let listen_replay_max =
        env_nonzero_usize("ELASTIK_LISTEN_REPLAY_MAX", DEFAULT_LISTEN_REPLAY_MAX)?;
    #[cfg(feature = "coap")]
    let coap_max_in_flight =
        env_nonzero_usize("ELASTIK_COAP_MAX_IN_FLIGHT", DEFAULT_COAP_MAX_IN_FLIGHT)?;
    #[cfg(feature = "mqtt")]
    let mqtt_max_packet_bytes = env_nonzero_usize(
        "ELASTIK_MQTT_MAX_PACKET_BYTES",
        mqtt_max_packet_default(max_world_bytes),
    )?;
    #[cfg(feature = "mqtt")]
    let mqtt_max_connections =
        env_nonzero_usize("ELASTIK_MQTT_MAX_CONNECTIONS", DEFAULT_MQTT_MAX_CONNECTIONS)?;
    #[cfg(feature = "mqtt")]
    let mqtt_max_pending_qos2_bytes = env_nonzero_usize(
        "ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES",
        DEFAULT_MQTT_MAX_PENDING_QOS2_BYTES,
    )?;
    #[cfg(feature = "mqtt")]
    let mqtt_connect_timeout_ms = env_nonzero_usize(
        "ELASTIK_MQTT_CONNECT_TIMEOUT_MS",
        DEFAULT_MQTT_CONNECT_TIMEOUT_MS,
    )?;
    #[cfg(feature = "mqtt")]
    let mqtt_max_preauth_per_ip = env_nonzero_usize(
        "ELASTIK_MQTT_MAX_PREAUTH_PER_IP",
        DEFAULT_MQTT_MAX_PREAUTH_PER_IP,
    )?;
    let read_cache_max_entries = env_nonzero_usize(
        "ELASTIK_READ_CACHE_MAX_ENTRIES",
        DEFAULT_READ_CACHE_MAX_ENTRIES,
    )?;
    let raw_hmac_key = match std::env::var("ELASTIK_KEY") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("ELASTIK_KEY is invalid: value is not valid Unicode".into());
        }
    };
    let hmac_key = match hmac_key_from_env_value(raw_hmac_key) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Err(
                "ELASTIK_KEY is required; the audit chain has no meaning without it".into(),
            );
        }
        Err(err) => return Err(format!("ELASTIK_KEY is invalid: {err}")),
    };
    let tokens = ServerTokens::from_env();
    let persist_header_allowlist = header_allowlist_from_env();
    let persist_header_user_deny = header_user_deny_from_env();
    let engine = build_engine_from_env(
        data,
        hmac_key,
        &tokens,
        EngineLimits {
            max_world_bytes,
            max_memory_bytes,
            max_storage_bytes,
            max_listen_connections,
            listen_replay_max,
            read_cache_max_entries,
        },
    )?;
    let state = ServerState::new(
        engine.clone(),
        max_world_bytes,
        persist_header_allowlist,
        persist_header_user_deny,
    );
    #[cfg(feature = "mqtt")]
    let state = if let Some(metrics) = mqtt_metrics.clone() {
        state.with_mqtt_metrics(metrics)
    } else {
        state
    };

    let addr = listen_addr(&host, port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|err| format!("bind {addr} failed: {err}"))?;
    let bind_ip = listener
        .local_addr()
        .map(|addr| addr.ip())
        .unwrap_or_else(|_| IpAddr::from([127, 0, 0, 1]));
    eprintln!("elastik-core v{VERSION} on http://{addr}/");
    print_auth_summary(&tokens, bind_ip);
    #[cfg(feature = "coap")]
    if let Some((coap_host, coap_port)) = coap_bind {
        let coap_addr = listen_addr(&coap_host, coap_port);
        let coap_engine = engine.clone();
        let coap_shutdown = coap_engine.shutdown_receiver();
        tokio::spawn(async move {
            coap::serve(coap_engine, coap_addr, coap_shutdown, coap_max_in_flight).await;
        });
    }
    #[cfg(feature = "mqtt")]
    if let Some((mqtt_host, mqtt_port)) = mqtt_bind {
        let mqtt_addr = listen_addr(&mqtt_host, mqtt_port);
        if mqtt_host
            .parse::<IpAddr>()
            .map(|ip| !ip.is_loopback())
            .unwrap_or(false)
        {
            eprintln!(
                "  WARNING: MQTT listens on non-loopback {mqtt_host}:{mqtt_port} without built-in TLS; terminate TLS before exposing it."
            );
        }
        let mqtt_engine = engine.clone();
        let mqtt_shutdown = mqtt_engine.shutdown_receiver();
        let Some(mqtt_metrics) = mqtt_metrics.clone() else {
            return Err(
                "internal error: MQTT metrics missing while MQTT bind is configured".into(),
            );
        };
        tokio::spawn(async move {
            mqtt::serve(
                mqtt_engine,
                mqtt_addr,
                mqtt_shutdown,
                mqtt::MqttServeConfig {
                    max_packet_bytes: mqtt_max_packet_bytes,
                    max_connections: mqtt_max_connections,
                    max_pending_qos2_bytes: mqtt_max_pending_qos2_bytes,
                    connect_timeout: Duration::from_millis(mqtt_connect_timeout_ms as u64),
                    max_preauth_per_ip: mqtt_max_preauth_per_ip,
                },
                mqtt_metrics,
            )
            .await;
        });
    }
    let app = route::build_app(state);

    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(engine.clone()))
        .await;
    serve_result.map_err(|err| format!("axum server failed: {err}"))?;
    drop(engine);
    Ok(())
}

#[cfg(not(test))]
struct EngineLimits {
    max_world_bytes: usize,
    max_memory_bytes: usize,
    max_storage_bytes: Option<usize>,
    max_listen_connections: usize,
    listen_replay_max: usize,
    read_cache_max_entries: usize,
}

#[cfg(not(test))]
struct ServerTokens {
    read: Option<Vec<u8>>,
    write: Option<Vec<u8>>,
    approve: Option<Vec<u8>>,
}

#[cfg(not(test))]
impl ServerTokens {
    fn from_env() -> Self {
        Self {
            read: nonempty_env("ELASTIK_READ_TOKEN"),
            write: nonempty_env("ELASTIK_WRITE_TOKEN").or_else(|| nonempty_env("ELASTIK_TOKEN")),
            approve: nonempty_env("ELASTIK_APPROVE_TOKEN"),
        }
    }

    fn read_required(&self) -> bool {
        self.read.is_some()
    }
}

#[cfg(not(test))]
fn build_engine_from_env(
    data: PathBuf,
    hmac_key: AuditHmacKey,
    tokens: &ServerTokens,
    limits: EngineLimits,
) -> Result<Engine, String> {
    let builder = Engine::builder()
        .data_root(data)
        .key(hmac_key)
        .max_world_bytes(limits.max_world_bytes)
        .max_memory_bytes(limits.max_memory_bytes)
        .max_storage_bytes(limits.max_storage_bytes)
        .max_listen_connections(limits.max_listen_connections)
        .listen_replay_max(limits.listen_replay_max)
        .read_cache_max_entries(limits.read_cache_max_entries);
    configure_tokens(builder, tokens)
        .build()
        .map_err(|err| format!("build Engine failed: {err}"))
}

#[cfg(not(test))]
fn configure_tokens(mut builder: EngineBuilder, tokens: &ServerTokens) -> EngineBuilder {
    if let Some(token) = &tokens.read {
        builder = builder.read_token(token.clone());
    }
    if let Some(token) = &tokens.write {
        builder = builder.write_token(token.clone());
    }
    if let Some(token) = &tokens.approve {
        builder = builder.approve_token(token.clone());
    }
    builder
}

#[cfg(not(test))]
fn print_auth_summary(tokens: &ServerTokens, bind_ip: IpAddr) {
    eprintln!("auth:");
    eprintln!(
        "  read:    {}",
        if tokens.read_required() {
            "token required"
        } else {
            "public (ELASTIK_READ_TOKEN not set)"
        }
    );
    eprintln!(
        "  write:   {}",
        if tokens.write.is_some() {
            "token required"
        } else {
            "disabled (ELASTIK_WRITE_TOKEN not set)"
        }
    );
    eprintln!(
        "  approve: {}",
        if tokens.approve.is_some() {
            "token required"
        } else {
            "disabled (ELASTIK_APPROVE_TOKEN not set)"
        }
    );
    if env_set_but_empty("ELASTIK_READ_TOKEN") {
        eprintln!("  warning: empty ELASTIK_READ_TOKEN treated as unset (reads public)");
    }
    if should_warn_public_read(bind_ip, tokens.read_required()) {
        eprintln!(
            "  WARNING: reads are public on non-loopback interface {bind_ip}; set ELASTIK_READ_TOKEN to gate reads."
        );
    }
    if env_set_but_empty("ELASTIK_WRITE_TOKEN") {
        eprintln!("  warning: empty ELASTIK_WRITE_TOKEN treated as unset (PUT/POST disabled)");
    }
    if std::env::var("ELASTIK_TOKEN").is_ok() {
        eprintln!("  warning: ELASTIK_TOKEN is deprecated; rename it to ELASTIK_WRITE_TOKEN.");
    }
    if env_set_but_empty("ELASTIK_APPROVE_TOKEN") {
        eprintln!(
            "  warning: empty ELASTIK_APPROVE_TOKEN treated as unset (DELETE/system writes disabled)"
        );
    }
    if tokens.write.is_none() {
        eprintln!("  warning: ELASTIK_WRITE_TOKEN not set; ordinary PUT/POST are disabled.");
    }
    if tokens.approve.is_none() {
        eprintln!(
            "  warning: ELASTIK_APPROVE_TOKEN not set; DELETE and system writes are disabled."
        );
    }
}

#[cfg(not(test))]
fn nonempty_env(name: &str) -> Option<Vec<u8>> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(String::into_bytes)
}

#[cfg(not(test))]
fn env_set_but_empty(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => value.trim().is_empty(),
        Err(_) => false,
    }
}

#[cfg(not(test))]
async fn shutdown_signal(engine: Engine) {
    wait_for_shutdown_signal().await;
    eprintln!("elastik-core: shutdown signal received");
    engine.shutdown();
}

#[cfg(all(not(test), unix))]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(sigterm) => sigterm,
        Err(e) => {
            eprintln!("elastik-core: failed to install SIGTERM handler: {e}; waiting for Ctrl-C");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(all(not(test), not(unix)))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
