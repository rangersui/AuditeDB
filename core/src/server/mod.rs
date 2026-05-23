//! Binary/server runtime assembly.
//!
//! During PR5 this module is still compiled by the library, but startup now
//! constructs the protocol-neutral `Engine` first and only hands legacy routes
//! a `Core` bridge until the adapters cross the crate boundary.

use std::net::IpAddr;
use std::path::PathBuf;

#[cfg(feature = "coap")]
use crate::config::{coap_bind_from_env, DEFAULT_COAP_MAX_IN_FLIGHT};
use crate::config::{
    env_nonzero_usize, env_optional_usize, env_usize, hmac_key_from_env_value, listen_addr,
    should_warn_public_read, DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS,
    DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WORLD_BYTES,
};
use crate::{
    auth,
    engine::{Engine, EngineBuilder},
    engine_types::SecretBytes,
    route, VERSION,
};

pub(crate) async fn run_from_env() {
    crate::pipeline::init_trace_from_env();

    let host = std::env::var("ELASTIK_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("ELASTIK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3105);
    #[cfg(feature = "coap")]
    let coap_bind = coap_bind_from_env();
    let data = PathBuf::from(std::env::var("ELASTIK_DATA").unwrap_or_else(|_| "./data".into()));
    let max_world_bytes = env_usize("ELASTIK_MAX_WORLD_BYTES", DEFAULT_MAX_WORLD_BYTES);
    let max_memory_bytes = env_usize("ELASTIK_MAX_MEMORY_BYTES", DEFAULT_MAX_MEMORY_BYTES);
    let max_storage_bytes = env_optional_usize("ELASTIK_MAX_STORAGE_BYTES");
    let max_listen_connections = env_nonzero_usize(
        "ELASTIK_MAX_LISTEN_CONNECTIONS",
        DEFAULT_MAX_LISTEN_CONNECTIONS,
    );
    let listen_replay_max =
        env_nonzero_usize("ELASTIK_LISTEN_REPLAY_MAX", DEFAULT_LISTEN_REPLAY_MAX);
    #[cfg(feature = "coap")]
    let coap_max_in_flight =
        env_nonzero_usize("ELASTIK_COAP_MAX_IN_FLIGHT", DEFAULT_COAP_MAX_IN_FLIGHT);
    let read_cache_max_entries = env_nonzero_usize(
        "ELASTIK_READ_CACHE_MAX_ENTRIES",
        crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES,
    );
    let hmac_key = hmac_key_from_env_value(std::env::var("ELASTIK_KEY").ok()).expect(
        "ELASTIK_KEY must be a non-empty string; the audit chain has no meaning without it",
    );
    let tokens = auth::Tokens::from_env();
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
    );
    let state = engine.core_arc();

    let addr = listen_addr(&host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    let bind_ip = listener
        .local_addr()
        .map(|addr| addr.ip())
        .unwrap_or_else(|_| IpAddr::from([127, 0, 0, 1]));
    eprintln!("elastik-core v{VERSION} on http://{addr}/");
    print_auth_summary(&state.tokens, bind_ip);
    #[cfg(feature = "coap")]
    if let Some((coap_host, coap_port)) = coap_bind {
        let coap_addr = listen_addr(&coap_host, coap_port);
        let coap_state = state.clone();
        let coap_shutdown = state.shutdown.clone();
        tokio::spawn(async move {
            crate::coap::serve(coap_state, coap_addr, coap_shutdown, coap_max_in_flight).await;
        });
    }
    let app = route::build_app(state, max_world_bytes);

    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(engine.clone()))
        .await;
    serve_result.expect("axum server failed");
    drop(engine);
}

struct EngineLimits {
    max_world_bytes: usize,
    max_memory_bytes: usize,
    max_storage_bytes: Option<usize>,
    max_listen_connections: usize,
    listen_replay_max: usize,
    read_cache_max_entries: usize,
}

fn build_engine_from_env(
    data: PathBuf,
    hmac_key: Vec<u8>,
    tokens: &auth::Tokens,
    limits: EngineLimits,
) -> Engine {
    let key = SecretBytes::new(hmac_key).expect("ELASTIK_KEY validated before Engine build");
    let builder = Engine::builder()
        .data_root(data)
        .key(key)
        .max_world_bytes(limits.max_world_bytes)
        .max_memory_bytes(limits.max_memory_bytes)
        .max_storage_bytes(limits.max_storage_bytes)
        .max_listen_connections(limits.max_listen_connections)
        .listen_replay_max(limits.listen_replay_max)
        .read_cache_max_entries(limits.read_cache_max_entries)
        .persist_header_allowlist(crate::config::header_allowlist_from_env())
        .persist_header_user_deny(crate::config::header_user_deny_from_env());
    configure_tokens(builder, tokens)
        .build()
        .unwrap_or_else(|err| panic!("build Engine failed: {err:?}"))
}

fn configure_tokens(mut builder: EngineBuilder, tokens: &auth::Tokens) -> EngineBuilder {
    if let Some(token) = &tokens.read {
        builder = builder.read_token(token.as_slice().to_vec());
    }
    if let Some(token) = &tokens.write {
        builder = builder.write_token(token.as_slice().to_vec());
    }
    if let Some(token) = &tokens.approve {
        builder = builder.approve_token(token.as_slice().to_vec());
    }
    builder
}

fn print_auth_summary(tokens: &auth::Tokens, bind_ip: IpAddr) {
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
    if auth::env_set_but_empty("ELASTIK_READ_TOKEN") {
        eprintln!("  warning: empty ELASTIK_READ_TOKEN treated as unset (reads public)");
    }
    if should_warn_public_read(bind_ip, tokens) {
        eprintln!(
            "  WARNING: reads are public on non-loopback interface {bind_ip}; set ELASTIK_READ_TOKEN to gate reads."
        );
    }
    if auth::env_set_but_empty("ELASTIK_WRITE_TOKEN") {
        eprintln!("  warning: empty ELASTIK_WRITE_TOKEN treated as unset (PUT/POST disabled)");
    }
    if std::env::var("ELASTIK_TOKEN").is_ok() {
        eprintln!("  warning: ELASTIK_TOKEN is deprecated; rename it to ELASTIK_WRITE_TOKEN.");
    }
    if auth::env_set_but_empty("ELASTIK_APPROVE_TOKEN") {
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

async fn shutdown_signal(engine: Engine) {
    wait_for_shutdown_signal().await;
    eprintln!("elastik-core: shutdown signal received");
    engine.shutdown();
}

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
