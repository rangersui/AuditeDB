//! Binary/server runtime assembly.
//!
//! This module is still compiled by the library during the PR5 transition.
//! The next split moves ownership of this module to `main.rs`.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Arc, Mutex as StdMutex,
};

use dashmap::DashMap;
use tokio::sync::{broadcast, watch, Semaphore};

#[cfg(feature = "coap")]
use crate::config::{coap_bind_from_env, DEFAULT_COAP_MAX_IN_FLIGHT};
use crate::config::{
    env_nonzero_usize, env_optional_usize, env_usize, hmac_key_from_env_value, listen_addr,
    should_warn_public_read, DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS,
    DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WORLD_BYTES,
};
use crate::{audit, auth, route, store, world, Core, VERSION};

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
    std::fs::create_dir_all(&data).expect("create data dir");
    let data_lock =
        crate::acquire_data_root_writer_lock(&data).expect("acquire data-root writer lock");
    let hmac_key = hmac_key_from_env_value(std::env::var("ELASTIK_KEY").ok()).expect(
        "ELASTIK_KEY must be a non-empty string; the audit chain has no meaning without it",
    );
    audit::verify_all_worlds(&data, &hmac_key).expect("verify audit chains at startup");
    let durable_sizes = world::sizes(&data).expect("read durable storage usage");
    let storage_body_bytes = durable_sizes.iter().map(|(_, size)| *size).sum();
    let durable_world_count = durable_sizes.len();
    let delete_ledger_created = durable_sizes
        .iter()
        .any(|(world_name, _)| world_name == "var/log/deletes");

    let (events, _) = broadcast::channel(listen_replay_max);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(Core {
        data,
        tokens: auth::Tokens::from_env(),
        hmac_key,
        mem: Arc::new(store::MemoryStore::new()),
        max_world_bytes,
        max_memory_bytes,
        max_storage_bytes,
        storage_body_bytes: Arc::new(AtomicUsize::new(storage_body_bytes)),
        durable_world_count: Arc::new(AtomicUsize::new(durable_world_count)),
        delete_ledger_created: Arc::new(AtomicBool::new(delete_ledger_created)),
        events,
        listen_slots: Arc::new(Semaphore::new(max_listen_connections)),
        listen_replay_max,
        event_log: Arc::new(StdMutex::new(VecDeque::with_capacity(listen_replay_max))),
        shutdown: shutdown_rx.clone(),
        next_event: crate::state::new_event_counter(),
        next_request: Arc::new(AtomicUsize::new(0)),
        world_locks: Arc::new(DashMap::new()),
        ledger: Arc::new(crate::ledger::LedgerWriter::new()),
        read_cache: Arc::new(crate::read_cache::ReadCache::new(read_cache_max_entries)),
        persist_header_allowlist: Arc::new(crate::config::header_allowlist_from_env()),
        persist_header_user_deny: Arc::new(crate::config::header_user_deny_from_env()),
    });

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
        let coap_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            crate::coap::serve(coap_state, coap_addr, coap_shutdown, coap_max_in_flight).await;
        });
    }
    let app = route::build_app(state, max_world_bytes);

    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await;
    drop(data_lock);
    serve_result.expect("axum server failed");
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

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    wait_for_shutdown_signal().await;
    eprintln!("elastik-core: shutdown signal received");
    let _ = shutdown_tx.send(true);
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
