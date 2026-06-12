use std::path::{Path, PathBuf};

use axum::body::Bytes;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use crate::{
    defaults::{DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_WORLD_BYTES},
    engine::Engine,
    engine_types::{AccessTier, AuditHmacKey, Preconditions, Representation, ValidatedWorldPath},
    server::{http::semantics::HeaderAllowlist, ServerState},
};

const TEST_DISK_ENCODE: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'.')
    .add(b'/')
    .add(b'\\')
    .add(b':')
    .add(b'*')
    .add(b'?')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'|')
    .add(b' ');

pub(crate) fn server_state_for_engine_for_tests(engine: Engine) -> ServerState {
    server_state_with_max_world_bytes_for_engine_for_tests(engine, DEFAULT_MAX_WORLD_BYTES)
}

pub(crate) fn server_state_with_max_world_bytes_for_engine_for_tests(
    engine: Engine,
    max_world_bytes: usize,
) -> ServerState {
    server_state_with_headers_for_engine_for_tests(
        engine,
        max_world_bytes,
        HeaderAllowlist::empty(),
        HeaderAllowlist::empty(),
    )
}

pub(crate) fn server_state_with_headers_for_engine_for_tests(
    engine: Engine,
    max_world_bytes: usize,
    persist_header_allowlist: HeaderAllowlist,
    persist_header_user_deny: HeaderAllowlist,
) -> ServerState {
    ServerState::new(
        engine,
        max_world_bytes,
        persist_header_allowlist,
        persist_header_user_deny,
    )
}

pub(crate) fn test_engine_for_server(label: &str) -> (Engine, std::path::PathBuf) {
    test_engine_for_server_with_listen_slots(label, DEFAULT_MAX_LISTEN_CONNECTIONS)
}

pub(crate) fn test_engine_for_server_with_read_token(
    label: &str,
    token: impl Into<Vec<u8>>,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .read_token(token)
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_auth_tokens(label: &str) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .read_token(b"reader".to_vec())
        .write_token(b"writer".to_vec())
        .approve_token(b"approve".to_vec())
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_storage_quota(
    label: &str,
    max_storage_bytes: usize,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .max_storage_bytes(Some(max_storage_bytes))
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_memory_cap(
    label: &str,
    max_memory_bytes: usize,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .max_memory_bytes(max_memory_bytes)
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_read_cache_max(
    label: &str,
    max_entries: usize,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .read_cache_max_entries(max_entries)
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_world_cap(
    label: &str,
    max_world_bytes: usize,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .max_world_bytes(max_world_bytes)
        .build()
        .expect("test engine should build");
    (engine, dir)
}

pub(crate) fn test_engine_for_server_with_listen_slots(
    label: &str,
    max_listen_connections: usize,
) -> (Engine, std::path::PathBuf) {
    let dir = test_data_root(label);
    let engine = Engine::builder()
        .data_root(dir.clone())
        .key(test_hmac_key())
        .max_listen_connections(max_listen_connections)
        .build()
        .expect("test engine should build");
    (engine, dir)
}

fn test_data_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "elastik-bin-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock should be after unix epoch")
            .as_nanos()
    ))
}

pub(crate) async fn write_text_world_for_tests(engine: &Engine, world: &str, body: &'static str) {
    let world = ValidatedWorldPath::new(world).expect("test world path should validate");
    engine
        .replace(
            &world,
            Representation::new(
                Bytes::from_static(body.as_bytes()),
                "text/plain",
                Vec::new(),
            ),
            Preconditions::none(),
            AccessTier::Write,
        )
        .await
        .expect("test write should succeed");
}

pub(crate) fn world_db_path_for_server_tests(data_root: impl AsRef<Path>, world: &str) -> PathBuf {
    let disk_name = utf8_percent_encode(world, TEST_DISK_ENCODE).to_string();
    data_root.as_ref().join(disk_name).join("universe.db")
}
const TEST_HMAC_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

fn test_hmac_key() -> AuditHmacKey {
    AuditHmacKey::try_from_slice(TEST_HMAC_KEY).expect("test hmac key")
}
