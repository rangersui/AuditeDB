//! elastik-core — bedrock HTTP+SQLite+HMAC.
//!
//! The core has exactly one interface: HTTP requests in, HTTP responses
//! out. It does not know or care whether a request came from curl, a
//! browser, WebDAV, SMTP, an AI agent, or an SDK bridge. Translation is
//! external; the core only sees HTTP.
//!
//! v5.0 grammar:
//!
//!   GET    /<world>                → body bytes with stored Content-Type
//!   HEAD   /<world>                → metadata headers, no body
//!   PUT    /<world>                → replace body, update meta, audit
//!   POST   /<world>                → append to body, no meta change, audit
//!   DELETE /<world>                → drop world (sqlite) or evict (memory)
//!   GET    /proc/worlds            → text/plain, one world per line
//!   GET    /proc/version           → "elastik-core <ver>\n"
//!
//! Path prefix decides backend (one core, one port, no two daemons):
//!
//!   /home/* /etc/* /lib/* /boot/* /usr/* /var/*  → SQLite, durable, audited
//!   /tmp/*  /dev/*  /sys/*                       → memory, transient
//!
//! Out of scope (deliberately):
//!   protocol bridges      → SDK clients / external endpoint apps
//!   AI shaping/routing    → SDK clients / external endpoint apps
//!   /lib/* code running   → never in core; /lib is inert storage
//!   application behavior  → outside core, expressed as HTTP
//!
//! Env:
//!   ELASTIK_HOST           default 127.0.0.1
//!   ELASTIK_PORT           default 3105
//!   ELASTIK_DATA           default ./data
//!   ELASTIK_TOKEN          T2 token  (writes to /home/*)
//!   ELASTIK_APPROVE_TOKEN  T3 token  (writes to /lib/, /etc/, deletes)
//!   ELASTIK_KEY            HMAC key for the audit chain (required)
mod audit;
mod auth;
mod store;
mod world;

use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;

use crate::world::{AppendResult, Stage};

#[derive(Clone)]
struct Core {
    data: PathBuf,
    tokens: auth::Tokens,
    hmac_key: Vec<u8>,
    mem: Arc<store::MemoryStore>,
}

impl Core {
    fn read_world(&self, world: &str) -> Option<Stage> {
        if store::is_memory_world(world) {
            self.mem.read(world)
        } else {
            world::read(&self.data, world)
        }
    }

    fn write_world(
        &self,
        world: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
    ) -> rusqlite::Result<()> {
        if store::is_memory_world(world) {
            self.mem.write(world, body, content_type, headers);
            Ok(())
        } else {
            world::write(&self.data, world, body, content_type, headers)
        }
    }

    fn append_world(&self, world: &str, body: &[u8]) -> rusqlite::Result<Option<AppendResult>> {
        if store::is_memory_world(world) {
            Ok(self.mem.append(world, body))
        } else {
            world::append(&self.data, world, body)
        }
    }

    fn delete_world(&self, world: &str) -> bool {
        if store::is_memory_world(world) {
            self.mem.delete(world)
        } else {
            world::delete(&self.data, world)
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    let host = std::env::var("ELASTIK_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("ELASTIK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3105);
    let data = PathBuf::from(std::env::var("ELASTIK_DATA").unwrap_or_else(|_| "./data".into()));
    std::fs::create_dir_all(&data).expect("create data dir");
    let hmac_key = std::env::var("ELASTIK_KEY")
        .expect("ELASTIK_KEY required — the audit chain has no meaning without it")
        .into_bytes();

    let state = Core {
        data,
        tokens: auth::Tokens::from_env(),
        hmac_key,
        mem: Arc::new(store::MemoryStore::new()),
    };

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("elastik-core v{VERSION} on http://{addr}/");
    // Warn if the env declares tokens but leaves them empty. `from_env`
    // already treats those as unset, but the user almost certainly
    // meant to fill them in — silent acceptance was the old footgun.
    if auth::env_set_but_empty("ELASTIK_TOKEN") {
        eprintln!("  auth: ⚠ ELASTIK_TOKEN set but empty — treated as unset (T2 disabled)");
    }
    if auth::env_set_but_empty("ELASTIK_APPROVE_TOKEN") {
        eprintln!("  auth: ⚠ ELASTIK_APPROVE_TOKEN set but empty — treated as unset (T3 disabled)");
    }
    let app = Router::new()
        .route("/", get(root_hint))
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/*world", any(world_handler))
        .with_state(Arc::new(state))
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    axum::serve(listener, app).await.unwrap();
}

/// Bare `GET /` — not protocol, not UI. Just a courtesy text/plain
/// signpost so a curious human doesn't white-screen. The protocol
/// surface starts under `/home`, `/tmp`, `/dev`, `/sys`, `/proc`,
/// `/etc`, `/lib`, `/var`. Browser shells are SDK-app territory; core
/// never serves HTML, never sets CSP, never thinks about iframes.
async fn root_hint() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("elastik-core {VERSION}\ntry: curl /proc/worlds\n"),
    )
}

// ─── /proc/version ──────────────────────────────────────────────────
async fn proc_version() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("elastik-core {VERSION}\n"),
    )
}

// ─── /proc/worlds ───────────────────────────────────────────────────
async fn proc_worlds(State(core): State<Arc<Core>>) -> impl IntoResponse {
    let names = store::list_all(&core.data, &core.mem);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        world_list_body(&names),
    )
}

// ─── /<world> all five methods ──────────────────────────────────────
async fn world_handler(
    State(core): State<Arc<Core>>,
    method: Method,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let world_name = canonicalize_path(&path);
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);

    match method {
        Method::GET => handle_get(&core, &world_name),
        Method::HEAD => handle_head(&core, &world_name),
        Method::PUT => handle_put(&core, &world_name, &headers, body, tier),
        Method::POST => handle_post(&core, &world_name, &headers, body, tier),
        Method::DELETE => handle_delete(&core, &world_name, &headers, tier),
        _ => (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response(),
    }
}

/// Path prefix is policy: `/home/tmp/foo` must stay a durable home
/// world, not silently become transient `/tmp/foo`. Bare `/foo` is the
/// convenience spelling for `/home/foo`; explicit namespaces are kept.
fn canonicalize_path(p: &str) -> String {
    let stripped = p.trim_start_matches('/');
    let first = stripped.split('/').next().unwrap_or("");
    match first {
        "home" | "tmp" | "dev" | "sys" | "proc" | "etc" | "lib" | "boot" | "usr" | "var" => {
            stripped.to_owned()
        }
        _ => format!("home/{stripped}"),
    }
}

// ─── handlers ───────────────────────────────────────────────────────

/// GET: body bytes with stored Content-Type. No JSON envelope.
fn handle_get(core: &Core, world_name: &str) -> Response {
    let Some(stage) = core.read_world(world_name) else {
        return not_found();
    };
    let etag = current_etag(core, world_name, &stage);
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ETAG, etag_header(&etag)),
    ];
    apply_meta_headers(&stage.headers, &mut resp_headers);
    (StatusCode::OK, to_header_map(resp_headers), stage.body).into_response()
}

/// HEAD — same headers as GET, no body.
fn handle_head(core: &Core, world_name: &str) -> Response {
    let Some(stage) = core.read_world(world_name) else {
        return not_found();
    };
    let etag = current_etag(core, world_name, &stage);
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
        ),
        (header::ETAG, etag_header(&etag)),
    ];
    apply_meta_headers(&stage.headers, &mut resp_headers);
    (StatusCode::OK, to_header_map(resp_headers), "").into_response()
}

fn handle_put(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    if !can_write(world_name, tier) {
        return unauthorized("write requires token; system worlds need approve token");
    }
    if let Err(resp) = check_write_preconditions(core, world_name, req_headers) {
        return resp;
    }
    let existed = core.read_world(world_name).is_some();
    let content_type = request_content_type(req_headers);

    let meta = request_meta_headers(req_headers);

    let new_etag = if store::is_persistent(world_name) {
        match world::write_with_audit(
            &core.data,
            world_name,
            &body,
            &content_type,
            &meta,
            &core.hmac_key,
        ) {
            Ok(h) => hmac_etag(&h),
            Err(e) => return server_error(format!("storage/audit: {e}")),
        }
    } else {
        match core.write_world(world_name, &body, &content_type, &meta) {
            Ok(()) => body_etag(&body),
            Err(e) => return server_error(format!("storage: {e}")),
        }
    };

    let resp_headers = [(header::ETAG, etag_header(&new_etag))];
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (status, resp_headers, "").into_response()
}

/// POST — append body bytes to existing world. 404 if world absent
/// (PUT is the create/replace path). Never updates X-Meta-*.
fn handle_post(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    if !can_write(world_name, tier) {
        return unauthorized("write requires token; system worlds need approve token");
    }
    if let Err(resp) = check_write_preconditions(core, world_name, req_headers) {
        return resp;
    }
    let content_type = request_content_type(req_headers);
    let meta = request_meta_headers(req_headers);
    let new_etag = if store::is_persistent(world_name) {
        match world::append_with_audit(
            &core.data,
            world_name,
            &body,
            &content_type,
            &meta,
            &core.hmac_key,
        ) {
            Ok(Some((_result, h))) => hmac_etag(&h),
            Ok(None) => return not_found(),
            Err(e) => return server_error(format!("storage/audit: {e}")),
        }
    } else {
        let result = match core.append_world(world_name, &body) {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(),
            Err(e) => return server_error(format!("storage: {e}")),
        };
        format!("sha256-{}", result.body_sha256_after)
    };

    let resp_headers = [(header::ETAG, etag_header(&new_etag))];
    (StatusCode::OK, resp_headers, "").into_response()
}

fn handle_delete(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    tier: auth::Tier,
) -> Response {
    if !can_write(world_name, tier) {
        return unauthorized("delete requires token; system worlds need approve token");
    }
    if let Err(resp) = check_write_preconditions(core, world_name, req_headers) {
        return resp;
    }

    // Capture body hash BEFORE the world disappears, for the
    // var/log/deletes ledger. If the world doesn't exist we'll 404
    // below, but reading first is harmless.
    let body_sha256_before = core
        .read_world(world_name)
        .map(|s| world::sha256_hex(&s.body))
        .unwrap_or_default();

    // Audit BEFORE the disk op — write to a global ledger world, not
    // the world being deleted (otherwise audit::append reopens its dir
    // and recreates it). Memory deletes still audit here because the
    // ledger itself is sqlite.
    let delete_meta = request_meta_headers(req_headers);
    if let Err(e) = audit::append(
        &core.data,
        "var/log/deletes",
        "delete",
        world_name,
        &body_sha256_before,
        0,
        req_headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        &delete_meta,
        &core.hmac_key,
    ) {
        return server_error(format!("audit: {e}"));
    }

    let ok = core.delete_world(world_name);
    if !ok {
        return not_found();
    }
    (StatusCode::NO_CONTENT, "").into_response()
}

// ─── helpers ────────────────────────────────────────────────────────

fn can_write(world_name: &str, tier: auth::Tier) -> bool {
    // Harvard gate: /lib/, /etc/, /boot/, /usr/, and audit logs
    // require approve. /home/, /tmp/, /dev/, /sys/, and non-log
    // /var/ worlds accept the normal token. Anon refused.
    let needs_approve = world_name.starts_with("lib/")
        || world_name.starts_with("etc/")
        || world_name.starts_with("boot/")
        || world_name.starts_with("usr/")
        || world_name.starts_with("var/log/");
    match tier {
        auth::Tier::Anon => false,
        auth::Tier::Auth => !needs_approve,
        auth::Tier::Approve => true,
    }
}

fn current_etag(core: &Core, world_name: &str, stage: &Stage) -> String {
    if store::is_persistent(world_name) {
        if let Some(h) = audit::latest_hmac(&core.data, world_name) {
            return hmac_etag(&h);
        }
    }
    body_etag(&stage.body)
}

fn hmac_etag(hmac: &str) -> String {
    format!("hmac-{hmac}")
}

fn body_etag(body: &[u8]) -> String {
    format!("sha256-{}", world::sha256_hex(body))
}

fn etag_header(etag: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{etag}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("\"invalid\""))
}

fn check_write_preconditions(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
) -> Result<(), Response> {
    let current = core.read_world(world_name);
    let current_tag = current
        .as_ref()
        .map(|stage| current_etag(core, world_name, stage));

    if let Some(h) = req_headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let Some(tag) = &current_tag else {
            return Err(precondition_failed("If-Match requires an existing world"));
        };
        if !etag_list_strong_matches(h, tag) {
            return Err(precondition_failed("If-Match did not match current ETag"));
        }
    }

    if let Some(h) = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tag) = &current_tag {
            if etag_list_weak_matches(h, tag) {
                return Err(precondition_failed("If-None-Match matched current ETag"));
            }
        }
    }

    Ok(())
}

fn etag_list_strong_matches(header_value: &str, current: &str) -> bool {
    header_value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == format!("\"{current}\""))
}

fn etag_list_weak_matches(header_value: &str, current: &str) -> bool {
    header_value.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || candidate == format!("\"{current}\"")
            || candidate
                .strip_prefix("W/")
                .map(|weak| weak == format!("\"{current}\""))
                .unwrap_or(false)
    })
}

fn request_content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

fn request_meta_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if name.to_ascii_lowercase().starts_with("x-meta-") {
                v.to_str()
                    .ok()
                    .map(|val| (name.to_string(), val.to_string()))
            } else {
                None
            }
        })
        .collect()
}

fn world_list_body(names: &[String]) -> String {
    if names.is_empty() {
        String::new()
    } else {
        format!("{}\n", names.join("\n"))
    }
}

fn to_header_map(pairs: Vec<(HeaderName, HeaderValue)>) -> HeaderMap {
    let mut hm = HeaderMap::with_capacity(pairs.len());
    for (k, v) in pairs {
        hm.append(k, v);
    }
    hm
}

fn apply_meta_headers(headers: &[(String, String)], out: &mut Vec<(HeaderName, HeaderValue)>) {
    for (k, v) in headers {
        let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else {
            continue;
        };
        let Ok(val) = HeaderValue::from_str(v) else {
            continue;
        };
        out.push((name, val));
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "world not found\n",
    )
        .into_response()
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::WWW_AUTHENTICATE, "Bearer realm=\"elastik\""),
        ],
        format!("auth required: {msg}\n"),
    )
        .into_response()
}

fn precondition_failed(msg: &str) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("precondition failed: {msg}\n"),
    )
        .into_response()
}

fn server_error(msg: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("internal error: {msg}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_log_requires_approve_token() {
        assert!(!can_write("var/log/deletes", auth::Tier::Anon));
        assert!(!can_write("var/log/deletes", auth::Tier::Auth));
        assert!(can_write("var/log/deletes", auth::Tier::Approve));
    }

    #[test]
    fn non_log_var_still_accepts_auth_token() {
        assert!(!can_write("var/cache/rag", auth::Tier::Anon));
        assert!(can_write("var/cache/rag", auth::Tier::Auth));
        assert!(can_write("var/cache/rag", auth::Tier::Approve));
    }

    #[test]
    fn canonicalize_preserves_explicit_namespaces() {
        assert_eq!(canonicalize_path("/home/tmp/foo"), "home/tmp/foo");
        assert_eq!(canonicalize_path("/home/etc/foo"), "home/etc/foo");
        assert_eq!(canonicalize_path("/tmp/foo"), "tmp/foo");
        assert_eq!(canonicalize_path("/etc/foo"), "etc/foo");
        assert_eq!(canonicalize_path("/foo"), "home/foo");
    }

    #[test]
    fn etag_lists_match_http_strong_and_weak_rules() {
        assert!(etag_list_strong_matches("\"hmac-abc\"", "hmac-abc"));
        assert!(etag_list_strong_matches(
            "\"other\", \"hmac-abc\"",
            "hmac-abc"
        ));
        assert!(etag_list_strong_matches("*", "hmac-abc"));
        assert!(!etag_list_strong_matches("W/\"hmac-abc\"", "hmac-abc"));
        assert!(!etag_list_strong_matches("\"other\"", "hmac-abc"));

        assert!(etag_list_weak_matches("W/\"hmac-abc\"", "hmac-abc"));
    }

    #[test]
    fn if_none_match_star_blocks_existing_world() {
        let (core, dir) = test_core("if-none-match-star");
        core.write_world("home/cas", b"one", "text/plain; charset=utf-8", &[])
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));

        assert!(check_write_preconditions(&core, "home/cas", &headers).is_err());
        assert!(check_write_preconditions(&core, "home/new", &headers).is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn if_match_accepts_current_hmac_etag_only() {
        let (core, dir) = test_core("if-match-hmac");
        core.write_world("home/cas", b"one", "text/plain; charset=utf-8", &[])
            .unwrap();
        let h = audit::append(
            &core.data,
            "home/cas",
            "put",
            "home/cas",
            &world::sha256_hex(b"one"),
            3,
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let etag = format!("\"{}\"", hmac_etag(&h));

        let mut good = HeaderMap::new();
        good.insert(header::IF_MATCH, HeaderValue::from_str(&etag).unwrap());
        assert!(check_write_preconditions(&core, "home/cas", &good).is_ok());

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        assert!(check_write_preconditions(&core, "home/cas", &stale).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_content_type_preserves_http_content_type_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        );
        assert_eq!(request_content_type(&headers), "application/pdf");

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        assert_eq!(request_content_type(&headers), "text/html; charset=utf-8");

        headers.clear();
        assert_eq!(request_content_type(&headers), "application/octet-stream");
    }

    #[test]
    fn worlds_store_content_type_not_private_extensions() {
        let (core, dir) = test_core("content-type");
        core.write_world("home/pdf", b"%PDF-1.7", "application/pdf", &[])
            .unwrap();

        let stage = core.read_world("home/pdf").unwrap();
        assert_eq!(stage.content_type, "application/pdf");
        assert_eq!(stage.body, b"%PDF-1.7");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_keeps_historical_metadata_without_json_payload() {
        let (core, dir) = test_core("audit-meta");
        let headers = vec![("x-meta-author".to_string(), "ranger".to_string())];
        let h = world::write_with_audit(
            &core.data,
            "home/audit-meta",
            b"hello",
            "text/plain; charset=utf-8",
            &headers,
            &core.hmac_key,
        )
        .unwrap();

        let c = rusqlite::Connection::open(world::world_db(&core.data, "home/audit-meta")).unwrap();
        let (content_type, meta_sha256): (String, String) = c
            .query_row(
                "SELECT content_type, meta_sha256 FROM events WHERE hmac=?",
                [h],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert_eq!(
            meta_sha256,
            audit::meta_sha256("text/plain; charset=utf-8", &headers)
        );

        let author: String = c
            .query_row(
                "SELECT value FROM event_headers WHERE name='x-meta-author'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(author, "ranger");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delete_honors_if_match_before_audit_or_remove() {
        let (core, dir) = test_core("delete-if-match");
        let h = world::write_with_audit(
            &core.data,
            "home/delete-cas",
            b"alive",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        let resp = handle_delete(&core, "home/delete-cas", &stale, auth::Tier::Approve);
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(core.read_world("home/delete-cas").is_some());

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", hmac_etag(&h))).unwrap(),
        );
        let resp = handle_delete(&core, "home/delete-cas", &good, auth::Tier::Approve);
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(core.read_world("home/delete-cas").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn proc_worlds_body_is_plain_lines() {
        assert_eq!(world_list_body(&[]), "");
        assert_eq!(
            world_list_body(&["home/a".to_owned(), "tmp/b".to_owned()]),
            "home/a\ntmp/b\n"
        );
    }

    fn test_core(label: &str) -> (Core, PathBuf) {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!(
            "elastik-core-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (
            Core {
                data: dir.clone(),
                tokens: auth::Tokens {
                    auth: None,
                    approve: None,
                },
                hmac_key: b"test-key".to_vec(),
                mem: Arc::new(store::MemoryStore::new()),
            },
            dir,
        )
    }
}
