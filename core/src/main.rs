//! elastik-core — bedrock HTTP+SQLite+HMAC.
//!
//! The core has one semantic interface: method + path + representation bytes.
//! HTTP is the first-class surface. SCoAP is a small UDP-curl surface because
//! CoAP has semantic zero distance from HTTP. Everything else must arrive
//! through SDK/client adapters that collapse it into the same tuple.
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
//!   ELASTIK_COAP_PORT      optional; enables SCoAP/UDP when set
//!   ELASTIK_COAP_HOST      default 127.0.0.1 when CoAP is enabled
//!   ELASTIK_DATA           default ./data
//!   ELASTIK_READ_TOKEN     T1 token  (optional read gate)
//!   ELASTIK_WRITE_TOKEN    T2 token  (writes to /home/*, includes read)
//!   ELASTIK_APPROVE_TOKEN  T3 token  (system writes/deletes, includes read)
//!   ELASTIK_KEY            HMAC key for the audit chain (required)
mod audit;
mod auth;
mod coap;
mod http_semantics;
mod listen;
mod store;
mod world;

use axum::{
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::Instant;
use tokio::sync::{broadcast, watch, Mutex};

use crate::http_semantics as hs;
use crate::world::{AppendResult, Stage};

pub(crate) struct WriteOutcome {
    pub status: StatusCode,
    pub etag: String,
}

#[derive(Clone)]
struct Core {
    data: PathBuf,
    tokens: auth::Tokens,
    hmac_key: Vec<u8>,
    mem: Arc<store::MemoryStore>,
    max_world_bytes: usize,
    max_memory_bytes: usize,
    events: broadcast::Sender<listen::ChangeEvent>,
    event_log: Arc<StdMutex<VecDeque<listen::ChangeEvent>>>,
    shutdown: watch::Receiver<bool>,
    next_event: Arc<AtomicU64>,
    next_request: Arc<AtomicU64>,
    // One writer at a time keeps If-Match/If-None-Match + write atomic.
    // tokio::Mutex avoids blocking a runtime worker while queued writers wait.
    write_lock: Arc<Mutex<()>>,
}

impl Core {
    fn read_world(&self, world: &str) -> Option<Stage> {
        self.read_world_with_etag(world).map(|(stage, _)| stage)
    }

    fn read_world_with_etag(&self, world: &str) -> Option<(Stage, String)> {
        if store::is_memory_world(world) {
            self.mem.read(world).map(|stage| {
                let etag = hs::body_etag(&stage.body);
                (stage, etag)
            })
        } else {
            world::read_with_hmac(&self.data, world).map(|(stage, hmac)| {
                let etag = hmac
                    .map(|h| hs::hmac_etag(&h))
                    .unwrap_or_else(|| hs::body_etag(&stage.body));
                (stage, etag)
            })
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

    fn notify(&self, method: &'static str, world: &str, etag: &str) {
        let id = self.next_event.fetch_add(1, Ordering::Relaxed) + 1;
        let change = listen::ChangeEvent {
            id,
            method,
            path: format!("/{world}"),
            etag: etag.to_owned(),
        };
        {
            let mut log = self
                .event_log
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            log.push_back(change.clone());
            while log.len() > LISTEN_REPLAY_MAX {
                log.pop_front();
            }
        }
        let _ = self.events.send(change);
    }

    async fn put_bytes(
        &self,
        world_name: &str,
        body: &[u8],
        content_type: &str,
        headers: &[(String, String)],
        tier: auth::Tier,
        preconditions: Option<&HeaderMap>,
    ) -> Result<WriteOutcome, Response> {
        if !can_write(world_name, tier) {
            return Err(unauthorized(
                "write requires token; system worlds need approve token",
            ));
        }
        if body.len() > self.max_world_bytes {
            return Err(payload_too_large(self.max_world_bytes));
        }
        let _write_guard = self.write_lock.lock().await;
        if let Some(req_headers) = preconditions {
            hs::check_write_preconditions(self, world_name, req_headers)?;
        }
        let existed = self.read_world(world_name).is_some();
        let new_etag = if store::is_persistent(world_name) {
            match world::write_with_audit(
                &self.data,
                world_name,
                body,
                content_type,
                headers,
                &self.hmac_key,
            ) {
                Ok(h) => hs::hmac_etag(&h),
                Err(e) => return Err(server_error(format!("storage/audit: {e}"))),
            }
        } else {
            if memory_write_projected_bytes(self, world_name, body.len()) > self.max_memory_bytes {
                return Err(payload_too_large(self.max_memory_bytes));
            }
            match self.write_world(world_name, body, content_type, headers) {
                Ok(()) => hs::body_etag(body),
                Err(e) => return Err(server_error(format!("storage: {e}"))),
            }
        };
        self.notify("PUT", world_name, &new_etag);
        Ok(WriteOutcome {
            status: if existed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            etag: new_etag,
        })
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ROOT_ALLOW: &str = "GET, HEAD, OPTIONS";
const PROC_ALLOW: &str = "GET, HEAD, OPTIONS";
const AUDIT_VERIFY_ALLOW: &str = "GET, HEAD, OPTIONS";
const WORLD_ALLOW: &str = "GET, HEAD, PUT, POST, DELETE, OPTIONS";
const LISTEN_REPLAY_MAX: usize = 1024;
const DEFAULT_MAX_WORLD_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

#[tokio::main]
async fn main() {
    let host = std::env::var("ELASTIK_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("ELASTIK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3105);
    let coap_bind = coap_bind_from_env();
    let data = PathBuf::from(std::env::var("ELASTIK_DATA").unwrap_or_else(|_| "./data".into()));
    let max_world_bytes = env_usize("ELASTIK_MAX_WORLD_BYTES", DEFAULT_MAX_WORLD_BYTES);
    let max_memory_bytes = env_usize("ELASTIK_MAX_MEMORY_BYTES", DEFAULT_MAX_MEMORY_BYTES);
    std::fs::create_dir_all(&data).expect("create data dir");
    let hmac_key = std::env::var("ELASTIK_KEY")
        .expect("ELASTIK_KEY required: the audit chain has no meaning without it")
        .into_bytes();

    let (events, _) = broadcast::channel(1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(Core {
        data,
        tokens: auth::Tokens::from_env(),
        hmac_key,
        mem: Arc::new(store::MemoryStore::new()),
        max_world_bytes,
        max_memory_bytes,
        events,
        event_log: Arc::new(StdMutex::new(VecDeque::new())),
        shutdown: shutdown_rx.clone(),
        next_event: Arc::new(AtomicU64::new(0)),
        next_request: Arc::new(AtomicU64::new(0)),
        write_lock: Arc::new(Mutex::new(())),
    });

    let addr = listen_addr(&host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    let bind_ip = listener
        .local_addr()
        .map(|addr| addr.ip())
        .unwrap_or_else(|_| IpAddr::from([127, 0, 0, 1]));
    eprintln!("elastik-core v{VERSION} on http://{addr}/");
    print_auth_summary(&state.tokens, bind_ip);
    if let Some((coap_host, coap_port)) = coap_bind {
        let coap_addr = listen_addr(&coap_host, coap_port);
        let coap_state = state.clone();
        let coap_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            coap::serve(coap_state, coap_addr, coap_shutdown).await;
        });
    }
    let app = Router::new()
        .route("/", any(root_hint))
        .route("/listen/*pattern", any(listen::handler))
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/proc/audit/*audit_path", any(proc_audit_verify))
        .route("/proc", any(proc_reserved))
        .route("/proc/*reserved", any(proc_reserved))
        .route("/*world", any(world_handler))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(max_world_bytes))
        .layer(middleware::from_fn_with_state(
            state,
            add_core_response_headers,
        ));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await
        .unwrap();
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
    // Warn if the env declares tokens but leaves them empty. `from_env`
    // already treats those as unset, but the user almost certainly
    // meant to fill them in; silent acceptance was the old footgun.
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

async fn add_core_response_headers(
    State(core): State<Arc<Core>>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let request_id = core.next_request.fetch_add(1, Ordering::Relaxed) + 1;
    let start = Instant::now();
    let mut response = next.run(req).await;
    stamp_core_response_headers(
        request_id,
        start.elapsed().as_micros(),
        response.headers_mut(),
    );
    response
}

fn stamp_core_response_headers(request_id: u64, elapsed_us: u128, headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        HeaderName::from_static("x-elapsed-us"),
        HeaderValue::from_str(&elapsed_us.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Authorization"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn coap_bind_from_env() -> Option<(String, u16)> {
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

fn should_warn_public_read(bind_ip: IpAddr, tokens: &auth::Tokens) -> bool {
    !bind_ip.is_loopback() && !tokens.read_required()
}

fn listen_addr(host: &str, port: u16) -> String {
    host.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .unwrap_or_else(|_| format!("{host}:{port}"))
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("elastik-core: shutdown signal received");
    let _ = shutdown_tx.send(true);
}

/// Bare `GET /` — not protocol, not UI. Just a courtesy text/plain
/// signpost so a curious human doesn't white-screen. The protocol
/// surface starts under `/home`, `/tmp`, `/dev`, `/sys`, `/proc`,
/// `/etc`, `/lib`, `/var`. Browser shells are SDK-app territory; core
/// never serves HTML, never sets CSP, never thinks about iframes.
async fn root_hint(method: Method) -> Response {
    let body = format!("elastik-core {VERSION}\ntry: curl /proc/worlds\n");
    match method {
        Method::GET => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
        Method::HEAD => (
            StatusCode::OK,
            to_header_map(vec![
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&body.len().to_string()).unwrap(),
                ),
            ]),
            "",
        )
            .into_response(),
        Method::OPTIONS => options_response(ROOT_ALLOW),
        _ => method_not_allowed(ROOT_ALLOW),
    }
}

// ─── /proc/version ──────────────────────────────────────────────────
async fn proc_version(method: Method) -> Response {
    let body = format!("elastik-core {VERSION}\n");
    match method {
        Method::GET => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
        Method::HEAD => (
            StatusCode::OK,
            to_header_map(vec![
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&body.len().to_string()).unwrap(),
                ),
            ]),
            "",
        )
            .into_response(),
        Method::OPTIONS => options_response(PROC_ALLOW),
        _ => method_not_allowed(PROC_ALLOW),
    }
}

// ─── /proc/worlds ───────────────────────────────────────────────────
async fn proc_worlds(
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(PROC_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(PROC_ALLOW);
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if !can_read(&core, tier) {
        return unauthorized("read requires read token");
    }
    let names = store::list_all(&core.data, &core.mem);
    let body = world_list_body(&names);
    let mut resp_headers = vec![(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    )];
    if method == Method::HEAD {
        resp_headers.push((
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        ));
    }
    (
        StatusCode::OK,
        to_header_map(resp_headers),
        if method == Method::HEAD {
            String::new()
        } else {
            body
        },
    )
        .into_response()
}

// /proc/audit/{world}/verify
async fn proc_audit_verify(
    State(core): State<Arc<Core>>,
    method: Method,
    AxPath(audit_path): AxPath<String>,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(AUDIT_VERIFY_ALLOW);
    }
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed(AUDIT_VERIFY_ALLOW);
    }

    let Some(raw_world) = audit_path.strip_suffix("/verify") else {
        return not_found();
    };
    let raw_world = raw_world.trim_end_matches('/');
    if raw_world.is_empty() {
        return bad_request("audit verify requires a world path");
    }
    let world_name = canonicalize_path(raw_world);
    if !valid_world_name(&world_name) {
        return bad_request("invalid world path");
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if !can_read(&core, tier) {
        return unauthorized("read requires read token");
    }

    if store::is_memory_world(&world_name) {
        if !core.mem.contains(&world_name) {
            return not_found();
        }
        return audit_not_applicable();
    }

    match audit::verify_chain(&core.data, &world_name, &core.hmac_key) {
        Ok(Some(audit::VerifyReport::Valid(report))) => audit_valid(report),
        Ok(Some(audit::VerifyReport::Broken(report))) => audit_broken(report),
        Ok(None) => not_found(),
        Err(e) => server_error(format!("audit verify: {e}")),
    }
}

async fn proc_reserved(method: Method) -> Response {
    match method {
        Method::OPTIONS => options_response(PROC_ALLOW),
        Method::GET | Method::HEAD => not_found(),
        _ => method_not_allowed(PROC_ALLOW),
    }
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
    if !valid_world_name(&world_name) {
        return bad_request("world path contains control bytes");
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);

    handle_world_method(&core, method, &world_name, &headers, body, tier).await
}

async fn handle_world_method(
    core: &Core,
    method: Method,
    world_name: &str,
    headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    match method {
        Method::OPTIONS => options_response(WORLD_ALLOW),
        Method::GET => handle_get(core, world_name, headers, tier),
        Method::HEAD => handle_head(core, world_name, headers, tier),
        Method::PUT => handle_put(core, world_name, headers, body, tier).await,
        Method::POST => handle_post(core, world_name, headers, body, tier).await,
        Method::DELETE => handle_delete(core, world_name, headers, tier).await,
        _ => method_not_allowed(WORLD_ALLOW),
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

fn valid_world_name(world_name: &str) -> bool {
    !world_name.is_empty()
        && !is_reserved_world_name(world_name)
        && !world_name.contains('\\')
        && !world_name.chars().any(char::is_control)
        && world_name
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn is_reserved_world_name(world_name: &str) -> bool {
    matches!(
        world_name,
        "home"
            | "tmp"
            | "dev"
            | "sys"
            | "proc"
            | "etc"
            | "lib"
            | "boot"
            | "usr"
            | "var"
            | "var/log"
    ) || world_name.starts_with("proc/")
}

// ─── handlers ───────────────────────────────────────────────────────

/// GET: body bytes with stored Content-Type. No JSON envelope.
fn handle_get(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    tier: auth::Tier,
) -> Response {
    if !can_read(core, tier) {
        return unauthorized("read requires read token");
    }
    let Some((stage, etag)) = core.read_world_with_etag(world_name) else {
        return not_found();
    };
    if hs::read_not_modified(req_headers, &etag) {
        return hs::not_modified(world_name, &etag, &stage);
    }
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(world_name, &mut resp_headers);
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(req_headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            let chunk = stage.body[start..=end].to_vec();
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&chunk.len().to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
            ));
            return (
                StatusCode::PARTIAL_CONTENT,
                to_header_map(resp_headers),
                chunk,
            )
                .into_response();
        }
        Ok(None) => {
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
            ));
        }
        Err(()) => return hs::range_not_satisfiable(stage.body.len()),
    }
    (StatusCode::OK, to_header_map(resp_headers), stage.body).into_response()
}

/// HEAD — same headers as GET, no body.
fn handle_head(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    tier: auth::Tier,
) -> Response {
    if !can_read(core, tier) {
        return unauthorized("read requires read token");
    }
    let Some((stage, etag)) = core.read_world_with_etag(world_name) else {
        return not_found();
    };
    if hs::read_not_modified(req_headers, &etag) {
        return hs::not_modified(world_name, &etag, &stage);
    }
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
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::ETAG, hs::etag_header(&etag)),
    ];
    hs::apply_world_links(world_name, &mut resp_headers);
    apply_meta_headers(&stage.headers, &mut resp_headers);
    match hs::effective_range(req_headers, stage.body.len(), &etag) {
        Ok(Some((start, end))) => {
            resp_headers.retain(|(name, _)| name != header::CONTENT_LENGTH);
            resp_headers.push((
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&(end - start + 1).to_string()).unwrap(),
            ));
            resp_headers.push((
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", stage.body.len()))
                    .unwrap(),
            ));
            return (StatusCode::PARTIAL_CONTENT, to_header_map(resp_headers), "").into_response();
        }
        Ok(None) => {}
        Err(()) => return hs::range_not_satisfiable(stage.body.len()),
    }
    (StatusCode::OK, to_header_map(resp_headers), "").into_response()
}

async fn handle_put(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    let content_type = hs::request_content_type(req_headers);

    let meta = hs::request_meta_headers(req_headers);

    let outcome = match core
        .put_bytes(
            world_name,
            &body,
            &content_type,
            &meta,
            tier,
            Some(req_headers),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(resp) => return resp,
    };

    let mut resp_headers = vec![(header::ETAG, hs::etag_header(&outcome.etag))];
    if outcome.status == StatusCode::CREATED {
        resp_headers.push((
            header::LOCATION,
            HeaderValue::from_str(&hs::world_url(world_name))
                .unwrap_or_else(|_| HeaderValue::from_static("/")),
        ));
    }
    (outcome.status, to_header_map(resp_headers), "").into_response()
}

/// POST — append body bytes to existing world. 404 if world absent
/// (PUT is the create/replace path). Never updates X-Meta-*.
async fn handle_post(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    if !can_write(world_name, tier) {
        return unauthorized("write requires token; system worlds need approve token");
    }
    let _write_guard = core.write_lock.lock().await;
    if let Err(resp) = hs::check_write_preconditions(core, world_name, req_headers) {
        return resp;
    }
    let Some(stage) = core.read_world(world_name) else {
        return not_found();
    };
    let Some(projected_len) = stage.body.len().checked_add(body.len()) else {
        return payload_too_large(core.max_world_bytes);
    };
    if projected_len > core.max_world_bytes {
        return payload_too_large(core.max_world_bytes);
    }
    let new_etag = if store::is_persistent(world_name) {
        match world::append_with_audit(
            &core.data,
            world_name,
            &body,
            &stage.content_type,
            &stage.headers,
            &core.hmac_key,
        ) {
            Ok(Some((_result, h))) => hs::hmac_etag(&h),
            Ok(None) => return not_found(),
            Err(e) => return server_error(format!("storage/audit: {e}")),
        }
    } else {
        if memory_append_projected_bytes(core, world_name, body.len()) > core.max_memory_bytes {
            return payload_too_large(core.max_memory_bytes);
        }
        let result = match core.append_world(world_name, &body) {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(),
            Err(e) => return server_error(format!("storage: {e}")),
        };
        format!("sha256-{}", result.body_sha256_after)
    };

    let resp_headers = [(header::ETAG, hs::etag_header(&new_etag))];
    core.notify("POST", world_name, &new_etag);
    (StatusCode::OK, resp_headers, "").into_response()
}

async fn handle_delete(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
    tier: auth::Tier,
) -> Response {
    if !can_delete(tier) {
        return unauthorized("delete requires token; system worlds need approve token");
    }
    if world_name == "var/log/deletes" {
        return unauthorized("delete ledger is append-only");
    }
    let _write_guard = core.write_lock.lock().await;
    if let Err(resp) = hs::check_write_preconditions(core, world_name, req_headers) {
        return resp;
    }

    // Capture body hash BEFORE the world disappears. A missing world is
    // not a delete event; do not mutate the ledger for a 404.
    let Some(stage) = core.read_world(world_name) else {
        return not_found();
    };
    let body_sha256_before = world::sha256_hex(&stage.body);

    let ok = core.delete_world(world_name);
    if !ok {
        return server_error("delete failed after preflight".to_string());
    }

    // Audit AFTER the disk op, so the global ledger records successful
    // deletion, not merely an attempt. The ledger itself is sqlite even
    // when the deleted world was memory-backed.
    let delete_meta = hs::request_meta_headers(req_headers);
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
    core.notify("DELETE", world_name, "");
    (StatusCode::NO_CONTENT, "").into_response()
}

// ─── helpers ────────────────────────────────────────────────────────

fn can_write(world_name: &str, tier: auth::Tier) -> bool {
    // Harvard gate: /lib/, /etc/, /boot/, /usr/, and audit logs
    // require approve. /home/, /tmp/, /dev/, /sys/, and non-log
    // /var/ worlds accept the normal token. Anon refused.
    let needs_approve = exact_or_child(world_name, "lib")
        || exact_or_child(world_name, "etc")
        || exact_or_child(world_name, "boot")
        || exact_or_child(world_name, "usr")
        || exact_or_child(world_name, "var/log");
    match tier {
        auth::Tier::Anon => false,
        auth::Tier::Read => false,
        auth::Tier::Write => !needs_approve,
        auth::Tier::Approve => true,
    }
}

fn can_delete(tier: auth::Tier) -> bool {
    matches!(tier, auth::Tier::Approve)
}

fn memory_write_projected_bytes(core: &Core, world_name: &str, new_len: usize) -> usize {
    let current_len = core
        .mem
        .read(world_name)
        .map(|stage| stage.body.len())
        .unwrap_or(0);
    core.mem
        .total_bytes()
        .saturating_sub(current_len)
        .saturating_add(new_len)
}

fn memory_append_projected_bytes(core: &Core, _world_name: &str, add_len: usize) -> usize {
    core.mem.total_bytes().saturating_add(add_len)
}

fn exact_or_child(world_name: &str, prefix: &str) -> bool {
    world_name == prefix
        || world_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn can_read(core: &Core, tier: auth::Tier) -> bool {
    !core.tokens.read_required()
        || matches!(
            tier,
            auth::Tier::Read | auth::Tier::Write | auth::Tier::Approve
        )
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

fn audit_valid(report: audit::VerifyOk) -> Response {
    (
        StatusCode::OK,
        to_header_map(vec![
            (
                HeaderName::from_static("x-audit-valid"),
                HeaderValue::from_static("true"),
            ),
            (
                HeaderName::from_static("x-audit-events"),
                HeaderValue::from_str(&report.events.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-audit-genesis"),
                audit_header_value(&report.genesis),
            ),
            (
                HeaderName::from_static("x-audit-latest"),
                audit_header_value(&report.latest),
            ),
            (header::CONTENT_LENGTH, HeaderValue::from_static("0")),
        ]),
        "",
    )
        .into_response()
}

fn audit_broken(report: audit::VerifyBreak) -> Response {
    (
        StatusCode::CONFLICT,
        to_header_map(vec![
            (
                HeaderName::from_static("x-audit-valid"),
                HeaderValue::from_static("false"),
            ),
            (
                HeaderName::from_static("x-audit-break-at"),
                HeaderValue::from_str(&report.break_at.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-audit-expected"),
                audit_header_value(&report.expected),
            ),
            (
                HeaderName::from_static("x-audit-actual"),
                audit_header_value(&report.actual),
            ),
            (header::CONTENT_LENGTH, HeaderValue::from_static("0")),
        ]),
        "",
    )
        .into_response()
}

fn audit_header_value(value: &str) -> HeaderValue {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    HeaderValue::from_str(&out).expect("escaped audit header is visible ASCII")
}

fn audit_not_applicable() -> Response {
    (
        StatusCode::NO_CONTENT,
        to_header_map(vec![
            (
                HeaderName::from_static("x-audit-valid"),
                HeaderValue::from_static("n/a"),
            ),
            (header::CONTENT_LENGTH, HeaderValue::from_static("0")),
        ]),
        "",
    )
        .into_response()
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

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("bad request: {msg}\n"),
    )
        .into_response()
}

fn payload_too_large(max_bytes: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("payload too large: max bytes {max_bytes}\n"),
    )
        .into_response()
}

fn options_response(allow: &'static str) -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::ALLOW, allow), (header::CONTENT_LENGTH, "0")],
        "",
    )
        .into_response()
}

fn method_not_allowed(allow: &'static str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::ALLOW, allow),
        ],
        "method not allowed\n",
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
    use std::sync::{Mutex as TestMutex, OnceLock};

    fn env_lock() -> &'static TestMutex<()> {
        static LOCK: OnceLock<TestMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TestMutex::new(()))
    }

    struct CoapEnvGuard {
        host: Option<String>,
        port: Option<String>,
    }

    impl CoapEnvGuard {
        fn capture() -> Self {
            Self {
                host: std::env::var("ELASTIK_COAP_HOST").ok(),
                port: std::env::var("ELASTIK_COAP_PORT").ok(),
            }
        }
    }

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

    #[test]
    fn var_log_requires_approve_token() {
        assert!(!can_write("var/log", auth::Tier::Anon));
        assert!(!can_write("var/log", auth::Tier::Read));
        assert!(!can_write("var/log", auth::Tier::Write));
        assert!(can_write("var/log", auth::Tier::Approve));
        assert!(!can_write("var/log/deletes", auth::Tier::Anon));
        assert!(!can_write("var/log/deletes", auth::Tier::Read));
        assert!(!can_write("var/log/deletes", auth::Tier::Write));
        assert!(can_write("var/log/deletes", auth::Tier::Approve));
    }

    #[test]
    fn delete_requires_approve_token() {
        assert!(!can_delete(auth::Tier::Anon));
        assert!(!can_delete(auth::Tier::Read));
        assert!(!can_delete(auth::Tier::Write));
        assert!(can_delete(auth::Tier::Approve));
    }

    #[test]
    fn listen_addr_brackets_ipv6_hosts() {
        assert_eq!(listen_addr("127.0.0.1", 3105), "127.0.0.1:3105");
        assert_eq!(listen_addr("0.0.0.0", 3105), "0.0.0.0:3105");
        assert_eq!(listen_addr("::1", 3105), "[::1]:3105");
        assert_eq!(listen_addr("localhost", 3105), "localhost:3105");
    }

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

    #[test]
    fn non_loopback_public_read_gets_warning_flag() {
        let mut tokens = auth::Tokens {
            read: None,
            write: None,
            approve: None,
        };
        assert!(!should_warn_public_read(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            &tokens
        ));
        assert!(should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            &tokens
        ));

        tokens.read = Some(b"reader".to_vec());
        assert!(!should_warn_public_read(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            &tokens
        ));
    }

    #[tokio::test]
    async fn put_and_post_enforce_world_size_cap() {
        let (mut core, dir) = test_core("world-size-cap");
        core.max_world_bytes = 4;
        let headers = HeaderMap::new();

        let too_big = handle_put(
            &core,
            "home/too-big",
            &headers,
            Bytes::from_static(b"12345"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let ok = handle_put(
            &core,
            "home/four",
            &headers,
            Bytes::from_static(b"1234"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(ok.status(), StatusCode::CREATED);

        let append = handle_post(
            &core,
            "home/four",
            &headers,
            Bytes::from_static(b"5"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(append.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn memory_backend_enforces_total_quota() {
        let (mut core, dir) = test_core("memory-quota");
        core.max_memory_bytes = 4;
        let headers = HeaderMap::new();

        let first = handle_put(
            &core,
            "tmp/a",
            &headers,
            Bytes::from_static(b"12"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        let second = handle_put(
            &core,
            "tmp/b",
            &headers,
            Bytes::from_static(b"34"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(second.status(), StatusCode::CREATED);
        let third = handle_put(
            &core,
            "tmp/c",
            &headers,
            Bytes::from_static(b"5"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(third.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn system_namespace_roots_require_approve_even_if_called_directly() {
        for name in ["lib", "etc", "boot", "usr"] {
            assert!(!can_write(name, auth::Tier::Anon), "{name}");
            assert!(!can_write(name, auth::Tier::Read), "{name}");
            assert!(!can_write(name, auth::Tier::Write), "{name}");
            assert!(can_write(name, auth::Tier::Approve), "{name}");
        }
    }

    #[test]
    fn non_log_var_still_accepts_auth_token() {
        assert!(!can_write("var/cache/rag", auth::Tier::Anon));
        assert!(!can_write("var/cache/rag", auth::Tier::Read));
        assert!(can_write("var/cache/rag", auth::Tier::Write));
        assert!(can_write("var/cache/rag", auth::Tier::Approve));
    }

    #[test]
    fn read_token_is_optional_but_gates_reads_when_set() {
        let (mut core, dir) = test_core("read-token");
        assert!(can_read(&core, auth::Tier::Anon));

        core.tokens.read = Some(b"reader".to_vec());
        assert!(!can_read(&core, auth::Tier::Anon));
        assert!(can_read(&core, auth::Tier::Read));
        assert!(can_read(&core, auth::Tier::Write));
        assert!(can_read(&core, auth::Tier::Approve));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_and_head_require_read_token_when_enabled() {
        let (mut core, dir) = test_core("read-token-handlers");
        core.write_world("home/private", b"secret", "text/plain", &[])
            .unwrap();
        core.tokens.read = Some(b"reader".to_vec());

        let headers = HeaderMap::new();
        let get_anon = handle_get(&core, "home/private", &headers, auth::Tier::Anon);
        assert_eq!(get_anon.status(), StatusCode::UNAUTHORIZED);
        let head_reader = handle_head(&core, "home/private", &headers, auth::Tier::Read);
        assert_eq!(head_reader.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unauthorized_responses_advertise_bearer_challenge() {
        let resp = unauthorized("read requires read token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"elastik\""
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn core_response_headers_are_core_owned() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("*"));
        headers.insert("x-request-id", HeaderValue::from_static("stale"));
        headers.insert("x-elapsed-us", HeaderValue::from_static("999"));
        headers.insert("x-content-type-options", HeaderValue::from_static("sniff"));

        stamp_core_response_headers(42, 7, &mut headers);

        assert_eq!(headers.get("x-request-id").unwrap(), "42");
        assert_eq!(headers.get("x-elapsed-us").unwrap(), "7");
        assert_eq!(headers.get(header::VARY).unwrap(), "Authorization");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
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
    fn control_bytes_are_not_valid_world_names() {
        assert!(valid_world_name("home/ok"));
        assert!(!valid_world_name("home/bad\nname"));
        assert!(!valid_world_name(""));
    }

    #[test]
    fn dot_segments_empty_segments_and_backslashes_are_not_valid_world_names() {
        assert!(!valid_world_name("home/../etc/secret"));
        assert!(!valid_world_name("home/./x"));
        assert!(!valid_world_name("home//x"));
        assert!(!valid_world_name("home/x/"));
        assert!(!valid_world_name("home\\x"));
    }

    #[test]
    fn namespace_roots_and_proc_subtree_are_not_world_names() {
        for name in [
            "home",
            "tmp",
            "dev",
            "sys",
            "proc",
            "proc/anything",
            "etc",
            "lib",
            "boot",
            "usr",
            "var",
            "var/log",
        ] {
            assert!(!valid_world_name(name), "{name}");
        }
        assert!(valid_world_name("home/x"));
        assert!(valid_world_name("var/log/deletes"));
    }

    #[test]
    fn byte_ranges_cover_normal_open_and_suffix_forms() {
        let mut h = HeaderMap::new();
        assert_eq!(hs::parse_range(&h, 10), Ok(None));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((2, 5))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=7-"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=-3"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=8-99"));
        assert_eq!(hs::parse_range(&h, 10), Ok(Some((8, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=11-12"));
        assert_eq!(hs::parse_range(&h, 10), Err(()));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));
        assert_eq!(hs::parse_range(&h, 10), Ok(None));
    }

    #[test]
    fn get_and_head_honor_single_byte_range() {
        let (core, dir) = test_core("range-handler");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

        let get = handle_get(&core, "home/range", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            get.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 1-3/6"
        );
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

        let head = handle_head(&core, "home/range", &headers, auth::Tier::Anon);
        assert_eq!(head.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            head.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 1-3/6"
        );
        assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_and_head_advertise_accept_ranges_on_full_body() {
        let (core, dir) = test_core("accept-ranges");
        core.write_world("home/ranges", b"abcdef", "text/plain", &[])
            .unwrap();
        let headers = HeaderMap::new();

        let get = handle_get(&core, "home/ranges", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let head = handle_head(&core, "home/ranges", &headers, auth::Tier::Anon);
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unsatisfied_range_returns_416_with_content_range() {
        let (core, dir) = test_core("range-416");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=99-100"));

        let get = handle_get(&core, "home/range", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            get.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes */6"
        );
        assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn multi_range_is_ignored_and_returns_full_body() {
        let (core, dir) = test_core("multi-range");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));

        let get = handle_get(&core, "home/range", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::OK);
        assert!(get.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn world_reads_advertise_monitor_and_collection_links() {
        let (core, dir) = test_core("link-headers");
        core.write_world("home/links", b"hello", "text/plain", &[])
            .unwrap();
        let headers = HeaderMap::new();

        let get = handle_get(&core, "home/links", &headers, auth::Tier::Anon);
        let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
        assert_eq!(links.len(), 2);
        assert!(links
            .iter()
            .any(|v| *v == "</listen/home/links>; rel=\"monitor\""));
        assert!(links
            .iter()
            .any(|v| *v == "</proc/worlds>; rel=\"collection\""));

        let head = handle_head(&core, "home/links", &headers, auth::Tier::Anon);
        assert_eq!(head.headers().get_all(header::LINK).iter().count(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn if_range_controls_whether_range_is_applied() {
        let mut h = HeaderMap::new();
        h.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("\"hmac-current\""),
        );
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(Some((1, 3))));

        h.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(None));

        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("W/\"hmac-current\""),
        );
        assert_eq!(hs::effective_range(&h, 6, "hmac-current"), Ok(None));
    }

    #[test]
    fn stale_if_range_returns_full_body() {
        let (core, dir) = test_core("if-range-stale");
        core.write_world("home/range", b"abcdef", "text/plain", &[])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
        headers.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));

        let get = handle_get(&core, "home/range", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::OK);
        assert!(get.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_and_head_honor_if_none_match_cache_revalidation() {
        let (core, dir) = test_core("read-if-none-match");
        let h = world::write_with_audit(
            &core.data,
            "home/cache",
            b"cached body",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let etag = format!("\"{}\"", hs::hmac_etag(&h));
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());

        let get = handle_get(&core, "home/cache", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(get.headers().get(header::ETAG).unwrap(), etag.as_str());
        assert!(get
            .headers()
            .get_all(header::LINK)
            .iter()
            .any(|v| v == "</listen/home/cache>; rel=\"monitor\""));

        let head = handle_head(&core, "home/cache", &headers, auth::Tier::Anon);
        assert_eq!(head.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(head.headers().get(header::ETAG).unwrap(), etag.as_str());

        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"hmac-stale\""),
        );
        let get = handle_get(&core, "home/cache", &headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn options_and_405_advertise_allow_headers() {
        let (core, dir) = test_core("allow");
        let headers = HeaderMap::new();

        let options = handle_world_method(
            &core,
            Method::OPTIONS,
            "home/allow",
            &headers,
            Bytes::new(),
            auth::Tier::Anon,
        )
        .await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let patch = handle_world_method(
            &core,
            Method::PATCH,
            "home/allow",
            &headers,
            Bytes::new(),
            auth::Tier::Anon,
        )
        .await;
        assert_eq!(patch.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(patch.headers().get(header::ALLOW).unwrap(), WORLD_ALLOW);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn root_and_proc_endpoints_advertise_head_options_and_405() {
        let root_head = root_hint(Method::HEAD).await;
        assert_eq!(root_head.status(), StatusCode::OK);
        assert_eq!(
            root_head.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(root_head.headers().get(header::CONTENT_LENGTH).is_some());

        let root_options = root_hint(Method::OPTIONS).await;
        assert_eq!(root_options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            root_options.headers().get(header::ALLOW).unwrap(),
            ROOT_ALLOW
        );

        let root_post = root_hint(Method::POST).await;
        assert_eq!(root_post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(root_post.headers().get(header::ALLOW).unwrap(), ROOT_ALLOW);

        let version_head = proc_version(Method::HEAD).await;
        assert_eq!(version_head.status(), StatusCode::OK);
        assert!(version_head.headers().get(header::CONTENT_LENGTH).is_some());

        let version_delete = proc_version(Method::DELETE).await;
        assert_eq!(version_delete.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            version_delete.headers().get(header::ALLOW).unwrap(),
            PROC_ALLOW
        );
    }

    #[tokio::test]
    async fn proc_worlds_head_options_and_405_are_plain_http() {
        let (core, dir) = test_core("proc-worlds-http");
        core.write_world("home/a", b"a", "text/plain", &[]).unwrap();
        let state = Arc::new(core);
        let headers = HeaderMap::new();

        let head = proc_worlds(State(state.clone()), Method::HEAD, headers.clone()).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(head.headers().get(header::CONTENT_LENGTH).is_some());

        let options = proc_worlds(State(state.clone()), Method::OPTIONS, headers.clone()).await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let delete = proc_worlds(State(state), Method::DELETE, headers).await;
        assert_eq!(delete.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(delete.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_namespace_is_reserved_beyond_declared_endpoints() {
        let not_found = proc_reserved(Method::GET).await;
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let head = proc_reserved(Method::HEAD).await;
        assert_eq!(head.status(), StatusCode::NOT_FOUND);

        let options = proc_reserved(Method::OPTIONS).await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(options.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);

        let put = proc_reserved(Method::PUT).await;
        assert_eq!(put.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(put.headers().get(header::ALLOW).unwrap(), PROC_ALLOW);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_valid_chain_in_headers() {
        let (core, dir) = test_core("proc-audit-valid");
        let h = world::write_with_audit(
            &core.data,
            "home/audit-ok",
            b"hello",
            "text/plain",
            &[("x-meta-author".to_owned(), "ranger".to_owned())],
            &core.hmac_key,
        )
        .unwrap();
        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-ok/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "true");
        assert_eq!(resp.headers().get("x-audit-events").unwrap(), "1");
        assert_eq!(
            resp.headers().get("x-audit-latest").unwrap(),
            &format!("hmac-{h}")
        );
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "0");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_broken_chain_in_headers() {
        let (core, dir) = test_core("proc-audit-broken");
        world::write_with_audit(
            &core.data,
            "home/audit-broken",
            b"hello",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let db = world::world_db(&core.data, "home/audit-broken");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute("UPDATE events SET hmac='bad' WHERE id=1", [])
            .unwrap();

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-broken/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "false");
        assert_eq!(resp.headers().get("x-audit-break-at").unwrap(), "0");
        assert_eq!(resp.headers().get("x-audit-actual").unwrap(), "hmac-bad");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_escapes_tampered_header_values() {
        let (core, dir) = test_core("proc-audit-header-escape");
        world::write_with_audit(
            &core.data,
            "home/audit-escaped",
            b"hello",
            "text/plain",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let db = world::world_db(&core.data, "home/audit-escaped");
        let c = rusqlite::Connection::open(db).unwrap();
        c.execute(
            "UPDATE events SET hmac=? WHERE id=1",
            ["bad\nInjected: yes"],
        )
        .unwrap();

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/audit-escaped/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers().get("x-audit-actual").unwrap(),
            "hmac-bad\\x0aInjected: yes"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_reports_memory_world_not_applicable() {
        let (core, dir) = test_core("proc-audit-memory");
        core.write_world("tmp/scratch", b"draft", "text/plain", &[])
            .unwrap();
        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("tmp/scratch/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("x-audit-valid").unwrap(), "n/a");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn proc_audit_verify_missing_disk_world_does_not_create_db() {
        let (core, dir) = test_core("proc-audit-missing-no-create");
        let db = world::world_db(&core.data, "home/missing-audit");
        assert!(!db.exists());

        let state = Arc::new(core);
        let resp = proc_audit_verify(
            State(state),
            Method::HEAD,
            AxPath("home/missing-audit/verify".to_owned()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!db.exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn put_created_returns_location() {
        let (core, dir) = test_core("put-location");
        let headers = HeaderMap::new();
        let resp = handle_put(
            &core,
            "home/created",
            &headers,
            Bytes::from_static(b"new"),
            auth::Tier::Write,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/home/created"
        );

        let resp = handle_put(
            &core,
            "home/created",
            &headers,
            Bytes::from_static(b"again"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::LOCATION).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn location_and_link_headers_percent_encode_world_urls() {
        let (core, dir) = test_core("encoded-headers");
        let headers = HeaderMap::new();
        let resp = handle_put(
            &core,
            "home/café report",
            &headers,
            Bytes::from_static(b"new"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/home/caf%C3%A9%20report"
        );

        let get = handle_get(&core, "home/café report", &headers, auth::Tier::Anon);
        let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
        assert!(links
            .iter()
            .any(|v| *v == "</listen/home/caf%C3%A9%20report>; rel=\"monitor\""));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unicode_worlds_roundtrip_body_headers_and_proc_listing() {
        let (core, dir) = test_core("unicode-roundtrip");
        let headers = vec![(
            "content-disposition".to_string(),
            "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf".to_string(),
        )];
        core.write_world(
            "home/销售/报告",
            "你好，世界".as_bytes(),
            "text/plain; charset=utf-8",
            &headers,
        )
        .unwrap();

        let req_headers = HeaderMap::new();
        let get = handle_get(&core, "home/销售/报告", &req_headers, auth::Tier::Anon);
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            get.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf"
        );
        assert!(
            get.headers()
                .get_all(header::LINK)
                .iter()
                .any(|v| *v
                    == "</listen/home/%E9%94%80%E5%94%AE/%E6%8A%A5%E5%91%8A>; rel=\"monitor\"")
        );

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(world_list_body(&names), "home/销售/报告\n");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn etag_lists_match_http_strong_and_weak_rules() {
        assert!(hs::etag_list_strong_matches("\"hmac-abc\"", "hmac-abc"));
        assert!(hs::etag_list_strong_matches(
            "\"other\", \"hmac-abc\"",
            "hmac-abc"
        ));
        assert!(hs::etag_list_strong_matches("*", "hmac-abc"));
        assert!(!hs::etag_list_strong_matches("W/\"hmac-abc\"", "hmac-abc"));
        assert!(!hs::etag_list_strong_matches("\"other\"", "hmac-abc"));

        assert!(hs::etag_list_weak_matches("W/\"hmac-abc\"", "hmac-abc"));
    }

    #[test]
    fn if_none_match_star_blocks_existing_world() {
        let (core, dir) = test_core("if-none-match-star");
        core.write_world("home/cas", b"one", "text/plain; charset=utf-8", &[])
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));

        assert!(hs::check_write_preconditions(&core, "home/cas", &headers).is_err());
        assert!(hs::check_write_preconditions(&core, "home/new", &headers).is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn put_and_post_honor_write_preconditions_at_handler_level() {
        let (core, dir) = test_core("write-preconditions");
        let h = world::write_with_audit(
            &core.data,
            "home/cas",
            b"one",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        let put = handle_put(
            &core,
            "home/cas",
            &stale,
            Bytes::from_static(b"two"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(put.status(), StatusCode::PRECONDITION_FAILED);

        let post = handle_post(
            &core,
            "home/cas",
            &stale,
            Bytes::from_static(b" plus"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(post.status(), StatusCode::PRECONDITION_FAILED);

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", hs::hmac_etag(&h))).unwrap(),
        );
        let post = handle_post(
            &core,
            "home/cas",
            &good,
            Bytes::from_static(b" plus"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(post.status(), StatusCode::OK);

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
        let etag = format!("\"{}\"", hs::hmac_etag(&h));

        let mut good = HeaderMap::new();
        good.insert(header::IF_MATCH, HeaderValue::from_str(&etag).unwrap());
        assert!(hs::check_write_preconditions(&core, "home/cas", &good).is_ok());

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        assert!(hs::check_write_preconditions(&core, "home/cas", &stale).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_content_type_preserves_http_content_type_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        );
        assert_eq!(hs::request_content_type(&headers), "application/pdf");

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        assert_eq!(
            hs::request_content_type(&headers),
            "text/html; charset=utf-8"
        );

        headers.clear();
        assert_eq!(
            hs::request_content_type(&headers),
            "application/octet-stream"
        );
    }

    #[test]
    fn request_meta_headers_persist_safe_response_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"report.pdf\""),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, HEAD"),
        );
        headers.insert(
            "access-control-expose-headers",
            HeaderValue::from_static("ETag"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert("permissions-policy", HeaderValue::from_static("camera=()"));
        headers.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        headers.insert("x-future-http-thing", HeaderValue::from_static("ok"));
        headers.insert("x-meta-author", HeaderValue::from_static("ranger"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(header::COOKIE, HeaderValue::from_static("sid=secret"));
        headers.insert(header::SET_COOKIE, HeaderValue::from_static("sid=secret"));
        headers.insert(header::HOST, HeaderValue::from_static("localhost:3105"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::TRAILER, HeaderValue::from_static("expires"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("http2-settings", HeaderValue::from_static("abc"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("999"));
        headers.insert(header::ETAG, HeaderValue::from_static("\"fake\""));
        headers.insert(header::ALLOW, HeaderValue::from_static("GET"));
        headers.insert(header::LOCATION, HeaderValue::from_static("/elsewhere"));
        headers.insert(header::LINK, HeaderValue::from_static("</x>; rel=\"next\""));
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"x\""),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        headers.insert("accept-charset", HeaderValue::from_static("utf-8"));
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"abc\""));
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"abc\""));
        headers.insert(header::IF_RANGE, HeaderValue::from_static("\"abc\""));
        headers.insert(
            header::IF_MODIFIED_SINCE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(
            header::IF_UNMODIFIED_SINCE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        headers.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\""));
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://example.com/"),
        );
        headers.insert(header::USER_AGENT, HeaderValue::from_static("curl"));
        headers.insert(header::SERVER, HeaderValue::from_static("fake"));
        headers.insert(
            header::DATE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        headers.insert(header::AGE, HeaderValue::from_static("10"));
        headers.insert(header::VARY, HeaderValue::from_static("*"));
        headers.insert("via", HeaderValue::from_static("1.1 proxy"));
        headers.insert("forwarded", HeaderValue::from_static("for=127.0.0.1"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let meta = hs::request_meta_headers(&headers);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        assert!(meta.contains(&("content-encoding".to_string(), "gzip".to_string())));
        assert!(meta.contains(&("content-language".to_string(), "zh-CN".to_string())));
        assert!(meta.contains(&(
            "content-disposition".to_string(),
            "attachment; filename=\"report.pdf\"".to_string()
        )));
        assert!(meta.contains(&("cache-control".to_string(), "max-age=60".to_string())));
        assert!(meta.contains(&("x-meta-author".to_string(), "ranger".to_string())));
        assert!(meta.contains(&("access-control-allow-origin".to_string(), "*".to_string())));
        assert!(meta.contains(&(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string()
        )));
        assert!(meta.contains(&("x-frame-options".to_string(), "DENY".to_string())));
        assert!(meta.contains(&("permissions-policy".to_string(), "camera=()".to_string())));
        assert!(meta.contains(&("x-future-http-thing".to_string(), "ok".to_string())));

        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "host",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "http2-settings",
            "content-type",
            "content-length",
            "etag",
            "allow",
            "location",
            "link",
            "www-authenticate",
            "accept",
            "accept-encoding",
            "accept-language",
            "accept-charset",
            "range",
            "if-match",
            "if-none-match",
            "if-range",
            "if-modified-since",
            "if-unmodified-since",
            "expect",
            "sec-fetch-mode",
            "sec-ch-ua",
            "dnt",
            "origin",
            "referer",
            "user-agent",
            "server",
            "date",
            "age",
            "vary",
            "x-request-id",
            "x-elapsed-us",
            "x-elapsed-ms",
            "x-content-type-options",
            "via",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            assert!(!has(name), "{name} should not be persisted");
        }
    }

    #[test]
    fn request_meta_headers_deduplicate_repeated_names_last_wins() {
        let mut headers = HeaderMap::new();
        headers.append("x-meta-author", HeaderValue::from_static("alice"));
        headers.append("x-meta-author", HeaderValue::from_static("bob"));

        let meta = hs::request_meta_headers(&headers);

        assert_eq!(meta, vec![("x-meta-author".to_string(), "bob".to_string())]);
    }

    #[test]
    fn get_returns_stored_standard_representation_headers() {
        let (core, dir) = test_core("representation-headers");
        let headers = vec![
            ("content-encoding".to_string(), "gzip".to_string()),
            (
                "content-disposition".to_string(),
                "attachment; filename=\"report.pdf\"".to_string(),
            ),
            ("access-control-allow-origin".to_string(), "*".to_string()),
            (
                "content-security-policy".to_string(),
                "default-src 'self'".to_string(),
            ),
            ("x-frame-options".to_string(), "DENY".to_string()),
        ];
        core.write_world(
            "home/gzip",
            b"compressed bytes",
            "application/pdf",
            &headers,
        )
        .unwrap();

        let req_headers = HeaderMap::new();
        let resp = handle_get(&core, "home/gzip", &req_headers, auth::Tier::Anon);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"report.pdf\""
        );
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");

        let _ = std::fs::remove_dir_all(dir);
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
    fn storage_prefix_routes_memory_and_disk_modes() {
        assert!(!store::is_memory_world("home/report"));
        assert!(!store::is_memory_world("etc/config"));
        assert!(store::is_memory_world("tmp/scratch"));
        assert!(store::is_memory_world("dev/fb0"));
        assert!(store::is_memory_world("sys/status"));
        assert!(store::is_persistent("home/report"));
        assert!(!store::is_persistent("tmp/scratch"));
    }

    #[test]
    fn memory_worlds_do_not_create_sqlite_files_or_audit_chain() {
        let (core, dir) = test_core("memory-world");
        core.write_world(
            "tmp/scratch",
            b"draft",
            "text/plain; charset=utf-8",
            &[("x-meta-owner".to_string(), "agent".to_string())],
        )
        .unwrap();

        let stage = core.read_world("tmp/scratch").unwrap();
        assert_eq!(stage.body, b"draft");
        assert_eq!(stage.content_type, "text/plain; charset=utf-8");
        assert_eq!(
            stage.headers,
            vec![("x-meta-owner".to_string(), "agent".to_string())]
        );
        assert!(!world::world_db(&core.data, "tmp/scratch").exists());
        assert!(audit::latest_hmac(&core.data, "tmp/scratch").is_none());

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(names, vec!["tmp/scratch".to_string()]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disk_worlds_create_sqlite_files_and_audit_chain_when_using_audit_path() {
        let (core, dir) = test_core("disk-world");
        let h = world::write_with_audit(
            &core.data,
            "home/report",
            b"final",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();

        let stage = core.read_world("home/report").unwrap();
        assert_eq!(stage.body, b"final");
        assert!(world::world_db(&core.data, "home/report").exists());
        assert_eq!(audit::latest_hmac(&core.data, "home/report"), Some(h));

        let names = store::list_all(&core.data, &core.mem);
        assert_eq!(names, vec!["home/report".to_string()]);

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

    #[tokio::test]
    async fn post_audit_uses_existing_representation_metadata() {
        let (core, dir) = test_core("post-audit-meta");
        let headers = vec![
            ("content-encoding".to_string(), "gzip".to_string()),
            ("x-meta-author".to_string(), "ranger".to_string()),
        ];
        world::write_with_audit(
            &core.data,
            "home/post-audit-meta",
            b"hello",
            "text/plain",
            &headers,
            &core.hmac_key,
        )
        .unwrap();

        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        );
        req_headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
        let resp = handle_post(
            &core,
            "home/post-audit-meta",
            &req_headers,
            Bytes::from_static(b" world"),
            auth::Tier::Write,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let c = rusqlite::Connection::open(world::world_db(&core.data, "home/post-audit-meta"))
            .unwrap();
        let (content_type, meta_sha256): (String, String) = c
            .query_row(
                "SELECT content_type, meta_sha256 FROM events WHERE event_type='append'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(content_type, "text/plain");
        assert_eq!(meta_sha256, audit::meta_sha256("text/plain", &headers));

        let language_count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM event_headers WHERE name='content-language'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(language_count, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_honors_if_match_before_audit_or_remove() {
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
        let resp = handle_delete(&core, "home/delete-cas", &stale, auth::Tier::Approve).await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(core.read_world("home/delete-cas").is_some());

        let mut good = HeaderMap::new();
        good.insert(
            header::IF_MATCH,
            HeaderValue::from_str(&format!("\"{}\"", hs::hmac_etag(&h))).unwrap(),
        );
        let resp = handle_delete(&core, "home/delete-cas", &good, auth::Tier::Approve).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(core.read_world("home/delete-cas").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_rejects_auth_token_and_append_only_ledger() {
        let (core, dir) = test_core("delete-policy");
        world::write_with_audit(
            &core.data,
            "home/delete-policy",
            b"alive",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        world::write_with_audit(
            &core.data,
            "var/log/deletes",
            b"ledger",
            "text/plain; charset=utf-8",
            &[],
            &core.hmac_key,
        )
        .unwrap();
        let headers = HeaderMap::new();

        let auth_delete =
            handle_delete(&core, "home/delete-policy", &headers, auth::Tier::Write).await;
        assert_eq!(auth_delete.status(), StatusCode::UNAUTHORIZED);
        assert!(core.read_world("home/delete-policy").is_some());

        let ledger_delete =
            handle_delete(&core, "var/log/deletes", &headers, auth::Tier::Approve).await;
        assert_eq!(ledger_delete.status(), StatusCode::UNAUTHORIZED);
        assert!(core.read_world("var/log/deletes").is_some());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_missing_world_does_not_write_delete_ledger() {
        let (core, dir) = test_core("delete-missing");
        let headers = HeaderMap::new();
        let resp = handle_delete(&core, "home/missing", &headers, auth::Tier::Approve).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(core.read_world("var/log/deletes").is_none());

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
            {
                let (events, _) = broadcast::channel(16);
                Core {
                    data: dir.clone(),
                    tokens: auth::Tokens {
                        read: None,
                        write: None,
                        approve: None,
                    },
                    hmac_key: b"test-key".to_vec(),
                    mem: Arc::new(store::MemoryStore::new()),
                    max_world_bytes: DEFAULT_MAX_WORLD_BYTES,
                    max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                    events,
                    event_log: Arc::new(StdMutex::new(VecDeque::new())),
                    shutdown: watch::channel(false).1,
                    next_event: Arc::new(AtomicU64::new(0)),
                    next_request: Arc::new(AtomicU64::new(0)),
                    write_lock: Arc::new(Mutex::new(())),
                }
            },
            dir,
        )
    }
}
