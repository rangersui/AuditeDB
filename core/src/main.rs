//! elastik-core — bedrock HTTP+SQLite+HMAC. Python glue lives elsewhere.
//!
//! Scope (intentionally small):
//!   GET    /<world>          → JSON envelope {body, version, headers, ext}
//!   GET    /<world>?raw      → raw bytes with X-Elastik-* headers
//!   PUT    /<world>          → store body, increment version, append audit event
//!   DELETE /<world>          → drop world dir
//!   HEAD   /<world>          → headers only (size, version, ext, x-meta-*)
//!   GET    /proc/worlds      → JSON array of world keys
//!   GET    /proc/version     → "core: <ver>\n"
//!
//! Out of scope (deliberately):
//!   /shaped/*       → defer to Python proxy (calls AI)
//!   /lib/* execution → defer to Python plugin runtime
//!   WebDAV/SMTP/etc → defer to Python sidecars
//!   Cap tokens, NL auth, semantic router → defer to Python
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
mod fanout;
mod world;

use axum::{
    body::Bytes,
    extract::{Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Clone)]
struct Core {
    data: PathBuf,
    tokens: auth::Tokens,
    hmac_key: Vec<u8>,
    listeners: Vec<fanout::Listener>,
    http: reqwest::Client,
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

    let listeners = fanout::parse_env(
        std::env::var("ELASTIK_LISTENERS")
            .unwrap_or_default()
            .as_str(),
    );
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let state = Core {
        data,
        tokens: auth::Tokens::from_env(),
        hmac_key,
        listeners,
        http,
    };

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("elastik-core v{VERSION} on http://{addr}/");
    {
        let n = state.listeners.len();
        if n == 0 {
            eprintln!("  fanout: no listeners registered (ELASTIK_LISTENERS empty)");
        } else {
            eprintln!("  fanout: {n} listener(s) registered:");
            for l in &state.listeners {
                eprintln!("    {} → {}", l.pattern, l.url);
            }
        }
    }

    // ── CORS (default: off) ────────────────────────────────────────
    // ELASTIK_CORS_ORIGINS controls cross-origin browser access.
    //   unset / empty   → no CORS headers; localhost-only browsers OK,
    //                      cross-origin pages blocked. SAFE DEFAULT.
    //   "*"             → allow ANY origin. WARNING printed loudly —
    //                      any website the user visits could read this
    //                      elastik. Useful only for true public APIs.
    //   "https://a.com,http://localhost:5173"
    //                   → allowlist of exact origins.
    // OPTIONS preflight handled automatically by tower-http.
    let cors_env = std::env::var("ELASTIK_CORS_ORIGINS").unwrap_or_default();
    let cors_layer = build_cors(&cors_env);

    let app = Router::new()
        .route("/proc/version", any(proc_version))
        .route("/proc/worlds", any(proc_worlds))
        .route("/*world", any(world_handler))
        .with_state(Arc::new(state))
        .layer(cors_layer);

    axum::serve(listener, app).await.unwrap();
}

fn build_cors(spec: &str) -> CorsLayer {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        eprintln!("  cors: disabled (set ELASTIK_CORS_ORIGINS to enable)");
        return CorsLayer::new(); // no headers, default-deny via browser
    }
    let methods = [
        Method::GET,
        Method::PUT,
        Method::POST,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
    ];
    // Headers we actually care about for clients to send. Wildcard
    // can't be combined with credentials, but we don't require credentials.
    let allow_headers = [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        HeaderName::from_static("x-semantic-intent"),
        // x-meta-* — there's no wildcard support in tower-http for
        // header-name prefixes, so we add a few common ones explicitly.
        // Clients that send unusual x-meta-* names without listing them
        // here will still write — only the *response* header exposure
        // is restricted, not request acceptance.
    ];
    let expose_headers = [
        HeaderName::from_static("x-elastik-version"),
        HeaderName::from_static("x-elastik-ext"),
    ];

    if trimmed == "*" {
        eprintln!("  cors: ⚠ ALLOW-ALL ORIGINS — any website the user visits");
        eprintln!("        can read this elastik. Use only for public APIs.");
        return CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods(methods)
            .allow_headers(allow_headers)
            .expose_headers(expose_headers);
    }

    let origins: Vec<HeaderValue> = trimmed
        .split(',')
        .filter_map(|o| {
            let o = o.trim();
            if o.is_empty() {
                None
            } else {
                HeaderValue::from_str(o).ok()
            }
        })
        .collect();
    eprintln!("  cors: enabled for {} origin(s):", origins.len());
    for o in &origins {
        eprintln!("    {}", o.to_str().unwrap_or("?"));
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(methods)
        .allow_headers(allow_headers)
        .expose_headers(expose_headers)
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
    let names = world::list(&core.data);
    let json = serde_json::to_vec(
        &names
            .iter()
            .map(|n| serde_json::json!({ "name": n }))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json,
    )
}

// ─── /<world> with all four methods ─────────────────────────────────
async fn world_handler(
    State(core): State<Arc<Core>>,
    method: Method,
    AxPath(path): AxPath<String>,
    Query(qs): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let world_name = canonicalize_path(&path);
    // The original URL path (e.g. "/home/inbox/test") is what listener
    // patterns key off — they're addressed at the URL surface, not the
    // canonical storage key.
    let url_path = format!("/{}", path.trim_start_matches('/'));
    let raw = qs.contains_key("raw");
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);

    match method {
        Method::GET => handle_get(&core, &world_name, raw),
        Method::HEAD => handle_head(&core, &world_name),
        Method::PUT => handle_put(&core, &world_name, &url_path, &headers, body, tier),
        Method::DELETE => handle_delete(&core, &world_name, tier),
        _ => (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response(),
    }
}

/// elastik convention: `/home/foo` and `/foo` address the same world key
/// when the world was written under either. We canonicalize by stripping
/// a leading `home/` so writes via `/home/x` and reads via `/x` line up
/// — matches the Python reference's URL routing behaviour.
fn canonicalize_path(p: &str) -> String {
    let stripped = p.trim_start_matches('/');
    stripped
        .strip_prefix("home/")
        .map(str::to_owned)
        .unwrap_or_else(|| stripped.to_owned())
}

// ─── handlers ───────────────────────────────────────────────────────
fn handle_get(core: &Core, world_name: &str, raw: bool) -> Response {
    let Some(stage) = world::read(&core.data, world_name) else {
        return not_found();
    };
    let mut resp_headers = vec![
        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        (
            HeaderName::from_static("x-elastik-version"),
            HeaderValue::from_str(&stage.version.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        ),
        (
            HeaderName::from_static("x-elastik-ext"),
            HeaderValue::from_str(&stage.ext).unwrap_or_else(|_| HeaderValue::from_static("plain")),
        ),
    ];
    apply_meta_headers(&stage.headers_json, &mut resp_headers);

    if raw {
        let ct = ext_to_ct(&stage.ext);
        resp_headers.insert(
            0,
            (header::CONTENT_TYPE, HeaderValue::from_str(&ct).unwrap()),
        );
        return (StatusCode::OK, to_header_map(resp_headers), stage.body).into_response();
    }
    // Default JSON envelope
    let envelope = serde_json::json!({
        "stage_html": String::from_utf8_lossy(&stage.body),
        "version": stage.version,
        "ext": stage.ext,
        "updated_at": stage.updated_at,
        "headers": serde_json::from_str::<serde_json::Value>(&stage.headers_json)
            .unwrap_or(serde_json::Value::Array(vec![])),
    });
    let body = serde_json::to_vec(&envelope).unwrap();
    resp_headers.insert(
        0,
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        ),
    );
    (StatusCode::OK, to_header_map(resp_headers), body).into_response()
}

fn handle_head(core: &Core, world_name: &str) -> Response {
    let Some(stage) = world::read(&core.data, world_name) else {
        return not_found();
    };
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        ),
        (
            HeaderName::from_static("x-elastik-version"),
            HeaderValue::from_str(&stage.version.to_string()).unwrap(),
        ),
        (
            HeaderName::from_static("x-elastik-ext"),
            HeaderValue::from_str(&stage.ext).unwrap(),
        ),
        (
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&stage.body.len().to_string()).unwrap(),
        ),
    ];
    apply_meta_headers(&stage.headers_json, &mut resp_headers);
    (StatusCode::OK, to_header_map(resp_headers), "").into_response()
}

fn handle_put(
    core: &Core,
    world_name: &str,
    url_path: &str,
    req_headers: &HeaderMap,
    body: Bytes,
    tier: auth::Tier,
) -> Response {
    if !can_write(world_name, tier) {
        return unauthorized("write requires token; system worlds need approve token");
    }
    let ext = req_headers
        .get(HeaderName::from_static("x-elastik-ext"))
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req_headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(ct_to_ext)
        })
        .unwrap_or("plain")
        .to_owned();

    // Collect X-Meta-* headers as a JSON array of [key, value] pairs,
    // matching server.py's headers column shape.
    let meta: Vec<[String; 2]> = req_headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if name.to_ascii_lowercase().starts_with("x-meta-") {
                v.to_str()
                    .ok()
                    .map(|val| [name.to_string(), val.to_string()])
            } else {
                None
            }
        })
        .collect();
    let headers_json = serde_json::to_string(&meta).unwrap_or_else(|_| "[]".into());

    let version = match world::write(&core.data, world_name, &body, &ext, &headers_json) {
        Ok(v) => v,
        Err(e) => return server_error(format!("storage: {e}")),
    };
    let payload = serde_json::json!({
        "op": "put",
        "world": world_name,
        "version_after": version,
        "size": body.len(),
        "tier": format!("{:?}", tier).to_lowercase(),
    })
    .to_string();
    let _ = audit::append(&core.data, world_name, "put", &payload, &core.hmac_key);

    // Fanout to registered listeners. Same tokio runtime, fire-and-forget;
    // PUT response does not gate on listener completion. This is the
    // "PUT 进来 → 顺手看看有没有人 @listen → 触发" pattern, in tokio.
    // Match against the URL path (what clients see), not the canonical
    // storage key (what SQLite sees).
    fanout::fanout(
        &core.listeners,
        &core.http,
        url_path,
        version,
        body.clone(),
        req_headers,
    );

    let resp = serde_json::json!({
        "ok": true,
        "version": version,
        "world": world_name,
        "size": body.len(),
    });
    let headers = [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        ),
        (
            HeaderName::from_static("x-elastik-version"),
            HeaderValue::from_str(&version.to_string()).unwrap(),
        ),
    ];
    let status = if version == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, headers, serde_json::to_vec(&resp).unwrap()).into_response()
}

fn handle_delete(core: &Core, world_name: &str, tier: auth::Tier) -> Response {
    // Harvard gate is symmetric: if T2 can write /home/foo, T2 can
    // delete /home/foo. /lib/, /etc/, /boot/, /usr/ still need T3.
    if !can_write(world_name, tier) {
        return unauthorized("delete requires token; system worlds need approve token");
    }
    // Audit the delete BEFORE the disk goes away. We append to a
    // global ledger world (`var/log/deletes`), not the world being
    // removed — otherwise audit::append would reopen the world dir
    // and recreate it. Until that ledger world exists, this is a
    // best-effort breadcrumb; failures are silent.
    let _ = audit::append(
        &core.data,
        "var/log/deletes",
        "delete",
        &format!(r#"{{"op":"delete","world":"{world_name}"}}"#),
        &core.hmac_key,
    );
    let ok = world::delete(&core.data, world_name);
    if !ok {
        return not_found();
    }
    (StatusCode::NO_CONTENT, "").into_response()
}

// ─── helpers ────────────────────────────────────────────────────────
fn can_write(world_name: &str, tier: auth::Tier) -> bool {
    // Harvard gate: /lib/, /etc/, /boot/ require approve. /home/ and
    // peers accept auth or approve. Unauthenticated writes are refused.
    let needs_approve = world_name.starts_with("lib/")
        || world_name.starts_with("etc/")
        || world_name.starts_with("boot/")
        || world_name.starts_with("usr/");
    match tier {
        auth::Tier::Anon => false,
        auth::Tier::Auth => !needs_approve,
        auth::Tier::Approve => true,
    }
}

fn ext_to_ct(ext: &str) -> String {
    match ext {
        "html" => "text/html; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "py" => "text/x-python; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "eml" => "message/rfc822",
        "plain" | _ => "text/plain; charset=utf-8",
    }
    .to_owned()
}

fn ct_to_ext(ct: &str) -> Option<&'static str> {
    let base = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "text/html" => Some("html"),
        "application/json" => Some("json"),
        "text/x-python" => Some("py"),
        "text/markdown" => Some("md"),
        "text/css" => Some("css"),
        "text/javascript" | "application/javascript" => Some("js"),
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "message/rfc822" => Some("eml"),
        _ => None,
    }
}

fn to_header_map(pairs: Vec<(HeaderName, HeaderValue)>) -> HeaderMap {
    let mut hm = HeaderMap::with_capacity(pairs.len());
    for (k, v) in pairs {
        hm.append(k, v);
    }
    hm
}

fn apply_meta_headers(headers_json: &str, out: &mut Vec<(HeaderName, HeaderValue)>) {
    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(headers_json) {
        for pair in arr {
            let serde_json::Value::Array(kv) = pair else {
                continue;
            };
            if kv.len() != 2 {
                continue;
            }
            let (Some(k), Some(v)) = (kv[0].as_str(), kv[1].as_str()) else {
                continue;
            };
            let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else {
                continue;
            };
            let Ok(val) = HeaderValue::from_str(v) else {
                continue;
            };
            out.push((name, val));
        }
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        r#"{"error":"world not found"}"#,
    )
        .into_response()
}

fn unauthorized(msg: &str) -> Response {
    let body = serde_json::json!({"error": "auth required", "hint": msg});
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::WWW_AUTHENTICATE, "Bearer realm=\"elastik\""),
        ],
        serde_json::to_vec(&body).unwrap(),
    )
        .into_response()
}

fn server_error(msg: String) -> Response {
    let body = serde_json::json!({"error": "internal", "detail": msg});
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        serde_json::to_vec(&body).unwrap(),
    )
        .into_response()
}
