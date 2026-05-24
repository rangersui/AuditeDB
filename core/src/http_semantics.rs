use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::{BTreeMap, HashSet};

use crate::{
    engine_types::{EtagMatcher, Preconditions},
    to_header_map, unsatisfied_range_value,
};
#[cfg(test)]
use crate::{precondition_failed, storage_error, Core};

pub(crate) use crate::http_range::effective_range;
#[cfg(test)]
pub(crate) use crate::http_range::parse_range;

/// Entries are normalized to lowercase. A trailing `*` makes an
/// entry a prefix match (e.g. `x-my-*` matches `x-my-anything`).
/// Anything else is exact match.
#[derive(Default, Clone)]
pub(crate) struct HeaderAllowlist {
    exact: HashSet<String>,
    prefixes: Vec<String>,
}

impl HeaderAllowlist {
    /// Empty allowlist (default-deny custom headers). Used by
    /// test fixtures and as the inert state for `Core` constructors
    /// that don't read environment. The production startup path
    /// uses `config::header_allowlist_from_env()` instead, which
    /// returns an `empty()` for an unset env var anyway.
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Parse a comma-separated list. Whitespace per entry is
    /// trimmed; entries are lowercased. A trailing `*` denotes a
    /// prefix match. Empty or `*`-only entries are skipped.
    pub(crate) fn parse(raw: &str) -> Self {
        let mut exact = HashSet::new();
        let mut prefixes: Vec<String> = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            if let Some(prefix) = entry.strip_suffix('*') {
                if !prefix.is_empty() {
                    prefixes.push(prefix.to_string());
                }
                continue;
            }
            exact.insert(entry);
        }
        Self { exact, prefixes }
    }

    pub(crate) fn matches(&self, name_lower: &str) -> bool {
        self.exact.contains(name_lower) || self.prefixes.iter().any(|p| name_lower.starts_with(p))
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.prefixes.is_empty()
    }
}

/// Layer 2 -- built-in default allow. Standard representation
/// headers that "travel with the bytes" and that the vast majority
/// of users want round-tripped without configuring anything.
///
/// Closed list, hardcoded. Update only when a header is reviewed
/// as "describes the body, not the request or transport." Operators
/// who want to drop one for their deployment use
/// `ELASTIK_DENY_HEADERS` (Layer 1.5).
const DEFAULT_PERSIST_HEADERS: &[&str] = &[
    // Body representation: how the body is encoded/displayed/labeled.
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-md5",
    // `last-modified` is intentionally NOT here. Elastik uses the
    // HMAC-chained `ETag` as the canonical version identifier;
    // adding `Last-Modified` would invite clients to send
    // `If-Modified-Since` and bypass the audit-chained
    // `If-None-Match` flow. Don't re-add without revisiting that
    // contract.
    // Caching directives that travel with the body.
    "cache-control",
    "expires",
    // CORS family. The full set is shipped because any subset would
    // surprise an operator dropping bytes through a browser.
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    // Browser security policies for HTML / JS / image bodies.
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "permissions-policy",
    "cross-origin-resource-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    // Browser response-policy hints that travel with the body but
    // sit outside the CSP family.
    "referrer-policy",
    "x-robots-tag",
];

/// Layer 2 default-allow lookup. Caller contract identical to
/// `is_never_persisted_header`: `name_lower` must already be
/// ASCII-lowercased. The constant array entries are all lowercase.
fn is_default_persisted_header(name_lower: &str) -> bool {
    DEFAULT_PERSIST_HEADERS.contains(&name_lower)
}

/// Four-layer persist decision used by `request_meta_headers` and
/// `apply_meta_headers`:
///
///   L1   (hard deny, hardcoded): security / transport / tracing /
///        cloud / IP-leak / pseudo-header pollutants. Always wins.
///   L1.5 (user deny, env-configured): operator's `ELASTIK_DENY_HEADERS`
///        list. Lets an operator subtract from L2 defaults (e.g.
///        "I don't want `cache-control` round-tripping for my
///        deployment"). Same matcher shape as L3 (exact + `*`
///        prefix). Beats L2 and L3 below.
///   L2   (default allow, hardcoded): standard representation
///        headers that travel with the body. Persisted unless L1
///        or L1.5 blocks them.
///   L3   (user allow, env-configured): operator's `ELASTIK_PERSIST_HEADERS`
///        allowlist. Adds custom headers (`x-author`, `x-my-*`)
///        on top of L2.
///
/// Anything not matched by L2 or L3 is dropped -- the model is
/// default-deny for custom headers, default-allow for standard
/// representation headers, with both knobs (L1.5 and L3) for
/// operator-side fine-tuning.
pub(crate) fn should_persist_for_storage(
    name_lower: &str,
    user_allow: &HeaderAllowlist,
    user_deny: &HeaderAllowlist,
) -> bool {
    if is_never_persisted_header(name_lower) {
        return false;
    }
    if user_deny.matches(name_lower) {
        return false;
    }
    if is_default_persisted_header(name_lower) {
        return true;
    }
    user_allow.matches(name_lower)
}

pub(crate) fn apply_meta_headers(
    headers: &[(String, String)],
    out: &mut Vec<(HeaderName, HeaderValue)>,
) {
    // Read-side guard: `headers` is `Stage.headers` loaded from
    // SQLite (already filtered by `request_meta_headers` at write
    // time), so the L1 hard deny is the only check that matters
    // here. We don't re-apply L1.5 / L2 / L3 on read -- if the
    // operator changes either `ELASTIK_PERSIST_HEADERS` (L3) or
    // `ELASTIK_DENY_HEADERS` (L1.5) after data is already written,
    // the persisted bytes still round-trip. Operators wanting to
    // scrub stored headers re-PUT the affected worlds. The hard
    // deny (L1) stays in force so a write-time policy bug or a
    // corrupted database row can never replay credentials or
    // tracing context.
    for (k, v) in headers {
        if is_never_persisted_header(&k.to_ascii_lowercase()) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else {
            continue;
        };
        let Ok(val) = HeaderValue::from_str(v) else {
            continue;
        };
        out.push((name, val));
    }
}

const URL_PATH_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub(crate) fn world_url(world_name: &str) -> String {
    format!("/{}", utf8_percent_encode(world_name, URL_PATH_ENCODE))
}

pub(crate) fn apply_world_links(world_name: &str, out: &mut Vec<(HeaderName, HeaderValue)>) {
    let monitor = format!("</listen{}>; rel=\"monitor\"", world_url(world_name));
    if let Ok(v) = HeaderValue::from_str(&monitor) {
        out.push((header::LINK, v));
    }
    out.push((
        header::LINK,
        HeaderValue::from_static("</proc/worlds>; rel=\"collection\""),
    ));
}

pub(crate) fn etag_header(etag: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{etag}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("\"invalid\""))
}

pub(crate) fn request_preconditions(headers: &HeaderMap) -> Preconditions {
    Preconditions {
        if_match: headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(parse_public_etag_matchers)
            .unwrap_or_default(),
        if_none_match: headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(parse_public_etag_matchers)
            .unwrap_or_default(),
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
pub(crate) fn check_write_preconditions(
    core: &Core,
    world_name: &str,
    req_headers: &HeaderMap,
) -> Result<(), Response> {
    let preconditions = crate::etag::Preconditions::new(
        req_headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(crate::etag::parse_etag_matchers)
            .unwrap_or_default(),
        req_headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(crate::etag::parse_etag_matchers)
            .unwrap_or_default(),
    );
    if preconditions.is_empty() {
        return Ok(());
    }
    let current = core
        .read_world_with_etag(world_name)
        .map_err(|e| storage_error("precondition read", e))?;
    let current_tag = current.as_ref().map(|(_, etag)| etag.clone());

    crate::etag::check_preconditions(&preconditions, current_tag.as_deref())
        .map_err(precondition_failed)
}

pub(crate) fn read_not_modified(req_headers: &HeaderMap, current: &str) -> bool {
    req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|h| etag_list_weak_matches(h, current))
        .unwrap_or(false)
}

fn parse_public_etag_matchers(raw: &str) -> Vec<EtagMatcher> {
    crate::engine_types::parse_etag_matchers(raw)
}

fn etag_list_weak_matches(header_value: &str, current: &str) -> bool {
    parse_public_etag_matchers(header_value)
        .into_iter()
        .any(|matcher| match matcher {
            EtagMatcher::Any => true,
            EtagMatcher::Strong(value) | EtagMatcher::Weak(value) => value == current,
            EtagMatcher::Invalid => false,
            #[cfg(not(test))]
            _ => false,
        })
}

pub(crate) fn request_content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

pub(crate) fn request_meta_headers(
    headers: &HeaderMap,
    user_allow: &HeaderAllowlist,
    user_deny: &HeaderAllowlist,
) -> Vec<(String, String)> {
    let mut out = BTreeMap::new();
    for (k, v) in headers {
        let name = k.as_str().to_ascii_lowercase();
        if should_persist_for_storage(&name, user_allow, user_deny) {
            if let Ok(val) = v.to_str() {
                out.insert(name, val.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Layer 1 hard deny. **Caller contract: `name_lower` must already
/// be ASCII-lowercased.** RFC 7230 makes header names case-
/// insensitive; axum's `HeaderName::as_str()` returns the canonical
/// lowercase form, so headers entering through axum's `HeaderMap`
/// are already lowercase. Callers reading from non-axum sources
/// (Stage.headers loaded from SQLite, env-var allowlists, test
/// fixtures) must `.to_ascii_lowercase()` before calling this. The
/// internal arms below match against lowercase string literals;
/// passing mixed case yields a false negative.
pub(crate) fn is_never_persisted_header(name_lower: &str) -> bool {
    let name = name_lower;
    name.starts_with("sec-")
        || name.starts_with("access-control-request-")
        || name.starts_with("want-")
        // HTTP/2 and HTTP/3 pseudo-headers: `:method`, `:path`,
        // `:scheme`, `:authority`, `:status`. These are wire-level
        // metadata, never legitimate application headers; if axum
        // ever surfaces one as a normal header (server bug or
        // future spec change), it must not bleed into stored
        // representation. Defense in depth.
        || name.starts_with(":")
        // Distributed tracing: Zipkin's multi-header propagation
        // (`x-b3-traceid`, `x-b3-spanid`, `x-b3-sampled`, ...) is
        // per-call link metadata, never a property of stored data.
        // If APM auto-injection bleeds a header into a write, the
        // next reader would see the writer's trace ID -- breaks
        // every downstream tracing/correlation system.
        || name.starts_with("x-b3-")
        // AWS ALB / CloudFront / API Gateway runtime injections.
        // `x-amzn-trace-id` (X-Ray), `x-amzn-requestid`,
        // `x-amzn-mtls-clientcert`, etc.
        || name.starts_with("x-amzn-")
        // Cloudflare runtime injections. `cf-ray`, `cf-connecting-ip`,
        // `cf-visitor`, `cf-ipcountry`, `cf-warp-tag-id`, etc. None
        // describe stored representation; all describe the request's
        // path through Cloudflare's edge.
        || name.starts_with("cf-")
        || matches!(
            name,
            // Credentials and ambient identity must never come back as stored data.
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                // Hop-by-hop and transport headers are properties of this request,
                // not the stored representation.
                | "host"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "http2-settings"
                // Request controls are consumed at write/read time and then gone.
                | "accept"
                | "accept-charset"
                | "accept-encoding"
                | "accept-language"
                | "expect"
                | "from"
                | "max-forwards"
                | "origin"
                | "prefer"
                | "range"
                | "referer"
                | "referrer"
                | "dnt"
                | "user-agent"
                | "if-match"
                | "if-none-match"
                | "if-range"
                | "if-modified-since"
                | "if-unmodified-since"
                // Browser client hints are request-only hints, not response metadata.
                | "device-memory"
                | "downlink"
                | "dpr"
                | "ect"
                | "rtt"
                | "save-data"
                | "width"
                | "viewport-width"
                // Browser/client negotiation state is consumed per request.
                | "accept-ch"
                | "alt-used"
                | "attribution-reporting-eligible"
                | "available-dictionary"
                | "dictionary-id"
                | "early-data"
                | "idempotency-key"
                | "service-worker"
                | "service-worker-navigation-preload"
                | "upgrade-insecure-requests"
                // Server/transport advertisements describe this response or stream.
                | "alt-svc"
                | "server-timing"
                | "retry-after"
                | "x-powered-by"
                | "preference-applied"
                | "priority"
                | "critical-ch"
                | "clear-site-data"
                // Core-owned response headers are derived from stored bytes/audit.
                // Content-Type is persisted separately as Stage.content_type.
                | "content-type"
                | "content-length"
                | "etag"
                | "accept-ranges"
                | "content-range"
                | "link"
                | "location"
                | "allow"
                | "date"
                | "server"
                | "www-authenticate"
                | "age"
                | "vary"
                | "x-request-id"
                | "x-elapsed-us"
                | "x-elapsed-ms"
                | "x-content-type-options"
                // Proxy trail is about how the request arrived, not what was written.
                | "forwarded"
                | "via"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-real-ip"
                // Other client-IP forwarding headers from
                // load-balancers and CDNs. `true-client-ip` is
                // Akamai and Cloudflare Enterprise; `client-ip` is
                // the legacy form used by older proxies. Same data
                // class as `x-forwarded-for`.
                | "true-client-ip"
                | "client-ip"
                // Distributed tracing context: W3C Trace Context
                // via `traceparent` / `tracestate`, W3C Baggage,
                // and Zipkin's single-header b3 format. These
                // describe the request's RPC link, not the stored
                // representation. Auto-injected by every modern APM
                // or OpenTelemetry agent; if persisted, the next
                // reader replays the writer's trace ID and corrupts
                // every downstream tracing system.
                | "traceparent"
                | "tracestate"
                | "baggage"
                | "b3"
                // HTTP transport version markers. `http2-settings`
                // is HTTP/1.1->HTTP/2 upgrade negotiation;
                // `http3-settings` is its analog for QUIC. Either
                // landing in stored data means the listener saw
                // upgrade traffic and let it through. Defensive.
                | "http3-settings"
                // HTTP/1.0 cache-control control header. `Pragma:
                // no-cache` is a per-request directive, not stored
                // representation metadata. Living fossil from RFC
                // 1945 -- denylisting it now closes the round-trip
                // edge case where an old client tags a write.
                | "pragma"
        )
}

pub(crate) fn not_modified(
    world_name: &str,
    etag: &str,
    content_type: &str,
    meta_headers: &[(String, String)],
) -> Response {
    let mut headers = vec![
        (header::ETAG, etag_header(etag)),
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
    ];
    apply_world_links(world_name, &mut headers);
    apply_meta_headers(meta_headers, &mut headers);
    (StatusCode::NOT_MODIFIED, to_header_map(headers), "").into_response()
}

pub(crate) fn range_not_satisfiable(len: usize) -> Response {
    let headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (header::CONTENT_RANGE, unsatisfied_range_value(len)),
    ];
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        to_header_map(headers),
        "range not satisfiable\n",
    )
        .into_response()
}
