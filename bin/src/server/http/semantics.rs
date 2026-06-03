use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::{BTreeMap, HashSet};

use crate::{
    engine_types::{EtagMatcher, Preconditions},
    server::{to_header_map, unsatisfied_range_value},
};
#[cfg(test)]
use crate::{
    server::{precondition_failed, storage_error},
    Core,
};

pub(crate) use super::range::effective_range;
#[cfg(test)]
pub(crate) use super::range::parse_range;

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
    /// that don't read environment. The production startup path uses
    /// `header_allowlist_from_env()` instead, which returns
    /// an `empty()` for an unset env var anyway.
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

/// Parse `ELASTIK_PERSIST_HEADERS` into the user-configured
/// allowlist (Layer 3 of the persist policy). Comma-separated;
/// trailing `*` = prefix match. An unset, empty, or all-whitespace
/// value yields `HeaderAllowlist::empty()`, which means "no custom
/// headers beyond the built-in default-allow set."
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn header_allowlist_from_env() -> HeaderAllowlist {
    let raw = std::env::var("ELASTIK_PERSIST_HEADERS").unwrap_or_default();
    HeaderAllowlist::parse(&raw)
}

/// Parse `ELASTIK_DENY_HEADERS` into the user-configured deny set
/// (Layer 1.5 of the persist policy). Same matcher shape as
/// `header_allowlist_from_env`; lets the operator subtract a header
/// from the built-in `DEFAULT_PERSIST_HEADERS` allow set (e.g. "this
/// deployment doesn't want `cache-control` round-tripping"). L1
/// hard-deny still wins over this; this beats L2 default and L3 allow.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn header_user_deny_from_env() -> HeaderAllowlist {
    let raw = std::env::var("ELASTIK_DENY_HEADERS").unwrap_or_default();
    HeaderAllowlist::parse(&raw)
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
    Preconditions::new(
        headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(parse_public_etag_matchers)
            .unwrap_or_default(),
        headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(parse_public_etag_matchers)
            .unwrap_or_default(),
    )
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_core;
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn byte_ranges_cover_normal_open_and_suffix_forms() {
        let mut h = HeaderMap::new();
        assert_eq!(parse_range(&h, 10), Ok(None));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        assert_eq!(parse_range(&h, 10), Ok(Some((2, 5))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=7-"));
        assert_eq!(parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=-3"));
        assert_eq!(parse_range(&h, 10), Ok(Some((7, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=8-99"));
        assert_eq!(parse_range(&h, 10), Ok(Some((8, 9))));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=11-12"));
        assert_eq!(parse_range(&h, 10), Err(()));

        h.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));
        assert_eq!(parse_range(&h, 10), Ok(None));
    }

    #[test]
    fn if_range_controls_whether_range_is_applied() {
        let mut h = HeaderMap::new();
        h.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("\"hmac-current\""),
        );
        assert_eq!(effective_range(&h, 6, "hmac-current"), Ok(Some((1, 3))));

        h.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));
        assert_eq!(effective_range(&h, 6, "hmac-current"), Ok(None));

        h.insert(
            header::IF_RANGE,
            HeaderValue::from_static("W/\"hmac-current\""),
        );
        assert_eq!(effective_range(&h, 6, "hmac-current"), Ok(None));
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
    fn request_meta_headers_persist_default_representation_headers_only() {
        // L2 (DEFAULT_PERSIST_HEADERS) covers standard representation
        // headers that round-trip with the body without the operator
        // configuring anything. Custom headers (x-author,
        // x-future-http-thing, x-meta-*) are NOT persisted under the
        // empty allowlist -- the operator must opt in via
        // ELASTIK_PERSIST_HEADERS. Layer 1 hard-deny stays in force
        // either way.
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
            HeaderValue::from_str(&format!("{} {}", "Bearer", "secret")).unwrap(),
        );
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("{} {}", "Bearer", "secret")).unwrap(),
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
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("true-client-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("client-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("clear-site-data", HeaderValue::from_static("\"cookies\""));
        // Distributed tracing pollutants (W3C + Zipkin + AWS X-Ray).
        // Auto-injected by APM agents; if persisted, next reader
        // replays writer's trace ID and corrupts downstream tracing.
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        headers.insert(
            "tracestate",
            HeaderValue::from_static("rojo=00f067aa0ba902b7"),
        );
        headers.insert(
            "baggage",
            HeaderValue::from_static("userId=alice,serverNode=DF%2028"),
        );
        headers.insert(
            "b3",
            HeaderValue::from_static("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"),
        );
        headers.insert(
            "x-b3-traceid",
            HeaderValue::from_static("80f198ee56343ba864fe8b2a57d3eff7"),
        );
        headers.insert("x-b3-spanid", HeaderValue::from_static("e457b5a2e4d86bd1"));
        headers.insert("x-b3-sampled", HeaderValue::from_static("1"));
        headers.insert(
            "x-amzn-trace-id",
            HeaderValue::from_static("Root=1-5759e988-bd862e3fe1be46a994272793"),
        );
        headers.insert("cf-ray", HeaderValue::from_static("8f1234567abcdef0-IAD"));
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert(
            "cf-visitor",
            HeaderValue::from_static("{\"scheme\":\"https\"}"),
        );
        // HTTP transport version markers.
        headers.insert(
            "http3-settings",
            HeaderValue::from_static("AAMAAABkAARAAgAAAAAEAIAAAAA"),
        );
        headers.insert("pragma", HeaderValue::from_static("no-cache"));

        let allowlist = HeaderAllowlist::empty();
        let user_deny = HeaderAllowlist::empty();
        let meta = request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        assert!(meta.contains(&("content-encoding".to_string(), "gzip".to_string())));
        assert!(meta.contains(&("content-language".to_string(), "zh-CN".to_string())));
        assert!(meta.contains(&(
            "content-disposition".to_string(),
            "attachment; filename=\"report.pdf\"".to_string()
        )));
        assert!(meta.contains(&("cache-control".to_string(), "max-age=60".to_string())));
        assert!(meta.contains(&("access-control-allow-origin".to_string(), "*".to_string())));
        assert!(meta.contains(&(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string()
        )));
        assert!(meta.contains(&("x-frame-options".to_string(), "DENY".to_string())));
        assert!(meta.contains(&("permissions-policy".to_string(), "camera=()".to_string())));
        assert!(meta.contains(&(
            "cross-origin-resource-policy".to_string(),
            "same-origin".to_string()
        )));
        // Custom headers (no `x-` shortcut, no auto-allowlist for
        // x-meta-*) MUST NOT persist under the empty allowlist.
        assert!(
            !has("x-meta-author"),
            "x-meta-* is opt-in via ELASTIK_PERSIST_HEADERS"
        );
        assert!(
            !has("x-future-http-thing"),
            "unknown x- headers default-deny"
        );

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
            "x-real-ip",
            "true-client-ip",
            "client-ip",
            "clear-site-data",
            // Distributed tracing pollutants.
            "traceparent",
            "tracestate",
            "baggage",
            "b3",
            "x-b3-traceid",
            "x-b3-spanid",
            "x-b3-sampled",
            // Cloud-provider runtime injections.
            "x-amzn-trace-id",
            "cf-ray",
            "cf-connecting-ip",
            "cf-visitor",
            // Transport version markers + HTTP/1.0 living fossil.
            "http3-settings",
            "pragma",
        ] {
            assert!(!has(name), "{name} should not be persisted");
        }
    }

    #[test]
    fn request_meta_headers_deduplicate_repeated_names_last_wins() {
        let mut headers = HeaderMap::new();
        headers.append("x-meta-author", HeaderValue::from_static("alice"));
        headers.append("x-meta-author", HeaderValue::from_static("bob"));

        // Allowlist x-meta-* so the dedup behaviour is observable;
        // the empty allowlist would correctly drop both entries.
        let allowlist = HeaderAllowlist::parse("x-meta-*");
        let user_deny = HeaderAllowlist::empty();
        let meta = request_meta_headers(&headers, &allowlist, &user_deny);

        assert_eq!(meta, vec![("x-meta-author".to_string(), "bob".to_string())]);
    }

    #[test]
    fn poisoned_persisted_headers_are_not_replayed() {
        let mut out = Vec::new();
        apply_meta_headers(
            &[
                (
                    "x-custom".to_owned(),
                    "evil\r\nset-cookie: admin=true".to_owned(),
                ),
                ("set-cookie".to_owned(), "sid=admin; Path=/".to_owned()),
                ("clear-site-data".to_owned(), "\"cookies\"".to_owned()),
                ("bad name".to_owned(), "ok".to_owned()),
                ("x-safe".to_owned(), "ok".to_owned()),
            ],
            &mut out,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.as_str(), "x-safe");
        assert_eq!(out[0].1, "ok");
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
        let (_, etag) = core.read_world_with_etag("home/cas").unwrap().unwrap();
        let etag = format!("\"{etag}\"");

        let mut good = HeaderMap::new();
        good.insert(header::IF_MATCH, HeaderValue::from_str(&etag).unwrap());
        assert!(check_write_preconditions(&core, "home/cas", &good).is_ok());

        let mut stale = HeaderMap::new();
        stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
        assert!(check_write_preconditions(&core, "home/cas", &stale).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_meta_headers_user_allowlist_persists_custom_headers() {
        // Layer 3 (user allowlist) opens custom-header round-trip
        // on top of the default-allow set. Exact match and prefix
        // match (`x-my-*`) both work.
        let mut headers = HeaderMap::new();
        headers.insert("x-author", HeaderValue::from_static("ranger"));
        headers.insert("x-version", HeaderValue::from_static("7.1.0"));
        headers.insert("x-my-tag", HeaderValue::from_static("custom"));
        headers.insert("x-my-region", HeaderValue::from_static("ap-east-1"));
        headers.insert("x-other", HeaderValue::from_static("not-allowlisted"));
        // L1 hard deny -- must lose to user allowlist below.
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        // L2 default-allow stays on top of L3.
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );

        let allowlist = HeaderAllowlist::parse("x-author,x-version,x-my-*,traceparent");
        let user_deny = HeaderAllowlist::empty();
        let meta = request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // L3 named exact: persisted.
        assert!(has("x-author"));
        assert!(has("x-version"));
        // L3 prefix wildcard: persisted.
        assert!(has("x-my-tag"));
        assert!(has("x-my-region"));
        // Not allowlisted -> default-deny (L3 didn't match, L2 doesn't cover).
        assert!(!has("x-other"));
        // L1 hard deny ALWAYS wins -- even if traceparent is in the
        // user allowlist, it never persists.
        assert!(
            !has("traceparent"),
            "L1 hard deny must override user allowlist; tracing context never persists"
        );
        // L2 default-allow still applies alongside L3.
        assert!(has("cache-control"));
    }

    #[test]
    fn request_meta_headers_user_deny_subtracts_from_default_allow() {
        // Layer 1.5 (user deny / ELASTIK_DENY_HEADERS) lets an
        // operator subtract a header from the built-in
        // DEFAULT_PERSIST_HEADERS without recompiling. Order:
        //   L1 hard deny > L1.5 user deny > L2 default > L3 user allow.
        let mut headers = HeaderMap::new();
        // L2 defaults that should normally persist:
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert("permissions-policy", HeaderValue::from_static("camera=()"));
        // L3-allowlisted custom that user_deny should also win over:
        headers.insert("x-author", HeaderValue::from_static("ranger"));

        // Operator says: drop cache-control + permissions-policy
        // from defaults; also kill any allowlisted x-author (user
        // deny beats user allow).
        let allowlist = HeaderAllowlist::parse("x-author");
        let user_deny = HeaderAllowlist::parse("cache-control,permissions-policy,x-author");
        let meta = request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // L2 defaults the operator denied -> dropped.
        assert!(
            !has("cache-control"),
            "user-deny must subtract from L2 default-allow"
        );
        assert!(!has("permissions-policy"));
        // L2 default not in user_deny -> still persisted.
        assert!(has("content-encoding"));
        // L3 allowlisted but also user_denied -> deny wins.
        assert!(
            !has("x-author"),
            "user-deny must override user-allow when both match"
        );
    }

    #[test]
    fn request_meta_headers_is_case_insensitive_per_rfc_7230() {
        // RFC 7230: HTTP header field names are case-insensitive.
        // axum's HeaderMap canonicalizes incoming names to
        // lowercase via `HeaderName::as_str`; this test pins that
        // axum-side normalization PLUS verifies that the
        // env-var-side parser lowercases its input.
        let mut headers = HeaderMap::new();
        // Insert with mixed case -- axum stores keys in lowercase
        // canonical form, so the iteration in
        // `request_meta_headers` sees lowercase.
        headers.insert("X-Author", HeaderValue::from_static("ranger"));
        headers.insert("CACHE-CONTROL", HeaderValue::from_static("max-age=60"));
        headers.insert("Traceparent", HeaderValue::from_static("00-...-01"));
        headers.insert("X-Forwarded-For", HeaderValue::from_static("203.0.113.7"));

        // Operator wrote ELASTIK_PERSIST_HEADERS with mixed case --
        // parser lowercases.
        let allowlist = HeaderAllowlist::parse("X-AUTHOR, X-Version");
        let user_deny = HeaderAllowlist::empty();
        let meta = request_meta_headers(&headers, &allowlist, &user_deny);
        let has = |name: &str| meta.iter().any(|(n, _)| n == name);

        // Mixed-case allowlist entry persists the (lowercase-stored)
        // input header.
        assert!(has("x-author"), "X-Author allowlisted as X-AUTHOR persists");
        // L2 default catches CACHE-CONTROL regardless of input case.
        assert!(has("cache-control"));
        // L1 hard-deny still blocks tracing context regardless of
        // input case.
        assert!(!has("traceparent"));
        assert!(!has("x-forwarded-for"));

        // Stored header names are always lowercase canonical form.
        for (name, _) in &meta {
            assert_eq!(
                name,
                &name.to_ascii_lowercase(),
                "stored meta keys must be lowercase"
            );
        }
    }

    #[test]
    fn header_allowlist_parser_handles_whitespace_dedup_and_wildcards() {
        // Whitespace per entry trimmed; case folded; duplicates de-duped;
        // empty / all-* entries skipped.
        let allow = HeaderAllowlist::parse(
            "  X-Author , x-version, x-my-*, x-version, , *, x-my-* , x-AUTHOR",
        );
        assert!(allow.matches("x-author"));
        assert!(allow.matches("x-version"));
        assert!(allow.matches("x-my-tag"));
        assert!(allow.matches("x-my-region"));
        assert!(!allow.matches("x-other"));
        assert!(!allow.matches(""));
        // A bare `*` in the env doesn't open the floodgates.
        assert!(!allow.matches("anything-else"));

        // Empty input == empty allowlist.
        assert!(HeaderAllowlist::parse("").is_empty());
        assert!(HeaderAllowlist::parse("   ,  ,").is_empty());
    }
}
