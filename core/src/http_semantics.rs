use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::BTreeMap;

use crate::world::Stage;
use crate::{apply_meta_headers, audit, precondition_failed, store, to_header_map, world, Core};

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

pub(crate) fn current_etag(core: &Core, world_name: &str, stage: &Stage) -> String {
    if store::is_persistent(world_name) {
        if let Some(h) = audit::latest_hmac(&core.data, world_name) {
            return hmac_etag(&h);
        }
    }
    body_etag(&stage.body)
}

pub(crate) fn hmac_etag(hmac: &str) -> String {
    format!("hmac-{hmac}")
}

pub(crate) fn body_etag(body: &[u8]) -> String {
    format!("sha256-{}", world::sha256_hex(body))
}

pub(crate) fn etag_header(etag: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{etag}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("\"invalid\""))
}

#[allow(clippy::result_large_err)]
pub(crate) fn check_write_preconditions(
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

pub(crate) fn read_not_modified(req_headers: &HeaderMap, current: &str) -> bool {
    req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|h| etag_list_weak_matches(h, current))
        .unwrap_or(false)
}

pub(crate) fn etag_list_strong_matches(header_value: &str, current: &str) -> bool {
    header_value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == format!("\"{current}\""))
}

pub(crate) fn etag_list_weak_matches(header_value: &str, current: &str) -> bool {
    header_value.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || candidate == format!("\"{current}\"")
            || candidate
                .strip_prefix("W/")
                .map(|weak| weak == format!("\"{current}\""))
                .unwrap_or(false)
    })
}

pub(crate) fn effective_range(
    req_headers: &HeaderMap,
    len: usize,
    current_etag: &str,
) -> Result<Option<(usize, usize)>, ()> {
    if let Some(if_range) = req_headers
        .get(header::IF_RANGE)
        .and_then(|v| v.to_str().ok())
    {
        if !if_range_strong_matches(if_range, current_etag) {
            return Ok(None);
        }
    }
    parse_range(req_headers, len)
}

pub(crate) fn parse_range(
    req_headers: &HeaderMap,
    len: usize,
) -> Result<Option<(usize, usize)>, ()> {
    let Some(raw) = req_headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return Err(());
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((left, right)) = spec.split_once('-') else {
        return Err(());
    };
    if len == 0 {
        return Err(());
    }
    if left.is_empty() {
        let suffix: usize = right.parse().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        let take = suffix.min(len);
        return Ok(Some((len - take, len - 1)));
    }
    let start: usize = left.parse().map_err(|_| ())?;
    if start >= len {
        return Err(());
    }
    let end = if right.is_empty() {
        len - 1
    } else {
        right.parse().map_err(|_| ())?
    };
    if end < start {
        return Err(());
    }
    Ok(Some((start, end.min(len - 1))))
}

pub(crate) fn if_range_strong_matches(header_value: &str, current: &str) -> bool {
    header_value.trim() == format!("\"{current}\"")
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

pub(crate) fn request_meta_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = BTreeMap::new();
    for (k, v) in headers {
        let name = k.as_str().to_ascii_lowercase();
        if is_persisted_representation_header_lowercase(&name) {
            if let Ok(val) = v.to_str() {
                out.insert(name, val.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn is_persisted_representation_header_lowercase(name: &str) -> bool {
    !is_never_persisted_header(name)
}

fn is_never_persisted_header(name: &str) -> bool {
    name.starts_with("sec-")
        || name.starts_with("access-control-request-")
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
                | "x-content-type-options"
                // Proxy trail is about how the request arrived, not what was written.
                | "forwarded"
                | "via"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
        )
}

pub(crate) fn not_modified(world_name: &str, etag: &str, stage: &Stage) -> Response {
    let mut headers = vec![
        (header::ETAG, etag_header(etag)),
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&stage.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
    ];
    apply_world_links(world_name, &mut headers);
    apply_meta_headers(&stage.headers, &mut headers);
    (StatusCode::NOT_MODIFIED, to_header_map(headers), "").into_response()
}

pub(crate) fn range_not_satisfiable(len: usize) -> Response {
    let headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ),
        (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        (
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{len}")).unwrap(),
        ),
    ];
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        to_header_map(headers),
        "range not satisfiable\n",
    )
        .into_response()
}
