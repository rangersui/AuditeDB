//! HTTP response constructors and small header helpers.
//!
//! Centralized so handlers, audit verifiers, listen, and coap all emit
//! the same error/status shapes. Functions here are pure: they take
//! primitive inputs and return a `Response` (or a header value / body
//! string). They do not touch `Core`, locks, or storage.
//!
//! Re-exported into the crate root by `main.rs` so existing call sites
//! like `crate::not_found()` keep working without import changes.
//!
//! The blocking-task error scaffold (`BlockingSqliteError` enum and
//! `blocking_storage_error` mapper) lives in `main.rs`; that scaffold
//! belongs to the spawn_blocking glue, not to the response surface.

use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};

use crate::audit;

// ─── header utility ─────────────────────────────────────────────────

pub(crate) fn to_header_map(pairs: Vec<(HeaderName, HeaderValue)>) -> HeaderMap {
    let mut hm = HeaderMap::with_capacity(pairs.len());
    for (k, v) in pairs {
        hm.append(k, v);
    }
    hm
}

#[inline]
pub(crate) fn decimal_header_value(value: usize) -> HeaderValue {
    HeaderValue::from(value as u64)
}

#[inline]
pub(crate) fn content_range_value(start: usize, end: usize, len: usize) -> HeaderValue {
    HeaderValue::from_str(&format!("bytes {start}-{end}/{len}"))
        .expect("Content-Range format uses only visible ASCII bytes")
}

#[inline]
pub(crate) fn unsatisfied_range_value(len: usize) -> HeaderValue {
    HeaderValue::from_str(&format!("bytes */{len}"))
        .expect("Content-Range format uses only visible ASCII bytes")
}

// ─── basic error responses ──────────────────────────────────────────

pub(crate) fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "world not found\n",
    )
        .into_response()
}

pub(crate) fn unauthorized(msg: &str) -> Response {
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

pub(crate) fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("bad request: {msg}\n"),
    )
        .into_response()
}

pub(crate) fn payload_too_large(max_bytes: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("payload too large: max bytes {max_bytes}\n"),
    )
        .into_response()
}

pub(crate) fn precondition_failed(msg: &str) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("precondition failed: {msg}\n"),
    )
        .into_response()
}

pub(crate) fn server_error(msg: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("internal error: {msg}\n"),
    )
        .into_response()
}

pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
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

pub(crate) fn options_response(allow: &'static str) -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::ALLOW, allow), (header::CONTENT_LENGTH, "0")],
        "",
    )
        .into_response()
}

// ─── storage / quota responses ─────────────────────────────────────

pub(crate) fn insufficient_storage() -> Response {
    (
        StatusCode::INSUFFICIENT_STORAGE,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "insufficient storage: disk full\n",
    )
        .into_response()
}

pub(crate) fn storage_temporarily_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::RETRY_AFTER, "1"),
        ],
        "storage temporarily unavailable: database busy\n",
    )
        .into_response()
}

pub(crate) fn storage_quota_exceeded(used: usize, quota: usize, projected: usize) -> Response {
    let needed = projected.saturating_sub(quota);
    (
        StatusCode::INSUFFICIENT_STORAGE,
        to_header_map(vec![
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                HeaderName::from_static("x-storage-usage"),
                decimal_header_value(used),
            ),
            (
                HeaderName::from_static("x-storage-quota"),
                decimal_header_value(quota),
            ),
            (
                HeaderName::from_static("x-storage-needed"),
                decimal_header_value(needed),
            ),
        ]),
        format!(
            "storage quota exceeded: current {used} bytes, quota {quota} bytes, need {needed} more bytes\n"
        ),
    )
        .into_response()
}

pub(crate) fn storage_error(scope: &str, err: rusqlite::Error) -> Response {
    eprintln!("elastik-core internal {scope}: {err}");
    if is_insufficient_storage_error(&err) {
        insufficient_storage()
    } else if is_transient_storage_error(&err) {
        storage_temporarily_unavailable()
    } else {
        server_error("storage failure".to_string())
    }
}

pub(crate) fn is_transient_storage_error(err: &rusqlite::Error) -> bool {
    if matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked)
    ) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("database is locked") || msg.contains("database table is locked")
}

pub(crate) fn is_insufficient_storage_error(err: &rusqlite::Error) -> bool {
    if matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DiskFull)
    ) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("database or disk is full")
        || msg.contains("disk is full")
        || msg.contains("no space left")
        || msg.contains("not enough space")
}

// ─── audit verify responses ────────────────────────────────────────

pub(crate) fn audit_valid(report: audit::VerifyOk) -> Response {
    (
        StatusCode::OK,
        to_header_map(vec![
            (
                HeaderName::from_static("x-audit-valid"),
                HeaderValue::from_static("true"),
            ),
            (
                HeaderName::from_static("x-audit-events"),
                decimal_header_value(report.events),
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

pub(crate) fn audit_broken(report: audit::VerifyBreak) -> Response {
    (
        StatusCode::CONFLICT,
        to_header_map(vec![
            (
                HeaderName::from_static("x-audit-valid"),
                HeaderValue::from_static("false"),
            ),
            (
                HeaderName::from_static("x-audit-break-at"),
                decimal_header_value(report.break_at),
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

pub(crate) fn audit_not_applicable() -> Response {
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

pub(crate) fn audit_header_value(value: &str) -> HeaderValue {
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

// ─── proc/* response helpers ───────────────────────────────────────

pub(crate) fn proc_text_response(method: Method, body: String) -> Response {
    let mut resp_headers = vec![(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    )];
    if method == Method::HEAD {
        resp_headers.push((header::CONTENT_LENGTH, decimal_header_value(body.len())));
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

pub(crate) fn du_body(sizes: &[(String, usize)]) -> String {
    let mut out = String::new();
    for (world, size) in sizes {
        out.push_str(world);
        out.push('\t');
        out.push_str(&size.to_string());
        out.push('\n');
    }
    out
}

pub(crate) fn df_body(
    storage_used: usize,
    storage_quota: Option<usize>,
    memory_used: usize,
    memory_quota: usize,
    worlds: usize,
) -> String {
    let (storage_quota, storage_available) = match storage_quota {
        Some(quota) => (
            quota.to_string(),
            quota.saturating_sub(storage_used).to_string(),
        ),
        None => ("unlimited".to_string(), "unlimited".to_string()),
    };
    let memory_available = memory_quota.saturating_sub(memory_used);
    format!(
        "storage\t{storage_used}\t{storage_quota}\t{storage_available}\n\
         memory\t{memory_used}\t{memory_quota}\t{memory_available}\n\
         worlds\t{worlds}\tunlimited\tunlimited\n"
    )
}

pub(crate) fn world_list_body(names: &[String]) -> String {
    if names.is_empty() {
        String::new()
    } else {
        format!("{}\n", names.join("\n"))
    }
}
