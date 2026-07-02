//! HTTP byte range parsing and conditional range selection.

use axum::http::{header, HeaderMap};

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

fn if_range_strong_matches(header_value: &str, current: &str) -> bool {
    header_value.trim() == format!("\"{current}\"")
}
