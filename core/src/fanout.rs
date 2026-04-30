//! Listener fanout.
//!
//! "PUT 进来 → uvicorn 收了 → handler 跑了 → 存了 → 顺手: '有人 @listen
//! 这个 path 吗?' → 有 → 跑 handler → 全在一个 await 链里"
//!
//! Same pattern, in tokio: when a PUT is committed, spawn matching
//! listeners on the same runtime. Fire-and-forget — the PUT response
//! does not block on listener completion. Listeners receive the body
//! plus X-Elastik-* metadata via HTTP loopback to a Python sidecar.
//!
//! Configured via `ELASTIK_LISTENERS` env:
//!
//!     ELASTIK_LISTENERS="/home/inbox/*=http://localhost:3200/triage,/home/outbox/*=http://localhost:3201/relay"
//!
//! Pattern is a prefix-with-trailing-`*` glob. `*` alone matches all.
//! Each listener fires in its own `tokio::spawn` — failures are logged
//! and dropped. The listener does not gate the PUT 201.

use axum::body::Bytes;
use axum::http::HeaderMap;

#[derive(Clone, Debug)]
pub struct Listener {
    pub pattern: String,
    pub url: String,
}

pub fn parse_env(raw: &str) -> Vec<Listener> {
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let mut iter = pair.splitn(2, '=');
            let pattern = iter.next()?.trim().to_owned();
            let url = iter.next()?.trim().to_owned();
            if pattern.is_empty() || url.is_empty() {
                return None;
            }
            Some(Listener { pattern, url })
        })
        .collect()
}

pub fn matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

/// Fire-and-forget: spawn one task per matching listener.
/// PUT response does not wait for any of these.
pub fn fanout(
    listeners: &[Listener],
    client: &reqwest::Client,
    world_path: &str,
    version: i64,
    body: Bytes,
    meta_headers: &HeaderMap,
) {
    let path_with_slash = format!("/{}", world_path.trim_start_matches('/'));
    for listener in listeners {
        if !matches(&listener.pattern, &path_with_slash) {
            continue;
        }
        let url = listener.url.clone();
        let body = body.clone();
        let client = client.clone();
        let world = world_path.to_owned();
        let pattern = listener.pattern.clone();

        // Forward x-meta-* headers; rebuild as plain HeaderMap for reqwest.
        let mut forward = HeaderMap::with_capacity(meta_headers.len() + 3);
        for (k, v) in meta_headers.iter() {
            if k.as_str().to_ascii_lowercase().starts_with("x-meta-") {
                forward.append(k.clone(), v.clone());
            }
        }
        if let Ok(v) = axum::http::HeaderValue::from_str(&world) {
            forward.append("x-elastik-world", v);
        }
        if let Ok(v) = axum::http::HeaderValue::from_str(&version.to_string()) {
            forward.append("x-elastik-version", v);
        }
        forward.append(
            "x-elastik-pattern",
            axum::http::HeaderValue::from_str(&pattern)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("*")),
        );

        tokio::spawn(async move {
            let result = client
                .post(&url)
                .headers(forward)
                .body(body.to_vec())
                .send()
                .await;
            match result {
                Ok(resp) => {
                    eprintln!("  fanout → {} ({}): {}", url, pattern, resp.status());
                }
                Err(e) => {
                    eprintln!("  fanout → {} ({}) failed: {}", url, pattern, e);
                }
            }
        });
    }
}
