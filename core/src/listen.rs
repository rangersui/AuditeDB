use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, Method},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamExt,
};

use crate::{can_read, method_not_allowed, options_response, unauthorized, Core};

pub(crate) const ALLOW: &str = "GET, OPTIONS";

#[derive(Clone, Debug)]
pub(crate) struct ChangeEvent {
    pub(crate) id: u64,
    pub(crate) method: &'static str,
    pub(crate) path: String,
    pub(crate) etag: String,
}

// SSE event tap. Curl-first:
//   curl -N http://127.0.0.1:3105/listen/home/task/*
//
// The stream is control-plane only. It says which world changed; it
// never embeds the world's body, so stored Content-Type semantics stay
// entirely on GET/HEAD.
pub(crate) async fn handler(
    State(core): State<Arc<Core>>,
    method: Method,
    headers: HeaderMap,
    AxPath(raw_pattern): AxPath<String>,
) -> Response {
    if method == Method::OPTIONS {
        return options_response(ALLOW);
    }
    if method != Method::GET {
        return method_not_allowed(ALLOW);
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let tier = core.tokens.check(auth_header);
    if !can_read(&core, tier) {
        return unauthorized("listen requires read token");
    }
    let pattern = pattern(&raw_pattern);
    let rx = core.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        let pattern = pattern.clone();
        match item {
            Ok(change) if matches(&pattern, &change.path) => {
                Some(Ok::<Event, Infallible>(sse_change_event(change)))
            }
            Ok(_) => None,
            Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok(Event::default()
                .event("lag")
                .data(format!("missed: {n}")))),
        }
    });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

pub(crate) fn pattern(raw: &str) -> String {
    let p = raw.trim();
    if p == "*" || p == "/*" || p == "/" || p.is_empty() {
        "*".to_owned()
    } else if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    }
}

pub(crate) fn matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

fn sse_change_event(change: ChangeEvent) -> Event {
    let mut data = format!("path: {}\nmethod: {}", change.path, change.method);
    if !change.etag.is_empty() {
        data.push_str("\netag: ");
        data.push_str(&change.etag);
    }
    Event::default()
        .event(change.method.to_ascii_lowercase())
        .id(change.id.to_string())
        .data(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_prefix_or_exact() {
        assert_eq!(pattern("*"), "*");
        assert_eq!(pattern("/"), "*");
        assert_eq!(pattern("home/task/*"), "/home/task/*");
        assert_eq!(pattern("home/销售/*"), "/home/销售/*");
        assert!(matches("*", "/home/task/a"));
        assert!(matches("/home/task/*", "/home/task/a"));
        assert!(!matches("/home/task/*", "/home/other/a"));
        assert!(matches("/home/销售/*", "/home/销售/报告"));
        assert!(matches("/home/task/a", "/home/task/a"));
        assert!(!matches("/home/task/a", "/home/task/ab"));
    }

    #[test]
    fn sse_change_event_is_control_plane_only() {
        let event = sse_change_event(ChangeEvent {
            id: 42,
            method: "PUT",
            path: "/home/task/a".to_string(),
            etag: "hmac-abc".to_string(),
        });
        let wire = format!("{event:?}");
        assert!(wire.contains("put"));
        assert!(wire.contains("42"));
        assert!(wire.contains("/home/task/a"));
        assert!(wire.contains("hmac-abc"));
        assert!(!wire.contains("body"));
    }
}
