use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use std::time::Duration;

use crate::{
    engine::EngineError,
    engine_types::{ChangeEvent as EngineChangeEvent, SubscribePattern, SubscriptionRecvError},
    server::{method_not_allowed, options_response, server_error, unauthorized, ServerState},
};

pub(crate) const ALLOW: &str = "GET, OPTIONS";

// SSE event tap. Curl-first:
//   curl -N http://127.0.0.1:3105/listen/home/task/*
//
// The stream is control-plane only. It says which world changed; it
// never embeds the world's body, so stored Content-Type semantics stay
// entirely on GET/HEAD.
pub(crate) async fn handler(
    State(state): State<ServerState>,
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
    let tier = state.access_tier_from_headers(&headers);
    let pattern = SubscribePattern::new(&raw_pattern);
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let subscription = match state.engine().subscribe(&pattern, tier, last_event_id) {
        Ok(subscription) => subscription,
        Err(EngineError::Auth(_)) => return unauthorized("listen requires read token"),
        Err(EngineError::SubscriptionLimit) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (header::RETRY_AFTER, "1"),
                ],
                "too many listen connections\n",
            )
                .into_response();
        }
        Err(EngineError::ShuttingDown) | Err(EngineError::TransientStorage { .. }) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (header::RETRY_AFTER, "1"),
                ],
                "listen temporarily unavailable\n",
            )
                .into_response();
        }
        Err(_) => return server_error("listen failed".to_string()),
    };
    let stream = futures_util::stream::unfold(subscription, |mut subscription| async move {
        match subscription.recv().await {
            Ok(change) => Some((
                Ok::<Event, std::convert::Infallible>(sse_change_event(change)),
                subscription,
            )),
            Err(SubscriptionRecvError::Lagged { skipped }) => Some((
                Ok(Event::default()
                    .event("lag")
                    .data(format!("missed: {skipped}"))),
                subscription,
            )),
            Err(SubscriptionRecvError::Closed) => None,
            #[cfg(all(not(test), feature = "unstable-engine"))]
            Err(err) => {
                tracing::warn!(?err, "listen subscription receive failed");
                None
            }
            #[cfg(all(not(test), not(feature = "unstable-engine")))]
            Err(_) => None,
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

fn sse_change_event(change: EngineChangeEvent) -> Event {
    let mut data = format!("path: /{}\nmethod: {}", change.path, change.method);
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
    use crate::{event, server::test_support as server_test_support, test_support};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[test]
    fn patterns_are_prefix_or_exact() {
        assert_eq!(event::pattern("*"), "*");
        assert_eq!(event::pattern("/"), "*");
        assert_eq!(event::pattern("home/task/*"), "/home/task/*");
        assert_eq!(event::pattern("home/销售/*"), "/home/销售/*");
        assert!(event::matches("*", "/home/task/a"));
        assert!(event::matches("/home/task/*", "/home/task/a"));
        assert!(!event::matches("/home/task/*", "/home/other/a"));
        assert!(event::matches("/home/销售/*", "/home/销售/报告"));
        assert!(event::matches("/home/task/a", "/home/task/a"));
        assert!(!event::matches("/home/task/a", "/home/task/ab"));
    }

    #[test]
    fn sse_change_event_is_control_plane_only() {
        let event = sse_change_event(crate::engine_types::ChangeEvent::new(
            42,
            "PUT",
            crate::engine_types::ValidatedWorldPath::new("home/task/a").unwrap(),
            "hmac-abc".to_string(),
        ));
        let wire = format!("{event:?}");
        assert!(wire.contains("put"));
        assert!(wire.contains("42"));
        assert!(wire.contains("/home/task/a"));
        assert!(wire.contains("hmac-abc"));
        assert!(!wire.contains("body"));
    }

    #[tokio::test]
    async fn handler_returns_503_when_listen_slots_are_full() {
        let (mut core, dir) = test_support::test_core("listen-slots-full");
        core.listen_slots = Arc::new(Semaphore::new(0));
        let core = Arc::new(core);

        let resp = handler(
            State(server_test_support::server_state_with_max_world_bytes_for_tests(core, 1024)),
            Method::GET,
            HeaderMap::new(),
            AxPath("home/task/*".to_string()),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "1");

        let _ = std::fs::remove_dir_all(dir);
    }
}
