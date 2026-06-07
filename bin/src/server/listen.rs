use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use std::time::Duration;

use crate::{
    engine::EngineError,
    engine_types::{
        ChangeEvent as EngineChangeEvent, ChangeVerb, SubscribePattern, SubscriptionRecvError,
    },
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
        Err(EngineError::ShuttingDown) | Err(EngineError::TransientStorage) => {
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
            Err(_err) => {
                #[cfg(feature = "unstable-engine")]
                tracing::warn!(?_err, "listen subscription receive failed");
                None
            }
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
    let method = change_method(change.verb);
    let mut data = format!("path: /{}\nmethod: {method}", change.path);
    if !change.etag.is_empty() {
        data.push_str("\netag: ");
        data.push_str(&change.etag);
    }
    Event::default()
        .event(method.to_ascii_lowercase())
        .id(change.id.to_string())
        .data(data)
}

#[cfg_attr(test, allow(unreachable_patterns))]
fn change_method(verb: ChangeVerb) -> &'static str {
    match verb {
        ChangeVerb::Replace => "PUT",
        ChangeVerb::Append => "POST",
        ChangeVerb::Delete => "DELETE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine_types::{AccessTier, Preconditions, Representation, ValidatedWorldPath},
        server::test_support::{
            server_state_for_engine_for_tests, test_engine_for_server,
            test_engine_for_server_with_listen_slots,
        },
    };
    use axum::body::Bytes;

    #[tokio::test]
    async fn sse_change_event_is_control_plane_only() {
        let (engine, dir) = test_engine_for_server("listen-sse-event");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new("home/task/*"),
                AccessTier::Read,
                None,
            )
            .expect("test subscription should be accepted");
        let world = ValidatedWorldPath::new("home/task/a").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"secret-body"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .expect("test write should notify subscription");

        let event = sse_change_event(
            subscription
                .recv()
                .await
                .expect("test subscription should receive change"),
        );
        let wire = format!("{event:?}");
        assert!(wire.contains("put"));
        assert!(wire.contains("/home/task/a"));
        assert!(wire.contains("hmac-"));
        assert!(!wire.contains("body"));
        assert!(!wire.contains("secret-body"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn handler_returns_503_when_listen_slots_are_full() {
        let (engine, dir) = test_engine_for_server_with_listen_slots("listen-slots-full", 1);
        let _held_slot = engine
            .subscribe(&SubscribePattern::new("home/held"), AccessTier::Read, None)
            .expect("first subscription should consume the only listen slot");

        let resp = handler(
            State(server_state_for_engine_for_tests(engine)),
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
