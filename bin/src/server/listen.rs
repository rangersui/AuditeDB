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
    server::{
        bad_request, method_not_allowed, options_response, server_error, unauthorized, ServerState,
    },
};

pub(crate) const ALLOW: &str = "GET, OPTIONS";

// SSE event tap. Curl-first:
//   curl -N http://127.0.0.1:3105/listen/home/task/*
//
// The stream is control-plane only. Durable body writes carry a timeline
// address; they still never embed the world's body, so stored Content-Type
// semantics stay outside the SSE event.
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
    let last_event_id = match parse_last_event_id(&headers) {
        Ok(last_event_id) => last_event_id,
        Err(reason) => return bad_request(reason),
    };
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
            Err(SubscriptionRecvError::CursorAhead { since, newest }) => {
                Some((Ok(sse_reset_event(since, newest)), subscription))
            }
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

fn parse_last_event_id(headers: &HeaderMap) -> Result<Option<u64>, &'static str> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("invalid Last-Event-ID");
    }
    let raw = value.to_str().map_err(|_| "invalid Last-Event-ID")?;
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid Last-Event-ID");
    }

    let parsed = raw.parse::<u64>().map_err(|_| "invalid Last-Event-ID")?;
    if raw != parsed.to_string() {
        return Err("invalid Last-Event-ID");
    }
    Ok(Some(parsed))
}

/// Frame emitted when a resume cursor belongs to a previous engine process.
///
/// The `id` field deliberately rebases EventSource's automatic
/// `Last-Event-ID` buffer to the newest id in this process.
fn sse_reset_event(since: u64, newest: u64) -> Event {
    Event::default()
        .event("reset")
        .id(newest.to_string())
        .data(format!("since: {since}\nnewest: {newest}"))
}

fn sse_change_event(change: EngineChangeEvent) -> Event {
    let method = change_method(change.verb);
    let mut data = format!("path: /{}\nmethod: {method}", change.path);
    if !change.etag.is_empty() {
        data.push_str("\netag: ");
        data.push_str(&change.etag);
    }
    if let Some(address) = change.timeline_address.as_ref() {
        if address.world() == &change.path {
            data.push_str("\ntimeline-world: ");
            data.push_str(address.world().as_str());
            data.push_str("\ntimeline-generation: ");
            data.push_str(address.generation().as_str());
            data.push_str("\ntimeline-seq: ");
            data.push_str(&address.seq().get().to_string());
            data.push_str("\ntimeline-body-sha256: ");
            data.push_str(address.body_sha256().as_str());
        } else {
            #[cfg(feature = "unstable-engine")]
            tracing::warn!(
                event_path = %change.path,
                timeline_world = %address.world(),
                "dropping mismatched timeline address from SSE event"
            );
        }
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
    async fn sse_change_event_carries_timeline_address_without_body() {
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
        assert!(wire.contains("timeline-world: home/task/a"));
        assert!(wire.contains("timeline-generation: "));
        assert!(wire.contains("timeline-seq: 1"));
        assert!(wire.contains("timeline-body-sha256: "));
        assert!(!wire.contains("secret-body"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sse_change_event_drops_mismatched_timeline_address() {
        let (engine, dir) = test_engine_for_server("listen-sse-mismatch");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new("home/task/*"),
                AccessTier::Read,
                None,
            )
            .expect("test subscription should be accepted");
        let world = ValidatedWorldPath::new("home/task/source").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"body"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .expect("test write should notify subscription");

        let mut event = subscription
            .recv()
            .await
            .expect("test subscription should receive change");
        assert!(event.timeline_address.is_some());
        event.path = ValidatedWorldPath::new("home/task/other").unwrap();

        let wire = format!("{:?}", sse_change_event(event));
        assert!(wire.contains("path: /home/task/other"));
        assert!(!wire.contains("timeline-world"));
        assert!(!wire.contains("home/task/source"));

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

    #[tokio::test]
    async fn handler_rejects_non_decimal_last_event_id() {
        let (engine, dir) = test_engine_for_server("listen-invalid-last-event-id");
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "audit:42".parse().unwrap());

        let resp = handler(
            State(server_state_for_engine_for_tests(engine)),
            Method::GET,
            headers,
            AxPath("home/task/*".to_string()),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_last_event_id_rejects_non_canonical_values() {
        for value in ["", " 42", "42 ", "+42", "audit:42", "00", "00042"] {
            let mut headers = HeaderMap::new();
            headers.insert("last-event-id", value.parse().unwrap());
            assert_eq!(parse_last_event_id(&headers), Err("invalid Last-Event-ID"));
        }
    }

    #[test]
    fn parse_last_event_id_rejects_duplicate_values() {
        let mut headers = HeaderMap::new();
        headers.append("last-event-id", "1".parse().unwrap());
        headers.append("last-event-id", "2".parse().unwrap());
        assert_eq!(parse_last_event_id(&headers), Err("invalid Last-Event-ID"));
    }

    #[test]
    fn parse_last_event_id_accepts_single_ascii_decimal() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "42".parse().unwrap());
        assert_eq!(parse_last_event_id(&headers), Ok(Some(42)));
        headers.insert("last-event-id", "0".parse().unwrap());
        assert_eq!(parse_last_event_id(&headers), Ok(Some(0)));
        assert_eq!(parse_last_event_id(&HeaderMap::new()), Ok(None));
    }

    #[test]
    fn sse_reset_event_rebases_last_event_id() {
        let wire = format!("{:?}", sse_reset_event(42, 7));
        assert!(wire.contains("event: reset"), "{wire}");
        assert!(wire.contains("id: 7"), "{wire}");
        assert!(wire.contains("data: since: 42"), "{wire}");
        assert!(wire.contains("data: newest: 7"), "{wire}");
    }
}
