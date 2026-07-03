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
        ChangeEvent as EngineChangeEvent, ChangeEventIdentity, ChangeVerb, SubscribePattern,
        SubscriptionEventId, SubscriptionRecvError, SubscriptionResetReason, SubscriptionResume,
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
    let resume = match parse_last_event_id(&headers) {
        Ok(resume) => resume,
        Err(reason) => return bad_request(&reason),
    };
    let subscription = match state.engine().subscribe(&pattern, tier, resume).await {
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
        Err(EngineError::InvalidWorldName) => return bad_request("invalid listen pattern"),
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
            Err(SubscriptionRecvError::Reset { reason }) => {
                Some((Ok(sse_reset_event(reason)), subscription))
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

fn parse_last_event_id(headers: &HeaderMap) -> Result<SubscriptionResume, String> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(SubscriptionResume::none());
    };
    if values.next().is_some() {
        return Err("invalid Last-Event-ID: duplicate header".to_owned());
    }
    let raw = value
        .to_str()
        .map_err(|_| "invalid Last-Event-ID: header is not valid text".to_owned())?;
    if raw.is_empty() {
        return Err("invalid Last-Event-ID: empty value".to_owned());
    }

    SubscriptionEventId::from_sse_id(raw)
        .map(SubscriptionResume::after_event_id)
        .map_err(|err| format!("invalid Last-Event-ID: {err}"))
}

fn sse_reset_event(reason: SubscriptionResetReason) -> Event {
    Event::default()
        .event("reset")
        .data(format!("reason: {}", reset_reason_wire(reason)))
}

fn reset_reason_wire(reason: SubscriptionResetReason) -> &'static str {
    match reason {
        SubscriptionResetReason::Incarnation => "incarnation",
        SubscriptionResetReason::Truncation => "truncation",
        SubscriptionResetReason::RingMiss => "ring-miss",
        SubscriptionResetReason::Memory => "memory",
        _ => "unknown",
    }
}

fn sse_change_event(change: EngineChangeEvent) -> Event {
    let method = change_method(change.verb());
    let mut data = format!("path: /{}\nmethod: {method}", change.path());
    if !change.etag().is_empty() {
        data.push_str("\netag: ");
        data.push_str(change.etag());
    }
    if let Some(address) = change.timeline_address() {
        if address.world() == change.path() {
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
                event_path = %change.path(),
                timeline_world = %address.world(),
                "dropping mismatched timeline address from SSE event"
            );
        }
    }
    if let Some(id) = change.delete_ledger_event_id() {
        data.push_str("\nledger-cursor: ");
        data.push_str(&id.to_string());
        data.push_str("\nledger-seq: ");
        data.push_str(&id.seq().get().to_string());
    }
    if let Some(generation) = change.delete_subject_generation() {
        data.push_str("\ntarget-generation: ");
        data.push_str(generation.as_str());
    }
    if let Some(event_type) = change.audit_event_type() {
        data.push_str("\nevent-type: ");
        data.push_str(event_type.as_str());
    }
    if let Some(target) = change.audit_event_target() {
        data.push_str("\ntarget: /");
        data.push_str(target.as_str());
    }
    if let Some(body_sha256) = change.body_sha256() {
        data.push_str("\nbody-sha256: ");
        data.push_str(body_sha256.as_str());
    }
    if let Some(size) = change.body_size() {
        data.push_str("\nsize: ");
        data.push_str(&size.to_string());
    }
    if let Some(content_type) = change.content_type() {
        data.push_str("\ncontent-type: ");
        data.push_str(content_type);
    }
    let event = Event::default()
        .event(method.to_ascii_lowercase())
        .data(data);
    match durable_sse_id(&change) {
        Some(id) => event.id(id),
        None => event,
    }
}

fn durable_sse_id(change: &EngineChangeEvent) -> Option<String> {
    let ChangeEventIdentity::Chain(id) = change.identity() else {
        return None;
    };
    if id.world() == change.path() {
        Some(id.to_string())
    } else {
        None
    }
}

#[cfg_attr(test, allow(unreachable_patterns))]
fn change_method(verb: ChangeVerb) -> &'static str {
    match verb {
        ChangeVerb::Replace => "PUT",
        ChangeVerb::Append => "POST",
        ChangeVerb::Delete => "DELETE",
        ChangeVerb::Format => "FORMAT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        engine_types::{
            AccessTier, Preconditions, Representation, SubscriptionResume, ValidatedWorldPath,
        },
        server::test_support::{
            server_state_for_engine_for_tests, test_engine_for_server,
            test_engine_for_server_with_listen_slots,
        },
    };
    use axum::body::{to_bytes, Bytes};

    #[tokio::test]
    async fn sse_change_event_carries_timeline_address_without_body() {
        let (engine, dir) = test_engine_for_server("listen-sse-event");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new("home/task/*"),
                AccessTier::Read,
                SubscriptionResume::none(),
            )
            .await
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

        let format = sse_change_event(
            subscription
                .recv()
                .await
                .expect("test subscription should receive format change"),
        );
        let format_wire = format!("{format:?}");
        assert!(format_wire.contains("format"));
        assert!(format_wire.contains("body-sha256: "));
        assert!(format_wire.contains("size: 0"));

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
        assert!(wire.contains("timeline-seq: 2"));
        assert!(wire.contains("timeline-body-sha256: "));
        assert!(wire.contains("body-sha256: "));
        assert!(wire.contains("size: 11"));
        assert!(wire.contains("content-type: text/plain"));
        assert!(wire.contains("id: home/task/a@"), "{wire}");
        assert!(wire.contains("=2"), "{wire}");
        assert!(!wire.contains("secret-body"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sse_change_event_renders_matched_timeline_address() {
        let (engine, dir) = test_engine_for_server("listen-sse-mismatch");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new("home/task/*"),
                AccessTier::Read,
                SubscriptionResume::none(),
            )
            .await
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

        let _format = subscription
            .recv()
            .await
            .expect("test subscription should receive format change");
        let event = subscription
            .recv()
            .await
            .expect("test subscription should receive change");
        assert!(event.timeline_address().is_some());

        let wire = format!("{:?}", sse_change_event(event));
        assert!(wire.contains("path: /home/task/source"));
        assert!(wire.contains("id: home/task/source@"), "{wire}");
        assert!(wire.contains("timeline-world"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sse_change_event_carries_id_for_non_body_chain_event() {
        let (engine, dir) = test_engine_for_server("listen-sse-ledger-id");
        let ledger = ValidatedWorldPath::new("var/log/deletes").unwrap();
        let subject = ValidatedWorldPath::new("home/listen/delete-ledger").unwrap();
        engine
            .replace(
                &subject,
                Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .expect("subject write succeeds");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new(ledger.as_str()),
                AccessTier::Read,
                SubscriptionResume::none(),
            )
            .await
            .expect("ledger subscription opens");

        engine
            .delete(&subject, Preconditions::none(), AccessTier::Approve)
            .await
            .expect("delete succeeds");
        let format = subscription
            .recv()
            .await
            .expect("ledger format event should arrive");
        let format_wire = format!("{:?}", sse_change_event(format));
        assert!(format_wire.contains("format"));

        let change = subscription
            .recv()
            .await
            .expect("ledger event should arrive");
        assert!(change.timeline_address().is_none());
        let event = sse_change_event(change);
        let wire = format!("{event:?}");

        assert!(wire.contains("delete"));
        assert!(wire.contains("path: /var/log/deletes"));
        assert!(wire.contains("id: var/log/deletes@"), "{wire}");
        assert!(wire.contains("=2"), "{wire}");
        assert!(wire.contains("target-generation: "), "{wire}");
        assert!(wire.contains("body-sha256: "));
        assert!(wire.contains("size: 0"));
        assert!(wire.contains("content-type: "));
        assert!(!wire.contains("timeline-body-sha256"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sse_change_event_subject_delete_ping_is_idless_with_ledger_seq() {
        let (engine, dir) = test_engine_for_server("listen-sse-delete-subject-seq");
        let subject = ValidatedWorldPath::new("home/listen/delete-subject-seq").unwrap();
        engine
            .replace(
                &subject,
                Representation::new(Bytes::from_static(b"gone"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .expect("subject write succeeds");
        let mut subscription = engine
            .subscribe(
                &SubscribePattern::new(subject.as_str()),
                AccessTier::Read,
                SubscriptionResume::none(),
            )
            .await
            .expect("subject subscription opens");

        engine
            .delete(&subject, Preconditions::none(), AccessTier::Approve)
            .await
            .expect("delete succeeds");
        let change = subscription.recv().await.expect("subject delete event");
        assert!(matches!(change.identity(), ChangeEventIdentity::Ephemeral));
        let wire = format!("{:?}", sse_change_event(change));

        assert!(wire.contains("delete"));
        assert!(wire.contains("path: /home/listen/delete-subject-seq"));
        assert!(wire.contains("ledger-cursor: var/log/deletes@"), "{wire}");
        assert!(wire.contains("ledger-seq: 2"), "{wire}");
        assert!(wire.contains("target-generation: "), "{wire}");
        assert!(
            !wire.contains("id: home/listen/delete-subject-seq@"),
            "{wire}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sse_reset_event_uses_idless_reason_frame() {
        let wire = format!(
            "{:?}",
            sse_reset_event(SubscriptionResetReason::Incarnation)
        );
        assert!(wire.contains("event: reset"), "{wire}");
        assert!(wire.contains("reason: incarnation"), "{wire}");
        assert!(!wire.contains("id:"), "{wire}");
    }

    #[tokio::test]
    async fn handler_returns_503_when_listen_slots_are_full() {
        let (engine, dir) = test_engine_for_server_with_listen_slots("listen-slots-full", 1);
        let _held_slot = engine
            .subscribe(
                &SubscribePattern::new("home/held"),
                AccessTier::Read,
                SubscriptionResume::none(),
            )
            .await
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
    async fn handler_rejects_malformed_last_event_id() {
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
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body should buffer");
        let body = String::from_utf8(body.to_vec()).expect("response body should be utf-8");
        assert!(
            body.contains("subscription event id is missing seq delimiter"),
            "{body}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn handler_rejects_invalid_exact_listen_resume_pattern() {
        let (engine, dir) = test_engine_for_server("listen-invalid-exact-pattern");
        let mut headers = HeaderMap::new();
        headers.insert(
            "last-event-id",
            "home/task/a@0123456789abcdef0123456789abcdef=1"
                .parse()
                .unwrap(),
        );

        let resp = handler(
            State(server_state_for_engine_for_tests(engine)),
            Method::GET,
            headers,
            AxPath("proc/version".to_string()),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_last_event_id_rejects_non_canonical_values() {
        for value in [
            "",
            " 42",
            "42 ",
            "+42",
            "audit:42",
            "00",
            "00042",
            "0123456789abcdef0123456789abcdef:0042",
            "0123456789abcdef0123456789abcdeF:42",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("last-event-id", value.parse().unwrap());
            assert!(parse_last_event_id(&headers).is_err());
        }
    }

    #[test]
    fn parse_last_event_id_rejects_duplicate_values() {
        let mut headers = HeaderMap::new();
        headers.append("last-event-id", "1".parse().unwrap());
        headers.append("last-event-id", "2".parse().unwrap());
        assert_eq!(
            parse_last_event_id(&headers),
            Err("invalid Last-Event-ID: duplicate header".to_owned())
        );
    }

    #[test]
    fn parse_last_event_id_accepts_durable_event_id_only() {
        let cursor = "home/task/a@0123456789abcdef0123456789abcdef=42";
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", cursor.parse().unwrap());
        assert_eq!(
            parse_last_event_id(&headers),
            Ok(SubscriptionResume::after_event_id(
                SubscriptionEventId::from_sse_id(cursor).unwrap()
            ))
        );
        headers.insert("last-event-id", "42".parse().unwrap());
        assert_eq!(
            parse_last_event_id(&headers),
            Err("invalid Last-Event-ID: subscription event id is missing seq delimiter".to_owned())
        );
        headers.insert("last-event-id", "0".parse().unwrap());
        assert_eq!(
            parse_last_event_id(&headers),
            Err("invalid Last-Event-ID: subscription event id is missing seq delimiter".to_owned())
        );
        assert_eq!(
            parse_last_event_id(&HeaderMap::new()),
            Ok(SubscriptionResume::none())
        );
    }
}
