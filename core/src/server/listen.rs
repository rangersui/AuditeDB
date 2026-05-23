use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use std::{sync::Arc, time::Duration};

use crate::{
    engine::EngineError,
    engine_ops::EngineOps,
    engine_types::{ChangeEvent as EngineChangeEvent, SubscribePattern, SubscriptionRecvError},
    method_not_allowed, options_response, server_error, unauthorized, Core,
};

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
    let pattern = SubscribePattern::new(&raw_pattern);
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let subscription = match EngineOps::new(&core).subscribe(&pattern, tier, last_event_id) {
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
    use crate::{auth, store, Core};
    use dashmap::DashMap;
    use std::{
        collections::VecDeque,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize},
            Arc, Mutex as StdMutex,
        },
    };
    use tokio::sync::{broadcast, watch, Semaphore};

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
        let event = sse_change_event(crate::engine_types::ChangeEvent {
            id: 42,
            method: "PUT",
            path: crate::engine_types::ValidatedWorldPath::new("home/task/a").unwrap(),
            etag: "hmac-abc".to_string(),
        });
        let wire = format!("{event:?}");
        assert!(wire.contains("put"));
        assert!(wire.contains("42"));
        assert!(wire.contains("/home/task/a"));
        assert!(wire.contains("hmac-abc"));
        assert!(!wire.contains("body"));
    }

    #[tokio::test]
    async fn handler_returns_503_when_listen_slots_are_full() {
        let (events, _) = broadcast::channel(16);
        let core = Arc::new(Core {
            data: PathBuf::new(),
            tokens: auth::Tokens {
                read: None,
                write: None,
                approve: None,
            },
            hmac_key: b"test-key".to_vec(),
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: 1024,
            max_memory_bytes: 1024,
            max_storage_bytes: None,
            storage_body_bytes: Arc::new(AtomicUsize::new(0)),
            durable_world_count: Arc::new(AtomicUsize::new(0)),
            delete_ledger_created: Arc::new(AtomicBool::new(false)),
            events,
            listen_slots: Arc::new(Semaphore::new(0)),
            listen_replay_max: crate::DEFAULT_LISTEN_REPLAY_MAX,
            event_log: Arc::new(StdMutex::new(VecDeque::new())),
            shutdown: watch::channel(false).1,
            next_event: crate::state::new_event_counter(),
            world_locks: Arc::new(DashMap::new()),
            ledger: Arc::new(crate::ledger::LedgerWriter::new()),
            read_cache: Arc::new(crate::read_cache::ReadCache::new(
                crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES,
            )),
            persist_header_allowlist: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
            persist_header_user_deny: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
        });

        let resp = handler(
            State(core),
            Method::GET,
            HeaderMap::new(),
            AxPath("home/task/*".to_string()),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn replay_after_reports_ring_gap_and_replays_available_events() {
        let (events, _) = broadcast::channel(16);
        let core = Core {
            data: PathBuf::new(),
            tokens: auth::Tokens {
                read: None,
                write: None,
                approve: None,
            },
            hmac_key: b"test-key".to_vec(),
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: 1024,
            max_memory_bytes: 1024,
            max_storage_bytes: None,
            storage_body_bytes: Arc::new(AtomicUsize::new(0)),
            durable_world_count: Arc::new(AtomicUsize::new(0)),
            delete_ledger_created: Arc::new(AtomicBool::new(false)),
            events,
            listen_slots: Arc::new(Semaphore::new(crate::DEFAULT_MAX_LISTEN_CONNECTIONS)),
            listen_replay_max: crate::DEFAULT_LISTEN_REPLAY_MAX,
            event_log: Arc::new(StdMutex::new(VecDeque::new())),
            shutdown: watch::channel(false).1,
            next_event: crate::state::new_event_counter(),
            world_locks: Arc::new(DashMap::new()),
            ledger: Arc::new(crate::ledger::LedgerWriter::new()),
            read_cache: Arc::new(crate::read_cache::ReadCache::new(
                crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES,
            )),
            persist_header_allowlist: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
            persist_header_user_deny: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
        };
        {
            let mut log = core.event_log.lock().unwrap();
            for id in 10..=12 {
                log.push_back(ChangeEvent {
                    id,
                    method: "PUT",
                    path: format!("/home/task/{id}"),
                    etag: format!("hmac-{id}"),
                });
            }
        }

        let pattern = SubscribePattern::new("home/task/*");
        let (gap, replay, floor) = crate::engine_ops::replay_after(&core, Some(5), &pattern);

        assert_eq!(gap, Some(4));
        assert_eq!(replay.len(), 3);
        assert_eq!(replay[0].id, 10);
        assert_eq!(replay[0].path.as_str(), "home/task/10");
        assert_eq!(floor, 12);
    }

    #[test]
    fn replay_after_handles_max_last_event_id_without_overflow() {
        let (events, _) = broadcast::channel(16);
        let core = Core {
            data: PathBuf::new(),
            tokens: auth::Tokens {
                read: None,
                write: None,
                approve: None,
            },
            hmac_key: b"test-key".to_vec(),
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: 1024,
            max_memory_bytes: 1024,
            max_storage_bytes: None,
            storage_body_bytes: Arc::new(AtomicUsize::new(0)),
            durable_world_count: Arc::new(AtomicUsize::new(0)),
            delete_ledger_created: Arc::new(AtomicBool::new(false)),
            events,
            listen_slots: Arc::new(Semaphore::new(crate::DEFAULT_MAX_LISTEN_CONNECTIONS)),
            listen_replay_max: crate::DEFAULT_LISTEN_REPLAY_MAX,
            event_log: Arc::new(StdMutex::new(VecDeque::new())),
            shutdown: watch::channel(false).1,
            next_event: crate::state::new_event_counter(),
            world_locks: Arc::new(DashMap::new()),
            ledger: Arc::new(crate::ledger::LedgerWriter::new()),
            read_cache: Arc::new(crate::read_cache::ReadCache::new(
                crate::read_cache::DEFAULT_READ_CACHE_MAX_ENTRIES,
            )),
            persist_header_allowlist: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
            persist_header_user_deny: Arc::new(crate::http_semantics::HeaderAllowlist::empty()),
        };
        {
            let mut log = core.event_log.lock().unwrap();
            log.push_back(ChangeEvent {
                id: u64::MAX,
                method: "PUT",
                path: "/home/task/max".to_string(),
                etag: "hmac-max".to_string(),
            });
        }

        let pattern = SubscribePattern::new("home/task/*");
        let (gap, replay, floor) = crate::engine_ops::replay_after(&core, Some(u64::MAX), &pattern);

        assert_eq!(gap, None);
        assert!(replay.is_empty());
        assert_eq!(floor, u64::MAX);
    }
}
