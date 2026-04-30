use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, Method},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::{
    iter,
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
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
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let rx = core.events.subscribe();
    let (lag, replay, live_floor) = replay_after(&core, last_event_id, &pattern);
    let replay_mode = last_event_id.is_some();
    let lag_stream = iter(lag.into_iter().map(|missed| {
        Ok::<Event, Infallible>(
            Event::default()
                .event("lag")
                .data(format!("missed: {missed}")),
        )
    }));
    let replay_stream = iter(
        replay
            .into_iter()
            .map(|change| Ok::<Event, Infallible>(sse_change_event(change))),
    );
    let live_stream = tokio_stream::StreamExt::filter_map(BroadcastStream::new(rx), move |item| {
        let pattern = pattern.clone();
        match item {
            Ok(change)
                if (!replay_mode || change.id > live_floor) && matches(&pattern, &change.path) =>
            {
                Some(Ok::<Event, Infallible>(sse_change_event(change)))
            }
            Ok(_) => None,
            Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok(Event::default()
                .event("lag")
                .data(format!("missed: {n}")))),
        }
    });
    let mut shutdown = core.shutdown.clone();
    let shutdown_signal = async move {
        let _ = shutdown.changed().await;
    };
    let replay_stream = futures_util::StreamExt::chain(lag_stream, replay_stream);
    let live_stream = futures_util::StreamExt::take_until(live_stream, shutdown_signal);

    Sse::new(futures_util::StreamExt::chain(replay_stream, live_stream))
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

fn replay_after(
    core: &Core,
    last_event_id: Option<u64>,
    pattern: &str,
) -> (Option<u64>, Vec<ChangeEvent>, u64) {
    let Some(last_id) = last_event_id else {
        return (None, Vec::new(), 0);
    };
    let log = core
        .event_log
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let gap = log.front().and_then(|oldest| {
        let expected_next = last_id.saturating_add(1);
        if expected_next < oldest.id {
            Some(oldest.id - expected_next)
        } else {
            None
        }
    });
    let replay: Vec<_> = log
        .iter()
        .filter(|change| change.id > last_id && matches(pattern, &change.path))
        .cloned()
        .collect();
    let live_floor = replay.last().map(|change| change.id).unwrap_or(last_id);
    (gap, replay, live_floor)
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
    use crate::{auth, store, Core};
    use std::{
        collections::VecDeque,
        path::PathBuf,
        sync::{atomic::AtomicU64, Arc, Mutex as StdMutex},
    };
    use tokio::sync::{broadcast, watch, Mutex};

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

    #[test]
    fn replay_after_reports_ring_gap_and_replays_available_events() {
        let (events, _) = broadcast::channel(16);
        let core = Core {
            data: PathBuf::new(),
            tokens: auth::Tokens {
                read: None,
                auth: None,
                approve: None,
            },
            hmac_key: b"test-key".to_vec(),
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: 1024,
            max_memory_bytes: 1024,
            events,
            event_log: Arc::new(StdMutex::new(VecDeque::new())),
            shutdown: watch::channel(false).1,
            next_event: Arc::new(AtomicU64::new(0)),
            write_lock: Arc::new(Mutex::new(())),
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

        let (gap, replay, floor) = replay_after(&core, Some(5), "/home/task/*");

        assert_eq!(gap, Some(4));
        assert_eq!(replay.len(), 3);
        assert_eq!(replay[0].id, 10);
        assert_eq!(floor, 12);
    }

    #[test]
    fn replay_after_handles_max_last_event_id_without_overflow() {
        let (events, _) = broadcast::channel(16);
        let core = Core {
            data: PathBuf::new(),
            tokens: auth::Tokens {
                read: None,
                auth: None,
                approve: None,
            },
            hmac_key: b"test-key".to_vec(),
            mem: Arc::new(store::MemoryStore::new()),
            max_world_bytes: 1024,
            max_memory_bytes: 1024,
            events,
            event_log: Arc::new(StdMutex::new(VecDeque::new())),
            shutdown: watch::channel(false).1,
            next_event: Arc::new(AtomicU64::new(0)),
            write_lock: Arc::new(Mutex::new(())),
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

        let (gap, replay, floor) = replay_after(&core, Some(u64::MAX), "/home/task/*");

        assert_eq!(gap, None);
        assert!(replay.is_empty());
        assert_eq!(floor, u64::MAX);
    }
}
