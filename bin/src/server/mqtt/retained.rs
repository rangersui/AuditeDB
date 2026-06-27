use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use rumqttd::protocol::{Packet, Publish};
use tokio::sync::mpsc;

use crate::{
    engine::{Engine, EngineError},
    engine_types::{AccessTier, ValidatedWorldPath},
};

use super::{
    codec::send_packet,
    observability::{warn as mqtt_warn, MqttMetrics},
    topic::MqttSubscribeRoute,
};

const MAX_RETAINED_REPLAY_MESSAGES: usize = 4096;
const MAX_RETAINED_REPLAY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETAINED_REPLAY_SCANNED: usize = 16_384;

pub(super) type RetainedReplayEtags = Arc<Mutex<HashMap<ValidatedWorldPath, String>>>;

pub(super) struct RetainedReplay {
    scanned: usize,
    bytes: usize,
    messages: Vec<RetainedReplayMessage>,
    etags: HashMap<ValidatedWorldPath, String>,
}

struct RetainedReplayMessage {
    topic: Bytes,
    payload: Bytes,
}

enum RetainedReplayError {
    List {
        prefix: String,
        err: EngineError,
    },
    Read {
        world: ValidatedWorldPath,
        err: EngineError,
    },
    Limit {
        limit: &'static str,
        max: usize,
    },
}

#[derive(Clone, Copy)]
struct RetainedReplayLimits {
    messages: usize,
    bytes: usize,
    scanned: usize,
}

impl RetainedReplayLimits {
    const DEFAULT: Self = Self {
        messages: MAX_RETAINED_REPLAY_MESSAGES,
        bytes: MAX_RETAINED_REPLAY_BYTES,
        scanned: MAX_RETAINED_REPLAY_SCANNED,
    };
}

impl RetainedReplay {
    pub(super) fn empty() -> Self {
        Self {
            scanned: 0,
            bytes: 0,
            messages: Vec::new(),
            etags: HashMap::new(),
        }
    }

    pub(super) async fn send(
        self,
        outbound: &mpsc::Sender<Packet>,
        metrics: &MqttMetrics,
    ) -> Result<HashMap<ValidatedWorldPath, String>, String> {
        for message in self.messages {
            let publish = Publish::new(message.topic, message.payload, true);
            if let Err(err) = send_packet(outbound, Packet::Publish(publish, None)).await {
                metrics.retained_replay_failed();
                return Err(err);
            }
            metrics.retained_replay_sent();
        }
        Ok(self.etags)
    }
}

pub(super) async fn collect_retained_replay(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
    metrics: &MqttMetrics,
) -> Option<RetainedReplay> {
    let engine = engine.clone();
    let route = route.clone();
    let result = tokio::task::spawn_blocking(move || {
        collect_retained_replay_blocking(&engine, tier, &route)
    })
    .await;
    match result {
        Ok(Ok(replay)) => {
            metrics.retained_replay_scanned(replay.scanned);
            Some(replay)
        }
        Ok(Err(err)) => {
            log_replay_error(metrics, err);
            None
        }
        Err(err) => {
            let total = metrics.retained_replay_failed();
            mqtt_warn(format_args!(
                "mqtt: retained replay worker failed; failures={total}; err={err:?}"
            ));
            None
        }
    }
}

pub(super) fn should_skip_replayed_live(
    replayed: &RetainedReplayEtags,
    path: &ValidatedWorldPath,
    etag: &str,
) -> bool {
    match replayed
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .entry(path.clone())
    {
        Entry::Occupied(entry) if entry.get() == etag => true,
        Entry::Occupied(entry) => {
            entry.remove();
            false
        }
        Entry::Vacant(_) => false,
    }
}

fn collect_retained_replay_blocking(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
) -> Result<RetainedReplay, RetainedReplayError> {
    collect_retained_replay_blocking_with_limits(engine, tier, route, RetainedReplayLimits::DEFAULT)
}

fn collect_retained_replay_blocking_with_limits(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
    limits: RetainedReplayLimits,
) -> Result<RetainedReplay, RetainedReplayError> {
    let mut replay = RetainedReplay::empty();
    if let Some(world) = route.retained_exact() {
        add_scanned(&mut replay, 1, limits)?;
        collect_retained_world(engine, tier, route, world, &mut replay, limits)?;
    }

    if let Some(prefix) = route.retained_prefix() {
        let remaining = limits.scanned.saturating_sub(replay.scanned);
        let worlds = engine
            .list_worlds_with_prefix_bounded(prefix, tier, remaining)
            .map_err(|err| RetainedReplayError::List {
                prefix: prefix.to_owned(),
                err,
            })?
            .ok_or(RetainedReplayError::Limit {
                limit: "scanned_worlds",
                max: limits.scanned,
            })?;
        add_scanned(&mut replay, worlds.len(), limits)?;
        for world in worlds {
            if route.matches_retained_world(&world) {
                collect_retained_world(engine, tier, route, &world, &mut replay, limits)?;
            }
        }
    }
    Ok(replay)
}

fn add_scanned(
    replay: &mut RetainedReplay,
    count: usize,
    limits: RetainedReplayLimits,
) -> Result<(), RetainedReplayError> {
    let Some(next_scanned) = replay.scanned.checked_add(count) else {
        return Err(RetainedReplayError::Limit {
            limit: "scanned_worlds",
            max: limits.scanned,
        });
    };
    if next_scanned > limits.scanned {
        return Err(RetainedReplayError::Limit {
            limit: "scanned_worlds",
            max: limits.scanned,
        });
    }
    replay.scanned = next_scanned;
    Ok(())
}

fn collect_retained_world(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
    world: &ValidatedWorldPath,
    replay: &mut RetainedReplay,
    limits: RetainedReplayLimits,
) -> Result<(), RetainedReplayError> {
    if replay.etags.contains_key(world) {
        return Ok(());
    }
    let read = match engine.read(world, tier) {
        Ok(Some(read)) if !read.representation.body.is_empty() => read,
        Ok(_) => return Ok(()),
        Err(err) => {
            return Err(RetainedReplayError::Read {
                world: world.clone(),
                err,
            })
        }
    };
    if replay.messages.len() >= limits.messages {
        return Err(RetainedReplayError::Limit {
            limit: "messages",
            max: limits.messages,
        });
    }
    let payload_len = read.representation.body.len();
    let Some(next_bytes) = replay.bytes.checked_add(payload_len) else {
        return Err(RetainedReplayError::Limit {
            limit: "bytes",
            max: limits.bytes,
        });
    };
    if next_bytes > limits.bytes {
        return Err(RetainedReplayError::Limit {
            limit: "bytes",
            max: limits.bytes,
        });
    }
    replay.bytes = next_bytes;
    replay.etags.insert(world.clone(), read.etag);
    replay.messages.push(RetainedReplayMessage {
        topic: route.topic_for_world(world),
        payload: read.representation.body,
    });
    Ok(())
}

fn log_replay_error(metrics: &MqttMetrics, err: RetainedReplayError) {
    let total = metrics.retained_replay_failed();
    match err {
        RetainedReplayError::List { prefix, err } => {
            mqtt_warn(format_args!(
                "mqtt: retained replay list failed for prefix {prefix}; failures={total}; err={err:?}"
            ));
        }
        RetainedReplayError::Read { world, err } => {
            mqtt_warn(format_args!(
                "mqtt: retained replay read failed for {}; failures={total}; err={err:?}",
                world.as_str()
            ));
        }
        RetainedReplayError::Limit { limit, max } => {
            mqtt_warn(format_args!(
                "mqtt: retained replay exceeded {limit} limit {max}; failures={total}"
            ));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::topic::mqtt_filter_to_route;
    use super::*;
    use crate::engine_types::{AuditHmacKey, Preconditions, Representation};

    #[test]
    fn retained_replay_list_errors_are_counted() {
        let metrics = MqttMetrics::shared();

        log_replay_error(
            &metrics,
            RetainedReplayError::List {
                prefix: "home/sensor/".to_owned(),
                err: EngineError::Storage,
            },
        );

        assert_eq!(metrics.snapshot().retained_replay_failures, 1);
    }

    #[test]
    fn collect_retained_replay_blocking_reports_read_errors() {
        let (engine, dir) = test_engine_with_read_token("retained-read-error");
        let route = mqtt_filter_to_route("sensor/temp").unwrap();

        match collect_retained_replay_blocking(&engine, AccessTier::Anon, &route) {
            Err(RetainedReplayError::Read {
                world,
                err: EngineError::Auth(_),
            }) => assert_eq!(world.as_str(), "home/sensor/temp"),
            _ => panic!("expected retained replay read auth error"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn collect_retained_replay_blocking_reports_read_errors_for_wildcard_parent() {
        let (engine, dir) = test_engine_with_read_token("retained-wildcard-parent-read-error");
        write_world(&engine, "home/sensor", b"x").await;
        let route = mqtt_filter_to_route("sensor/#").unwrap();

        match collect_retained_replay_blocking(&engine, AccessTier::Anon, &route) {
            Err(RetainedReplayError::Read {
                world,
                err: EngineError::Auth(_),
            }) => assert_eq!(world.as_str(), "home/sensor"),
            _ => panic!("expected retained replay parent read auth error"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn collect_retained_replay_blocking_enforces_message_limit() {
        let (engine, dir) = test_engine_with_read_token("retained-message-limit");
        write_world(&engine, "home/sensor/a", b"a").await;
        write_world(&engine, "home/sensor/b", b"b").await;
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let limits = RetainedReplayLimits {
            messages: 1,
            bytes: 1024,
            scanned: 8,
        };

        match collect_retained_replay_blocking_with_limits(
            &engine,
            AccessTier::Read,
            &route,
            limits,
        ) {
            Err(RetainedReplayError::Limit {
                limit: "messages",
                max: 1,
            }) => {}
            _ => panic!("expected retained replay message limit"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn collect_retained_replay_blocking_counts_parent_and_child_toward_message_limit() {
        let (engine, dir) = test_engine_with_read_token("retained-parent-child-message-limit");
        write_world(&engine, "home/sensor", b"parent").await;
        write_world(&engine, "home/sensor/a", b"child").await;
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let limits = RetainedReplayLimits {
            messages: 1,
            bytes: 1024,
            scanned: 8,
        };

        match collect_retained_replay_blocking_with_limits(
            &engine,
            AccessTier::Read,
            &route,
            limits,
        ) {
            Err(RetainedReplayError::Limit {
                limit: "messages",
                max: 1,
            }) => {}
            _ => panic!("expected retained replay parent+child message limit"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn collect_retained_replay_blocking_enforces_scanned_limit_before_payload_limits() {
        let (engine, dir) = test_engine_with_read_token("retained-scanned-limit");
        write_world(&engine, "home/sensor/a", b"").await;
        write_world(&engine, "home/sensor/b", b"").await;
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let limits = RetainedReplayLimits {
            messages: 8,
            bytes: 1024,
            scanned: 2,
        };

        match collect_retained_replay_blocking_with_limits(
            &engine,
            AccessTier::Read,
            &route,
            limits,
        ) {
            Err(RetainedReplayError::Limit {
                limit: "scanned_worlds",
                max: 2,
            }) => {}
            _ => panic!("expected retained replay scanned world limit"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn collect_retained_replay_blocking_enforces_byte_limit() {
        let (engine, dir) = test_engine_with_read_token("retained-byte-limit");
        write_world(&engine, "home/sensor/a", b"abcd").await;
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let limits = RetainedReplayLimits {
            messages: 8,
            bytes: 3,
            scanned: 8,
        };

        match collect_retained_replay_blocking_with_limits(
            &engine,
            AccessTier::Read,
            &route,
            limits,
        ) {
            Err(RetainedReplayError::Limit {
                limit: "bytes",
                max: 3,
            }) => {}
            _ => panic!("expected retained replay byte limit"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    fn test_engine_with_read_token(label: &str) -> (Engine, std::path::PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "elastik-mqtt-retained-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let engine = Engine::builder()
            .data_root(&dir)
            .key(AuditHmacKey::try_from_slice(b"0123456789abcdef0123456789abcdef").unwrap())
            .read_token(b"read-token".to_vec())
            .write_token(b"write-token".to_vec())
            .build()
            .unwrap();
        (engine, dir)
    }

    async fn write_world(engine: &Engine, world: &str, body: &'static [u8]) {
        engine
            .replace(
                &ValidatedWorldPath::new(world).unwrap(),
                Representation::new(Bytes::from_static(body), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
    }
}
