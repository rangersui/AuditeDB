//! Native MQTT surface for elastik-core.
//!
//! This adapter deliberately keeps the broker state machine in Elastik instead
//! of handing authorization to rumqttd's router. rumqttd provides the MQTT
//! packet grammar; every accepted PUBLISH and SUBSCRIBE goes through the same
//! protocol-neutral Engine as HTTP and CoAP.

mod client_registry;
mod codec;
mod observability;
mod retained;
mod session;
mod topic;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use rumqttd::protocol::{ConnAck, ConnectReturnCode, Login, Packet};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{timeout, Duration},
};

use crate::{
    engine::{Engine, ShutdownToken},
    engine_types::AccessTier,
};

use self::{
    client_registry::ClientRegistry,
    codec::{send_packet, write_loop, PacketReadError, PacketReader},
    observability::{info as mqtt_info, warn as mqtt_warn, MqttConnectionGuard},
    session::MqttSession,
};

pub(crate) use observability::{MqttMetrics, MqttMetricsSnapshot};

const OUTBOUND_QUEUE: usize = 128;
const WRITE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLIENT_ID_BYTES: usize = 256;
const MAX_MQTT_CREDENTIAL_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttReject {
    Topic,
    Filter,
    UnsupportedWildcard,
    Auth,
    Storage,
    TooLarge,
    Quota,
    ShuttingDown,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) async fn serve(
    engine: Engine,
    bind: String,
    mut shutdown: ShutdownToken,
    config: MqttServeConfig,
    metrics: Arc<MqttMetrics>,
) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(e) => {
            mqtt_warn(format_args!("mqtt: failed to bind mqtt://{bind}/: {e}"));
            return;
        }
    };
    mqtt_info(format_args!("mqtt: listening on mqtt://{bind}/"));
    mqtt_info(format_args!("mqtt: CONNECT password maps to elastik token tier; username-only token auth is legacy fallback"));
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let runtime = MqttRuntime::new(
        config.max_packet_bytes,
        config.max_pending_qos2_bytes,
        config.connect_timeout,
        metrics.clone(),
        ClientRegistry::new(metrics),
    );
    let preauth_limiter = PreAuthLimiter::new(config.max_preauth_per_ip);

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                mqtt_info(format_args!("mqtt: shutdown signal received"));
                return;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        mqtt_warn(format_args!("mqtt: accept: {e}"));
                        continue;
                    }
                };
                let preauth_permit = match preauth_limiter.try_acquire(peer.ip()) {
                    Some(permit) => permit,
                    None => {
                        let total = runtime.metrics.preauth_rejected();
                        mqtt_warn(format_args!(
                            "mqtt: pre-auth connection limit reached for {}; total_preauth_rejections={total}; rejecting {peer}",
                            peer.ip(),
                        ));
                        continue;
                    }
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        mqtt_warn(format_args!("mqtt: connection limit reached; rejecting {peer}"));
                        continue;
                    }
                };
                let engine = engine.clone();
                let conn_shutdown = engine.shutdown_receiver();
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(engine, stream, peer, conn_shutdown, permit, preauth_permit, runtime).await {
                        mqtt_warn(format_args!("mqtt: connection {peer}: {e}"));
                    }
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MqttServeConfig {
    pub(crate) max_packet_bytes: usize,
    pub(crate) max_connections: usize,
    pub(crate) max_pending_qos2_bytes: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_preauth_per_ip: usize,
}

async fn handle_connection(
    engine: Engine,
    stream: TcpStream,
    peer: SocketAddr,
    mut shutdown: ShutdownToken,
    _permit: OwnedSemaphorePermit,
    preauth_permit: PreAuthPermit,
    runtime: MqttRuntime,
) -> Result<(), String> {
    let connection_guard = MqttConnectionGuard::new(runtime.metrics.clone());
    let session_id = connection_guard.id();
    mqtt_info(format_args!(
        "mqtt: session {session_id} accepted from {peer}"
    ));
    let (reader, writer) = stream.into_split();
    let (outbound, rx) = mpsc::channel(OUTBOUND_QUEUE);
    let mut writer = tokio::spawn(write_loop(writer, rx));
    let mut reader = PacketReader::new(reader, runtime.max_packet_bytes);

    let first = tokio::select! {
        _ = shutdown.wait() => return Ok(()),
        packet = timeout(runtime.connect_timeout, reader.read_packet()) => {
            packet
                .map_err(|_| "CONNECT timeout".to_owned())?
                .map_err(|e| e.to_string())?
        },
    };
    drop(preauth_permit);
    let connect = match connect_session(&engine, &first) {
        Ok(connect) => connect,
        Err(reject) => {
            if reject.code == Some(ConnectReturnCode::BadUserNamePassword) {
                let total = runtime.metrics.auth_failed();
                mqtt_warn(format_args!(
                    "mqtt: session {session_id} auth failed for {peer}; total_auth_failures={total}"
                ));
            }
            if let Some(code) = reject.code {
                let _ = send_connack(&outbound, code).await;
            }
            drop(outbound);
            finish_writer(peer, &mut writer).await;
            return Err(reject.reason.to_owned());
        }
    };
    let mut client_registration = runtime.clients.register(connect.client_id.clone());
    mqtt_info(format_args!(
        "mqtt: session {session_id} connected peer={peer} client_id={}",
        connect.client_id
    ));
    send_connack(&outbound, ConnectReturnCode::Success).await?;

    let mut session = MqttSession::new_with_metrics(
        engine,
        connect.tier,
        outbound,
        runtime.max_pending_qos2_bytes,
        runtime.metrics.clone(),
        session_id,
    );
    let mut connection_error = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            _ = client_registration.replaced() => {
                mqtt_info(format_args!(
                    "mqtt: session {session_id} client_id {} replaced; closing {peer}",
                    client_registration.client_id()
                ));
                break;
            }
            packet = reader.read_packet_with_timeout(connect.keep_alive_timeout) => {
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(PacketReadError::Closed) => break,
                    Err(PacketReadError::KeepAliveTimeout) => {
                        let total = runtime.metrics.keep_alive_timed_out();
                        mqtt_warn(format_args!(
                            "mqtt: session {session_id} keep-alive timeout for {peer}; total_keep_alive_timeouts={total}"
                        ));
                        connection_error = Some(PacketReadError::KeepAliveTimeout.to_string());
                        break;
                    }
                    Err(e) => {
                        connection_error = Some(e.to_string());
                        break;
                    }
                };
                match session.handle_packet(packet).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => {
                        connection_error = Some(e);
                        break;
                    }
                }
            }
        }
    }

    session.abort_subscriptions();
    drop(session);
    finish_writer(peer, &mut writer).await;
    mqtt_info(format_args!(
        "mqtt: session {session_id} disconnected {peer}"
    ));
    match connection_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[derive(Clone)]
struct PreAuthLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl PreAuthLimiter {
    fn new(max_per_ip: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<PreAuthPermit> {
        if self.max_per_ip == 0 {
            return None;
        }
        let mut counts = self.inner.lock().expect("pre-auth limiter poisoned");
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(PreAuthPermit {
            ip,
            limiter: self.clone(),
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut counts = self.inner.lock().expect("pre-auth limiter poisoned");
        let Some(count) = counts.get_mut(&ip) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&ip);
        }
    }

    #[cfg(test)]
    fn count_for(&self, ip: IpAddr) -> usize {
        self.inner
            .lock()
            .expect("pre-auth limiter poisoned")
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}

struct PreAuthPermit {
    ip: IpAddr,
    limiter: PreAuthLimiter,
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[derive(Clone)]
struct MqttRuntime {
    max_packet_bytes: usize,
    max_pending_qos2_bytes: usize,
    connect_timeout: Duration,
    metrics: Arc<MqttMetrics>,
    clients: ClientRegistry,
}

impl MqttRuntime {
    fn new(
        max_packet_bytes: usize,
        max_pending_qos2_bytes: usize,
        connect_timeout: Duration,
        metrics: Arc<MqttMetrics>,
        clients: ClientRegistry,
    ) -> Self {
        Self {
            max_packet_bytes,
            max_pending_qos2_bytes,
            connect_timeout,
            metrics,
            clients,
        }
    }
}

async fn finish_writer(peer: SocketAddr, writer: &mut JoinHandle<()>) {
    match timeout(WRITE_SHUTDOWN_TIMEOUT, &mut *writer).await {
        Ok(_) => {}
        Err(_) => {
            mqtt_warn(format_args!(
                "mqtt: writer shutdown timeout for {peer}; aborting writer task"
            ));
            writer.abort();
            let _ = writer.await;
        }
    }
}

async fn send_connack(
    outbound: &mpsc::Sender<Packet>,
    code: ConnectReturnCode,
) -> Result<(), String> {
    send_packet(
        outbound,
        Packet::ConnAck(
            ConnAck {
                session_present: false,
                code,
            },
            None,
        ),
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectSession {
    client_id: String,
    tier: AccessTier,
    keep_alive_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectReject {
    code: Option<ConnectReturnCode>,
    reason: &'static str,
}

impl ConnectReject {
    const fn without_connack(reason: &'static str) -> Self {
        Self { code: None, reason }
    }

    const fn with_connack(code: ConnectReturnCode, reason: &'static str) -> Self {
        Self {
            code: Some(code),
            reason,
        }
    }
}

fn connect_session(engine: &Engine, packet: &Packet) -> Result<ConnectSession, ConnectReject> {
    let Packet::Connect(connect, _props, will, will_props, login) = packet else {
        return Err(ConnectReject::without_connack(
            "first packet must be CONNECT",
        ));
    };
    if connect.client_id.contains(char::is_control) {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::ClientIdentifierNotValid,
            "client id contains control bytes",
        ));
    }
    if connect.client_id.is_empty() {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::ClientIdentifierNotValid,
            "client id is empty",
        ));
    }
    if connect.client_id.len() > MAX_CLIENT_ID_BYTES {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::ClientIdentifierNotValid,
            "client id is too long",
        ));
    }
    if !connect.clean_session {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::NotAuthorized,
            "persistent MQTT sessions are not supported",
        ));
    }
    if will.is_some() || will_props.is_some() {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::NotAuthorized,
            "MQTT Last Will is not supported",
        ));
    }
    let tier = verify_login(engine, login.as_ref())?;
    Ok(ConnectSession {
        client_id: connect.client_id.clone(),
        tier,
        keep_alive_timeout: keep_alive_timeout(connect.keep_alive),
    })
}

fn verify_login(engine: &Engine, login: Option<&Login>) -> Result<AccessTier, ConnectReject> {
    let Some(login) = login else {
        return Ok(AccessTier::Anon);
    };
    if login.password.len() > MAX_MQTT_CREDENTIAL_BYTES
        || login.username.len() > MAX_MQTT_CREDENTIAL_BYTES
    {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::BadUserNamePassword,
            "MQTT credentials too large",
        ));
    }
    let token = if !login.password.is_empty() {
        Some(login.password.as_bytes())
    } else if !login.username.is_empty() {
        Some(login.username.as_bytes())
    } else {
        None
    };
    let Some(token) = token else {
        return Ok(AccessTier::Anon);
    };
    let tier = engine.verify_token(token);
    if tier == AccessTier::Anon {
        return Err(ConnectReject::with_connack(
            ConnectReturnCode::BadUserNamePassword,
            "MQTT credentials rejected",
        ));
    }
    Ok(tier)
}

fn keep_alive_timeout(keep_alive_seconds: u16) -> Option<Duration> {
    if keep_alive_seconds == 0 {
        return None;
    }
    Some(Duration::from_millis(u64::from(keep_alive_seconds) * 1500))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use super::topic::{mqtt_filter_to_route, mqtt_publish_topic_to_world, publish_qos_pkid};
    use super::*;
    use crate::engine_types::{
        Preconditions, Representation, SubscribePattern, ValidatedWorldPath,
    };
    use bytes::{Bytes, BytesMut};
    use rumqttd::protocol::{
        self, v4::V4, Connect, Filter, LastWill, Login, Protocol, PubCompReason, PubRecReason,
        Publish, QoS, RetainForwardRule, Subscribe, SubscribeReasonCode,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    #[test]
    fn mqtt_publish_retain_selects_storage_namespace() {
        assert_eq!(
            mqtt_publish_topic_to_world("sensor/temp", false)
                .unwrap()
                .as_str(),
            "tmp/sensor/temp"
        );
        assert_eq!(
            mqtt_publish_topic_to_world("sensor/temp", true)
                .unwrap()
                .as_str(),
            "home/sensor/temp"
        );
        for topic in [
            "",
            "/sensor/temp",
            "sensor//temp",
            "sensor/temp/",
            "$SYS/broker",
            "sensor/+/temp",
            "sensor/#",
            "home/sensor/temp",
            "tmp/sensor/temp",
            "sensor/../etc/key",
        ] {
            assert!(
                mqtt_publish_topic_to_world(topic, false).is_err(),
                "publish topic should be rejected: {topic}"
            );
        }
    }

    #[test]
    fn mqtt_filters_map_to_merged_engine_subscribe_routes() {
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let live: Vec<&str> = route
            .live_patterns()
            .iter()
            .map(SubscribePattern::as_str)
            .collect();
        assert_eq!(
            live,
            vec![
                "/tmp/sensor",
                "/tmp/sensor/*",
                "/home/sensor",
                "/home/sensor/*"
            ]
        );
        assert_eq!(route.retained_prefix(), Some("home/sensor/"));
        assert_eq!(
            route.retained_exact().map(ValidatedWorldPath::as_str),
            Some("home/sensor")
        );
        assert!(route.matches_retained_world(&ValidatedWorldPath::new("home/sensor").unwrap()));
        assert!(route.matches_retained_world(&ValidatedWorldPath::new("home/sensor/temp").unwrap()));
        assert!(!route.matches_retained_world(&ValidatedWorldPath::new("tmp/sensor/temp").unwrap()));
        assert_eq!(
            route.topic_for_world(&ValidatedWorldPath::new("home/sensor/temp").unwrap()),
            Bytes::from_static(b"sensor/temp")
        );
        assert_eq!(
            route.topic_for_world(&ValidatedWorldPath::new("tmp/sensor/temp").unwrap()),
            Bytes::from_static(b"sensor/temp")
        );

        let exact = mqtt_filter_to_route("sensor/temp").unwrap();
        let live: Vec<&str> = exact
            .live_patterns()
            .iter()
            .map(SubscribePattern::as_str)
            .collect();
        assert_eq!(live, vec!["/tmp/sensor/temp", "/home/sensor/temp"]);
        assert_eq!(exact.retained_prefix(), None);
        assert_eq!(
            exact.retained_exact().map(ValidatedWorldPath::as_str),
            Some("home/sensor/temp")
        );

        assert_eq!(
            mqtt_filter_to_route("sensor/+/temp").unwrap_err(),
            MqttReject::UnsupportedWildcard
        );
        for filter in [
            "",
            "#",
            "/sensor/#",
            "sensor//temp",
            "sensor/temp/",
            "$SYS/#",
            "home/#",
            "tmp/sensor/#",
            "var/log/#",
        ] {
            assert!(
                mqtt_filter_to_route(filter).is_err(),
                "filter should be rejected: {filter}"
            );
        }
    }

    #[test]
    fn publish_qos_pkid_recovers_private_rumqttd_fields() {
        let mut raw = BytesMut::new();
        raw.extend_from_slice(&[
            0x32, 0x0b, 0x00, 0x06, b'h', b'o', b'm', b'e', b'/', b'a', 0x00, 0x07, b'x',
        ]);
        let packet = V4.read_mut(&mut raw, 1024).unwrap();
        let Packet::Publish(publish, None) = packet else {
            panic!("expected publish");
        };
        assert_eq!(publish_qos_pkid(&publish), Some((QoS::AtLeastOnce, 7)));
    }

    #[test]
    fn connect_password_maps_to_engine_tier() {
        let (engine, dir) = test_engine("mqtt-connect-tier");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: true,
            },
            None,
            None,
            None,
            Some(Login {
                username: "device-a".to_owned(),
                password: "write-token".to_owned(),
            }),
        );
        let session = connect_session(&engine, &packet).unwrap();
        assert_eq!(session.tier, AccessTier::Write);
        assert_eq!(session.keep_alive_timeout, Some(Duration::from_secs(45)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_rejects_bad_credentials() {
        let (engine, dir) = test_engine("mqtt-connect-bad-creds");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: true,
            },
            None,
            None,
            None,
            Some(Login {
                username: "device-a".to_owned(),
                password: "not-the-token".to_owned(),
            }),
        );
        let err = connect_session(&engine, &packet).unwrap_err();
        assert_eq!(err.code, Some(ConnectReturnCode::BadUserNamePassword));
        assert_eq!(err.reason, "MQTT credentials rejected");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_rejects_oversized_credentials() {
        let (engine, dir) = test_engine("mqtt-connect-big-creds");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: true,
            },
            None,
            None,
            None,
            Some(Login {
                username: "device-a".to_owned(),
                password: "x".repeat(MAX_MQTT_CREDENTIAL_BYTES + 1),
            }),
        );
        let err = connect_session(&engine, &packet).unwrap_err();
        assert_eq!(err.code, Some(ConnectReturnCode::BadUserNamePassword));
        assert_eq!(err.reason, "MQTT credentials too large");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_rejects_empty_client_id() {
        let (engine, dir) = test_engine("mqtt-connect-empty-client-id");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: String::new(),
                clean_session: true,
            },
            None,
            None,
            None,
            None,
        );
        let err = connect_session(&engine, &packet).unwrap_err();
        assert_eq!(err.code, Some(ConnectReturnCode::ClientIdentifierNotValid));
        assert_eq!(err.reason, "client id is empty");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_keeps_legacy_username_token_fallback() {
        let (engine, dir) = test_engine("mqtt-connect-legacy-username");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: true,
            },
            None,
            None,
            None,
            Some(Login {
                username: "write-token".to_owned(),
                password: String::new(),
            }),
        );
        let session = connect_session(&engine, &packet).unwrap();
        assert_eq!(session.tier, AccessTier::Write);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mqtt_keep_alive_uses_spec_timeout_multiplier() {
        assert_eq!(keep_alive_timeout(0), None);
        assert_eq!(keep_alive_timeout(1), Some(Duration::from_millis(1500)));
        assert_eq!(keep_alive_timeout(30), Some(Duration::from_secs(45)));
    }

    #[test]
    fn mqtt_preauth_limiter_caps_and_releases_per_ip() {
        let limiter = PreAuthLimiter::new(2);
        let first_ip = IpAddr::from([127, 0, 0, 1]);
        let second_ip = IpAddr::from([127, 0, 0, 2]);

        let first = limiter.try_acquire(first_ip).unwrap();
        let second = limiter.try_acquire(first_ip).unwrap();
        assert!(limiter.try_acquire(first_ip).is_none());
        assert!(limiter.try_acquire(second_ip).is_some());
        assert_eq!(limiter.count_for(first_ip), 2);

        drop(first);
        assert_eq!(limiter.count_for(first_ip), 1);
        assert!(limiter.try_acquire(first_ip).is_some());
        drop(second);

        let disabled = PreAuthLimiter::new(0);
        assert!(disabled.try_acquire(first_ip).is_none());
        assert_eq!(disabled.count_for(first_ip), 0);
    }

    #[test]
    fn mqtt_connect_timeout_keeps_preauth_slots_short_lived() {
        assert!(
            Duration::from_millis(crate::server::config::DEFAULT_MQTT_CONNECT_TIMEOUT_MS as u64)
                <= Duration::from_secs(3)
        );
    }

    #[test]
    fn connect_rejects_non_clean_sessions() {
        let (engine, dir) = test_engine("mqtt-connect-clean-only");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: false,
            },
            None,
            None,
            None,
            None,
        );
        let err = connect_session(&engine, &packet).unwrap_err();
        assert_eq!(err.code, Some(ConnectReturnCode::NotAuthorized));
        assert_eq!(err.reason, "persistent MQTT sessions are not supported");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_rejects_last_will() {
        let (engine, dir) = test_engine("mqtt-connect-last-will");
        let packet = Packet::Connect(
            Connect {
                keep_alive: 30,
                client_id: "client-a".to_owned(),
                clean_session: true,
            },
            None,
            Some(LastWill {
                topic: Bytes::from_static(b"home/status/client-a"),
                message: Bytes::from_static(b"offline"),
                qos: QoS::AtMostOnce,
                retain: false,
            }),
            None,
            None,
        );
        let err = connect_session(&engine, &packet).unwrap_err();
        assert_eq!(err.code, Some(ConnectReturnCode::NotAuthorized));
        assert_eq!(err.reason, "MQTT Last Will is not supported");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn publish_writes_through_engine() {
        let (engine, dir) = test_engine("mqtt-publish-engine");
        let (outbound, _rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session =
            MqttSession::new(engine.clone(), AccessTier::Write, outbound, 1024 * 1024);
        let publish = Publish::new(
            Bytes::from_static(b"sensor/temp"),
            Bytes::from_static(b"21.5"),
            false,
        );
        assert!(session.handle_publish(publish).await.unwrap());
        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        let read = engine.read(&world, AccessTier::Write).unwrap().unwrap();
        assert_eq!(read.representation.body, Bytes::from_static(b"21.5"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn invalid_publish_records_failure_metric() {
        let (engine, dir) = test_engine("mqtt-publish-failure-metric");
        let (outbound, _rx) = mpsc::channel(OUTBOUND_QUEUE);
        let metrics = MqttMetrics::shared();
        let mut session = MqttSession::new_with_metrics(
            engine,
            AccessTier::Write,
            outbound,
            1024 * 1024,
            metrics.clone(),
            17,
        );
        let publish = Publish::new(
            Bytes::from_static(b"home/sensor/temp"),
            Bytes::from_static(b"21.5"),
            false,
        );
        assert!(!session.handle_publish(publish).await.unwrap());
        assert_eq!(metrics.snapshot().publish_failures, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn retained_publish_routes_to_home() {
        let (engine, dir) = test_engine("mqtt-publish-retain");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session =
            MqttSession::new(engine.clone(), AccessTier::Write, outbound, 1024 * 1024);
        let publish = Publish::new(
            Bytes::from_static(b"sensor/temp"),
            Bytes::from_static(b"21.5"),
            true,
        );
        assert!(session.handle_publish(publish).await.unwrap());
        assert!(rx.try_recv().is_err());
        let world = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        let read = engine.read(&world, AccessTier::Write).unwrap().unwrap();
        assert_eq!(read.representation.body, Bytes::from_static(b"21.5"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn publish_with_read_tier_fails_closed_without_write() {
        let (engine, dir) = test_engine("mqtt-publish-auth");
        let (outbound, _rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine.clone(), AccessTier::Read, outbound, 1024 * 1024);
        let publish = Publish::new(
            Bytes::from_static(b"sensor/temp"),
            Bytes::from_static(b"21.5"),
            false,
        );
        assert!(!session.handle_publish(publish).await.unwrap());
        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        assert!(engine.read(&world, AccessTier::Write).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_pubrel_write_failure_does_not_pubcomp_or_drop_pending() {
        let (engine, dir) = test_engine("mqtt-qos2-pubrel-auth-fail");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine.clone(), AccessTier::Read, outbound, 1024 * 1024);
        let publish = qos2_publish(3, b"sensor/temp", b"21.5");
        assert!(session.handle_publish(publish).await.unwrap());
        expect_pubrec(&mut rx, 3).await;

        assert!(!session.handle_pubrel(3).await.unwrap());
        assert!(rx.try_recv().is_err());
        assert_eq!(session.qos2_pending_count(), 1);
        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        assert!(engine.read(&world, AccessTier::Write).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_publish_waits_for_pubrel_before_engine_write() {
        let (engine, dir) = test_engine("mqtt-qos2-waits");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session =
            MqttSession::new(engine.clone(), AccessTier::Write, outbound, 1024 * 1024);
        let publish = qos2_publish(42, b"sensor/temp", b"21.5");
        assert!(session.handle_publish(publish).await.unwrap());
        expect_pubrec(&mut rx, 42).await;

        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        assert!(engine.read(&world, AccessTier::Write).unwrap().is_none());

        assert!(session.handle_pubrel(42).await.unwrap());
        expect_pubcomp(&mut rx, 42).await;
        let read = engine.read(&world, AccessTier::Write).unwrap().unwrap();
        assert_eq!(read.representation.body, Bytes::from_static(b"21.5"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_duplicate_publish_and_pubrel_commit_once() {
        let (engine, dir) = test_engine("mqtt-qos2-duplicates");
        let mut changes = engine
            .subscribe(
                &SubscribePattern::new("tmp/sensor/*"),
                AccessTier::Read,
                Some(0),
            )
            .unwrap();
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session =
            MqttSession::new(engine.clone(), AccessTier::Write, outbound, 1024 * 1024);
        let publish = qos2_publish(7, b"sensor/temp", b"23.0");
        assert!(session.handle_publish(publish.clone()).await.unwrap());
        expect_pubrec(&mut rx, 7).await;
        assert!(session.handle_publish(publish).await.unwrap());
        expect_pubrec(&mut rx, 7).await;

        assert!(session.handle_pubrel(7).await.unwrap());
        expect_pubcomp(&mut rx, 7).await;
        timeout(Duration::from_secs(2), changes.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(session.handle_pubrel(7).await.unwrap());
        expect_pubcomp(&mut rx, 7).await;
        assert!(
            timeout(Duration::from_millis(100), changes.recv())
                .await
                .is_err(),
            "duplicate PUBREL must not produce a second Engine write"
        );
        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        let read = engine.read(&world, AccessTier::Write).unwrap().unwrap();
        assert_eq!(read.representation.body, Bytes::from_static(b"23.0"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_unknown_pubrel_replies_pubcomp_per_spec() {
        let (engine, dir) = test_engine("mqtt-qos2-unknown-pubrel");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Write, outbound, 1024 * 1024);

        assert!(session.handle_pubrel(99).await.unwrap());
        expect_pubcomp(&mut rx, 99).await;
        assert_eq!(session.qos2_pending_count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_pending_bytes_limit_fails_closed_without_pubrec() {
        let (engine, dir) = test_engine("mqtt-qos2-byte-limit");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Write, outbound, 4);
        let publish = qos2_publish(1, b"sensor/temp", b"12345");
        assert!(!session.handle_publish(publish).await.unwrap());
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn qos2_pending_count_limit_fails_closed_without_pubrec() {
        let (engine, dir) = test_engine("mqtt-qos2-count-limit");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Write, outbound, 1024 * 1024);
        for pkid in 1..=session::MAX_PENDING_QOS2_PUBLISHES as u16 {
            let publish = qos2_publish(pkid, b"sensor/temp", b"x");
            assert!(session.handle_publish(publish).await.unwrap());
            expect_pubrec(&mut rx, pkid).await;
        }
        let publish = qos2_publish(
            session::MAX_PENDING_QOS2_PUBLISHES as u16 + 1,
            b"sensor/temp",
            b"x",
        );
        assert!(!session.handle_publish(publish).await.unwrap());
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribe_without_read_tier_returns_failure() {
        let (engine, dir) = test_engine_with_read_token("mqtt-subscribe-auth");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Anon, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 12,
            filters: vec![Filter {
                path: "sensor/#".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.pkid, 12);
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::Failure]);
        assert_eq!(session.subscription_count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribe_caps_per_session_and_fails_extra_filters() {
        let (engine, dir) = test_engine("mqtt-subscribe-cap");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Read, outbound, 1024 * 1024);
        let filters = (0..session::MAX_SUBSCRIPTIONS_PER_SESSION + 2)
            .map(|idx| Filter {
                path: format!("sensor/{idx}"),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            })
            .collect();
        let subscribe = Subscribe { pkid: 13, filters };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.pkid, 13);
        assert_eq!(
            suback
                .return_codes
                .iter()
                .filter(|code| matches!(code, SubscribeReasonCode::QoS0))
                .count(),
            session::MAX_SUBSCRIPTIONS_PER_SESSION
        );
        assert_eq!(
            suback
                .return_codes
                .iter()
                .filter(|code| matches!(code, SubscribeReasonCode::Failure))
                .count(),
            2
        );
        assert_eq!(
            session.subscription_count(),
            session::MAX_SUBSCRIPTIONS_PER_SESSION
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribe_fanout_reads_engine_body() {
        let (engine, dir) = test_engine("mqtt-subscribe-fanout");
        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine.clone(), AccessTier::Read, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 11,
            filters: vec![Filter {
                path: "sensor/#".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.pkid, 11);
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS0]);

        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"22.1"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Packet::Publish(publish, None) = packet else {
            panic!("expected fanout publish");
        };
        assert_eq!(publish.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(publish.payload, Bytes::from_static(b"22.1"));
        session.abort_subscriptions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribe_replays_durable_retained_home_value_with_client_topic() {
        let (engine, dir) = test_engine("mqtt-subscribe-retained-replay");
        for (world, body) in [
            ("home/sensor", b"root-retained".as_slice()),
            ("home/sensor/temp", b"22.5".as_slice()),
        ] {
            engine
                .replace(
                    &ValidatedWorldPath::new(world).unwrap(),
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }
        let live = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        engine
            .replace(
                &live,
                Representation::new(Bytes::from_static(b"23.0"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Read, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 15,
            filters: vec![Filter {
                path: "sensor/#".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS0]);
        let Packet::Publish(publish, None) = rx.recv().await.unwrap() else {
            panic!("expected retained replay");
        };
        assert_eq!(publish.topic, Bytes::from_static(b"sensor"));
        assert_eq!(publish.payload, Bytes::from_static(b"root-retained"));
        assert!(publish.retain);
        let Packet::Publish(publish, None) = rx.recv().await.unwrap() else {
            panic!("expected retained child replay");
        };
        assert_eq!(publish.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(publish.payload, Bytes::from_static(b"22.5"));
        assert!(publish.retain);
        assert!(rx.try_recv().is_err());
        session.abort_subscriptions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn exact_filter_replays_only_exact_retained_world() {
        let (engine, dir) = test_engine("mqtt-subscribe-retained-exact");
        for (world, body) in [
            ("home/sensor/temp", b"22.5".as_slice()),
            ("home/sensor/temperature", b"too-wide".as_slice()),
            ("home/sensor/temp2", b"too-wide".as_slice()),
        ] {
            engine
                .replace(
                    &ValidatedWorldPath::new(world).unwrap(),
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Read, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 18,
            filters: vec![Filter {
                path: "sensor/temp".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS0]);
        let Packet::Publish(publish, None) = rx.recv().await.unwrap() else {
            panic!("expected retained replay");
        };
        assert_eq!(publish.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(publish.payload, Bytes::from_static(b"22.5"));
        assert!(publish.retain);
        assert!(rx.try_recv().is_err());
        session.abort_subscriptions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribe_filter_fails_when_retained_replay_prep_errors() {
        let (engine, dir) = test_engine("mqtt-subscribe-retained-prep-fail");
        let retained = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        engine
            .replace(
                &retained,
                Representation::new(Bytes::from_static(b"22.5"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        corrupt_world_schema(&dir, retained.as_str());

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let metrics = MqttMetrics::shared();
        let mut session = MqttSession::new_with_metrics(
            engine,
            AccessTier::Read,
            outbound,
            1024 * 1024,
            metrics.clone(),
            0,
        );
        let subscribe = Subscribe {
            pkid: 19,
            filters: vec![Filter {
                path: "sensor/temp".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };

        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::Failure]);
        assert_eq!(session.subscription_count(), 0);
        assert_eq!(metrics.snapshot().retained_replay_failures, 1);
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn list_worlds_with_prefix_bounds_retained_replay_scope() {
        let (engine, dir) = test_engine("mqtt-list-prefix");
        for (world, body) in [
            ("home/sensor/temp", b"22.5".as_slice()),
            ("home/other/temp", b"nope".as_slice()),
            ("tmp/sensor/temp", b"live".as_slice()),
        ] {
            engine
                .replace(
                    &ValidatedWorldPath::new(world).unwrap(),
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let worlds = engine
            .list_worlds_with_prefix("home/sensor/", AccessTier::Read)
            .unwrap();
        let names: Vec<&str> = worlds.iter().map(ValidatedWorldPath::as_str).collect();
        assert_eq!(names, vec!["home/sensor/temp"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn duplicate_filters_share_one_subscription_and_one_replay() {
        let (engine, dir) = test_engine("mqtt-subscribe-duplicate-filter");
        let retained = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        engine
            .replace(
                &retained,
                Representation::new(Bytes::from_static(b"22.5"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Read, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 17,
            filters: vec![
                Filter {
                    path: "sensor/#".to_owned(),
                    qos: QoS::AtMostOnce,
                    nolocal: false,
                    preserve_retain: false,
                    retain_forward_rule: RetainForwardRule::Never,
                },
                Filter {
                    path: "sensor/#".to_owned(),
                    qos: QoS::AtMostOnce,
                    nolocal: false,
                    preserve_retain: false,
                    retain_forward_rule: RetainForwardRule::Never,
                },
            ],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(
            suback.return_codes,
            vec![SubscribeReasonCode::QoS0, SubscribeReasonCode::QoS0]
        );
        let Packet::Publish(publish, None) = rx.recv().await.unwrap() else {
            panic!("expected retained replay");
        };
        assert_eq!(publish.payload, Bytes::from_static(b"22.5"));
        assert!(publish.retain);
        assert!(rx.try_recv().is_err());
        assert_eq!(session.subscription_count(), 1);
        session.abort_subscriptions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn retained_replay_etag_suppresses_buffered_live_duplicate() {
        let (engine, dir) = test_engine("mqtt-retained-replay-skip-live");
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let subscription = engine
            .subscribe(
                &SubscribePattern::new("home/sensor/*"),
                AccessTier::Read,
                None,
            )
            .unwrap();
        let world = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"22.5"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let read = engine.read(&world, AccessTier::Read).unwrap().unwrap();
        let mut replayed = HashMap::new();
        replayed.insert(world.clone(), read.etag);

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let task = tokio::spawn(session::subscription_loop(
            subscription,
            session::SubscriptionLoopCtx {
                engine: engine.clone(),
                tier: AccessTier::Read,
                outbound,
                route,
                replayed: Arc::new(Mutex::new(replayed)),
                metrics: MqttMetrics::shared(),
                session_id: 0,
            },
        ));

        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "buffered live event with the replayed ETag must be suppressed"
        );

        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"23.0"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();
        let packet = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Packet::Publish(publish, None) = packet else {
            panic!("expected live publish");
        };
        assert_eq!(publish.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(publish.payload, Bytes::from_static(b"23.0"));
        assert!(!publish.retain);
        task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscription_loop_increments_fanout_read_failures_metric() {
        let (engine, dir) = test_engine_with_read_token("mqtt-fanout-read-fail");
        let route = mqtt_filter_to_route("sensor/#").unwrap();
        let subscription = engine
            .subscribe(
                &SubscribePattern::new("home/sensor/*"),
                AccessTier::Read,
                None,
            )
            .unwrap();
        let world = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        engine
            .replace(
                &world,
                Representation::new(Bytes::from_static(b"22.5"), "text/plain", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let metrics = MqttMetrics::shared();
        let task = tokio::spawn(session::subscription_loop(
            subscription,
            session::SubscriptionLoopCtx {
                engine: engine.clone(),
                tier: AccessTier::Anon,
                outbound,
                route,
                replayed: Arc::new(Mutex::new(HashMap::new())),
                metrics: metrics.clone(),
                session_id: 0,
            },
        ));

        timeout(Duration::from_secs(2), async {
            loop {
                if metrics.snapshot().fanout_read_failures == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(rx.try_recv().is_err());
        task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn empty_retained_home_value_is_not_replayed() {
        let (engine, dir) = test_engine("mqtt-subscribe-retained-clear");
        let retained = ValidatedWorldPath::new("home/sensor/temp").unwrap();
        engine
            .replace(
                &retained,
                Representation::new(Bytes::new(), "application/octet-stream", Vec::new()),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let (outbound, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut session = MqttSession::new(engine, AccessTier::Read, outbound, 1024 * 1024);
        let subscribe = Subscribe {
            pkid: 16,
            filters: vec![Filter {
                path: "sensor/#".to_owned(),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: false,
                retain_forward_rule: RetainForwardRule::Never,
            }],
        };
        assert!(session.handle_subscribe(subscribe).await.unwrap());
        let Packet::SubAck(suback, None) = rx.recv().await.unwrap() else {
            panic!("expected suback");
        };
        assert_eq!(suback.return_codes, vec![SubscribeReasonCode::QoS0]);
        assert!(rx.try_recv().is_err());
        session.abort_subscriptions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn mqtt_tcp_connect_publish_and_subscribe_use_engine() {
        let (engine, dir) = test_engine("mqtt-tcp-roundtrip");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_engine = engine.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(
                server_engine.clone(),
                stream,
                peer,
                server_engine.shutdown_receiver(),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                PreAuthLimiter::new(1).try_acquire(peer.ip()).unwrap(),
                MqttRuntime::new(
                    1024 * 1024,
                    1024 * 1024,
                    Duration::from_secs(3),
                    MqttMetrics::shared(),
                    ClientRegistry::new(MqttMetrics::shared()),
                ),
            )
            .await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut client,
            Packet::Connect(
                Connect {
                    keep_alive: 30,
                    client_id: "wire-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "wire-client".to_owned(),
                    password: "write-token".to_owned(),
                }),
            ),
        )
        .await;
        let mut client_buffer = BytesMut::new();
        let Packet::ConnAck(connack, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected connack");
        };
        assert_eq!(connack.code, ConnectReturnCode::Success);

        write_client_packet(
            &mut client,
            Packet::Subscribe(
                Subscribe {
                    pkid: 9,
                    filters: vec![Filter {
                        path: "sensor/#".to_owned(),
                        qos: QoS::AtMostOnce,
                        nolocal: false,
                        preserve_retain: false,
                        retain_forward_rule: RetainForwardRule::Never,
                    }],
                },
                None,
            ),
        )
        .await;
        let Packet::SubAck(suback, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected suback");
        };
        assert_eq!(suback.pkid, 9);
        assert_eq!(suback.return_codes.len(), 1);
        assert!(
            matches!(
                suback.return_codes[0],
                SubscribeReasonCode::QoS0 | SubscribeReasonCode::Success(QoS::AtMostOnce)
            ),
            "expected QoS0 subscription success, got {:?}",
            suback.return_codes
        );

        write_client_packet(
            &mut client,
            Packet::Publish(
                Publish::new(
                    Bytes::from_static(b"sensor/temp"),
                    Bytes::from_static(b"23.0"),
                    false,
                ),
                None,
            ),
        )
        .await;

        let Packet::Publish(fanout, None) = read_client_packet(&mut client).await else {
            panic!("expected fanout publish");
        };
        assert_eq!(fanout.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(fanout.payload, Bytes::from_static(b"23.0"));

        let world = ValidatedWorldPath::new("tmp/sensor/temp").unwrap();
        let read = engine.read(&world, AccessTier::Write).unwrap().unwrap();
        assert_eq!(read.representation.body, Bytes::from_static(b"23.0"));

        drop(client);
        let result = timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok(), "server connection failed: {result:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn mqtt_tcp_subscribe_replays_retained_parent_and_child() {
        let (engine, dir) = test_engine_with_read_token("mqtt-tcp-retained-parent-child");
        for (world, body) in [
            ("home/sensor", b"root-retained".as_slice()),
            ("home/sensor/temp", b"22.5".as_slice()),
        ] {
            engine
                .replace(
                    &ValidatedWorldPath::new(world).unwrap(),
                    Representation::new(Bytes::copy_from_slice(body), "text/plain", Vec::new()),
                    Preconditions::none(),
                    AccessTier::Write,
                )
                .await
                .unwrap();
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_engine = engine.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(
                server_engine.clone(),
                stream,
                peer,
                server_engine.shutdown_receiver(),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                PreAuthLimiter::new(1).try_acquire(peer.ip()).unwrap(),
                MqttRuntime::new(
                    1024 * 1024,
                    1024 * 1024,
                    Duration::from_secs(3),
                    MqttMetrics::shared(),
                    ClientRegistry::new(MqttMetrics::shared()),
                ),
            )
            .await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut client,
            Packet::Connect(
                Connect {
                    keep_alive: 30,
                    client_id: "wire-retained-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "wire-retained-client".to_owned(),
                    password: "read-token".to_owned(),
                }),
            ),
        )
        .await;
        let mut client_buffer = BytesMut::new();
        let Packet::ConnAck(connack, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected connack");
        };
        assert_eq!(connack.code, ConnectReturnCode::Success);

        write_client_packet(
            &mut client,
            Packet::Subscribe(
                Subscribe {
                    pkid: 20,
                    filters: vec![Filter {
                        path: "sensor/#".to_owned(),
                        qos: QoS::AtMostOnce,
                        nolocal: false,
                        preserve_retain: false,
                        retain_forward_rule: RetainForwardRule::Never,
                    }],
                },
                None,
            ),
        )
        .await;
        let Packet::SubAck(suback, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected suback");
        };
        assert!(matches!(
            suback.return_codes.as_slice(),
            [SubscribeReasonCode::QoS0 | SubscribeReasonCode::Success(QoS::AtMostOnce)]
        ));

        let Packet::Publish(parent, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected parent retained publish");
        };
        assert_eq!(parent.topic, Bytes::from_static(b"sensor"));
        assert_eq!(parent.payload, Bytes::from_static(b"root-retained"));
        assert!(parent.retain);

        let Packet::Publish(child, None) =
            read_client_packet_buffered(&mut client, &mut client_buffer).await
        else {
            panic!("expected child retained publish");
        };
        assert_eq!(child.topic, Bytes::from_static(b"sensor/temp"));
        assert_eq!(child.payload, Bytes::from_static(b"22.5"));
        assert!(child.retain);

        drop(client);
        let result = timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok(), "server connection failed: {result:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn mqtt_tcp_bad_credentials_get_connack_failure() {
        let (engine, dir) = test_engine("mqtt-tcp-bad-creds");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_engine = engine.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(
                server_engine.clone(),
                stream,
                peer,
                server_engine.shutdown_receiver(),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                PreAuthLimiter::new(1).try_acquire(peer.ip()).unwrap(),
                MqttRuntime::new(
                    1024 * 1024,
                    1024 * 1024,
                    Duration::from_secs(3),
                    MqttMetrics::shared(),
                    ClientRegistry::new(MqttMetrics::shared()),
                ),
            )
            .await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut client,
            Packet::Connect(
                Connect {
                    keep_alive: 30,
                    client_id: "bad-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "bad-client".to_owned(),
                    password: "wrong".to_owned(),
                }),
            ),
        )
        .await;
        let Packet::ConnAck(connack, None) = read_client_packet(&mut client).await else {
            panic!("expected connack");
        };
        assert_eq!(connack.code, ConnectReturnCode::BadUserNamePassword);

        let result = timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err(), "MQTT credentials rejected");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn mqtt_tcp_duplicate_client_id_closes_old_connection() {
        let (engine, dir) = test_engine("mqtt-tcp-duplicate-client-id");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = MqttRuntime::new(
            1024 * 1024,
            1024 * 1024,
            Duration::from_secs(3),
            MqttMetrics::shared(),
            ClientRegistry::new(MqttMetrics::shared()),
        );
        let permits = Arc::new(Semaphore::new(2));
        let server_engine = engine.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, peer) = listener.accept().await.unwrap();
                let runtime = runtime.clone();
                let permit = permits.clone().try_acquire_owned().unwrap();
                let preauth_permit = PreAuthLimiter::new(2).try_acquire(peer.ip()).unwrap();
                let engine = server_engine.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(
                        engine.clone(),
                        stream,
                        peer,
                        engine.shutdown_receiver(),
                        permit,
                        preauth_permit,
                        runtime,
                    )
                    .await;
                });
            }
        });

        let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut first,
            Packet::Connect(
                Connect {
                    keep_alive: 30,
                    client_id: "same-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "first".to_owned(),
                    password: "write-token".to_owned(),
                }),
            ),
        )
        .await;
        let Packet::ConnAck(first_connack, None) = read_client_packet(&mut first).await else {
            panic!("expected first connack");
        };
        assert_eq!(first_connack.code, ConnectReturnCode::Success);

        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut second,
            Packet::Connect(
                Connect {
                    keep_alive: 30,
                    client_id: "same-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "second".to_owned(),
                    password: "write-token".to_owned(),
                }),
            ),
        )
        .await;
        let Packet::ConnAck(second_connack, None) = read_client_packet(&mut second).await else {
            panic!("expected second connack");
        };
        assert_eq!(second_connack.code, ConnectReturnCode::Success);

        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(2), first.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0, "old duplicate client_id connection should close");

        drop(second);
        server.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn mqtt_tcp_idle_client_is_reaped_by_keep_alive() {
        let (engine, dir) = test_engine("mqtt-tcp-keepalive");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_engine = engine.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(
                server_engine.clone(),
                stream,
                peer,
                server_engine.shutdown_receiver(),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                PreAuthLimiter::new(1).try_acquire(peer.ip()).unwrap(),
                MqttRuntime::new(
                    1024 * 1024,
                    1024 * 1024,
                    Duration::from_secs(3),
                    MqttMetrics::shared(),
                    ClientRegistry::new(MqttMetrics::shared()),
                ),
            )
            .await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_client_packet(
            &mut client,
            Packet::Connect(
                Connect {
                    keep_alive: 1,
                    client_id: "idle-client".to_owned(),
                    clean_session: true,
                },
                None,
                None,
                None,
                Some(Login {
                    username: "idle-client".to_owned(),
                    password: "write-token".to_owned(),
                }),
            ),
        )
        .await;
        let Packet::ConnAck(connack, None) = read_client_packet(&mut client).await else {
            panic!("expected connack");
        };
        assert_eq!(connack.code, ConnectReturnCode::Success);

        let result = timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err(), "MQTT keep-alive timeout");
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn write_client_packet(stream: &mut tokio::net::TcpStream, packet: Packet) {
        let mut bytes = BytesMut::new();
        V4.write(packet, &mut bytes).unwrap();
        stream.write_all(&bytes).await.unwrap();
    }

    async fn read_client_packet(stream: &mut tokio::net::TcpStream) -> Packet {
        read_client_packet_buffered(stream, &mut BytesMut::new()).await
    }

    async fn read_client_packet_buffered(
        stream: &mut tokio::net::TcpStream,
        buffer: &mut BytesMut,
    ) -> Packet {
        let mut protocol = V4;
        loop {
            match protocol.read_mut(buffer, 1024 * 1024) {
                Ok(packet) => return packet,
                Err(protocol::Error::InsufficientBytes(_)) => {
                    let read = stream.read_buf(buffer).await.unwrap();
                    assert_ne!(read, 0, "mqtt client stream closed");
                }
                Err(err) => panic!("mqtt client protocol error: {err}"),
            }
        }
    }

    fn qos2_publish(pkid: u16, topic: &[u8], payload: &[u8]) -> Publish {
        let remaining = 2 + topic.len() + 2 + payload.len();
        assert!(remaining < 128, "test helper only encodes tiny packets");
        let mut raw = BytesMut::new();
        raw.extend_from_slice(&[0x34, remaining as u8]);
        raw.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        raw.extend_from_slice(topic);
        raw.extend_from_slice(&pkid.to_be_bytes());
        raw.extend_from_slice(payload);
        let Packet::Publish(publish, None) = V4.read_mut(&mut raw, 1024).unwrap() else {
            panic!("expected qos2 publish");
        };
        publish
    }

    async fn expect_pubrec(rx: &mut mpsc::Receiver<Packet>, pkid: u16) {
        let Packet::PubRec(pubrec, None) = rx.recv().await.unwrap() else {
            panic!("expected pubrec");
        };
        assert_eq!(pubrec.pkid, pkid);
        assert_eq!(pubrec.reason, PubRecReason::Success);
    }

    async fn expect_pubcomp(rx: &mut mpsc::Receiver<Packet>, pkid: u16) {
        let Packet::PubComp(pubcomp, None) = rx.recv().await.unwrap() else {
            panic!("expected pubcomp");
        };
        assert_eq!(pubcomp.pkid, pkid);
        assert_eq!(pubcomp.reason, PubCompReason::Success);
    }

    fn test_engine(label: &str) -> (Engine, std::path::PathBuf) {
        build_test_engine(label, false)
    }

    fn test_engine_with_read_token(label: &str) -> (Engine, std::path::PathBuf) {
        build_test_engine(label, true)
    }

    fn build_test_engine(label: &str, read_token: bool) -> (Engine, std::path::PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "elastik-mqtt-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut builder = Engine::builder()
            .data_root(&dir)
            .key(crate::engine_types::SecretBytes::new(b"test-hmac-key".to_vec()).unwrap())
            .write_token(b"write-token".to_vec());
        if read_token {
            builder = builder.read_token(b"read-token".to_vec());
        }
        let engine = builder.build().unwrap();
        (engine, dir)
    }

    fn corrupt_world_schema(data_root: &std::path::Path, world: &str) {
        let db = crate::server::test_support::world_db_path_for_server_tests(data_root, world);
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute_batch("DROP TABLE stage_meta;").unwrap();
    }
}
