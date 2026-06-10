use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use rumqttd::protocol::{
    Disconnect, DisconnectReasonCode, Packet, PingResp, PubAck, PubAckReason, PubComp,
    PubCompReason, PubRec, PubRecReason, Publish, QoS, SubAck, SubscribeReasonCode, UnsubAck,
    UnsubAckReason,
};
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    task::JoinHandle,
};

use crate::{
    engine::{Engine, EngineError},
    engine_types::{
        AccessTier, EngineSubscription, Preconditions, Representation, SubscriptionRecvError,
        ValidatedWorldPath,
    },
};

use super::{
    codec::send_packet,
    observability::{warn as mqtt_warn, MqttMetrics},
    retained::{collect_retained_replay, should_skip_replayed_live, RetainedReplayEtags},
    topic::{mqtt_filter_to_route, publish_qos_pkid, publish_topic_to_world, MqttSubscribeRoute},
    MqttReject,
};

pub(super) const MAX_PENDING_QOS2_PUBLISHES: usize = 64;
pub(super) const MAX_SUBSCRIPTIONS_PER_SESSION: usize = 64;

pub(super) struct MqttSession {
    engine: Engine,
    tier: AccessTier,
    outbound: mpsc::Sender<Packet>,
    subscriptions: HashMap<String, Vec<JoinHandle<()>>>,
    qos2: HashMap<u16, PendingQos2Publish>,
    qos2_pending_bytes: usize,
    max_pending_qos2_bytes: usize,
    metrics: Arc<MqttMetrics>,
    session_id: u64,
}

#[derive(Clone)]
struct PendingQos2Publish {
    world: ValidatedWorldPath,
    payload: Bytes,
}

struct PreparedSubscription {
    filter: String,
    route: MqttSubscribeRoute,
    subscriptions: Vec<EngineSubscription>,
}

pub(super) struct SubscriptionLoopCtx {
    pub(super) engine: Engine,
    pub(super) tier: AccessTier,
    pub(super) outbound: mpsc::Sender<Packet>,
    pub(super) route: MqttSubscribeRoute,
    pub(super) replayed: RetainedReplayEtags,
    pub(super) metrics: Arc<MqttMetrics>,
    pub(super) session_id: u64,
}

impl MqttSession {
    #[cfg(test)]
    pub(super) fn new(
        engine: Engine,
        tier: AccessTier,
        outbound: mpsc::Sender<Packet>,
        max_pending_qos2_bytes: usize,
    ) -> Self {
        Self::new_with_metrics(
            engine,
            tier,
            outbound,
            max_pending_qos2_bytes,
            MqttMetrics::shared(),
            0,
        )
    }

    pub(super) fn new_with_metrics(
        engine: Engine,
        tier: AccessTier,
        outbound: mpsc::Sender<Packet>,
        max_pending_qos2_bytes: usize,
        metrics: Arc<MqttMetrics>,
        session_id: u64,
    ) -> Self {
        Self {
            engine,
            tier,
            outbound,
            subscriptions: HashMap::new(),
            qos2: HashMap::new(),
            qos2_pending_bytes: 0,
            max_pending_qos2_bytes,
            metrics,
            session_id,
        }
    }

    pub(super) async fn handle_packet(&mut self, packet: Packet) -> Result<bool, String> {
        match packet {
            Packet::Publish(publish, _props) => self.handle_publish(publish).await,
            Packet::PubRel(pubrel, _props) => self.handle_pubrel(pubrel.pkid).await,
            Packet::Subscribe(subscribe, _props) => self.handle_subscribe(subscribe).await,
            Packet::Unsubscribe(unsubscribe, _props) => {
                let reasons = unsubscribe
                    .filters
                    .into_iter()
                    .map(|filter| {
                        if let Some(handles) = self.subscriptions.remove(&filter) {
                            abort_handles(handles);
                        }
                        UnsubAckReason::Success
                    })
                    .collect();
                send_packet(
                    &self.outbound,
                    Packet::UnsubAck(
                        UnsubAck {
                            pkid: unsubscribe.pkid,
                            reasons,
                        },
                        None,
                    ),
                )
                .await?;
                Ok(true)
            }
            Packet::PingReq(_) => {
                send_packet(&self.outbound, Packet::PingResp(PingResp)).await?;
                Ok(true)
            }
            Packet::Disconnect(_, _) => Ok(false),
            _ => {
                send_packet(
                    &self.outbound,
                    Packet::Disconnect(
                        Disconnect {
                            reason_code: DisconnectReasonCode::ProtocolError,
                        },
                        None,
                    ),
                )
                .await?;
                Ok(false)
            }
        }
    }

    pub(super) async fn handle_publish(&mut self, publish: Publish) -> Result<bool, String> {
        let Some((qos, pkid)) = publish_qos_pkid(&publish) else {
            return self.fail_publish("invalid_publish_header", None);
        };
        if qos == QoS::ExactlyOnce {
            return self.handle_qos2_publish(publish, pkid).await;
        }
        let world = match publish_topic_to_world(&publish) {
            Ok(world) => world,
            Err(_) => return self.fail_publish("invalid_topic", None),
        };
        match self.replace_payload(&world, publish.payload.clone()).await {
            Ok(_) => {
                self.record_retained_publish(&world);
                if qos == QoS::AtLeastOnce {
                    send_packet(
                        &self.outbound,
                        Packet::PubAck(
                            PubAck {
                                pkid,
                                reason: PubAckReason::Success,
                            },
                            None,
                        ),
                    )
                    .await?;
                }
                Ok(true)
            }
            Err(err) => self.fail_publish("replace_failed", Some(&err)),
        }
    }

    async fn handle_qos2_publish(&mut self, publish: Publish, pkid: u16) -> Result<bool, String> {
        if pkid == 0 {
            return self.fail_publish("qos2_zero_packet_id", None);
        }
        if !self.qos2.contains_key(&pkid) {
            if self.qos2.len() >= MAX_PENDING_QOS2_PUBLISHES {
                return self.fail_publish("qos2_pending_count_limit", None);
            }
            let payload_len = publish.payload.len();
            let Some(new_pending_bytes) = self.qos2_pending_bytes.checked_add(payload_len) else {
                return self.fail_publish("qos2_pending_bytes_overflow", None);
            };
            if new_pending_bytes > self.max_pending_qos2_bytes {
                return self.fail_publish("qos2_pending_bytes_limit", None);
            }
            let world = match publish_topic_to_world(&publish) {
                Ok(world) => world,
                Err(_) => return self.fail_publish("invalid_topic", None),
            };
            self.qos2.insert(
                pkid,
                PendingQos2Publish {
                    world,
                    payload: publish.payload.clone(),
                },
            );
            self.qos2_pending_bytes = new_pending_bytes;
            self.metrics.qos2_pending_added(payload_len);
        }
        send_packet(
            &self.outbound,
            Packet::PubRec(
                PubRec {
                    pkid,
                    reason: PubRecReason::Success,
                },
                None,
            ),
        )
        .await?;
        Ok(true)
    }

    pub(super) async fn handle_pubrel(&mut self, pkid: u16) -> Result<bool, String> {
        let Some(pending) = self.qos2.get(&pkid).cloned() else {
            mqtt_warn(format_args!(
                "mqtt: PUBREL without pending QoS2 publish pkid={pkid}; replying PUBCOMP"
            ));
            return send_pubcomp(&self.outbound, pkid).await;
        };
        if self
            .replace_payload(&pending.world, pending.payload.clone())
            .await
            .is_err()
        {
            let total = self.metrics.publish_failed();
            mqtt_warn(format_args!(
                "mqtt: session {} QoS2 commit failed for pkid={pkid}; total_publish_failures={total}; closing without PUBCOMP",
                self.session_id,
            ));
            return Ok(false);
        }
        let removed = self.qos2.remove(&pkid);
        debug_assert!(removed.is_some());
        self.record_retained_publish(&pending.world);
        self.qos2_pending_bytes = self
            .qos2_pending_bytes
            .saturating_sub(pending.payload.len());
        self.metrics.qos2_pending_removed(pending.payload.len());
        send_pubcomp(&self.outbound, pkid).await
    }

    async fn replace_payload(
        &self,
        world: &ValidatedWorldPath,
        payload: Bytes,
    ) -> Result<(), EngineError> {
        let representation = Representation::new(payload, "application/octet-stream", Vec::new());
        self.engine
            .replace(world, representation, Preconditions::none(), self.tier)
            .await?;
        Ok(())
    }

    fn record_retained_publish(&self, world: &ValidatedWorldPath) {
        if world.as_str().starts_with("home/") {
            self.metrics.retained_published();
        }
    }

    fn fail_publish(
        &self,
        reason: &'static str,
        err: Option<&EngineError>,
    ) -> Result<bool, String> {
        let total = self.metrics.publish_failed();
        let detail = err.map(|err| format!("; err={err:?}")).unwrap_or_default();
        mqtt_warn(format_args!(
            "mqtt: session {} publish failed; reason={reason}; total_publish_failures={total}{detail}",
            self.session_id
        ));
        Ok(false)
    }

    pub(super) async fn handle_subscribe(
        &mut self,
        subscribe: rumqttd::protocol::Subscribe,
    ) -> Result<bool, String> {
        let mut return_codes = Vec::with_capacity(subscribe.filters.len());
        let mut prepared = Vec::new();
        let mut accepted_new = HashSet::new();
        let mut seen_results: HashMap<String, SubscribeReasonCode> = HashMap::new();
        for filter in subscribe.filters {
            let filter_path = filter.path;
            if let Some(code) = seen_results.get(&filter_path).cloned() {
                return_codes.push(code);
                continue;
            }
            let is_new = !self.subscriptions.contains_key(&filter_path)
                && !accepted_new.contains(&filter_path);
            if is_new
                && self.subscriptions.len() + accepted_new.len() >= MAX_SUBSCRIPTIONS_PER_SESSION
            {
                return_codes.push(SubscribeReasonCode::Failure);
                seen_results.insert(filter_path, SubscribeReasonCode::Failure);
                continue;
            }
            match self.prepare_subscription(filter_path.clone()) {
                Ok(item) => {
                    let Some(replay) = collect_retained_replay(
                        &self.engine,
                        self.tier,
                        &item.route,
                        &self.metrics,
                    )
                    .await
                    else {
                        return_codes.push(SubscribeReasonCode::Failure);
                        seen_results.insert(filter_path, SubscribeReasonCode::Failure);
                        continue;
                    };
                    if is_new {
                        accepted_new.insert(filter_path.clone());
                    }
                    prepared.push((item, replay));
                    return_codes.push(SubscribeReasonCode::QoS0);
                    seen_results.insert(filter_path, SubscribeReasonCode::QoS0);
                }
                Err(_) => {
                    return_codes.push(SubscribeReasonCode::Failure);
                    seen_results.insert(filter_path, SubscribeReasonCode::Failure);
                }
            }
        }
        send_packet(
            &self.outbound,
            Packet::SubAck(
                SubAck {
                    pkid: subscribe.pkid,
                    return_codes,
                },
                None,
            ),
        )
        .await?;
        for (item, replay) in prepared {
            let replayed = replay.send(&self.outbound, &self.metrics).await?;
            self.install_subscription(item, replayed);
        }
        Ok(true)
    }

    fn prepare_subscription(&self, filter: String) -> Result<PreparedSubscription, MqttReject> {
        let route = mqtt_filter_to_route(&filter)?;
        let mut subscriptions = Vec::with_capacity(route.live_patterns().len());
        for pattern in route.live_patterns() {
            let subscription = self
                .engine
                .subscribe(pattern, self.tier, None)
                .map_err(mqtt_reject_from_engine)?;
            subscriptions.push(subscription);
        }
        Ok(PreparedSubscription {
            filter,
            route,
            subscriptions,
        })
    }

    fn install_subscription(
        &mut self,
        prepared: PreparedSubscription,
        replayed: HashMap<ValidatedWorldPath, String>,
    ) {
        if let Some(old) = self.subscriptions.remove(&prepared.filter) {
            abort_handles(old);
        }
        let mut tasks = Vec::with_capacity(prepared.subscriptions.len());
        let replayed = Arc::new(Mutex::new(replayed));
        for subscription in prepared.subscriptions {
            let ctx = SubscriptionLoopCtx {
                engine: self.engine.clone(),
                tier: self.tier,
                outbound: self.outbound.clone(),
                route: prepared.route.clone(),
                replayed: replayed.clone(),
                metrics: self.metrics.clone(),
                session_id: self.session_id,
            };
            tasks.push(tokio::spawn(subscription_loop(subscription, ctx)));
        }
        self.subscriptions.insert(prepared.filter, tasks);
    }

    pub(super) fn abort_subscriptions(&mut self) {
        for (_, tasks) in self.subscriptions.drain() {
            abort_handles(tasks);
        }
    }

    #[cfg(test)]
    pub(super) fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    #[cfg(test)]
    pub(super) fn qos2_pending_count(&self) -> usize {
        self.qos2.len()
    }
}

fn abort_handles(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        task.abort();
    }
}

impl Drop for MqttSession {
    fn drop(&mut self) {
        self.metrics
            .qos2_pending_removed_many(self.qos2.len(), self.qos2_pending_bytes);
        self.abort_subscriptions();
    }
}

pub(super) async fn subscription_loop(
    mut subscription: EngineSubscription,
    ctx: SubscriptionLoopCtx,
) {
    let mut dropped_fanout = 0_u64;
    let mut read_failures = 0_u64;
    loop {
        let change = match subscription.recv().await {
            Ok(change) => change,
            Err(SubscriptionRecvError::Lagged { skipped }) => {
                mqtt_warn(format_args!(
                    "mqtt: subscription lagged; skipped {skipped} events"
                ));
                continue;
            }
            // Defensive arm: currently unreachable — this adapter always
            // subscribes with since=None (no MQTT resume-cursor concept), and
            // CursorAhead is only produced for Some(cursor). Kept explicit so
            // a future resume feature cannot silently fall into a wildcard.
            Err(SubscriptionRecvError::CursorAhead { since, newest }) => {
                mqtt_warn(format_args!(
                    "mqtt: subscription cursor {since} predates an engine restart \
                     (newest issued id is {newest}); continuing live"
                ));
                continue;
            }
            Err(SubscriptionRecvError::Closed) => break,
            #[allow(unreachable_patterns)]
            Err(_) => continue,
        };
        let read = match ctx.engine.read(&change.path, ctx.tier) {
            Ok(Some(read)) => read,
            Ok(None) => continue,
            Err(err) => {
                read_failures = read_failures.saturating_add(1);
                let total = ctx.metrics.fanout_read_failed();
                if read_failures == 1 || read_failures.is_power_of_two() {
                    mqtt_warn(format_args!(
                        "mqtt: session {session_id} fanout read failed {read_failures} times on this subscription; total_fanout_read_failures={total}; world={}; err={err:?}",
                        change.path.as_str(),
                        session_id = ctx.session_id
                    ));
                }
                continue;
            }
        };
        if should_skip_replayed_live(&ctx.replayed, &change.path, &read.etag) {
            continue;
        }
        let payload = read.representation.body;
        let topic = ctx.route.topic_for_world(&change.path);
        let publish = Publish::new(topic, payload, false);
        match ctx.outbound.try_send(Packet::Publish(publish, None)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped_fanout = dropped_fanout.saturating_add(1);
                let total = ctx.metrics.fanout_dropped();
                if dropped_fanout == 1 || dropped_fanout.is_power_of_two() {
                    mqtt_warn(format_args!(
                        "mqtt: session {session_id} outbound queue full; dropped {dropped_fanout} QoS0 fanout messages on this subscription; total_fanout_drops={total}; latest {}",
                        change.path.as_str(),
                        session_id = ctx.session_id
                    ));
                }
            }
            Err(TrySendError::Closed(_)) => break,
        }
    }
}

async fn send_pubcomp(outbound: &mpsc::Sender<Packet>, pkid: u16) -> Result<bool, String> {
    send_packet(
        outbound,
        Packet::PubComp(
            PubComp {
                pkid,
                reason: PubCompReason::Success,
            },
            None,
        ),
    )
    .await?;
    Ok(true)
}

fn mqtt_reject_from_engine(err: EngineError) -> MqttReject {
    match err {
        EngineError::Auth(_) => MqttReject::Auth,
        EngineError::PayloadTooLarge { .. } => MqttReject::TooLarge,
        EngineError::QuotaExceeded { .. } => MqttReject::Quota,
        EngineError::SubscriptionLimit => MqttReject::Quota,
        EngineError::ShuttingDown => MqttReject::ShuttingDown,
        _ => MqttReject::Storage,
    }
}
