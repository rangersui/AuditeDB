use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
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
    topic::{mqtt_filter_to_route, publish_qos_pkid, publish_topic_to_world, MqttSubscribeRoute},
    MqttReject,
};

pub(super) const MAX_PENDING_QOS2_PUBLISHES: usize = 64;
pub(super) const MAX_SUBSCRIPTIONS_PER_SESSION: usize = 128;

type RetainedReplayEtags = Arc<Mutex<HashMap<ValidatedWorldPath, String>>>;

pub(super) struct MqttSession {
    engine: Engine,
    tier: AccessTier,
    outbound: mpsc::Sender<Packet>,
    subscriptions: HashMap<String, Vec<JoinHandle<()>>>,
    qos2: HashMap<u16, PendingQos2Publish>,
    qos2_pending_bytes: usize,
    max_pending_qos2_bytes: usize,
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

impl MqttSession {
    pub(super) fn new(
        engine: Engine,
        tier: AccessTier,
        outbound: mpsc::Sender<Packet>,
        max_pending_qos2_bytes: usize,
    ) -> Self {
        Self {
            engine,
            tier,
            outbound,
            subscriptions: HashMap::new(),
            qos2: HashMap::new(),
            qos2_pending_bytes: 0,
            max_pending_qos2_bytes,
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
            return Ok(false);
        };
        if qos == QoS::ExactlyOnce {
            return self.handle_qos2_publish(publish, pkid).await;
        }
        let world = match publish_topic_to_world(&publish) {
            Ok(world) => world,
            Err(_) => return Ok(false),
        };
        match self.replace_payload(&world, publish.payload.clone()).await {
            Ok(_) => {
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
            Err(_) => Ok(false),
        }
    }

    async fn handle_qos2_publish(&mut self, publish: Publish, pkid: u16) -> Result<bool, String> {
        if pkid == 0 {
            return Ok(false);
        }
        let pending_count = self.qos2.len();
        if let Entry::Vacant(entry) = self.qos2.entry(pkid) {
            if pending_count >= MAX_PENDING_QOS2_PUBLISHES {
                return Ok(false);
            }
            let payload_len = publish.payload.len();
            let Some(new_pending_bytes) = self.qos2_pending_bytes.checked_add(payload_len) else {
                return Ok(false);
            };
            if new_pending_bytes > self.max_pending_qos2_bytes {
                return Ok(false);
            }
            let world = match publish_topic_to_world(&publish) {
                Ok(world) => world,
                Err(_) => return Ok(false),
            };
            entry.insert(PendingQos2Publish {
                world,
                payload: publish.payload.clone(),
            });
            self.qos2_pending_bytes = new_pending_bytes;
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
            eprintln!("mqtt: PUBREL without pending QoS2 publish pkid={pkid}; replying PUBCOMP");
            return send_pubcomp(&self.outbound, pkid).await;
        };
        if self
            .replace_payload(&pending.world, pending.payload.clone())
            .await
            .is_err()
        {
            eprintln!("mqtt: QoS2 commit failed for pkid={pkid}; closing without PUBCOMP");
            return Ok(false);
        }
        let removed = self.qos2.remove(&pkid);
        debug_assert!(removed.is_some());
        self.qos2_pending_bytes = self
            .qos2_pending_bytes
            .saturating_sub(pending.payload.len());
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
                    if is_new {
                        accepted_new.insert(filter_path.clone());
                    }
                    prepared.push(item);
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
        for item in prepared {
            let replayed =
                send_retained_replay(&self.engine, self.tier, &item.route, &self.outbound).await?;
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
            tasks.push(tokio::spawn(subscription_loop(
                self.engine.clone(),
                self.tier,
                subscription,
                self.outbound.clone(),
                prepared.route.clone(),
                replayed.clone(),
            )));
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
        self.abort_subscriptions();
    }
}

pub(super) async fn subscription_loop(
    engine: Engine,
    tier: AccessTier,
    mut subscription: EngineSubscription,
    outbound: mpsc::Sender<Packet>,
    route: MqttSubscribeRoute,
    replayed: RetainedReplayEtags,
) {
    let mut dropped_fanout = 0_u64;
    loop {
        let change = match subscription.recv().await {
            Ok(change) => change,
            Err(SubscriptionRecvError::Lagged { skipped }) => {
                eprintln!("mqtt: subscription lagged; skipped {skipped} events");
                continue;
            }
            Err(SubscriptionRecvError::Closed) => break,
            #[allow(unreachable_patterns)]
            Err(_) => continue,
        };
        let read = match engine.read(&change.path, tier) {
            Ok(Some(read)) => read,
            Ok(None) => continue,
            Err(_) => continue,
        };
        if should_skip_replayed_live(&replayed, &change.path, &read.etag) {
            continue;
        }
        let payload = read.representation.body;
        let topic = route.topic_for_world(&change.path);
        let publish = Publish::new(topic, payload, false);
        match outbound.try_send(Packet::Publish(publish, None)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped_fanout = dropped_fanout.saturating_add(1);
                if dropped_fanout == 1 || dropped_fanout.is_power_of_two() {
                    eprintln!(
                        "mqtt: outbound queue full; dropped {dropped_fanout} QoS0 fanout messages; latest {}",
                        change.path.as_str()
                    );
                }
            }
            Err(TrySendError::Closed(_)) => break,
        }
    }
}

async fn send_retained_replay(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
    outbound: &mpsc::Sender<Packet>,
) -> Result<HashMap<ValidatedWorldPath, String>, String> {
    let mut replayed = HashMap::new();
    if let Some(world) = route.retained_exact() {
        replay_retained_world(engine, tier, route, outbound, world, &mut replayed).await?;
        return Ok(replayed);
    }

    let worlds = match engine.list_worlds_with_prefix(route.retained_prefix(), tier) {
        Ok(worlds) => worlds,
        Err(err) => {
            eprintln!(
                "mqtt: retained replay list failed for prefix {}; err={err:?}",
                route.retained_prefix()
            );
            return Ok(HashMap::new());
        }
    };
    for world in worlds {
        if !route.matches_retained_world(&world) {
            continue;
        }
        replay_retained_world(engine, tier, route, outbound, &world, &mut replayed).await?;
    }
    Ok(replayed)
}

async fn replay_retained_world(
    engine: &Engine,
    tier: AccessTier,
    route: &MqttSubscribeRoute,
    outbound: &mpsc::Sender<Packet>,
    world: &ValidatedWorldPath,
    replayed: &mut HashMap<ValidatedWorldPath, String>,
) -> Result<(), String> {
    let read = match engine.read(world, tier) {
        Ok(Some(read)) if !read.representation.body.is_empty() => read,
        Ok(_) => return Ok(()),
        Err(err) => {
            eprintln!(
                "mqtt: retained replay read failed for {}; err={err:?}",
                world.as_str()
            );
            return Ok(());
        }
    };
    let publish = Publish::new(route.topic_for_world(world), read.representation.body, true);
    send_packet(outbound, Packet::Publish(publish, None)).await?;
    replayed.insert(world.clone(), read.etag);
    Ok(())
}

fn should_skip_replayed_live(
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
