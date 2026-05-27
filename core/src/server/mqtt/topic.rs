use std::str;

use bytes::Bytes;
use rumqttd::protocol::{self, Publish, QoS};

use crate::engine_types::{SubscribePattern, ValidatedWorldPath};

use super::MqttReject;

const RETAINED_MQTT_NAMESPACE: &str = "home";
const LIVE_MQTT_NAMESPACE: &str = "tmp";

#[derive(Clone, Debug)]
pub(super) struct MqttSubscribeRoute {
    live_patterns: Vec<SubscribePattern>,
    retained_pattern: SubscribePattern,
    retained_prefix: String,
    retained_exact: Option<ValidatedWorldPath>,
}

impl MqttSubscribeRoute {
    pub(super) fn live_patterns(&self) -> &[SubscribePattern] {
        &self.live_patterns
    }

    pub(super) fn matches_retained_world(&self, world: &ValidatedWorldPath) -> bool {
        matches_pattern(&self.retained_pattern, world)
    }

    pub(super) fn retained_prefix(&self) -> &str {
        &self.retained_prefix
    }

    pub(super) fn retained_exact(&self) -> Option<&ValidatedWorldPath> {
        self.retained_exact.as_ref()
    }

    pub(super) fn topic_for_world(&self, world: &ValidatedWorldPath) -> Bytes {
        let path = world.as_str();
        let topic = path
            .strip_prefix("home/")
            .or_else(|| path.strip_prefix("tmp/"))
            .unwrap_or(path);
        Bytes::copy_from_slice(topic.as_bytes())
    }
}

pub(super) fn publish_topic_to_world(publish: &Publish) -> Result<ValidatedWorldPath, MqttReject> {
    let topic = str::from_utf8(&publish.topic).map_err(|_| MqttReject::Topic)?;
    mqtt_publish_topic_to_world(topic, publish.retain)
}

pub(super) fn mqtt_publish_topic_to_world(
    topic: &str,
    retain: bool,
) -> Result<ValidatedWorldPath, MqttReject> {
    validate_topic_shape(topic)?;
    if topic.contains('+') || topic.contains('#') {
        return Err(MqttReject::Topic);
    }
    if has_explicit_namespace(topic) {
        return Err(MqttReject::Topic);
    }
    let namespace = if retain {
        RETAINED_MQTT_NAMESPACE
    } else {
        LIVE_MQTT_NAMESPACE
    };
    ValidatedWorldPath::new(world_path_for_topic(namespace, topic)).map_err(|_| MqttReject::Topic)
}

pub(super) fn mqtt_filter_to_route(filter: &str) -> Result<MqttSubscribeRoute, MqttReject> {
    if !protocol::valid_filter(filter) {
        return Err(MqttReject::Filter);
    }
    if filter == "#" {
        return Err(MqttReject::Filter);
    }
    if filter.contains('+') {
        return Err(MqttReject::UnsupportedWildcard);
    }
    if let Some(prefix) = filter.strip_suffix("/#") {
        validate_filter_prefix(prefix)?;
        return Ok(MqttSubscribeRoute {
            live_patterns: vec![
                SubscribePattern::new(format!("{}/{}/*", LIVE_MQTT_NAMESPACE, prefix)),
                SubscribePattern::new(format!("{}/{}/*", RETAINED_MQTT_NAMESPACE, prefix)),
            ],
            retained_pattern: SubscribePattern::new(format!(
                "{}/{}/*",
                RETAINED_MQTT_NAMESPACE, prefix
            )),
            retained_prefix: format!("{}/{}/", RETAINED_MQTT_NAMESPACE, prefix),
            retained_exact: None,
        });
    }
    validate_topic_shape(filter).map_err(|_| MqttReject::Filter)?;
    if has_explicit_namespace(filter) {
        return Err(MqttReject::Filter);
    }
    let live_world = ValidatedWorldPath::new(world_path_for_topic(LIVE_MQTT_NAMESPACE, filter))
        .map_err(|_| MqttReject::Filter)?;
    let retained_world =
        ValidatedWorldPath::new(world_path_for_topic(RETAINED_MQTT_NAMESPACE, filter))
            .map_err(|_| MqttReject::Filter)?;
    Ok(MqttSubscribeRoute {
        live_patterns: vec![
            SubscribePattern::new(live_world.as_str()),
            SubscribePattern::new(retained_world.as_str()),
        ],
        retained_pattern: SubscribePattern::new(retained_world.as_str()),
        retained_prefix: retained_world.as_str().to_owned(),
        retained_exact: Some(retained_world),
    })
}

fn validate_topic_shape(value: &str) -> Result<(), MqttReject> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.starts_with('$')
        || value.contains("//")
        || value.chars().any(char::is_control)
    {
        return Err(MqttReject::Topic);
    }
    Ok(())
}

fn validate_filter_prefix(prefix: &str) -> Result<(), MqttReject> {
    validate_topic_shape(prefix).map_err(|_| MqttReject::Filter)?;
    if prefix.contains('+') || prefix.contains('#') {
        return Err(MqttReject::Filter);
    }
    if has_explicit_namespace(prefix) {
        return Err(MqttReject::Filter);
    }
    crate::path::validate_world_name(&format!(
        "{}/_",
        world_path_for_topic(RETAINED_MQTT_NAMESPACE, prefix)
    ))
    .map_err(|_| MqttReject::Filter)
}

fn has_explicit_namespace(topic: &str) -> bool {
    crate::path::NAMESPACE_PREFIXES.contains(&topic.split('/').next().unwrap_or(""))
}

fn world_path_for_topic(namespace: &str, topic: &str) -> String {
    format!("{namespace}/{topic}")
}

fn matches_pattern(pattern: &SubscribePattern, world: &ValidatedWorldPath) -> bool {
    let path = format!("/{}", world.as_str());
    if let Some(prefix) = pattern.as_str().strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern.as_str()
    }
}

pub(super) fn publish_qos_pkid(publish: &Publish) -> Option<(QoS, u16)> {
    // rumqttd 0.20 keeps `qos` and `pkid` private. Serialize is the only stable
    // surface available here, so fail closed if that layout stops matching.
    let encoded = publish.serialize();
    if encoded.len() < 3 {
        return None;
    }
    let qos = protocol::qos((encoded[0] & 0b0110) >> 1)?;
    let pkid = u16::from_be_bytes([encoded[1], encoded[2]]);
    Some((qos, pkid))
}
