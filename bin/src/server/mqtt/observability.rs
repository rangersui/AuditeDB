use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub(super) fn info(args: fmt::Arguments<'_>) {
    #[cfg(feature = "unstable-engine")]
    tracing::info!(target: "elastik_core::mqtt", "{}", args);
    #[cfg(not(feature = "unstable-engine"))]
    eprintln!("{}", args);
}

pub(super) fn warn(args: fmt::Arguments<'_>) {
    #[cfg(feature = "unstable-engine")]
    tracing::warn!(target: "elastik_core::mqtt", "{}", args);
    #[cfg(not(feature = "unstable-engine"))]
    eprintln!("{}", args);
}

#[derive(Default)]
pub(crate) struct MqttMetrics {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    auth_failures: AtomicU64,
    publish_failures: AtomicU64,
    retained_publishes: AtomicU64,
    keep_alive_timeouts: AtomicU64,
    retained_replay_failures: AtomicU64,
    retained_replay_messages: AtomicU64,
    retained_replay_worlds_scanned: AtomicU64,
    preauth_rejections: AtomicU64,
    client_id_replacements: AtomicU64,
    fanout_drops: AtomicU64,
    fanout_read_failures: AtomicU64,
    qos2_pending_messages: AtomicU64,
    qos2_pending_bytes: AtomicU64,
    qos2_pending_bytes_peak: AtomicU64,
}

impl MqttMetrics {
    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn connection_opened(&self) -> u64 {
        // Also serves as the MQTT session id. This counter is monotonic for
        // process lifetime and must not be reset independently.
        let id = self.total_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        id
    }

    fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn auth_failed(&self) -> u64 {
        self.auth_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn publish_failed(&self) -> u64 {
        self.publish_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn retained_published(&self) -> u64 {
        self.retained_publishes.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn keep_alive_timed_out(&self) -> u64 {
        self.keep_alive_timeouts.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn retained_replay_failed(&self) -> u64 {
        self.retained_replay_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub(super) fn retained_replay_sent(&self) -> u64 {
        self.retained_replay_messages
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub(super) fn retained_replay_scanned(&self, worlds: usize) -> u64 {
        self.retained_replay_worlds_scanned
            .fetch_add(worlds as u64, Ordering::Relaxed)
            + worlds as u64
    }

    pub(super) fn preauth_rejected(&self) -> u64 {
        self.preauth_rejections.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn client_id_replaced(&self) -> u64 {
        self.client_id_replacements.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn fanout_dropped(&self) -> u64 {
        self.fanout_drops.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn fanout_read_failed(&self) -> u64 {
        self.fanout_read_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn qos2_pending_added(&self, bytes: usize) {
        self.qos2_pending_messages.fetch_add(1, Ordering::Relaxed);
        let current = self
            .qos2_pending_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed)
            + bytes as u64;
        self.record_qos2_peak(current);
    }

    pub(super) fn qos2_pending_removed(&self, bytes: usize) {
        self.qos2_pending_messages.fetch_sub(1, Ordering::Relaxed);
        self.qos2_pending_bytes
            .fetch_sub(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn qos2_pending_removed_many(&self, messages: usize, bytes: usize) {
        if messages > 0 {
            self.qos2_pending_messages
                .fetch_sub(messages as u64, Ordering::Relaxed);
        }
        if bytes > 0 {
            self.qos2_pending_bytes
                .fetch_sub(bytes as u64, Ordering::Relaxed);
        }
    }

    fn record_qos2_peak(&self, current: u64) {
        let mut observed = self.qos2_pending_bytes_peak.load(Ordering::Relaxed);
        while current > observed {
            match self.qos2_pending_bytes_peak.compare_exchange_weak(
                observed,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => observed = next,
            }
        }
    }

    pub(crate) fn snapshot(&self) -> MqttMetricsSnapshot {
        MqttMetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            publish_failures: self.publish_failures.load(Ordering::Relaxed),
            retained_publishes: self.retained_publishes.load(Ordering::Relaxed),
            keep_alive_timeouts: self.keep_alive_timeouts.load(Ordering::Relaxed),
            retained_replay_failures: self.retained_replay_failures.load(Ordering::Relaxed),
            retained_replay_messages: self.retained_replay_messages.load(Ordering::Relaxed),
            retained_replay_worlds_scanned: self
                .retained_replay_worlds_scanned
                .load(Ordering::Relaxed),
            preauth_rejections: self.preauth_rejections.load(Ordering::Relaxed),
            client_id_replacements: self.client_id_replacements.load(Ordering::Relaxed),
            fanout_drops: self.fanout_drops.load(Ordering::Relaxed),
            fanout_read_failures: self.fanout_read_failures.load(Ordering::Relaxed),
            qos2_pending_messages: self.qos2_pending_messages.load(Ordering::Relaxed),
            qos2_pending_bytes: self.qos2_pending_bytes.load(Ordering::Relaxed),
            qos2_pending_bytes_peak: self.qos2_pending_bytes_peak.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct MqttConnectionGuard {
    metrics: Arc<MqttMetrics>,
    id: u64,
}

impl MqttConnectionGuard {
    pub(super) fn new(metrics: Arc<MqttMetrics>) -> Self {
        let id = metrics.connection_opened();
        Self { metrics, id }
    }

    pub(super) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for MqttConnectionGuard {
    fn drop(&mut self) {
        self.metrics.connection_closed();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MqttMetricsSnapshot {
    pub(crate) active_connections: u64,
    pub(crate) total_connections: u64,
    pub(crate) auth_failures: u64,
    pub(crate) publish_failures: u64,
    pub(crate) retained_publishes: u64,
    pub(crate) keep_alive_timeouts: u64,
    pub(crate) retained_replay_failures: u64,
    pub(crate) retained_replay_messages: u64,
    pub(crate) retained_replay_worlds_scanned: u64,
    pub(crate) preauth_rejections: u64,
    pub(crate) client_id_replacements: u64,
    pub(crate) fanout_drops: u64,
    pub(crate) fanout_read_failures: u64,
    pub(crate) qos2_pending_messages: u64,
    pub(crate) qos2_pending_bytes: u64,
    pub(crate) qos2_pending_bytes_peak: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mqtt_metrics_track_connection_auth_fanout_and_qos2() {
        let metrics = MqttMetrics::shared();
        {
            let _guard = MqttConnectionGuard::new(metrics.clone());
            assert_eq!(metrics.auth_failed(), 1);
            assert_eq!(metrics.publish_failed(), 1);
            assert_eq!(metrics.retained_published(), 1);
            assert_eq!(metrics.keep_alive_timed_out(), 1);
            assert_eq!(metrics.retained_replay_failed(), 1);
            assert_eq!(metrics.retained_replay_sent(), 1);
            assert_eq!(metrics.retained_replay_scanned(3), 3);
            assert_eq!(metrics.preauth_rejected(), 1);
            assert_eq!(metrics.client_id_replaced(), 1);
            assert_eq!(metrics.fanout_dropped(), 1);
            assert_eq!(metrics.fanout_read_failed(), 1);
            metrics.qos2_pending_added(10);
            metrics.qos2_pending_added(5);
            metrics.qos2_pending_removed(10);
            assert_eq!(
                metrics.snapshot(),
                MqttMetricsSnapshot {
                    active_connections: 1,
                    total_connections: 1,
                    auth_failures: 1,
                    publish_failures: 1,
                    retained_publishes: 1,
                    keep_alive_timeouts: 1,
                    retained_replay_failures: 1,
                    retained_replay_messages: 1,
                    retained_replay_worlds_scanned: 3,
                    preauth_rejections: 1,
                    client_id_replacements: 1,
                    fanout_drops: 1,
                    fanout_read_failures: 1,
                    qos2_pending_messages: 1,
                    qos2_pending_bytes: 5,
                    qos2_pending_bytes_peak: 15,
                }
            );
        }
        assert_eq!(metrics.snapshot().active_connections, 0);
    }
}
