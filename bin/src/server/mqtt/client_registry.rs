use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use tokio::sync::mpsc;

use super::observability::{info as mqtt_info, MqttMetrics};

#[derive(Clone)]
pub(super) struct ClientRegistry {
    inner: Arc<ClientRegistryInner>,
    metrics: Arc<MqttMetrics>,
}

#[derive(Default)]
struct ClientRegistryInner {
    entries: Mutex<HashMap<String, ClientEntry>>,
    next_generation: AtomicU64,
}

struct ClientEntry {
    generation: u64,
    shutdown: mpsc::Sender<()>,
}

pub(super) struct ClientRegistration {
    client_id: String,
    generation: u64,
    registry: ClientRegistry,
    shutdown: mpsc::Receiver<()>,
}

impl ClientRegistry {
    pub(super) fn new(metrics: Arc<MqttMetrics>) -> Self {
        Self {
            inner: Arc::new(ClientRegistryInner::default()),
            metrics,
        }
    }

    pub(super) fn register(&self, client_id: String) -> ClientRegistration {
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let (shutdown, shutdown_rx) = mpsc::channel(1);
        let old = self.inner.entries_guard().insert(
            client_id.clone(),
            ClientEntry {
                generation,
                shutdown,
            },
        );
        if let Some(old) = old {
            let _ = old.shutdown.try_send(());
            let total = self.metrics.client_id_replaced();
            mqtt_info(format_args!(
                "mqtt: replacing existing client_id {}; previous_generation={}; total_client_id_replacements={total}",
                client_id, old.generation,
            ));
        }
        ClientRegistration {
            client_id,
            generation,
            registry: self.clone(),
            shutdown: shutdown_rx,
        }
    }

    fn unregister(&self, client_id: &str, generation: u64) {
        let mut entries = self.inner.entries_guard();
        let Some(entry) = entries.get(client_id) else {
            return;
        };
        if entry.generation == generation {
            entries.remove(client_id);
        }
    }

    #[cfg(test)]
    fn contains_generation(&self, client_id: &str, generation: u64) -> bool {
        self.inner
            .entries_guard()
            .get(client_id)
            .map(|entry| entry.generation == generation)
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.entries_guard().len()
    }
}

impl ClientRegistryInner {
    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<String, ClientEntry>> {
        // Poison means a previous registry mutation panicked while holding the
        // lock. The registry is now internally suspect; fail loud instead of
        // continuing with possibly stale client shutdown state.
        #[allow(clippy::expect_used)]
        self.entries.lock().expect("mqtt client registry poisoned")
    }
}

impl ClientRegistration {
    pub(super) async fn replaced(&mut self) {
        let _ = self.shutdown.recv().await;
    }

    pub(super) fn client_id(&self) -> &str {
        &self.client_id
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    fn is_replaced_now(&mut self) -> bool {
        self.shutdown.try_recv().is_ok()
    }
}

impl Drop for ClientRegistration {
    fn drop(&mut self) {
        self.registry.unregister(&self.client_id, self.generation);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn client_registry_replaces_old_client_without_removing_new_registration() {
        let metrics = MqttMetrics::shared();
        let registry = ClientRegistry::new(metrics.clone());
        let mut first = registry.register("sensor-a".to_owned());
        let second = registry.register("sensor-a".to_owned());

        assert!(first.is_replaced_now());
        assert_eq!(metrics.snapshot().client_id_replacements, 1);
        assert!(registry.contains_generation("sensor-a", second.generation()));
        drop(first);
        assert!(registry.contains_generation("sensor-a", second.generation()));
        drop(second);
        assert_eq!(registry.len(), 0);
    }
}
