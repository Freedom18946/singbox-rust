//! Data-plane contract and registry used by Shadowsocks Manager API.

use dashmap::DashMap;
use std::sync::{Arc, Weak};

/// Traffic sink installed by control-plane SSMAPI service.
pub trait TrafficTracker: Send + Sync + 'static {
    fn record_uplink(&self, username: &str, bytes: i64, packets: i64);
    fn record_downlink(&self, username: &str, bytes: i64, packets: i64);
    fn increment_tcp_sessions(&self, username: &str, delta: i64);
    fn increment_udp_sessions(&self, username: &str, delta: i64);
}

/// Shadowsocks inbound contract consumed by SSMAPI.
pub trait ManagedSSMServer: Send + Sync {
    fn set_tracker(&self, tracker: Arc<dyn TrafficTracker>);
    fn tag(&self) -> &str;
    fn inbound_type(&self) -> &str;
    fn update_users(&self, users: Vec<String>, passwords: Vec<String>) -> Result<(), String>;
}

static REGISTRY: once_cell::sync::Lazy<DashMap<String, Weak<dyn ManagedSSMServer>>> =
    once_cell::sync::Lazy::new(DashMap::new);

pub fn register_managed_ssm_server(tag: &str, server: Weak<dyn ManagedSSMServer>) {
    REGISTRY.insert(tag.to_string(), server);
}

#[must_use]
pub fn get_managed_ssm_server(tag: &str) -> Option<Arc<dyn ManagedSSMServer>> {
    let entry = REGISTRY.get(tag)?;
    match entry.value().upgrade() {
        Some(server) => Some(server),
        None => {
            drop(entry);
            REGISTRY.remove(tag);
            None
        }
    }
}

pub fn unregister_managed_ssm_server(tag: &str) {
    REGISTRY.remove(tag);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyManaged {
        tag: String,
    }

    impl ManagedSSMServer for DummyManaged {
        fn set_tracker(&self, _tracker: Arc<dyn TrafficTracker>) {}
        fn tag(&self) -> &str {
            &self.tag
        }
        fn inbound_type(&self) -> &str {
            "shadowsocks"
        }
        fn update_users(&self, _users: Vec<String>, _passwords: Vec<String>) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn registry_drops_stale_weak_entries() {
        let server: Arc<dyn ManagedSSMServer> = Arc::new(DummyManaged {
            tag: "ss-in".into(),
        });
        register_managed_ssm_server("ss-in", Arc::downgrade(&server));
        assert!(get_managed_ssm_server("ss-in").is_some());
        drop(server);
        assert!(get_managed_ssm_server("ss-in").is_none());
    }
}
