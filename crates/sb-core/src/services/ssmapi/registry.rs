//! ManagedSSMServer registry for SSMAPI service binding.
//!
//! This is a small global registry that allows the SSMAPI service to locate
//! managed Shadowsocks inbounds by tag at runtime, without forcing Bridge
//! legacy inbounds into `InboundManager`.

use dashmap::DashMap;
use std::sync::{Arc, Weak};

use super::ManagedSSMServer;

static REGISTRY: once_cell::sync::Lazy<DashMap<String, Weak<dyn ManagedSSMServer>>> =
    once_cell::sync::Lazy::new(DashMap::new);

/// Register a managed Shadowsocks inbound for SSMAPI binding.
pub fn register_managed_ssm_server(tag: &str, server: Weak<dyn ManagedSSMServer>) {
    if tag.trim().is_empty() {
        return;
    }
    REGISTRY.insert(tag.to_string(), server);
}

/// Get a managed Shadowsocks inbound by tag.
///
/// Returns `None` when the entry is missing or the Weak pointer has expired.
pub fn get_managed_ssm_server(tag: &str) -> Option<Arc<dyn ManagedSSMServer>> {
    let tag = tag.trim();
    if tag.is_empty() {
        return None;
    }

    let entry = REGISTRY.get(tag)?;
    match entry.value().upgrade() {
        Some(v) => Some(v),
        None => {
            drop(entry);
            REGISTRY.remove(tag);
            None
        }
    }
}

/// Remove a managed Shadowsocks inbound by tag.
pub fn unregister_managed_ssm_server(tag: &str) {
    let tag = tag.trim();
    if tag.is_empty() {
        return;
    }
    REGISTRY.remove(tag);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ssmapi::TrafficTracker;

    #[derive(Default)]
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
    fn registry_register_get_unreg() {
        let srv: Arc<dyn ManagedSSMServer> = Arc::new(DummyManaged {
            tag: "ss-in".to_string(),
        });
        register_managed_ssm_server("ss-in", Arc::downgrade(&srv));

        let got = get_managed_ssm_server("ss-in");
        assert!(got.is_some());
        assert_eq!(got.unwrap().tag(), "ss-in");

        unregister_managed_ssm_server("ss-in");
        assert!(get_managed_ssm_server("ss-in").is_none());
    }
}

