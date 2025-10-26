//! Outbound manager for handling multiple outbound connectors
//!
//! This module provides the `OutboundManager` that holds and manages
//! different outbound connector instances.

use crate::outbound::traits::OutboundConnector;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Thread-safe manager for outbound connectors
#[derive(Debug, Clone)]
pub struct OutboundManager {
    connectors: Arc<RwLock<HashMap<String, Arc<dyn OutboundConnector>>>>,
}

impl OutboundManager {
    /// Create a new empty outbound manager
    pub fn new() -> Self {
        Self {
            connectors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an outbound connector with the given tag
    pub async fn add_connector(&self, tag: String, connector: Arc<dyn OutboundConnector>) {
        let mut connectors = self.connectors.write().await;
        connectors.insert(tag, connector);
    }

    /// Get an outbound connector by tag
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        let connectors = self.connectors.read().await;
        connectors.get(tag).cloned()
    }

    /// Remove an outbound connector by tag
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        let mut connectors = self.connectors.write().await;
        connectors.remove(tag)
    }

    /// List all available outbound tags
    pub async fn list_tags(&self) -> Vec<String> {
        let connectors = self.connectors.read().await;
        connectors.keys().cloned().collect()
    }

    /// Check if a tag exists
    pub async fn contains(&self, tag: &str) -> bool {
        let connectors = self.connectors.read().await;
        connectors.contains_key(tag)
    }

    /// Get the number of registered connectors
    pub async fn len(&self) -> usize {
        let connectors = self.connectors.read().await;
        connectors.len()
    }

    /// Check if the manager is empty
    pub async fn is_empty(&self) -> bool {
        let connectors = self.connectors.read().await;
        connectors.is_empty()
    }

    /// Clear all connectors
    pub async fn clear(&self) {
        let mut connectors = self.connectors.write().await;
        connectors.clear();
    }
}

impl Default for OutboundManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectConnector;

    #[tokio::test]
    async fn test_outbound_manager_basic_operations() {
        let manager = OutboundManager::new();
        assert!(manager.is_empty().await);
        assert_eq!(manager.len().await, 0);

        // Add a connector
        let connector = Arc::new(DirectConnector::new());
        manager
            .add_connector("direct".to_string(), connector.clone())
            .await;

        assert!(!manager.is_empty().await);
        assert_eq!(manager.len().await, 1);
        assert!(manager.contains("direct").await);
        assert!(!manager.contains("nonexistent").await);

        // Get the connector
        let retrieved = manager.get("direct").await;
        assert!(retrieved.is_some());

        // List tags
        let tags = manager.list_tags().await;
        assert_eq!(tags.len(), 1);
        assert!(tags.contains(&"direct".to_string()));

        // Remove the connector
        let removed = manager.remove("direct").await;
        assert!(removed.is_some());
        assert!(manager.is_empty().await);

        // Clear
        manager
            .add_connector("direct1".to_string(), Arc::new(DirectConnector::new()))
            .await;
        manager
            .add_connector("direct2".to_string(), Arc::new(DirectConnector::new()))
            .await;
        assert_eq!(manager.len().await, 2);
        manager.clear().await;
        assert!(manager.is_empty().await);
    }
}
