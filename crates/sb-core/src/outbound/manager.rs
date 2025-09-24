//! Outbound manager for handling multiple outbound connectors
//!
//! This module provides the OutboundManager that holds and manages
//! different outbound connector instances.

use crate::outbound::traits::OutboundConnector;
use std::collections::HashMap;
use std::sync::Arc;

/// Manager for outbound connectors
#[derive(Debug, Clone)]
pub struct OutboundManager {
    connectors: HashMap<String, Arc<dyn OutboundConnector>>,
}

impl OutboundManager {
    /// Create a new empty outbound manager
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }

    /// Add an outbound connector with the given tag
    pub fn add_connector(&mut self, tag: String, connector: Arc<dyn OutboundConnector>) {
        self.connectors.insert(tag, connector);
    }

    /// Get an outbound connector by tag
    pub fn get(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.connectors.get(tag).cloned()
    }

    /// Remove an outbound connector by tag
    pub fn remove(&mut self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.connectors.remove(tag)
    }

    /// List all available outbound tags
    pub fn list_tags(&self) -> Vec<&str> {
        self.connectors.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a tag exists
    pub fn contains(&self, tag: &str) -> bool {
        self.connectors.contains_key(tag)
    }

    /// Get the number of registered connectors
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    /// Check if the manager is empty
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    /// Clear all connectors
    pub fn clear(&mut self) {
        self.connectors.clear();
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

    #[test]
    fn test_outbound_manager_basic_operations() {
        let mut manager = OutboundManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);

        // Add a connector
        let connector = Arc::new(DirectConnector::new());
        manager.add_connector("direct".to_string(), connector.clone());

        assert!(!manager.is_empty());
        assert_eq!(manager.len(), 1);
        assert!(manager.contains("direct"));
        assert!(!manager.contains("nonexistent"));

        // Get the connector
        let retrieved = manager.get("direct");
        assert!(retrieved.is_some());

        // List tags
        let tags = manager.list_tags();
        assert_eq!(tags.len(), 1);
        assert!(tags.contains(&"direct"));

        // Remove the connector
        let removed = manager.remove("direct");
        assert!(removed.is_some());
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_outbound_manager_multiple_connectors() {
        let mut manager = OutboundManager::new();

        // Add multiple connectors
        let direct1 = Arc::new(DirectConnector::new());
        let direct2 = Arc::new(DirectConnector::new());

        manager.add_connector("direct1".to_string(), direct1);
        manager.add_connector("direct2".to_string(), direct2);

        assert_eq!(manager.len(), 2);
        assert!(manager.contains("direct1"));
        assert!(manager.contains("direct2"));

        let tags = manager.list_tags();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains(&"direct1"));
        assert!(tags.contains(&"direct2"));

        // Clear all
        manager.clear();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_outbound_manager_overwrite() {
        let mut manager = OutboundManager::new();

        let connector1 = Arc::new(DirectConnector::new());
        let connector2 = Arc::new(DirectConnector::new());

        // Add first connector
        manager.add_connector("test".to_string(), connector1);
        assert_eq!(manager.len(), 1);

        // Overwrite with second connector
        manager.add_connector("test".to_string(), connector2);
        assert_eq!(manager.len(), 1); // Still only one connector

        // The connector should still be retrievable
        assert!(manager.get("test").is_some());
    }
}
