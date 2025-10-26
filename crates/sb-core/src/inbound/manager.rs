//! Inbound manager for handling multiple inbound handlers
//!
//! This module provides the `InboundManager` that holds and manages
//! different inbound handler instances.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Type alias for an inbound handler
pub type InboundHandler = Arc<dyn std::any::Any + Send + Sync>;

/// Thread-safe manager for inbound handlers
#[derive(Debug, Clone)]
pub struct InboundManager {
    handlers: Arc<RwLock<HashMap<String, InboundHandler>>>,
}

impl InboundManager {
    /// Create a new empty inbound manager
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an inbound handler with the given tag
    pub async fn add_handler(&self, tag: String, handler: InboundHandler) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(tag, handler);
    }

    /// Get an inbound handler by tag
    pub async fn get(&self, tag: &str) -> Option<InboundHandler> {
        let handlers = self.handlers.read().await;
        handlers.get(tag).cloned()
    }

    /// Remove an inbound handler by tag
    pub async fn remove(&self, tag: &str) -> Option<InboundHandler> {
        let mut handlers = self.handlers.write().await;
        handlers.remove(tag)
    }

    /// List all available inbound tags
    pub async fn list_tags(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers.keys().cloned().collect()
    }

    /// Check if a tag exists
    pub async fn contains(&self, tag: &str) -> bool {
        let handlers = self.handlers.read().await;
        handlers.contains_key(tag)
    }

    /// Get the number of registered handlers
    pub async fn len(&self) -> usize {
        let handlers = self.handlers.read().await;
        handlers.len()
    }

    /// Check if the manager is empty
    pub async fn is_empty(&self) -> bool {
        let handlers = self.handlers.read().await;
        handlers.is_empty()
    }

    /// Clear all handlers
    pub async fn clear(&self) {
        let mut handlers = self.handlers.write().await;
        handlers.clear();
    }
}

impl Default for InboundManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inbound_manager_basic_operations() {
        let manager = InboundManager::new();
        assert!(manager.is_empty().await);
        assert_eq!(manager.len().await, 0);

        // Add a handler
        let handler: InboundHandler = Arc::new("test_handler".to_string());
        manager
            .add_handler("http".to_string(), handler.clone())
            .await;

        assert!(!manager.is_empty().await);
        assert_eq!(manager.len().await, 1);
        assert!(manager.contains("http").await);
        assert!(!manager.contains("nonexistent").await);

        // Get the handler
        let retrieved = manager.get("http").await;
        assert!(retrieved.is_some());

        // List tags
        let tags = manager.list_tags().await;
        assert_eq!(tags.len(), 1);
        assert!(tags.contains(&"http".to_string()));

        // Remove the handler
        let removed = manager.remove("http").await;
        assert!(removed.is_some());
        assert!(manager.is_empty().await);

        // Clear
        manager.add_handler("http1".to_string(), Arc::new(1)).await;
        manager.add_handler("http2".to_string(), Arc::new(2)).await;
        assert_eq!(manager.len().await, 2);
        manager.clear().await;
        assert!(manager.is_empty().await);
    }
}
