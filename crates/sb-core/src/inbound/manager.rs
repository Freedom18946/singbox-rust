//! Inbound manager for handling multiple inbound handlers
//!
//! This module provides the `InboundManager` that holds and manages
//! different inbound handler instances with lifecycle support.
//! 此模块提供 `InboundManager`，用于管理不同的入站处理程序实例，并支持生命周期管理。

use crate::service::{Lifecycle, StartStage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Inbound adapter trait for handlers with lifecycle and tag.
/// 具有生命周期和标签的入站适配器 trait。
pub trait InboundAdapter: Lifecycle {
    /// Return the inbound tag/identifier.
    /// 返回入站标签/标识符。
    fn tag(&self) -> &str;

    /// Return the inbound type (e.g., "http", "socks", "vmess").
    /// 返回入站类型（例如 "http", "socks", "vmess"）。
    fn inbound_type(&self) -> &str;
}

/// Type alias for an inbound handler (legacy compatibility).
/// 入站处理程序的类型别名（传统兼容性）。
pub type InboundHandler = Arc<dyn InboundAdapter>;

/// Thread-safe manager for inbound handlers with lifecycle support.
/// 具有生命周期支持的入站处理程序的线程安全管理器。
#[derive(Clone)]
pub struct InboundManager {
    handlers: Arc<RwLock<HashMap<String, InboundHandler>>>,
}

impl std::fmt::Debug for InboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundManager")
            .field("handlers", &"<dyn InboundAdapter>")
            .finish()
    }
}

impl InboundManager {
    /// Create a new empty inbound manager.
    /// 创建一个新的空入站管理器。
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an inbound handler with the given tag.
    /// 添加具有给定标签的入站处理程序。
    pub async fn add_handler(&self, tag: String, handler: InboundHandler) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(tag, handler);
    }

    /// Get an inbound handler by tag.
    /// 按标签获取入站处理程序。
    pub async fn get(&self, tag: &str) -> Option<InboundHandler> {
        let handlers = self.handlers.read().await;
        handlers.get(tag).cloned()
    }

    /// Remove an inbound handler by tag.
    /// 按标签移除入站处理程序。
    pub async fn remove(&self, tag: &str) -> Option<InboundHandler> {
        let mut handlers = self.handlers.write().await;
        handlers.remove(tag)
    }

    /// List all available inbound tags.
    /// 列出所有可用的入站标签。
    pub async fn list_tags(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers.keys().cloned().collect()
    }

    /// Check if a tag exists.
    /// 检查标签是否存在。
    pub async fn contains(&self, tag: &str) -> bool {
        let handlers = self.handlers.read().await;
        handlers.contains_key(tag)
    }

    /// Get the number of registered handlers.
    /// 获取注册的处理程序数量。
    pub async fn len(&self) -> usize {
        let handlers = self.handlers.read().await;
        handlers.len()
    }

    /// Check if the manager is empty.
    /// 检查管理器是否为空。
    pub async fn is_empty(&self) -> bool {
        let handlers = self.handlers.read().await;
        handlers.is_empty()
    }

    /// Clear all handlers.
    /// 清除所有处理程序。
    pub async fn clear(&self) {
        let mut handlers = self.handlers.write().await;
        handlers.clear();
    }

    /// Start all handlers at the given lifecycle stage.
    /// 在给定的生命周期阶段启动所有处理程序。
    ///
    /// Errors are logged but don't stop other handlers from starting.
    /// 错误会被记录，但不会阻止其他处理程序启动。
    pub async fn start_all(&self, stage: StartStage) {
        let handlers = self.handlers.read().await;
        for (tag, handler) in handlers.iter() {
            debug!(tag = %tag, stage = ?stage, "inbound: starting handler");
            if let Err(e) = handler.start(stage) {
                warn!(tag = %tag, stage = ?stage, error = %e, "inbound: failed to start handler");
            }
        }
    }

    /// Close all handlers.
    /// 关闭所有处理程序。
    ///
    /// Errors are logged but don't stop other handlers from closing.
    /// 错误会被记录，但不会阻止其他处理程序关闭。
    pub async fn close_all(&self) {
        let handlers = self.handlers.read().await;
        for (tag, handler) in handlers.iter() {
            debug!(tag = %tag, "inbound: closing handler");
            if let Err(e) = handler.close() {
                warn!(tag = %tag, error = %e, "inbound: failed to close handler");
            }
        }
    }

    /// Remove with validation (Go parity: ErrInvalid if tag is empty).
    /// 带验证的移除（Go 对等：标签为空时返回 ErrInvalid）。
    pub async fn remove_with_check(&self, tag: &str) -> Result<Option<InboundHandler>, String> {
        if tag.is_empty() {
            return Err("empty tag invalid".to_string());
        }
        Ok(self.remove(tag).await)
    }

    /// Replace an inbound handler, closing the old one if present (Go parity: close-on-replace).
    /// 替换入站处理程序，如果存在则关闭旧的（Go 对等：替换时关闭）。
    pub async fn replace(&self, tag: String, handler: InboundHandler) {
        // Close old handler if exists
        if let Some(old) = self.get(&tag).await {
            debug!(tag = %tag, "inbound: closing old handler before replace");
            if let Err(e) = old.close() {
                warn!(tag = %tag, error = %e, "inbound: failed to close old handler during replace");
            }
        }
        
        // Replace in handlers
        let mut handlers = self.handlers.write().await;
        handlers.insert(tag, handler);
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

    struct MockInboundAdapter {
        tag: String,
    }

    impl InboundAdapter for MockInboundAdapter {
        fn tag(&self) -> &str {
            &self.tag
        }
        fn inbound_type(&self) -> &str {
            "mock"
        }
    }

    impl Lifecycle for MockInboundAdapter {
        fn start(&self, _stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_inbound_manager_basic_operations() {
        let manager = InboundManager::new();
        assert!(manager.is_empty().await);
        assert_eq!(manager.len().await, 0);

        // Add a handler
        let handler: InboundHandler = Arc::new(MockInboundAdapter {
            tag: "http".to_string(),
        });
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
    }

    #[tokio::test]
    async fn test_inbound_manager_lifecycle() {
        let manager = InboundManager::new();
        
        let handler1: InboundHandler = Arc::new(MockInboundAdapter {
            tag: "h1".to_string(),
        });
        let handler2: InboundHandler = Arc::new(MockInboundAdapter {
            tag: "h2".to_string(),
        });
        
        manager.add_handler("h1".into(), handler1).await;
        manager.add_handler("h2".into(), handler2).await;

        // Test lifecycle stages
        manager.start_all(StartStage::Initialize).await;
        manager.start_all(StartStage::Start).await;
        manager.start_all(StartStage::PostStart).await;
        manager.start_all(StartStage::Started).await;
        manager.close_all().await;
        
        // Should still have handlers registered
        assert_eq!(manager.len().await, 2);
    }
}
