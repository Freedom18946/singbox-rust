//! Outbound manager for handling multiple outbound connectors
//!
//! This module provides the `OutboundManager` that holds and manages
//! different outbound connector instances with lifecycle support.
//! 此模块提供 `OutboundManager`，用于管理不同的出站连接器实例，并支持生命周期管理。

use crate::outbound::traits::OutboundConnector;
use crate::service::{Lifecycle, StartStage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Outbound adapter trait for connectors with lifecycle and tag.
/// 具有生命周期和标签的出站适配器 trait。
pub trait OutboundAdapter: OutboundConnector + Lifecycle {
    /// Return the outbound tag/identifier.
    /// 返回出站标签/标识符。
    fn tag(&self) -> &str;

    /// Return the outbound type (e.g., "direct", "socks", "vmess").
    /// 返回出站类型（例如 "direct", "socks", "vmess"）。
    fn outbound_type(&self) -> &str;
}

/// Type alias for an outbound connector (to maintain API compatibility).
/// 出站连接器的类型别名（保持 API 兼容性）。
pub type OutboundHandler = Arc<dyn OutboundAdapter>;

/// Thread-safe manager for outbound connectors with lifecycle support.
/// 具有生命周期支持的出站连接器的线程安全管理器。
#[derive(Clone)]
pub struct OutboundManager {
    /// Connectors stored by tag (supports OutboundAdapter with lifecycle)
    adapters: Arc<RwLock<HashMap<String, OutboundHandler>>>,
    /// Legacy connectors for backward compatibility (no lifecycle)
    legacy_connectors: Arc<RwLock<HashMap<String, Arc<dyn OutboundConnector>>>>,
    /// Default outbound tag
    default_tag: Arc<RwLock<Option<String>>>,
    /// Dependency graph: tag -> list of tags it depends on
    /// 依赖图：标签 -> 它依赖的标签列表
    dependencies: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
            .field("adapters", &"<dyn OutboundAdapter>")
            .field("legacy_connectors", &"<dyn OutboundConnector>")
            .finish()
    }
}

impl OutboundManager {
    /// Create a new empty outbound manager.
    /// 创建一个新的空出站管理器。
    pub fn new() -> Self {
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
            legacy_connectors: Arc::new(RwLock::new(HashMap::new())),
            default_tag: Arc::new(RwLock::new(None)),
            dependencies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an outbound adapter with the given tag.
    /// 添加具有给定标签的出站适配器。
    pub async fn add_adapter(&self, tag: String, adapter: OutboundHandler) {
        let mut adapters = self.adapters.write().await;
        adapters.insert(tag, adapter);
    }

    /// Add a legacy outbound connector with the given tag (no lifecycle).
    /// 添加具有给定标签的传统出站连接器（无生命周期）。
    pub async fn add_connector(&self, tag: String, connector: Arc<dyn OutboundConnector>) {
        let mut connectors = self.legacy_connectors.write().await;
        connectors.insert(tag, connector);
    }

    /// Get an outbound connector by tag.
    /// 按标签获取出站连接器。
    ///
    /// Checks adapters first, then legacy connectors.
    /// 首先检查适配器，然后检查传统连接器。
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        // Check adapters first
        let adapters = self.adapters.read().await;
        if let Some(adapter) = adapters.get(tag) {
            return Some(adapter.clone() as Arc<dyn OutboundConnector>);
        }
        drop(adapters);

        // Fall back to legacy connectors
        let connectors = self.legacy_connectors.read().await;
        connectors.get(tag).cloned()
    }

    /// Get an outbound adapter by tag (with lifecycle support).
    /// 按标签获取出站适配器（支持生命周期）。
    pub async fn get_adapter(&self, tag: &str) -> Option<OutboundHandler> {
        let adapters = self.adapters.read().await;
        adapters.get(tag).cloned()
    }

    /// Remove an outbound connector by tag.
    /// 按标签移除出站连接器。
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn OutboundConnector>> {
        // Remove from dependencies
        self.dependencies.write().await.remove(tag);
        
        // Try adapters first
        let mut adapters = self.adapters.write().await;
        if let Some(adapter) = adapters.remove(tag) {
            return Some(adapter as Arc<dyn OutboundConnector>);
        }
        drop(adapters);

        // Try legacy connectors
        let mut connectors = self.legacy_connectors.write().await;
        connectors.remove(tag)
    }

    /// Remove with dependency check (Go parity: ErrInvalid if tag is empty or has dependents).
    /// 带依赖检查的移除（Go 对等：标签为空或有依赖项时返回 ErrInvalid）。
    pub async fn remove_with_check(&self, tag: &str) -> Result<Option<Arc<dyn OutboundConnector>>, String> {
        if tag.is_empty() {
            return Err("empty tag invalid".to_string());
        }
        
        // Check for dependents
        if self.has_dependents(tag).await {
            return Err(format!("cannot remove '{}': other outbounds depend on it", tag));
        }
        
        Ok(self.remove(tag).await)
    }

    /// Check if any other outbound depends on this tag.
    /// 检查是否有其他出站依赖于此标签。
    pub async fn has_dependents(&self, tag: &str) -> bool {
        let deps = self.dependencies.read().await;
        for dep_list in deps.values() {
            if dep_list.contains(&tag.to_string()) {
                return true;
            }
        }
        false
    }

    /// Replace an outbound adapter, closing the old one if present (Go parity: close-on-replace).
    /// 替换出站适配器，如果存在则关闭旧的（Go 对等：替换时关闭）。
    pub async fn replace(&self, tag: String, adapter: OutboundHandler) {
        // Close old adapter if exists
        if let Some(old) = self.get_adapter(&tag).await {
            debug!(tag = %tag, "outbound: closing old adapter before replace");
            if let Err(e) = old.close() {
                warn!(tag = %tag, error = %e, "outbound: failed to close old adapter during replace");
            }
        }
        
        // Replace in adapters
        let mut adapters = self.adapters.write().await;
        adapters.insert(tag.clone(), adapter);
        drop(adapters);
        
        // Also remove from legacy if present
        let mut legacy = self.legacy_connectors.write().await;
        legacy.remove(&tag);
    }

    /// Replace a legacy connector, removing from adapters if present.
    /// 替换传统连接器，如果存在则从适配器中移除。
    pub async fn replace_connector(&self, tag: String, connector: Arc<dyn OutboundConnector>) {
        // Close old adapter if exists
        if let Some(old) = self.get_adapter(&tag).await {
            debug!(tag = %tag, "outbound: closing old adapter before replace");
            if let Err(e) = old.close() {
                warn!(tag = %tag, error = %e, "outbound: failed to close old adapter during replace");
            }
            self.adapters.write().await.remove(&tag);
        }
        
        // Replace in legacy connectors
        let mut legacy = self.legacy_connectors.write().await;
        legacy.insert(tag, connector);
    }

    /// List all available outbound tags.
    /// 列出所有可用的出站标签。
    pub async fn list_tags(&self) -> Vec<String> {
        let adapters = self.adapters.read().await;
        let connectors = self.legacy_connectors.read().await;
        
        let mut tags: Vec<String> = adapters.keys().cloned().collect();
        tags.extend(connectors.keys().cloned());
        tags
    }

    /// Check if a tag exists.
    /// 检查标签是否存在。
    pub async fn contains(&self, tag: &str) -> bool {
        let adapters = self.adapters.read().await;
        if adapters.contains_key(tag) {
            return true;
        }
        drop(adapters);

        let connectors = self.legacy_connectors.read().await;
        connectors.contains_key(tag)
    }

    /// Get the number of registered connectors.
    /// 获取注册的连接器数量。
    pub async fn len(&self) -> usize {
        let adapters = self.adapters.read().await;
        let connectors = self.legacy_connectors.read().await;
        adapters.len() + connectors.len()
    }

    /// Check if the manager is empty.
    /// 检查管理器是否为空。
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all connectors.
    /// 清除所有连接器。
    pub async fn clear(&self) {
        let mut adapters = self.adapters.write().await;
        adapters.clear();
        drop(adapters);

        let mut connectors = self.legacy_connectors.write().await;
        connectors.clear();
    }

    /// Set the default outbound tag.
    /// 设置默认出站标签。
    pub async fn set_default(&self, tag: Option<String>) {
        let mut default = self.default_tag.write().await;
        *default = tag;
    }

    /// Get the default outbound tag.
    /// 获取默认出站标签。
    pub async fn get_default(&self) -> Option<String> {
        let default = self.default_tag.read().await;
        default.clone()
    }

    /// Start all adapters at the given lifecycle stage.
    /// 在给定的生命周期阶段启动所有适配器。
    ///
    /// Note: Legacy connectors don't have lifecycle support and are skipped.
    /// 注意：传统连接器没有生命周期支持，会被跳过。
    pub async fn start_all(&self, stage: StartStage) {
        let adapters = self.adapters.read().await;
        for (tag, adapter) in adapters.iter() {
            debug!(tag = %tag, stage = ?stage, "outbound: starting adapter");
            if let Err(e) = adapter.start(stage) {
                warn!(tag = %tag, stage = ?stage, error = %e, "outbound: failed to start adapter");
            }
        }
    }

    /// Close all adapters.
    /// 关闭所有适配器。
    ///
    /// Note: Legacy connectors don't have lifecycle support and are skipped.
    /// 注意：传统连接器没有生命周期支持，会被跳过。
    pub async fn close_all(&self) {
        let adapters = self.adapters.read().await;
        for (tag, adapter) in adapters.iter() {
            debug!(tag = %tag, "outbound: closing adapter");
            if let Err(e) = adapter.close() {
                warn!(tag = %tag, error = %e, "outbound: failed to close adapter");
            }
        }
    }

    // =========================================================================
    // Dependency Tracking (Go parity: outbound dependency order)
    // =========================================================================

    /// Add a dependency: `tag` depends on `depends_on`.
    /// 添加依赖：`tag` 依赖于 `depends_on`。
    pub async fn add_dependency(&self, tag: &str, depends_on: &str) {
        let mut deps = self.dependencies.write().await;
        deps.entry(tag.to_string())
            .or_insert_with(Vec::new)
            .push(depends_on.to_string());
    }

    /// Get startup order using topological sort (dependencies first).
    /// 使用拓扑排序获取启动顺序（依赖项优先）。
    ///
    /// Returns `Err` with cycle path if a dependency cycle is detected.
    /// 如果检测到依赖循环，返回带有循环路径的 `Err`。
    pub async fn get_startup_order(&self) -> Result<Vec<String>, String> {
        let adapters = self.adapters.read().await;
        let legacy = self.legacy_connectors.read().await;
        let deps = self.dependencies.read().await;

        // Collect all tags
        let mut all_tags: Vec<String> = adapters.keys().cloned().collect();
        all_tags.extend(legacy.keys().cloned());

        // Kahn's algorithm for topological sort
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();

        // Initialize in-degree for all nodes
        for tag in &all_tags {
            in_degree.entry(tag.clone()).or_insert(0);
            graph.entry(tag.clone()).or_default();
        }

        // Build graph (reverse: if A depends on B, add edge B -> A)
        for (tag, dep_list) in deps.iter() {
            for dep in dep_list {
                if all_tags.contains(dep) {
                    graph.entry(dep.clone()).or_default().push(tag.clone());
                    *in_degree.entry(tag.clone()).or_insert(0) += 1;
                }
            }
        }

        // Queue nodes with in-degree 0
        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(tag, _)| tag.clone())
            .collect();
        queue.sort(); // Deterministic order

        let mut result = Vec::new();
        while let Some(node) = queue.pop() {
            result.push(node.clone());
            if let Some(neighbors) = graph.get(&node) {
                for neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(neighbor.clone());
                            queue.sort();
                        }
                    }
                }
            }
        }

        if result.len() != all_tags.len() {
            // Cycle detected - find a node still with non-zero in-degree
            let cycle_nodes: Vec<_> = in_degree
                .iter()
                .filter(|(_, &deg)| deg > 0)
                .map(|(tag, _)| tag.clone())
                .collect();
            return Err(format!("Dependency cycle detected involving: {:?}", cycle_nodes));
        }

        Ok(result)
    }

    /// Ensure a fallback "direct" outbound exists.
    /// 确保存在后备 "direct" 出站。
    pub async fn ensure_fallback_direct(&self) {
        use crate::outbound::DirectConnector;

        let has_direct = {
            let adapters = self.adapters.read().await;
            let legacy = self.legacy_connectors.read().await;
            adapters.contains_key("direct") || legacy.contains_key("direct")
        };

        if !has_direct {
            debug!("outbound: adding fallback direct connector");
            let direct = Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>;
            self.add_connector("direct".to_string(), direct).await;
        }
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

        // Add a connector (legacy)
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

    #[tokio::test]
    async fn test_outbound_manager_default_tag() {
        let manager = OutboundManager::new();
        
        // No default initially
        assert!(manager.get_default().await.is_none());
        
        // Set default
        manager.set_default(Some("proxy".to_string())).await;
        assert_eq!(manager.get_default().await, Some("proxy".to_string()));
        
        // Clear default
        manager.set_default(None).await;
        assert!(manager.get_default().await.is_none());
    }
}
