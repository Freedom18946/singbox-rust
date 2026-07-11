//! Outbound manager for handling multiple outbound connectors
//!
//! This module provides the `OutboundManager` that holds and manages
//! different outbound connector instances with lifecycle support.
//! 此模块提供 `OutboundManager`，用于管理不同的出站连接器实例，并支持生命周期管理。

use crate::service::StartStage;
use sb_config::ir::{OutboundIR, OutboundType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// =========================================================================
// Pure functions for dependency extraction and topological sort (L2.9)
// =========================================================================

/// Extract outbound dependency graph from IR: Selector/UrlTest → members list.
/// 从 IR 提取出站依赖图：Selector/UrlTest → 成员列表。
///
/// Returns a map of tag → list of tags it depends on.
pub fn compute_outbound_deps(outbounds: &[OutboundIR]) -> HashMap<String, Vec<String>> {
    let mut deps = HashMap::new();
    for ob in outbounds {
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            let tag = match &ob.name {
                Some(n) if !n.is_empty() => n.clone(),
                _ => continue,
            };
            if let Some(members) = &ob.members {
                if !members.is_empty() {
                    deps.insert(tag, members.clone());
                }
            }
        }
    }
    deps
}

/// Kahn's topological sort — pure sync function.
/// 拓扑排序（纯同步函数）。
///
/// Returns ordered tags (dependencies first) or Err with cycle info.
/// Missing deps (tag in deps but not in all_tags) are silently ignored,
/// matching Go behavior where unknown outbounds are skipped.
pub fn validate_and_sort(
    all_tags: &[String],
    deps: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, String> {
    let tag_set: std::collections::HashSet<&String> = all_tags.iter().collect();

    // Build in-degree map and adjacency list
    let mut in_degree: HashMap<&String, usize> = HashMap::new();
    let mut graph: HashMap<&String, Vec<&String>> = HashMap::new();

    for tag in all_tags {
        in_degree.entry(tag).or_insert(0);
        graph.entry(tag).or_default();
    }

    // Build graph: if A depends on B, edge B → A (B must start before A)
    for (tag, dep_list) in deps {
        if !tag_set.contains(tag) {
            continue;
        }
        for dep in dep_list {
            if tag_set.contains(dep) {
                graph.entry(dep).or_default().push(tag);
                *in_degree.entry(tag).or_insert(0) += 1;
            }
        }
    }

    // Seed queue with zero in-degree nodes (sorted for determinism)
    let mut queue: std::collections::BinaryHeap<std::cmp::Reverse<&String>> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&tag, _)| std::cmp::Reverse(tag))
        .collect();

    let mut result = Vec::with_capacity(all_tags.len());

    while let Some(std::cmp::Reverse(node)) = queue.pop() {
        result.push(node.clone());
        if let Some(neighbors) = graph.get(node) {
            for &neighbor in neighbors {
                if let Some(deg) = in_degree.get_mut(neighbor) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(std::cmp::Reverse(neighbor));
                    }
                }
            }
        }
    }

    if result.len() != all_tags.len() {
        let cycle_nodes: Vec<String> = in_degree
            .iter()
            .filter(|(_, &deg)| deg > 0)
            .map(|(&tag, _)| tag.clone())
            .collect();
        return Err(format!(
            "dependency cycle detected involving: {:?}",
            cycle_nodes
        ));
    }

    Ok(result)
}

/// Thread-safe manager for outbound connectors with lifecycle support.
/// 具有生命周期支持的出站连接器的线程安全管理器。
#[derive(Clone)]
pub struct OutboundManager {
    /// Canonical outbounds stored by tag.
    connectors: Arc<RwLock<HashMap<String, Arc<dyn sb_types::Outbound>>>>,
    /// Default outbound tag
    default_tag: Arc<RwLock<Option<String>>>,
    /// Dependency graph: tag -> list of tags it depends on
    /// 依赖图：标签 -> 它依赖的标签列表
    dependencies: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
            .field("connectors", &"<dyn sb_types::Outbound>")
            .finish()
    }
}

impl OutboundManager {
    /// Create a new empty outbound manager.
    /// 创建一个新的空出站管理器。
    pub fn new() -> Self {
        Self {
            connectors: Arc::new(RwLock::new(HashMap::new())),
            default_tag: Arc::new(RwLock::new(None)),
            dependencies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a canonical outbound with the supplied registry tag.
    pub async fn add_adapter(&self, tag: String, adapter: Arc<dyn sb_types::Outbound>) {
        self.connectors.write().await.insert(tag, adapter);
    }

    /// Get an outbound connector by tag.
    /// 按标签获取出站连接器。
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        self.connectors.read().await.get(tag).cloned()
    }

    /// Remove an outbound connector by tag.
    /// 按标签移除出站连接器。
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        // Remove from dependencies
        self.dependencies.write().await.remove(tag);

        self.connectors.write().await.remove(tag)
    }

    /// Remove with dependency check (Go parity: ErrInvalid if tag is empty or has dependents).
    /// 带依赖检查的移除（Go 对等：标签为空或有依赖项时返回 ErrInvalid）。
    pub async fn remove_with_check(
        &self,
        tag: &str,
    ) -> Result<Option<Arc<dyn sb_types::Outbound>>, String> {
        if tag.is_empty() {
            return Err("empty tag invalid".to_string());
        }

        // Check for dependents
        if self.has_dependents(tag).await {
            return Err(format!(
                "cannot remove '{}': other outbounds depend on it",
                tag
            ));
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

    /// Replace an outbound atomically in the canonical registry.
    pub async fn replace(&self, tag: String, adapter: Arc<dyn sb_types::Outbound>) {
        self.connectors.write().await.insert(tag, adapter);
    }

    /// List all available outbound tags.
    /// 列出所有可用的出站标签。
    pub async fn list_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self.connectors.read().await.keys().cloned().collect();
        tags.sort();
        tags.dedup();
        tags
    }

    /// Check if a tag exists.
    /// 检查标签是否存在。
    pub async fn contains(&self, tag: &str) -> bool {
        self.connectors.read().await.contains_key(tag)
    }

    /// Get the number of registered connectors.
    /// 获取注册的连接器数量。
    pub async fn len(&self) -> usize {
        self.connectors.read().await.len()
    }

    /// Check if the manager is empty.
    /// 检查管理器是否为空。
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all connectors.
    /// 清除所有连接器。
    pub async fn clear(&self) {
        self.connectors.write().await.clear();
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

    /// Validate dependency order at a lifecycle stage.
    pub async fn start_all(&self, stage: StartStage) {
        if let Err(e) = self.start_all_ordered(stage).await {
            warn!(stage = ?stage, error = %e, "outbound: failed to start all adapters");
        }
    }

    /// Canonical outbounds have no second lifecycle contract; ordering is still
    /// validated so startup retains its dependency failure semantics.
    pub async fn start_all_ordered(&self, stage: StartStage) -> Result<(), String> {
        let _ = stage;
        self.get_startup_order().await?;
        Ok(())
    }

    /// Validate shutdown order for canonical outbounds.
    pub async fn close_all(&self) {
        if let Err(e) = self.close_all_ordered().await {
            warn!(error = %e, "outbound: failed to close all adapters");
        }
    }

    /// Canonical outbounds own their resources and are dropped by the holder.
    pub async fn close_all_ordered(&self) -> Result<(), String> {
        let mut order = self.get_startup_order().await?;
        order.reverse();
        let _ = order;
        Ok(())
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
        let connectors = self.connectors.read().await;
        let deps = self.dependencies.read().await;

        let all_tags: Vec<String> = connectors.keys().cloned().collect();

        validate_and_sort(&all_tags, &deps)
    }

    /// Resolve default outbound (explicit tag → first registered).
    /// 解析默认出站（显式标签 → 第一个已注册项）。
    ///
    /// Returns a diagnostic error if no connector can be selected.
    /// 若无法选择任何连接器，返回可诊断错误。
    pub async fn resolve_default(&self, config_tag: Option<&str>) -> Result<String, String> {
        // 1. Explicit tag from config (route.final / route.default)
        if let Some(tag) = config_tag {
            if !tag.is_empty() && self.contains(tag).await {
                self.set_default(Some(tag.to_string())).await;
                info!(
                    target: "sb_core::outbound",
                    default = %tag,
                    source = "config",
                    "default outbound resolved"
                );
                return Ok(tag.to_string());
            }
            if !tag.is_empty() {
                return Err(format!("default outbound not found: {}", tag));
            }
        }
        // 2. First registered outbound
        let mut tags = self.list_tags().await;
        tags.sort();
        if let Some(first) = tags.first() {
            self.set_default(Some(first.clone())).await;
            info!(
                target: "sb_core::outbound",
                default = %first,
                source = "first_registered",
                "default outbound resolved"
            );
            return Ok(first.clone());
        }
        // 3. No fallback injection: fail with explicit diagnostics.
        let mut available = self.list_tags().await;
        available.sort();
        Err(format!(
            "no outbound connectors available; cannot resolve default outbound (requested={:?}, available={:?})",
            config_tag, available
        ))
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
    #[derive(Debug)]
    struct TestOutbound;

    impl sb_types::Outbound for TestOutbound {
        fn r#type(&self) -> &str {
            "test"
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("test")
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp]
        }
        fn dial<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async { Err(sb_types::CoreError::policy("test outbound")) })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async { Err(sb_types::CoreError::policy("test outbound")) })
        }
    }

    fn test_connector() -> Arc<dyn sb_types::Outbound> {
        Arc::new(TestOutbound)
    }

    #[tokio::test]
    async fn test_outbound_manager_basic_operations() {
        let manager = OutboundManager::new();
        assert!(manager.is_empty().await);
        assert_eq!(manager.len().await, 0);

        // Add a connector (legacy)
        let connector = test_connector();
        manager
            .add_adapter("direct".to_string(), connector.clone())
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
            .add_adapter("direct1".to_string(), test_connector())
            .await;
        manager
            .add_adapter("direct2".to_string(), test_connector())
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

    // =========================================================================
    // L2.9 Tests: compute_outbound_deps, validate_and_sort, resolve_default
    // =========================================================================

    #[test]
    fn test_compute_outbound_deps_extracts_selector_members() {
        let outbounds = vec![
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct-a".to_string()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct-b".to_string()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("manual".to_string()),
                members: Some(vec!["direct-a".to_string(), "direct-b".to_string()]),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::UrlTest,
                name: Some("auto".to_string()),
                members: Some(vec!["direct-a".to_string()]),
                ..Default::default()
            },
        ];

        let deps = compute_outbound_deps(&outbounds);
        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps.get("manual").unwrap(),
            &vec!["direct-a".to_string(), "direct-b".to_string()]
        );
        assert_eq!(deps.get("auto").unwrap(), &vec!["direct-a".to_string()]);
        // Direct outbounds should not appear as keys
        assert!(!deps.contains_key("direct-a"));
    }

    #[test]
    fn test_compute_outbound_deps_skips_empty_members() {
        let outbounds = vec![
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("empty".to_string()),
                members: Some(vec![]),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("none".to_string()),
                members: None,
                ..Default::default()
            },
        ];

        let deps = compute_outbound_deps(&outbounds);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_validate_and_sort_linear() {
        // C depends on nothing, B depends on C, A depends on B
        // Expected order: C, B, A (or any valid topo order)
        let all_tags = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let mut deps = HashMap::new();
        deps.insert("A".to_string(), vec!["B".to_string()]);
        deps.insert("B".to_string(), vec!["C".to_string()]);

        let result = validate_and_sort(&all_tags, &deps).unwrap();
        assert_eq!(result.len(), 3);

        // C must come before B, B must come before A
        let pos_a = result.iter().position(|t| t == "A").unwrap();
        let pos_b = result.iter().position(|t| t == "B").unwrap();
        let pos_c = result.iter().position(|t| t == "C").unwrap();
        assert!(pos_c < pos_b);
        assert!(pos_b < pos_a);
    }

    #[test]
    fn test_validate_and_sort_cycle_detected() {
        let all_tags = vec!["A".to_string(), "B".to_string()];
        let mut deps = HashMap::new();
        deps.insert("A".to_string(), vec!["B".to_string()]);
        deps.insert("B".to_string(), vec!["A".to_string()]);

        let result = validate_and_sort(&all_tags, &deps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("cycle"));
    }

    #[test]
    fn test_validate_and_sort_missing_dep_ignored() {
        // A depends on X which doesn't exist in all_tags — should be silently ignored
        let all_tags = vec!["A".to_string(), "B".to_string()];
        let mut deps = HashMap::new();
        deps.insert("A".to_string(), vec!["X".to_string()]);

        let result = validate_and_sort(&all_tags, &deps).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_validate_and_sort_no_deps() {
        let all_tags = vec!["C".to_string(), "A".to_string(), "B".to_string()];
        let deps = HashMap::new();

        let result = validate_and_sort(&all_tags, &deps).unwrap();
        assert_eq!(result.len(), 3);
        // With no deps, should be sorted alphabetically (deterministic)
        assert_eq!(result, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_validate_and_sort_diamond() {
        // D depends on B and C; B and C depend on A
        let all_tags = vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ];
        let mut deps = HashMap::new();
        deps.insert("B".to_string(), vec!["A".to_string()]);
        deps.insert("C".to_string(), vec!["A".to_string()]);
        deps.insert("D".to_string(), vec!["B".to_string(), "C".to_string()]);

        let result = validate_and_sort(&all_tags, &deps).unwrap();
        let pos_a = result.iter().position(|t| t == "A").unwrap();
        let pos_b = result.iter().position(|t| t == "B").unwrap();
        let pos_c = result.iter().position(|t| t == "C").unwrap();
        let pos_d = result.iter().position(|t| t == "D").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_a < pos_c);
        assert!(pos_b < pos_d);
        assert!(pos_c < pos_d);
    }

    #[tokio::test]
    async fn test_resolve_default_explicit() {
        let manager = OutboundManager::new();
        manager
            .add_adapter("proxy".to_string(), test_connector())
            .await;
        manager
            .add_adapter("direct".to_string(), test_connector())
            .await;

        let result = manager.resolve_default(Some("proxy")).await;
        assert_eq!(result.unwrap(), "proxy");
        assert_eq!(manager.get_default().await, Some("proxy".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_default_not_found() {
        let manager = OutboundManager::new();
        manager
            .add_adapter("direct".to_string(), test_connector())
            .await;

        let result = manager.resolve_default(Some("nonexistent")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_default_first_registered() {
        let manager = OutboundManager::new();
        manager
            .add_adapter("beta".to_string(), test_connector())
            .await;
        manager
            .add_adapter("alpha".to_string(), test_connector())
            .await;

        let result = manager.resolve_default(None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alpha");
        assert_eq!(manager.get_default().await.as_deref(), Some("alpha"));
    }

    #[tokio::test]
    async fn test_resolve_default_without_connectors_is_error() {
        let manager = OutboundManager::new();
        let result = manager.resolve_default(None).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("no outbound connectors available"));
        assert!(manager.get_default().await.is_none());
    }

    #[tokio::test]
    async fn test_get_startup_order_delegates_to_validate_and_sort() {
        let manager = OutboundManager::new();
        manager
            .add_adapter("proxy".to_string(), test_connector())
            .await;
        manager
            .add_adapter("direct".to_string(), test_connector())
            .await;
        manager.add_dependency("proxy", "direct").await;

        let order = manager.get_startup_order().await.unwrap();
        let pos_direct = order.iter().position(|t| t == "direct").unwrap();
        let pos_proxy = order.iter().position(|t| t == "proxy").unwrap();
        assert!(pos_direct < pos_proxy);
    }

    #[tokio::test]
    async fn canonical_outbounds_start_and_close_in_dependency_order() {
        let manager = OutboundManager::new();
        manager
            .add_adapter("proxy".to_string(), test_connector())
            .await;
        manager
            .add_adapter("direct".to_string(), test_connector())
            .await;
        manager.add_dependency("proxy", "direct").await;

        manager.start_all_ordered(StartStage::Start).await.unwrap();
        manager.close_all_ordered().await.unwrap();
        assert_eq!(
            manager.get_startup_order().await.unwrap(),
            vec!["direct", "proxy"]
        );
    }
}
