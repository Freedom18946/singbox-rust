//! Route Connection Interface (Go parity: route.Router)
//!
//! Provides Go-style connection routing interfaces for TCP and UDP.
//! 提供 Go 风格的 TCP 和 UDP 连接路由接口。

use std::net::IpAddr;

use async_trait::async_trait;

use super::rules::Decision;
use super::RouteCtx;

/// Result of a routing decision.
/// 路由决策结果。
#[derive(Debug, Clone)]
pub struct RouteResult {
    /// The routing decision (action to take).
    /// 路由决策（要采取的动作）。
    pub decision: Decision,
    /// The outbound tag to use (if routing to an outbound).
    /// 要使用的出站标签（如果路由到出站）。
    pub outbound: Option<String>,
    /// Index of the matched rule (for debugging/explain).
    /// 匹配规则的索引（用于调试/解释）。
    pub matched_rule: Option<usize>,
    /// Resolved IP addresses (if DNS resolution was performed).
    /// 解析的 IP 地址（如果执行了 DNS 解析）。
    pub resolved_ips: Vec<IpAddr>,
    /// Sniffed protocol (if protocol sniffing was performed).
    /// 嗅探的协议（如果执行了协议嗅探）。
    pub sniffed_protocol: Option<String>,
    /// Sniffed domain (if domain was extracted from protocol sniffing).
    /// 嗅探的域名（如果从协议嗅探中提取了域名）。
    pub sniffed_domain: Option<String>,
}

impl Default for RouteResult {
    fn default() -> Self {
        Self {
            decision: Decision::Direct,
            outbound: None,
            matched_rule: None,
            resolved_ips: Vec::new(),
            sniffed_protocol: None,
            sniffed_domain: None,
        }
    }
}

impl RouteResult {
    /// Create a new RouteResult with a decision.
    /// 使用决策创建新的 RouteResult。
    #[must_use]
    pub fn new(decision: Decision) -> Self {
        Self {
            decision,
            ..Default::default()
        }
    }

    /// Create a direct route result.
    /// 创建直连路由结果。
    #[must_use]
    pub fn direct() -> Self {
        Self::new(Decision::Direct)
    }

    /// Create a proxy route result.
    /// 创建代理路由结果。
    #[must_use]
    pub fn proxy(outbound: impl Into<String>) -> Self {
        let outbound = outbound.into();
        Self {
            decision: Decision::Proxy(Some(outbound.clone())),
            outbound: Some(outbound),
            ..Default::default()
        }
    }

    /// Create a reject route result.
    /// 创建拒绝路由结果。
    #[must_use]
    pub fn reject() -> Self {
        Self::new(Decision::Reject)
    }

    /// Set the matched rule index.
    /// 设置匹配规则索引。
    #[must_use]
    pub fn with_matched_rule(mut self, index: usize) -> Self {
        self.matched_rule = Some(index);
        self
    }

    /// Set resolved IPs.
    /// 设置解析的 IP。
    #[must_use]
    pub fn with_resolved_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.resolved_ips = ips;
        self
    }

    /// Set sniffed protocol.
    /// 设置嗅探的协议。
    #[must_use]
    pub fn with_sniffed(mut self, protocol: String, domain: Option<String>) -> Self {
        self.sniffed_protocol = Some(protocol);
        self.sniffed_domain = domain;
        self
    }
}

/// Connection Router interface (Go parity: route.Router).
///
/// Provides async routing for TCP streams and UDP packets.
/// 提供 TCP 流和 UDP 包的异步路由。
#[async_trait]
pub trait ConnectionRouter: Send + Sync {
    /// Route a TCP connection based on the routing context.
    /// 根据路由上下文路由 TCP 连接。
    ///
    /// This is called when a new TCP connection is accepted.
    /// 当接受新 TCP 连接时调用。
    async fn route_connection<'a>(&self, ctx: &RouteCtx<'a>) -> RouteResult;

    /// Route a UDP packet based on the routing context.
    /// 根据路由上下文路由 UDP 包。
    ///
    /// This is called for each UDP packet or association.
    /// 为每个 UDP 包或关联调用。
    async fn route_packet<'a>(&self, ctx: &RouteCtx<'a>) -> RouteResult;

    /// Pre-match hook for connection acceptance checks.
    /// 连接接受检查的预匹配钩子。
    ///
    /// Returns `true` if the connection should proceed to full routing.
    /// 如果连接应继续进行完整路由，则返回 `true`。
    fn pre_match(&self, ctx: &RouteCtx<'_>) -> bool {
        // Default: accept all connections
        let _ = ctx;
        true
    }
}

/// A no-op connection router that always returns Direct.
/// 始终返回 Direct 的无操作连接路由器。
#[derive(Debug, Clone, Default)]
pub struct DirectRouter;

#[async_trait]
impl ConnectionRouter for DirectRouter {
    async fn route_connection<'a>(&self, _ctx: &RouteCtx<'a>) -> RouteResult {
        RouteResult::direct()
    }

    async fn route_packet<'a>(&self, _ctx: &RouteCtx<'a>) -> RouteResult {
        RouteResult::direct()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_result_builders() {
        let direct = RouteResult::direct();
        assert_eq!(direct.decision, Decision::Direct);
        assert!(direct.outbound.is_none());

        let proxy = RouteResult::proxy("my-proxy");
        assert_eq!(
            proxy.decision,
            Decision::Proxy(Some("my-proxy".to_string()))
        );
        assert_eq!(proxy.outbound.as_deref(), Some("my-proxy"));

        let reject = RouteResult::reject();
        assert_eq!(reject.decision, Decision::Reject);
    }

    #[test]
    fn test_route_result_with_rule() {
        let result = RouteResult::direct().with_matched_rule(5);
        assert_eq!(result.matched_rule, Some(5));
    }

    #[test]
    fn test_route_result_with_sniffed() {
        let result = RouteResult::proxy("tls-out")
            .with_sniffed("tls".to_string(), Some("example.com".to_string()));
        assert_eq!(result.sniffed_protocol.as_deref(), Some("tls"));
        assert_eq!(result.sniffed_domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn test_direct_router() {
        let router = DirectRouter;
        let ctx = RouteCtx::default();
        let result = router.route_connection(&ctx).await;
        assert_eq!(result.decision, Decision::Direct);
    }
}
