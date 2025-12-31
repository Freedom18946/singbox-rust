//! DNS Router Interface (Go parity: adapter.DNSRouter)
//!
//! Provides Go-style DNS routing interface for integration with the adapter layer.
//! DNS 路由接口（Go 对齐：adapter.DNSRouter）
//!
//! 为适配器层集成提供 Go 风格的 DNS 路由接口。

use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;

use super::DnsAnswer;

/// DNS query context for routing decisions.
/// DNS 查询上下文，用于路由决策。
#[derive(Debug, Clone, Default)]
pub struct DnsQueryContext {
    /// Source inbound tag (if available).
    /// 源入站标签（如果可用）。
    pub inbound: Option<String>,
    /// Client address.
    /// 客户端地址。
    pub client: Option<std::net::SocketAddr>,
    /// Transport protocol.
    /// 传输协议。
    pub transport: Option<String>,
    /// Whether this is a FakeIP query.
    /// 是否为 FakeIP 查询。
    pub fakeip: bool,
}

impl DnsQueryContext {
    /// Create a new empty context.
    /// 创建一个新的空上下文。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the inbound tag.
    /// 设置入站标签。
    #[must_use]
    pub fn with_inbound(mut self, inbound: impl Into<String>) -> Self {
        self.inbound = Some(inbound.into());
        self
    }

    /// Set the client address.
    /// 设置客户端地址。
    #[must_use]
    pub fn with_client(mut self, client: std::net::SocketAddr) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the transport protocol.
    /// 设置传输协议。
    #[must_use]
    pub fn with_transport(mut self, transport: impl Into<String>) -> Self {
        self.transport = Some(transport.into());
        self
    }

    /// Mark as FakeIP query.
    /// 标记为 FakeIP 查询。
    #[must_use]
    pub fn with_fakeip(mut self, fakeip: bool) -> Self {
        self.fakeip = fakeip;
        self
    }
}

/// DNS Router interface (Go parity: adapter.DNSRouter).
/// DNS 路由接口（Go 对齐：adapter.DNSRouter）。
///
/// Provides DNS routing capabilities including:
/// - Query exchange with upstream servers
/// - Domain lookup with routing rules
/// - Cache management
///
/// 提供 DNS 路由功能，包括：
/// - 与上游服务器交换查询
/// - 带路由规则的域名查找
/// - 缓存管理
#[async_trait]
pub trait DnsRouter: Send + Sync {
    /// Exchange a DNS message with the appropriate upstream.
    /// 与适当的上游交换 DNS 消息。
    ///
    /// This is the low-level interface that takes raw DNS wire-format messages.
    /// 这是接收原始 DNS 线格式消息的低级接口。
    async fn exchange(
        &self,
        ctx: &DnsQueryContext,
        message: &[u8],
    ) -> Result<Vec<u8>>;

    /// Lookup IP addresses for a domain using routing rules.
    /// 使用路由规则查找域名的 IP 地址。
    ///
    /// The context provides routing hints (inbound, client, transport).
    /// 上下文提供路由提示（入站、客户端、传输）。
    async fn lookup(&self, ctx: &DnsQueryContext, domain: &str) -> Result<Vec<IpAddr>>;

    /// Lookup IP addresses using the default transport.
    /// 使用默认传输查找 IP 地址。
    ///
    /// This bypasses routing rules and uses the default upstream.
    /// 这绑过路由规则并使用默认上游。
    async fn lookup_default(&self, domain: &str) -> Result<Vec<IpAddr>>;

    /// Resolve a domain to a full DNS answer.
    /// 将域名解析为完整的 DNS 答案。
    async fn resolve(&self, ctx: &DnsQueryContext, domain: &str) -> Result<DnsAnswer>;

    /// Clear the DNS cache.
    /// 清除 DNS 缓存。
    fn clear_cache(&self);

    /// Get router name for logging.
    /// 获取路由名称用于日志记录。
    fn name(&self) -> &str {
        "dns_router"
    }
}

/// A no-op DNS router that always fails (for testing/placeholder).
/// 一个始终失败的无操作 DNS 路由（用于测试/占位）。
#[derive(Debug, Clone, Default)]
pub struct NullDnsRouter;

#[async_trait]
impl DnsRouter for NullDnsRouter {
    async fn exchange(
        &self,
        _ctx: &DnsQueryContext,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("NullDnsRouter: exchange not supported"))
    }

    async fn lookup(&self, _ctx: &DnsQueryContext, _domain: &str) -> Result<Vec<IpAddr>> {
        Err(anyhow::anyhow!("NullDnsRouter: lookup not supported"))
    }

    async fn lookup_default(&self, _domain: &str) -> Result<Vec<IpAddr>> {
        Err(anyhow::anyhow!("NullDnsRouter: lookup_default not supported"))
    }

    async fn resolve(&self, _ctx: &DnsQueryContext, _domain: &str) -> Result<DnsAnswer> {
        Err(anyhow::anyhow!("NullDnsRouter: resolve not supported"))
    }

    fn clear_cache(&self) {
        // No-op
    }

    fn name(&self) -> &str {
        "null"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_context_builder() {
        let ctx = DnsQueryContext::new()
            .with_inbound("http-in")
            .with_transport("tcp")
            .with_fakeip(true);

        assert_eq!(ctx.inbound.as_deref(), Some("http-in"));
        assert_eq!(ctx.transport.as_deref(), Some("tcp"));
        assert!(ctx.fakeip);
        assert!(ctx.client.is_none());
    }

    #[tokio::test]
    async fn test_null_router_fails() {
        let router = NullDnsRouter;
        let ctx = DnsQueryContext::new();

        assert!(router.exchange(&ctx, &[]).await.is_err());
        assert!(router.lookup(&ctx, "example.com").await.is_err());
        assert!(router.lookup_default("example.com").await.is_err());
        assert!(router.resolve(&ctx, "example.com").await.is_err());
    }
}
