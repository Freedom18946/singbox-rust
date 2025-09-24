//! DNS 传输抽象与实现
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait DnsTransport: Send + Sync {
    /// 发送 DNS 报文（wire-format），返回应答（wire-format）
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>>;
    /// 传输名（用于日志/诊断）
    fn name(&self) -> &'static str;
}

pub mod enhanced_udp;
mod udp;

#[cfg(feature = "dns_doh")]
pub mod doh;
#[cfg(feature = "dns_dot")]
pub mod dot;

pub use enhanced_udp::EnhancedUdpTransport;
pub use udp::{UdpTransport, UdpUpstream};

#[cfg(feature = "dns_doh")]
pub use doh::{DohConfig, DohServers, DohTransport};
#[cfg(feature = "dns_dot")]
pub use dot::DotTransport;

// Client type aliases for compatibility
#[cfg(feature = "dns_doh")]
pub type DohClient = DohTransport;
#[cfg(feature = "dns_dot")]
pub type DotClient = DotTransport;

// Placeholder for DHCP resolver - needs implementation
pub struct DhcpResolver;

impl DhcpResolver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl super::Resolver for DhcpResolver {
    async fn resolve(&self, _domain: &str) -> Result<super::DnsAnswer> {
        use std::time::Duration;
        // Placeholder implementation
        anyhow::bail!("DHCP DNS resolver not implemented yet")
    }

    fn name(&self) -> &str {
        "dhcp"
    }
}
