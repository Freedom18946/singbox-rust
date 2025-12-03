//! DNS 传输抽象与实现
//! DNS Transport Abstraction and Implementations
//!
//! This module provides the core trait and implementations for DNS transports
//! (UDP, TCP, DoH, DoT, DoQ, etc.) with Go-parity lifecycle management.
//! 本模块提供 DNS 传输的核心 trait 和实现（UDP、TCP、DoH、DoT、DoQ 等），
//! 具有与 Go 对等的生命周期管理。

use anyhow::Result;
use async_trait::async_trait;

/// Lifecycle stages for DNS transport initialization.
/// DNS 传输初始化的生命周期阶段。
///
/// Mirrors Go's `adapter.StartStage` for DNS transports.
/// 镜像 Go 的 `adapter.StartStage` 用于 DNS 传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsStartStage {
    /// Initialize resources (pre-start).
    /// 初始化资源（启动前）。
    Initialize,
    /// Start the transport (main startup).
    /// 启动传输（主启动阶段）。
    Start,
    /// Post-start configuration.
    /// 启动后配置。
    PostStart,
}

/// DNS transport error classification (Go-parity).
/// DNS 传输错误分类（Go 对等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransportError {
    /// Network I/O error.
    /// 网络 I/O 错误。
    Network,
    /// Connection timeout.
    /// 连接超时。
    Timeout,
    /// Protocol error (malformed response, etc.).
    /// 协议错误（响应格式错误等）。
    Protocol,
    /// Transport closed.
    /// 传输已关闭。
    Closed,
    /// Other/unknown error.
    /// 其他/未知错误。
    Other,
}

impl DnsTransportError {
    /// Classify an error into a transport error category.
    /// 将错误分类为传输错误类别。
    pub fn classify(err: &anyhow::Error) -> Self {
        let err_str = err.to_string().to_lowercase();
        if err_str.contains("timeout") || err_str.contains("timed out") {
            Self::Timeout
        } else if err_str.contains("closed") || err_str.contains("eof") {
            Self::Closed
        } else if err_str.contains("protocol")
            || err_str.contains("invalid")
            || err_str.contains("malformed")
        {
            Self::Protocol
        } else if err_str.contains("connection")
            || err_str.contains("network")
            || err_str.contains("io")
        {
            Self::Network
        } else {
            Self::Other
        }
    }
}

#[async_trait]
pub trait DnsTransport: Send + Sync {
    /// 发送 DNS 报文（wire-format），返回应答（wire-format）
    /// Send a DNS packet (wire-format), return the response (wire-format).
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>>;

    /// 传输名（用于日志/诊断）
    /// Transport name (for logging/diagnostics).
    fn name(&self) -> &'static str;

    /// Start the transport at a specific lifecycle stage.
    /// 在特定的生命周期阶段启动传输。
    ///
    /// Default implementation does nothing (backward compatible).
    /// 默认实现不执行任何操作（向后兼容）。
    async fn start(&self, _stage: DnsStartStage) -> Result<()> {
        Ok(())
    }

    /// Close and clean up the transport.
    /// 关闭并清理传输。
    ///
    /// Default implementation does nothing (backward compatible).
    /// 默认实现不执行任何操作（向后兼容）。
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

pub mod enhanced_udp;
pub mod local;
pub mod tcp;
mod udp;

#[cfg(feature = "dns_doh")]
pub mod doh;
#[cfg(feature = "dns_doh3")]
pub mod doh3;
#[cfg(feature = "dns_doq")]
pub mod doq;
#[cfg(feature = "dns_dot")]
pub mod dot;

pub use enhanced_udp::EnhancedUdpTransport;
pub use local::LocalTransport;
pub use tcp::TcpTransport;
pub use udp::{DefaultUdpDialer, UdpDialer, UdpTransport, UdpUpstream};

#[cfg(feature = "dns_doh")]
pub use doh::{DohConfig, DohServers, DohTransport};
#[cfg(feature = "dns_doh3")]
pub use doh3::Doh3Transport;
#[cfg(feature = "dns_doq")]
pub use doq::DoqTransport;
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
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DhcpResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::Resolver for DhcpResolver {
    async fn resolve(&self, _domain: &str) -> Result<super::DnsAnswer> {
        // Placeholder implementation
        anyhow::bail!("DHCP DNS resolver not implemented yet")
    }

    fn name(&self) -> &'static str {
        "dhcp"
    }
}
