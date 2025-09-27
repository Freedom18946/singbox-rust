//! sb-adapters 的"出站适配器"模块
//!
//! 包含各种协议的出站连接器实现，包括：
//! - 直连和阻断
//! - HTTP 代理连接器
//! - SOCKS5 代理连接器
//! - Shadowsocks 连接器
//! - VMess 协议连接器
//! - VLESS 协议连接器
//! - TUIC 协议连接器

pub mod prelude {
    //! Common imports for all adapter implementations
    pub use crate::error::{AdapterError, Result};
    pub use crate::traits::{OutboundConnector, Target, TransportKind, BoxedStream, DialOpts};
    pub use async_trait::async_trait;
    pub use std::fmt::Debug;
    pub use std::time::Duration;
}

pub mod block;
pub mod direct;

// Helper functions for tracing
#[allow(dead_code)]
pub(crate) fn span_dial(adapter: &'static str, target: &crate::traits::Target) -> tracing::Span {
    tracing::info_span!("dial",
        adapter = adapter,
        dest = %format!("{}:{}", target.host, target.port),
        kind = ?target.kind
    )
}

// Feature-gated adapter modules
#[cfg(feature = "adapter-http")]
pub mod http;
#[cfg(feature = "adapter-socks")]
pub mod socks5;
#[cfg(feature = "adapter-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "adapter-trojan")]
pub mod trojan;
#[cfg(feature = "adapter-vmess")]
pub mod vmess;
#[cfg(feature = "adapter-vless")]
pub mod vless;
#[cfg(feature = "adapter-hysteria2")]
pub mod hysteria2;
#[cfg(feature = "adapter-dns")]
pub mod dns;
#[cfg(feature = "tuic")]
pub mod tuic;

// Re-export traits for easy access
pub use crate::traits::*;

// IR to adapter construction bridges
#[cfg(feature = "adapter-http")]
impl TryFrom<&sb_config::ir::OutboundIR> for http::HttpProxyConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Http {
            return Err(crate::error::AdapterError::InvalidConfig("Expected HTTP outbound type"));
        }

        let server = ir.server.as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig("HTTP proxy server address required"))?;
        let port = ir.port.unwrap_or(8080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::HttpProxyConfig {
            server: server_addr,
            tag: ir.name.clone(),
            username: ir.credentials.as_ref().and_then(|c| c.username.clone()),
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            connect_timeout_sec: Some(30),
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-socks")]
impl TryFrom<&sb_config::ir::OutboundIR> for socks5::Socks5Connector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Socks {
            return Err(crate::error::AdapterError::InvalidConfig("Expected SOCKS outbound type"));
        }

        let server = ir.server.as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig("SOCKS5 proxy server address required"))?;
        let port = ir.port.unwrap_or(1080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::Socks5Config {
            server: server_addr,
            tag: ir.name.clone(),
            username: ir.credentials.as_ref().and_then(|c| c.username.clone()),
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            connect_timeout_sec: Some(30),
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowsocks::ShadowsocksConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "adapter-trojan")]
impl TryFrom<&sb_config::ir::OutboundIR> for trojan::TrojanConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "adapter-vmess")]
impl TryFrom<&sb_config::ir::OutboundIR> for vmess::VmessConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "adapter-vless")]
impl TryFrom<&sb_config::ir::OutboundIR> for vless::VlessConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "adapter-hysteria2")]
impl TryFrom<&sb_config::ir::OutboundIR> for hysteria2::Hysteria2Connector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "adapter-dns")]
impl TryFrom<&sb_config::ir::OutboundIR> for dns::DnsConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}

#[cfg(feature = "tuic")]
impl TryFrom<&sb_config::ir::OutboundIR> for tuic::TuicConnector {
    type Error = crate::error::AdapterError;

    fn try_from(_ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        // For now, create default connector - real implementation would parse IR
        Ok(Self::default())
    }
}
