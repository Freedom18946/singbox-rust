//! Outbound adapters module.
//! sb-adapters 的"出站适配器"模块。
//!
//! Contains outbound connector implementations for various protocols, including:
//! 包含各种协议的出站连接器实现，包括：
//! - Direct and Block (直连和阻断)
//! - HTTP Proxy Connector (HTTP 代理连接器)
//! - SOCKS5 Proxy Connector (SOCKS5 代理连接器)
//! - Shadowsocks Connector (Shadowsocks 连接器)
//! - VMess Protocol Connector (VMess 协议连接器)
//! - VLESS Protocol Connector (VLESS 协议连接器)
//! - TUIC Protocol Connector (TUIC 协议连接器)

pub mod prelude {
    //! Common imports for all adapter implementations
    //! 所有适配器实现的通用导入
    pub use crate::error::{AdapterError, Result};
    pub use crate::traits::{BoxedStream, DialOpts, OutboundConnector, Target, TransportKind};
    pub use async_trait::async_trait;
    pub use std::fmt::Debug;
    pub use std::time::Duration;
}

/// Block outbound adapter - rejects all connection attempts
/// 阻断出站适配器 - 拒绝所有连接尝试
pub mod block;
/// Direct outbound adapter - connects directly to target
/// 直连出站适配器 - 直接连接到目标
pub mod direct;

// Helper functions for tracing
// 用于追踪的辅助函数
#[allow(dead_code)]
pub(crate) fn span_dial(adapter: &'static str, target: &crate::traits::Target) -> tracing::Span {
    tracing::info_span!("dial",
        adapter = adapter,
        dest = %format!("{}:{}", target.host, target.port),
        kind = ?target.kind
    )
}

// Feature-gated adapter modules
// 特性门控的适配器模块
#[cfg(feature = "adapter-anytls")]
pub mod anytls;
#[cfg(feature = "adapter-dns")]
pub mod dns;
#[cfg(feature = "adapter-http")]
pub mod http;
#[cfg(feature = "adapter-hysteria")]
pub mod hysteria;
#[cfg(feature = "adapter-hysteria2")]
pub mod hysteria2;
#[cfg(feature = "adapter-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "adapter-shadowsocks")]
pub mod shadowsocksr;
#[cfg(feature = "adapter-shadowtls")]
pub mod shadowtls;
#[cfg(feature = "adapter-socks")]
pub mod socks4;
#[cfg(feature = "adapter-socks")]
pub mod socks5;
#[cfg(feature = "adapter-ssh")]
pub mod ssh;
#[cfg(feature = "adapter-tailscale")]
pub mod tailscale;
#[cfg(feature = "adapter-tor")]
pub mod tor;
#[cfg(feature = "adapter-trojan")]
pub mod trojan;
#[cfg(feature = "tuic")]
pub mod tuic;
#[cfg(feature = "adapter-vless")]
pub mod vless;
#[cfg(feature = "adapter-vmess")]
pub mod vmess;
#[cfg(feature = "adapter-wireguard-outbound")]
pub mod wireguard;
// Selector group adapters (always available since they're core functionality)
// 选择器组适配器（始终可用，因为它们是核心功能）
pub mod selector;
pub mod urltest;

// Re-export traits for easy access
// 重导出 trait 以便轻松访问
pub use crate::traits::*;

// IR to adapter construction bridges
// IR 到适配器构造的桥接
#[cfg(feature = "adapter-http")]
impl TryFrom<&sb_config::ir::OutboundIR> for http::HttpProxyConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Http {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected HTTP outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "HTTP proxy server address required",
            ))?;
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
            tls: None,
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
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected SOCKS outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SOCKS5 proxy server address required",
            ))?;
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
            tls: None,
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-socks")]
impl TryFrom<&sb_config::ir::OutboundIR> for socks4::Socks4Connector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Socks {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected SOCKS4 outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SOCKS4 proxy server address required",
            ))?;
        let port = ir.port.unwrap_or(1080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::Socks4Config {
            server: server_addr,
            tag: ir.name.clone(),
            user_id: ir.credentials.as_ref().and_then(|c| c.username.clone()),
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

#[cfg(feature = "adapter-shadowsocks")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowsocksr::ShadowsocksROutbound {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::ShadowsocksR {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected ShadowsocksR outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "ShadowsocksR requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(0);
        let method = ir.method.clone().unwrap_or_default();
        let password = ir.password.clone().unwrap_or_default();
        let obfs = ir.obfs.clone().unwrap_or_default();
        let protocol = ir.protocol.clone().unwrap_or_default();

        let config = shadowsocksr::ShadowsocksROutboundConfig {
            server,
            port,
            method,
            password,
            obfs,
            obfs_param: ir.obfs_param.clone(),
            protocol,
            protocol_param: ir.protocol_param.clone(),
        };

        Self::new(config).map_err(|e| crate::error::AdapterError::Other(e.to_string()))
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

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Hysteria2 {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected hysteria2 outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "hysteria2 requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(443);
        let password = ir
            .password
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "hysteria2 requires password",
            ))?
            .clone();

        let cfg = crate::outbound::hysteria2::Hysteria2AdapterConfig {
            server,
            port,
            password,
            skip_cert_verify: false,
            sni: ir.tls_sni.clone(),
            alpn: ir.tls_alpn.clone(),
            congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            salamander: None,
        };

        Ok(Self::new(cfg))
    }
}

// ShadowTLS outbound: IR mapping is not available yet because OutboundType
// does not include `shadowtls` in sb-config IR. Adapter can still be used
// programmatically.

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

#[cfg(feature = "adapter-shadowtls")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowtls::ShadowTlsConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Shadowtls {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected shadowtls outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "shadowtls requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(443);
        let cfg = crate::outbound::shadowtls::ShadowTlsAdapterConfig {
            server,
            port,
            sni: ir
                .tls_sni
                .clone()
                .unwrap_or_else(|| "example.com".to_string()),
            alpn: ir.tls_alpn.as_ref().map(|v| v.join(",")),
            skip_cert_verify: false,
            utls_fingerprint: ir.utls_fingerprint.clone(),
        };
        Ok(Self::new(cfg))
    }
}

#[cfg(feature = "adapter-ssh")]
impl TryFrom<&sb_config::ir::OutboundIR> for ssh::SshConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Ssh {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected ssh outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SSH requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(22);
        let username = ir
            .credentials
            .as_ref()
            .and_then(|c| c.username.clone())
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SSH requires username",
            ))?;

        let cfg = crate::outbound::ssh::SshAdapterConfig {
            server,
            port,
            username,
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            private_key: ir.ssh_private_key.clone(),
            private_key_passphrase: ir.ssh_private_key_passphrase.clone(),
            host_key_verification: ir.ssh_host_key_verification.unwrap_or(true),
            known_hosts_path: ir.ssh_known_hosts_path.clone(),
            connection_pool_size: ir.ssh_connection_pool_size,
            compression: ir.ssh_compression.unwrap_or(false),
            keepalive_interval: ir.ssh_keepalive_interval,
            connect_timeout: ir.connect_timeout_sec.map(|s| s as u64),
        };

        Ok(Self::new(cfg))
    }
}
