//! VMess outbound connector implementation
//! VMess 出站连接器实现
//!
//! This module provides VMess protocol support for outbound connections.
//! 本模块提供 VMess 协议的出站连接支持。
//! VMess is a stateful protocol used by V2Ray with strong encryption and obfuscation.
//! VMess 是 V2Ray 使用的一种有状态协议，具有强大的加密和混淆功能。

use crate::outbound::prelude::*;
use crate::transport_config::TransportConfig;
use crate::vmess::{
    client_connect, command_key, SECURITY_AES128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
};
use std::collections::HashMap;
use uuid::Uuid;

/// VMess security levels
/// VMess 安全级别
#[derive(Debug, Clone, PartialEq)]
pub enum Security {
    /// No encryption (not recommended for production)
    /// 无加密 (不建议用于生产环境)
    None,
    /// AES-128-GCM
    Aes128Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Auto selection based on client capabilities
    /// 根据客户端能力自动选择
    Auto,
    /// Zero encryption (legacy)
    /// 零加密 (旧版)
    Zero,
}

impl Security {
    #[allow(dead_code)]
    fn as_str(&self) -> &str {
        match self {
            Security::None => "none",
            Security::Aes128Gcm => "aes-128-gcm",
            Security::ChaCha20Poly1305 => "chacha20-poly1305",
            Security::Auto => "auto",
            Security::Zero => "zero",
        }
    }
}

/// VMess authentication settings
/// VMess 认证设置
#[derive(Debug, Clone)]
pub struct VmessAuth {
    /// User UUID
    /// 用户 UUID
    pub uuid: Uuid,
    /// Alter ID for additional security (0-65535)
    /// Alter ID 用于额外的安全性 (0-65535)
    pub alter_id: u16,
    /// Security level
    /// 安全级别
    pub security: Security,
    /// Additional authentication data
    /// 额外的认证数据
    pub additional_data: Option<Vec<u8>>,
}

/// VMess transport settings
/// VMess 传输设置
#[derive(Debug, Clone)]
pub struct VmessTransport {
    /// Enable TCP fast open
    /// 启用 TCP 快速打开
    pub tcp_fast_open: bool,
    /// Enable TCP no delay
    /// 启用 TCP 无延迟
    pub tcp_no_delay: bool,
    /// Connection keep alive interval
    /// 连接保持活跃间隔
    pub keep_alive: Option<std::time::Duration>,
    /// Socket mark (Linux only)
    /// Socket 标记 (仅限 Linux)
    pub socket_mark: Option<u32>,
}

impl Default for VmessTransport {
    fn default() -> Self {
        Self {
            tcp_fast_open: false,
            tcp_no_delay: true,
            keep_alive: Some(std::time::Duration::from_secs(30)),
            socket_mark: None,
        }
    }
}

/// VMess configuration
/// VMess 配置
#[derive(Debug, Clone)]
pub struct VmessConfig {
    /// Optional configured outbound tag.
    pub tag: Option<String>,
    /// Server host
    /// 服务端主机
    pub server: String,
    /// Server port
    /// 服务端端口
    pub port: u16,
    /// Authentication settings
    /// 认证设置
    pub auth: VmessAuth,
    /// Transport settings (TCP-level options)
    /// 传输设置 (TCP 级选项)
    pub transport: VmessTransport,
    /// Transport layer (TCP/WebSocket/gRPC/HTTPUpgrade)
    /// 传输层 (TCP/WebSocket/gRPC/HTTPUpgrade)
    pub transport_layer: TransportConfig,
    /// Connection timeout
    /// 连接超时
    pub timeout: Option<std::time::Duration>,
    /// Enable packet encoding
    /// 启用数据包编码
    pub packet_encoding: bool,
    /// Custom headers for obfuscation
    /// 用于混淆的自定义头
    pub headers: HashMap<String, String>,
    /// Multiplex configuration
    /// 多路复用配置
    #[cfg(feature = "transport_mux")]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
    /// TLS configuration (experimental, requires working TLS transport layer)
    /// TLS 配置 (实验性，需要工作的 TLS 传输层)
    #[cfg(feature = "transport_tls")]
    pub tls: Option<sb_transport::TlsConfig>,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            tag: None,
            server: "127.0.0.1".to_string(),
            port: 443,
            auth: VmessAuth {
                uuid: Uuid::new_v4(),
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            transport_layer: TransportConfig::default(),
            timeout: Some(std::time::Duration::from_secs(30)),
            packet_encoding: false,
            headers: HashMap::new(),
            #[cfg(feature = "transport_mux")]
            multiplex: None,
            #[cfg(feature = "transport_tls")]
            tls: None,
        }
    }
}

/// VMess outbound connector
/// VMess 出站连接器
#[derive(Clone)]
pub struct VmessConnector {
    config: VmessConfig,
    /// Cached authentication data
    /// 缓存的认证数据
    #[allow(dead_code)]
    auth_cache: Option<Vec<u8>>,
    /// Transport dialer with optional TLS and Multiplex layers
    /// 带有可选 TLS 和多路复用层的传输拨号器
    #[cfg(feature = "sb-transport")]
    dialer: Option<std::sync::Arc<dyn sb_transport::Dialer>>,
}

impl std::fmt::Debug for VmessConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessConnector")
            .field("config", &self.config)
            .field("auth_cache", &self.auth_cache)
            .field("dialer", &"<dialer>")
            .finish()
    }
}

impl VmessConnector {
    pub const fn name(&self) -> &'static str {
        "vmess"
    }

    /// Create a new VMess connector with the given configuration
    /// 使用给定的配置创建一个新的 VMess 连接器
    pub fn new(config: VmessConfig) -> Self {
        // Create dialer with transport layer, TLS, and multiplex layers
        // 创建带有传输层、TLS 和多路复用层的拨号器
        #[cfg(feature = "sb-transport")]
        let dialer = {
            #[cfg(feature = "transport_tls")]
            let tls_config = config.tls.as_ref();
            #[cfg(not(feature = "transport_tls"))]
            let tls_config = None;

            #[cfg(feature = "transport_mux")]
            let multiplex_config = config.multiplex.as_ref();
            #[cfg(not(feature = "transport_mux"))]
            let multiplex_config = None;

            Some(
                config
                    .transport_layer
                    .create_dialer_with_layers(tls_config, multiplex_config),
            )
        };

        Self {
            config,
            auth_cache: None,
            #[cfg(feature = "sb-transport")]
            dialer,
        }
    }

    /// Resolve the effective VMess body security byte (wire constant).
    ///
    /// Go sing-box rewrites `auto` to `zero` when TLS is enabled. Without TLS,
    /// amd64/arm64 select AES-128-GCM. Explicit `none` and `zero` share Go's
    /// TCP SECURITY_NONE wire mode.
    fn security_byte(&self) -> Result<u8> {
        #[cfg(feature = "transport_tls")]
        let tls_enabled = self.config.tls.is_some();
        #[cfg(not(feature = "transport_tls"))]
        let tls_enabled = false;

        match self.config.auth.security {
            Security::Auto if tls_enabled => Ok(SECURITY_NONE),
            Security::Auto | Security::Aes128Gcm => Ok(SECURITY_AES128_GCM),
            Security::ChaCha20Poly1305 => Ok(SECURITY_CHACHA20_POLY1305),
            Security::None | Security::Zero => Ok(SECURITY_NONE),
        }
    }

    /// Create connection to VMess server
    /// 创建到 VMess 服务端的连接
    async fn create_connection(&self) -> Result<BoxedStream> {
        let timeout = self
            .config
            .timeout
            .unwrap_or(std::time::Duration::from_secs(30));

        #[cfg(feature = "sb-transport")]
        {
            // Use the configured dialer (which already has Transport → TLS → Multiplex layers)
            // 使用配置的拨号器 (已经包含 传输 → TLS → 多路复用 层)
            if let Some(ref dialer) = self.dialer {
                tracing::debug!(
                    "Using transport dialer for VMess connection (transport: {:?})",
                    self.config.transport_layer.transport_type()
                );

                let stream = tokio::time::timeout(
                    timeout,
                    dialer.connect(&self.config.server, self.config.port),
                )
                .await
                .map_err(|_| AdapterError::Timeout(timeout))?
                .map_err(|e| AdapterError::Other(format!("Transport dial failed: {}", e)))?;

                return Ok(crate::traits::from_transport_stream(stream));
            }
        }

        // Fallback to direct TCP connection (for backward compatibility or when sb-transport feature is disabled)
        // 回退到直接 TCP 连接 (为了向后兼容或当 sb-transport 特性被禁用时)
        tracing::debug!("Using direct TCP connection for VMess");
        let tcp_stream = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port)),
        )
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;

        // Configure transport options
        if self.config.transport.tcp_no_delay {
            if let Err(e) = tcp_stream.set_nodelay(true) {
                tracing::warn!("Failed to set TCP_NODELAY: {}", e);
            }
        }

        Ok(Box::new(tcp_stream))
    }

    /// Validate configuration
    /// 验证配置
    fn validate_config(&self) -> Result<()> {
        // Go-equivalence: sing-vmess's `vmess.NewClient` accepts any well-formed UUID including
        // `uuid.Nil` (all-zeros) — the UUID only derives the auth key, and a nil UUID is rejected
        // by the server, not client-side. Fast-failing nil here would diverge from Go.
        // alter_id is u16, so it's always <= 65535 — validation passes automatically.
        Ok(())
    }
}

impl Default for VmessConnector {
    fn default() -> Self {
        Self::new(VmessConfig::default())
    }
}

impl VmessConnector {
    pub async fn dial(&self, session: &Session) -> Result<BoxedStream> {
        let target = &session.target;
        tracing::debug!("VMess dialing target: {:?}", target);

        self.validate_config()?;

        let security = self.security_byte()?;
        let cmd_key = command_key(self.config.auth.uuid.as_bytes());
        let host = target.host();
        let port = target.port();

        // Create connection to VMess server (transport/TLS/mux layers already applied)
        let inner = self.create_connection().await?;

        // Perform the canonical VMess handshake and return the body stream.
        let stream = client_connect(inner, cmd_key, security, &host, port)
            .await
            .map_err(|e| AdapterError::Other(format!("VMess handshake failed: {e}")))?;

        tracing::debug!("VMess connection established to: {:?}", target);

        Ok(Box::new(stream))
    }
}

crate::impl_canonical_outbound!(
    VmessConnector,
    "vmess",
    |this: &VmessConnector| this
        .config
        .tag
        .clone()
        .unwrap_or_else(|| "vmess".to_string()),
    crate::outbound::TCP
);

#[cfg(test)]
mod tests {
    use super::*;

    fn connector(security: Security, tls: bool) -> VmessConnector {
        let mut config = VmessConfig::default();
        config.auth.security = security;
        #[cfg(feature = "transport_tls")]
        if tls {
            config.tls = Some(sb_transport::TlsConfig::Standard(
                sb_transport::StandardTlsConfig {
                    insecure: true,
                    ..Default::default()
                },
            ));
        }
        #[cfg(not(feature = "transport_tls"))]
        assert!(!tls, "TLS feature required by this test");
        VmessConnector::new(config)
    }

    #[test]
    fn plain_auto_keeps_aes_body_security() {
        assert_eq!(
            connector(Security::Auto, false).security_byte().unwrap(),
            SECURITY_AES128_GCM
        );
    }

    #[cfg(feature = "transport_tls")]
    #[test]
    fn tls_auto_uses_go_zero_body_security() {
        assert_eq!(
            connector(Security::Auto, true).security_byte().unwrap(),
            SECURITY_NONE
        );
    }

    #[test]
    fn explicit_security_modes_are_preserved() {
        assert_eq!(
            connector(Security::Aes128Gcm, false)
                .security_byte()
                .unwrap(),
            SECURITY_AES128_GCM
        );
        assert_eq!(
            connector(Security::ChaCha20Poly1305, false)
                .security_byte()
                .unwrap(),
            SECURITY_CHACHA20_POLY1305
        );
        assert_eq!(
            connector(Security::Zero, false).security_byte().unwrap(),
            SECURITY_NONE
        );
        assert_eq!(
            connector(Security::None, false).security_byte().unwrap(),
            SECURITY_NONE
        );
    }
}
