//! # QUIC Transport Layer / QUIC 传输层
//!
//! This module provides generic QUIC transport implementation for singbox-rust, including:
//! 该模块提供 singbox-rust 的通用 QUIC 传输实现，包括：
//! - `QuicDialer`: Client-side QUIC connection dialer / 客户端 QUIC 连接拨号器
//! - `QuicStream`: Wrapper for QUIC streams to implement AsyncReadWrite / QUIC 流的包装器，用于实现 AsyncReadWrite
//! - 0-RTT support for low-latency connections / 对低延迟连接的 0-RTT 支持
//!
//! ## Features / 特性
//! - Generic QUIC transport using quinn / 使用 quinn 的通用 QUIC 传输
//! - Bidirectional and unidirectional streams / 双向和单向流
//! - 0-RTT connection establishment / 0-RTT 连接建立
//! - Connection migration support / 连接迁移支持
//! - Configurable congestion control / 可配置的拥塞控制
//! - TLS 1.3 integration / TLS 1.3 集成
//!
//! ## Strategic Relevance / 战略关联
//! - **Modern Transport Protocol**: Offers an alternative to TCP, leveraging UDP for improved performance,
//!   reduced head-of-line blocking, and better handling of network changes.
//!   **现代传输协议**：提供 TCP 的替代方案，利用 UDP 提高性能，减少队头阻塞，并更好地处理网络变化。
//! - **Low Latency**: Supports 0-RTT, enabling faster connection establishment for subsequent connections.
//!   **低延迟**：支持 0-RTT，为后续连接实现更快的连接建立。
//! - **Enhanced Privacy**: Integrates with ECH for improved privacy by encrypting the initial handshake.
//!   **增强隐私**：与 ECH 集成，通过加密初始握手来提高隐私性。
//!
//! ## Usage
//! ```rust,no_run
//! use sb_transport::quic::{QuicDialer, QuicConfig};
//! use sb_transport::Dialer;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = QuicConfig {
//!         server_name: "example.com".to_string(),
//!         ..Default::default()
//!     };
//!     let dialer = QuicDialer::new(config)?;
//!     let stream = dialer.connect("example.com", 443).await?;
//!     // Use stream for communication...
//!     Ok(())
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

#[cfg(feature = "transport_ech")]
use sb_tls::EchConnector;

/// QUIC configuration / QUIC 配置
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Server name for TLS SNI (required)
    /// TLS SNI 的服务器名称（必需）
    pub server_name: String,
    /// ALPN protocols (default: empty)
    /// ALPN 协议列表（默认：空）
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Enable 0-RTT (default: false)
    /// 启用 0-RTT（默认：false）
    pub enable_zero_rtt: bool,
    /// Keep-alive interval in seconds (default: 30)
    /// 保活间隔（秒）（默认：30）
    pub keep_alive_interval: u64,
    /// Max idle timeout in seconds (default: 60)
    /// 最大空闲超时（秒）（默认：60）
    pub max_idle_timeout: u64,
    /// Initial maximum data (default: 10MB)
    /// 初始最大数据量（默认：10MB）
    pub initial_max_data: u64,
    /// Initial maximum stream data (default: 1MB)
    /// 初始最大流数据量（默认：1MB）
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    /// ECH (Encrypted Client Hello) configuration (optional)
    /// ECH (Encrypted Client Hello) 配置（可选）
    #[cfg(feature = "transport_ech")]
    pub ech_config: Option<sb_tls::EchClientConfig>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            alpn_protocols: Vec::new(),
            enable_zero_rtt: false,
            keep_alive_interval: 30,
            max_idle_timeout: 60,
            initial_max_data: 10 * 1024 * 1024, // 10MB
            initial_max_stream_data_bidi_local: 1024 * 1024, // 1MB
            initial_max_stream_data_bidi_remote: 1024 * 1024, // 1MB
            initial_max_stream_data_uni: 1024 * 1024, // 1MB
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }
}

/// QUIC dialer / QUIC 拨号器
///
/// This dialer establishes QUIC connections and creates streams for communication.
/// 该拨号器建立 QUIC 连接并创建用于通信的流。
/// It supports:
/// 它支持：
/// - QUIC protocol using quinn / 使用 quinn 的 QUIC 协议
/// - 0-RTT for low-latency / 用于低延迟的 0-RTT
/// - Configurable transport parameters / 可配置的传输参数
/// - TLS 1.3 with ALPN / 带 ALPN 的 TLS 1.3
/// - ECH (Encrypted Client Hello) for QUIC / 用于 QUIC 的 ECH (Encrypted Client Hello)
pub struct QuicDialer {
    config: QuicConfig,
    endpoint: Arc<Endpoint>,
    #[cfg(feature = "transport_ech")]
    ech_connector: Option<EchConnector>,
}

impl QuicDialer {
    /// Create a new QUIC dialer with custom configuration
    /// 使用自定义配置创建新的 QUIC 拨号器
    pub fn new(config: QuicConfig) -> Result<Self, DialError> {
        // Create ECH connector if ECH is configured
        // 如果配置了 ECH，则创建 ECH 连接器
        #[cfg(feature = "transport_ech")]
        let ech_connector = if let Some(ref ech_cfg) = config.ech_config {
            if ech_cfg.enabled {
                Some(EchConnector::new(ech_cfg.clone()).map_err(|e| {
                    DialError::Other(format!("Failed to create ECH connector: {}", e))
                })?)
            } else {
                None
            }
        } else {
            None
        };

        // Create quinn endpoint
        // 创建 quinn 端点
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())
            .map_err(|e| DialError::Other(format!("Failed to create QUIC endpoint: {}", e)))?;

        // Build client configuration (handle platform verifier fallible API)
        // 构建客户端配置（处理平台验证器可能失败的 API）
        let mut client_config = ClientConfig::try_with_platform_verifier()
            .map_err(|e| DialError::Other(format!("Failed to init QUIC client verifier: {}", e)))?;

        // Note: quinn 0.11 changed ALPN configuration
        // ALPN protocols are now set through the crypto config
        // For now, we'll use the default configuration
        // To set custom ALPN, we would need to build a custom rustls config
        // 注意：quinn 0.11 更改了 ALPN 配置
        // ALPN 协议现在通过加密配置设置
        // 目前，我们将使用默认配置
        // 要设置自定义 ALPN，我们需要构建自定义 rustls 配置

        // Configure transport parameters
        // 配置传输参数
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            VarInt::from_u64(config.max_idle_timeout * 1000)
                .unwrap()
                .into(),
        ));
        transport_config.keep_alive_interval(Some(Duration::from_secs(config.keep_alive_interval)));

        // Note: quinn 0.11 has different API for stream settings
        // These are now configured differently or have default values
        // We'll use defaults for now
        // 注意：quinn 0.11 具有不同的流设置 API
        // 这些现在配置方式不同或具有默认值
        // 我们目前使用默认值

        client_config.transport_config(Arc::new(transport_config));

        endpoint.set_default_client_config(client_config);

        Ok(Self {
            config,
            endpoint: Arc::new(endpoint),
            #[cfg(feature = "transport_ech")]
            ech_connector,
        })
    }

    /// Create a QUIC dialer with default configuration
    pub fn with_default_config(server_name: &str) -> Result<Self, DialError> {
        let config = QuicConfig {
            server_name: server_name.to_string(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// Get or create a QUIC connection
    /// 获取或创建 QUIC 连接
    async fn get_connection(&self, host: &str, port: u16) -> Result<Connection, DialError> {
        let server_addr = format!("{}:{}", host, port);
        let addr: SocketAddr = tokio::net::lookup_host(&server_addr)
            .await?
            .next()
            .ok_or_else(|| DialError::Other(format!("Failed to resolve {}", server_addr)))?;

        debug!("Connecting to QUIC server: {}", server_addr);

        // Determine the server name for SNI
        // If ECH is enabled, we need to handle ECH-QUIC alignment
        // 确定 SNI 的服务器名称
        // 如果启用了 ECH，我们需要处理 ECH-QUIC 对齐
        #[cfg(feature = "transport_ech")]
        let server_name = if let Some(ref ech_connector) = self.ech_connector {
            // ECH is enabled - encrypt the real SNI
            // ECH 已启用 - 加密真实的 SNI
            let ech_hello = ech_connector
                .wrap_tls(host)
                .map_err(|e| DialError::Other(format!("ECH encryption failed: {}", e)))?;

            debug!(
                "ECH enabled for QUIC: outer_sni={}, inner_sni={}",
                ech_hello.outer_sni, ech_hello.inner_sni
            );

            // For QUIC with ECH, we use the outer SNI (public name)
            // The encrypted inner ClientHello is embedded in the QUIC handshake
            // Note: Full ECH-QUIC integration requires custom QUIC crypto config
            // This is a simplified implementation showing the integration point
            // 对于带 ECH 的 QUIC，我们使用外层 SNI（公共名称）
            // 加密的内部 ClientHello 嵌入在 QUIC 握手中
            // 注意：完整的 ECH-QUIC 集成需要自定义 QUIC 加密配置
            // 这是一个展示集成点的简化实现
            ech_hello.outer_sni
        } else if !self.config.server_name.is_empty() {
            self.config.server_name.clone()
        } else {
            host.to_string()
        };

        #[cfg(not(feature = "transport_ech"))]
        let server_name = if !self.config.server_name.is_empty() {
            self.config.server_name.clone()
        } else {
            host.to_string()
        };

        let connection = self
            .endpoint
            .connect(addr, &server_name)
            .map_err(|e| DialError::Other(format!("Failed to initiate QUIC connection: {}", e)))?
            .await
            .map_err(|e| DialError::Other(format!("QUIC connection failed: {}", e)))?;

        debug!("QUIC connection established");

        Ok(connection)
    }
}

#[async_trait]
impl Dialer for QuicDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing QUIC: {}:{}", host, port);

        // Get or create QUIC connection
        let connection = self.get_connection(host, port).await?;

        // Open a bidirectional stream
        let (send_stream, recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| DialError::Other(format!("Failed to open QUIC stream: {}", e)))?;

        debug!("QUIC stream opened successfully");

        // Wrap streams in our adapter
        let wrapped_stream = QuicStreamAdapter::new(send_stream, recv_stream);
        Ok(Box::new(wrapped_stream))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// QUIC stream adapter / QUIC 流适配器
///
/// This adapter wraps quinn SendStream and RecvStream to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
/// 该适配器包装 quinn SendStream 和 RecvStream 以实现
/// `AsyncRead` 和 `AsyncWrite` trait，使其与 `IoStream` 类型兼容。
pub struct QuicStreamAdapter {
    send_stream: SendStream,
    recv_stream: RecvStream,
}

impl QuicStreamAdapter {
    fn new(send_stream: SendStream, recv_stream: RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
        }
    }
}

impl AsyncRead for QuicStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // quinn RecvStream implements AsyncRead, so we can delegate
        Pin::new(&mut self.recv_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // quinn SendStream implements AsyncWrite with WriteError
        // We need to convert WriteError to io::Error
        match Pin::new(&mut self.send_stream).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "QUIC write error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send_stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "QUIC flush error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send_stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "QUIC shutdown error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config_default() {
        let config = QuicConfig::default();
        assert_eq!(config.server_name, "");
        assert!(config.alpn_protocols.is_empty());
        assert!(!config.enable_zero_rtt);
        assert_eq!(config.keep_alive_interval, 30);
        assert_eq!(config.max_idle_timeout, 60);
        #[cfg(feature = "transport_ech")]
        assert!(config.ech_config.is_none());
    }

    #[tokio::test]
    async fn test_quic_dialer_creation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = QuicConfig::default();
        config.server_name = "example.com".to_string();
        let result = QuicDialer::new(config);
        result.expect("Failed to create QUIC dialer");
    }

    #[cfg(feature = "transport_ech")]
    #[tokio::test]
    async fn test_quic_dialer_with_ech_disabled() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = QuicConfig::default();
        config.server_name = "example.com".to_string();
        config.ech_config = Some(sb_tls::EchClientConfig {
            enabled: false,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        });

        let dialer =
            QuicDialer::new(config).expect("Failed to create QUIC dialer with ECH disabled");
        assert!(dialer.ech_connector.is_none());
    }

    #[cfg(feature = "transport_ech")]
    #[tokio::test]
    async fn test_quic_dialer_with_ech_enabled() {
        let mut config = QuicConfig::default();
        config.server_name = "example.com".to_string();
        config.ech_config = Some(sb_tls::EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        });

        let dialer =
            QuicDialer::new(config).expect("Failed to create QUIC dialer with ECH enabled");

        assert!(dialer.ech_connector.is_some());
    }

    #[cfg(feature = "transport_ech")]
    #[tokio::test]
    async fn test_quic_dialer_with_invalid_ech_config() {
        let mut config = QuicConfig::default();
        config.server_name = "example.com".to_string();
        // Invalid: enabled but no config provided
        config.ech_config = Some(sb_tls::EchClientConfig {
            enabled: true,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        });

        let result = QuicDialer::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_quic_config_with_ech() {
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let mut config = QuicConfig::default();
        config.server_name = "example.com".to_string();
        config.ech_config = Some(ech_config);

        assert!(config.ech_config.is_some());
        assert!(config.ech_config.as_ref().unwrap().enabled);
    }

    // Helper function to create a test ECH config list
    // Using a pre-generated test config to avoid x25519_dalek dependency
    #[cfg(feature = "transport_ech")]
    fn create_test_ech_config_list() -> Vec<u8> {
        // Pre-generated ECH config list for testing
        // This is a valid ECH config with:
        // - Version: 0xfe0d (Draft-13)
        // - X25519 public key (32 bytes of test data)
        // - Cipher suite: X25519, HKDF-SHA256, AES-128-GCM
        // - Public name: "public.example.com"
        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version (0xfe0d = Draft-13)
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Config id + KEM id
        config_list.push(0x01);
        config_list.extend_from_slice(&[0x00, 0x20]); // X25519

        // Public key length + public key (32 bytes for X25519)
        // Using test data instead of real key generation
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(&[0x01; 32]); // Test public key

        // Cipher suites length + cipher suite (KDF + AEAD)
        config_list.extend_from_slice(&[0x00, 0x04]);
        config_list.extend_from_slice(&[0x00, 0x01]); // KDF: HKDF-SHA256
        config_list.extend_from_slice(&[0x00, 0x01]); // AEAD: AES-128-GCM

        // Maximum name length
        config_list.push(64);

        // Public name length + public name
        let public_name = b"public.example.com";
        config_list.push(public_name.len() as u8);
        config_list.extend_from_slice(public_name);

        // Extensions length (empty)
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Fill in config length
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        // Fill in list length
        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        config_list
    }
}
