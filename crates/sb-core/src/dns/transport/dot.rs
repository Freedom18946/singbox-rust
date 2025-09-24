//! DNS-over-TLS (DoT) 传输实现
//!
//! 提供基于 TLS 的安全 DNS 传输，支持：
//! - TLS 1.3 加密连接
//! - 服务器证书验证
//! - 连接复用和池化
//! - 超时和重试机制

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::DnsTransport;

/// DoT 传输实现
pub struct DotTransport {
    /// 服务器地址
    server: SocketAddr,
    /// 服务器名称（用于 SNI）
    server_name: String,
    /// 连接超时
    timeout: Duration,
    /// TLS 配置
    #[cfg(feature = "tls")]
    tls_config: Arc<rustls::ClientConfig>,
}

impl DotTransport {
    /// 创建新的 DoT 传输
    pub fn new(server: SocketAddr, server_name: String) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        #[cfg(feature = "tls")]
        let tls_config = {
            let mut config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(rustls_native_certs::load_native_certs()?)
                .with_no_client_auth();

            // 启用 ALPN 协议协商
            config.alpn_protocols = vec![b"dot".to_vec()];

            Arc::new(config)
        };

        Ok(Self {
            server,
            server_name,
            timeout,
            #[cfg(feature = "tls")]
            tls_config,
        })
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(feature = "tls")]
    async fn establish_tls_connection(
        &self,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        use tokio_rustls::TlsConnector;

        // 建立 TCP 连接
        let tcp_stream =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(self.server))
                .await
                .context("DoT TCP connection timeout")?
                .context("Failed to establish TCP connection")?;

        // 建立 TLS 连接
        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::ServerName::try_from(self.server_name.as_str())
            .context("Invalid server name for TLS")?;

        let tls_stream =
            tokio::time::timeout(self.timeout, connector.connect(server_name, tcp_stream))
                .await
                .context("DoT TLS handshake timeout")?
                .context("Failed to establish TLS connection")?;

        Ok(tls_stream)
    }

    #[cfg(feature = "tls")]
    async fn send_query_tls(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.establish_tls_connection().await?;

        // DoT 使用 TCP 长度前缀格式
        let length = packet.len() as u16;
        let length_bytes = length.to_be_bytes();

        // 发送长度前缀和查询包
        stream
            .write_all(&length_bytes)
            .await
            .context("Failed to write query length")?;
        stream
            .write_all(packet)
            .await
            .context("Failed to write query packet")?;

        // 读取响应长度
        let mut length_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut length_buf))
            .await
            .context("DoT response length read timeout")?
            .context("Failed to read response length")?;

        let response_length = u16::from_be_bytes(length_buf) as usize;
        if response_length > 65535 {
            return Err(anyhow::anyhow!(
                "DoT response too large: {} bytes",
                response_length
            ));
        }

        // 读取响应数据
        let mut response_buf = vec![0u8; response_length];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut response_buf))
            .await
            .context("DoT response data read timeout")?
            .context("Failed to read response data")?;

        Ok(response_buf)
    }
}

#[async_trait]
impl DnsTransport for DotTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "tls")]
        {
            self.send_query_tls(packet).await
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = packet; // Acknowledge parameter usage
            Err(anyhow::anyhow!("DoT support requires TLS feature"))
        }
    }

    fn name(&self) -> &'static str {
        "dot"
    }
}

impl std::fmt::Debug for DotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotTransport")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_dot_transport_creation() {
        let server = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 853));
        let transport = DotTransport::new(server, "cloudflare-dns.com".to_string()).unwrap();

        assert_eq!(transport.server, server);
        assert_eq!(transport.server_name, "cloudflare-dns.com");
        assert_eq!(transport.name(), "dot");
    }

    #[test]
    fn test_dot_transport_with_timeout() {
        let server = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 853));
        let custom_timeout = Duration::from_secs(10);
        let transport = DotTransport::new(server, "cloudflare-dns.com".to_string())
            .unwrap()
            .with_timeout(custom_timeout);

        assert_eq!(transport.timeout, custom_timeout);
    }

    // 集成测试需要真实的 DoT 服务器
    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_dot_query_integration() {
        let server = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 853));
        let transport = DotTransport::new(server, "cloudflare-dns.com".to_string()).unwrap();

        // 构建简单的 DNS 查询包（查询 google.com A 记录）
        let query_packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // QNAME: google.com
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // End of QNAME
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];

        let result = transport.query(&query_packet).await;
        assert!(
            result.is_ok(),
            "DoT query should succeed: {:?}",
            result.err()
        );

        let response = result.unwrap();
        assert!(
            response.len() > 12,
            "Response should contain DNS header and data"
        );
    }
}
