//! DNS-over-TCP 传输实现
//!
//! 提供基于 TCP 的 DNS 传输，支持：
//! - RFC 1035 标准 DNS-over-TCP 格式（2字节长度前缀）
//! - 连接超时和重试机制
//! - 适用于大查询包或需要可靠传输的场景

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::DnsTransport;

/// TCP DNS 传输实现
pub struct TcpTransport {
    /// DNS 服务器地址
    server: SocketAddr,
    /// 连接超时
    timeout: Duration,
}

impl TcpTransport {
    /// 创建新的 TCP DNS 传输
    pub fn new(server: SocketAddr) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_TCP_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        Self { server, timeout }
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 建立 TCP 连接
    async fn connect(&self) -> Result<TcpStream> {
        tokio::time::timeout(self.timeout, TcpStream::connect(self.server))
            .await
            .context("TCP DNS connection timeout")?
            .context("Failed to connect to DNS server")
    }

    /// 发送 DNS 查询并接收响应
    async fn send_query(&self, stream: &mut TcpStream, packet: &[u8]) -> Result<Vec<u8>> {
        // TCP DNS 使用 2 字节长度前缀（big-endian）
        let length = packet.len() as u16;
        if length == 0 {
            return Err(anyhow::anyhow!("Empty DNS query packet"));
        }

        let length_bytes = length.to_be_bytes();

        // 发送长度前缀和查询包
        tokio::time::timeout(
            self.timeout,
            async {
                stream.write_all(&length_bytes).await?;
                stream.write_all(packet).await?;
                stream.flush().await?;
                Ok::<(), std::io::Error>(())
            },
        )
        .await
        .context("TCP DNS write timeout")?
        .context("Failed to write DNS query")?;

        // 读取响应长度（2字节）
        let mut length_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut length_buf))
            .await
            .context("TCP DNS response length read timeout")?
            .context("Failed to read response length")?;

        let response_length = u16::from_be_bytes(length_buf) as usize;
        if response_length == 0 {
            return Err(anyhow::anyhow!("DNS server returned zero-length response"));
        }
        if response_length > 65535 {
            return Err(anyhow::anyhow!(
                "DNS response too large: {} bytes",
                response_length
            ));
        }

        // 读取响应数据
        let mut response_buf = vec![0u8; response_length];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut response_buf))
            .await
            .context("TCP DNS response data read timeout")?
            .context("Failed to read response data")?;

        Ok(response_buf)
    }
}

#[async_trait]
impl DnsTransport for TcpTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "metrics")]
        let start_time = std::time::Instant::now();

        // 建立连接
        let mut stream = self.connect().await?;

        // 发送查询并接收响应
        let result = self.send_query(&mut stream, packet).await;

        // 记录查询延迟
        #[cfg(feature = "metrics")]
        {
            let latency_ms = start_time.elapsed().as_millis() as f64;
            metrics::histogram!("dns_tcp_query_duration_ms").record(latency_ms);

            match &result {
                Ok(_) => {
                    metrics::counter!("dns_tcp_query_total", "result" => "success").increment(1);
                }
                Err(_) => {
                    metrics::counter!("dns_tcp_query_total", "result" => "error").increment(1);
                }
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "tcp"
    }
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("server", &self.server)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_tcp_transport_creation() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let transport = TcpTransport::new(server);

        assert_eq!(transport.server, server);
        assert_eq!(transport.name(), "tcp");
    }

    #[test]
    fn test_tcp_transport_with_timeout() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let custom_timeout = Duration::from_secs(10);
        let transport = TcpTransport::new(server).with_timeout(custom_timeout);

        assert_eq!(transport.timeout, custom_timeout);
    }

    // 集成测试需要真实的 DNS 服务器
    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_tcp_query_integration() {
        // Google Public DNS 支持 TCP
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let transport = TcpTransport::new(server);

        // 构建简单的 DNS 查询包（查询 google.com A 记录）
        let query_packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
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
            "TCP DNS query should succeed: {:?}",
            result.err()
        );

        let response = result.unwrap();
        assert!(
            response.len() > 12,
            "Response should contain DNS header and data"
        );

        // 验证响应标识与查询匹配
        assert_eq!(response[0..2], query_packet[0..2], "Transaction ID mismatch");
    }

    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_tcp_large_query() {
        // TCP DNS 适用于大查询包（UDP 限制为 512 字节）
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let transport = TcpTransport::new(server);

        // 构建较大的 DNS 查询（多个问题）
        let mut query_packet = vec![
            0xab, 0xcd, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x02, // Questions: 2
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];

        // 第一个问题: google.com
        query_packet.extend_from_slice(&[
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
            0x00, 0x01,
        ]);

        // 第二个问题: example.com
        query_packet.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);

        let result = transport.query(&query_packet).await;
        assert!(
            result.is_ok(),
            "TCP DNS large query should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_tcp_invalid_server() {
        // 使用无效的服务器地址测试超时
        let server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53)); // TEST-NET-1, should be unreachable
        let transport = TcpTransport::new(server).with_timeout(Duration::from_millis(100));

        let query_packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g',
            b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let result = transport.query(&query_packet).await;
        assert!(
            result.is_err(),
            "Query to invalid server should fail with timeout"
        );
    }
}
