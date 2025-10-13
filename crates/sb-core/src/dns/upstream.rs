//! DNS 上游服务器实现
//!
//! 提供各种 DNS 传输协议的上游实现：
//! - UDP 上游
//! - DNS-over-TLS (DoT) 上游
//! - DNS-over-HTTPS (DoH) 上游
//! - 系统解析器上游

use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, time::Duration};

use super::{DnsAnswer, DnsUpstream, RecordType};

/// UDP DNS 上游实现
pub struct UdpUpstream {
    /// 上游服务器地址
    server: SocketAddr,
    /// 查询超时时间
    timeout: Duration,
    /// 重试次数
    retries: usize,
    /// 上游名称
    name: String,
}

impl UdpUpstream {
    /// 创建新的 UDP 上游
    pub fn new(server: SocketAddr) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_UDP_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2000),
        );

        let retries = std::env::var("SB_DNS_UDP_RETRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);

        Self {
            server,
            timeout,
            retries,
            name: format!("udp://{}", server),
        }
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置重试次数
    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// 执行单次 UDP DNS 查询
    async fn query_once(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // 构建 DNS 查询包
        let query_packet = self.build_query_packet(domain, record_type)?;

        // 创建 UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server).await?;

        // 发送查询
        socket.send(&query_packet).await?;

        // 接收响应
        let mut response_buf = vec![0u8; 512];
        let response_len = timeout(self.timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS query timeout"))?
            .map_err(|e| anyhow::anyhow!("Failed to receive DNS response: {}", e))?;

        response_buf.truncate(response_len);

        // 解析响应
        self.parse_response(&response_buf, record_type)
    }

    /// 构建 DNS 查询包
    fn build_query_packet(&self, domain: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // DNS Header (12 bytes)
        let transaction_id_val: u16 =
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_nanos() as u16,
                Err(_) => 0,
            };
        let transaction_id = transaction_id_val.to_be_bytes();

        packet.extend_from_slice(&transaction_id); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query, recursion desired
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section
        // QNAME: domain name in label format
        for label in domain.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(anyhow::anyhow!("Invalid domain label: {}", label));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // QTYPE and QCLASS
        packet.extend_from_slice(&record_type.as_u16().to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN class

        Ok(packet)
    }

    /// 解析 DNS 响应包
    fn parse_response(&self, packet: &[u8], expected_type: RecordType) -> Result<DnsAnswer> {
        if packet.len() < 12 {
            return Err(anyhow::anyhow!("DNS response too short"));
        }

        // 解析 header
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
        if answer_count == 0 {
            return Err(anyhow::anyhow!("No answers in DNS response"));
        }

        // 跳过 question section
        let mut offset = 12;
        offset = self.skip_question_section(packet, offset)?;

        // 解析 answer section
        let mut ips = Vec::new();
        let mut min_ttl: Option<u32> = None;

        for _ in 0..answer_count {
            let (ip_opt, ttl, new_offset) =
                self.parse_answer_record(packet, offset, expected_type)?;
            offset = new_offset;

            if let Some(ip) = ip_opt {
                ips.push(ip);
                min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
            }
        }

        if ips.is_empty() {
            return Err(anyhow::anyhow!("No valid IP addresses in DNS response"));
        }

        Ok(DnsAnswer::new(
            ips,
            Duration::from_secs(min_ttl.unwrap_or(300) as u64),
            super::cache::Source::Upstream,
            super::cache::Rcode::NoError,
        ))
    }

    /// 跳过 question section
    fn skip_question_section(&self, packet: &[u8], mut offset: usize) -> Result<usize> {
        // 跳过 QNAME
        while offset < packet.len() {
            let label_len = packet[offset] as usize;
            offset += 1;

            if label_len == 0 {
                break; // End of QNAME
            }

            if (label_len & 0xC0) == 0xC0 {
                // Compression pointer
                offset += 1;
                break;
            }

            offset += label_len;
        }

        // 跳过 QTYPE 和 QCLASS
        offset += 4;

        Ok(offset)
    }

    /// 解析单个 answer record
    fn parse_answer_record(
        &self,
        packet: &[u8],
        mut offset: usize,
        expected_type: RecordType,
    ) -> Result<(Option<std::net::IpAddr>, u32, usize)> {
        // 跳过 NAME (可能是压缩指针)
        if offset >= packet.len() {
            return Err(anyhow::anyhow!("Unexpected end of packet"));
        }

        if (packet[offset] & 0xC0) == 0xC0 {
            // Compression pointer
            offset += 2;
        } else {
            // Full name
            while offset < packet.len() {
                let label_len = packet[offset] as usize;
                offset += 1;
                if label_len == 0 {
                    break;
                }
                offset += label_len;
            }
        }

        if offset + 10 > packet.len() {
            return Err(anyhow::anyhow!("Insufficient data for answer record"));
        }

        // 解析 TYPE, CLASS, TTL, RDLENGTH
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let _class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > packet.len() {
            return Err(anyhow::anyhow!("Insufficient data for RDATA"));
        }

        let rdata = &packet[offset..offset + rdlength];
        offset += rdlength;

        // 解析 IP 地址，只处理期望的记录类型
        let ip = match (rtype, expected_type) {
            (1, RecordType::A) if rdlength == 4 => {
                // A record
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )))
            }
            (28, RecordType::AAAA) if rdlength == 16 => {
                // AAAA record
                let mut addr = [0u8; 16];
                addr.copy_from_slice(rdata);
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
            }
            _ => None, // 其他记录类型忽略
        };

        Ok((ip, ttl, offset))
    }
}

#[async_trait]
impl DnsUpstream for UdpUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let mut last_error = None;

        for attempt in 0..=self.retries {
            match self.query_once(domain, record_type).await {
                Ok(answer) => {
                    tracing::debug!(
                        "UDP DNS query successful: server={}, domain={}, attempt={}",
                        self.server,
                        domain,
                        attempt
                    );
                    return Ok(answer);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.retries {
                        tracing::debug!(
                            "UDP DNS query failed, retrying: server={}, domain={}, attempt={}, error={}",
                            self.server,
                            domain,
                            attempt,
                            // Log the latest error without risking panic on None
                            last_error.as_ref().map(|err| err.to_string()).unwrap_or_else(|| "unknown".to_string())
                        );
                        // 短暂延迟后重试
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        match last_error {
            Some(err) => Err(err),
            None => Err(anyhow::anyhow!("All UDP DNS queries failed")),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        // 简单的健康检查：尝试查询一个已知域名
        matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                self.query_once("dns.google", RecordType::A),
            )
            .await,
            Ok(Ok(_))
        )
    }
}

/// DNS-over-TLS (DoT) 上游实现
pub struct DotUpstream {
    server: SocketAddr,
    server_name: String,
    timeout: Duration,
    name: String,
}

impl DotUpstream {
    /// 创建新的 DoT 上游
    pub fn new(server: SocketAddr, server_name: String) -> Self {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        Self {
            server,
            server_name: server_name.clone(),
            timeout,
            name: format!("dot://{}@{}", server_name, server),
        }
    }
}

#[async_trait]
impl DnsUpstream for DotUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let _ = (&self.server, &self.server_name, &self.timeout);
        // DoT 实现需要 TLS 支持，这里提供基础框架
        // 实际实现需要使用 rustls 或其他 TLS 库
        #[cfg(feature = "dns_dot")]
        {
            self.query_dot(domain, record_type).await
        }
        #[cfg(not(feature = "dns_dot"))]
        {
            let _ = (domain, record_type);
            Err(anyhow::anyhow!("DoT support requires dns_dot feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_dot")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_dot"))]
        {
            false
        }
    }
}

#[cfg(feature = "dns_dot")]
impl DotUpstream {
    async fn query_dot(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        // Create TLS configuration
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        // Connect to DoT server
        let tcp_stream = TcpStream::connect(self.server).await?;
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // Build DNS query packet
        let query_id = fastrand::u16(..);
        let query_packet = self.build_dns_query(query_id, domain, record_type)?;

        // Send query with length prefix (DoT uses TCP-style length-prefixed messages)
        let length = query_packet.len() as u16;
        let mut full_packet = Vec::with_capacity(2 + query_packet.len());
        full_packet.extend_from_slice(&length.to_be_bytes());
        full_packet.extend_from_slice(&query_packet);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls_stream.write_all(&full_packet).await?;

        // Read response length
        let mut length_buf = [0u8; 2];
        tls_stream.read_exact(&mut length_buf).await?;
        let response_length = u16::from_be_bytes(length_buf) as usize;

        // Read response data
        let mut response_buf = vec![0u8; response_length];
        tls_stream.read_exact(&mut response_buf).await?;

        // Parse DNS response
        self.parse_dns_response(&response_buf, query_id)
    }

    fn build_dns_query(&self, id: u16, domain: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let qtype = match record_type {
            RecordType::A => 1u16,
            RecordType::AAAA => 28u16,
            RecordType::CNAME => 5u16,
            RecordType::MX => 15u16,
            RecordType::TXT => 16u16,
        };

        let id_bytes = id.to_be_bytes();
        let mut packet = vec![
            id_bytes[0],
            id_bytes[1], // ID
            0x01,
            0x00, // RD=1, standard query
            0x00,
            0x01, // QDCOUNT=1
            0x00,
            0x00, // ANCOUNT=0
            0x00,
            0x00, // NSCOUNT=0
            0x00,
            0x00, // ARCOUNT=0
        ];

        // Build QNAME
        for label in domain.trim_end_matches('.').split('.') {
            let label_bytes = label.as_bytes();
            if label_bytes.is_empty() || label_bytes.len() > 63 {
                return Err(anyhow::anyhow!("Invalid domain label: {}", label));
            }
            packet.push(label_bytes.len() as u8);
            packet.extend_from_slice(label_bytes);
        }
        packet.push(0); // Root label terminator

        // QTYPE and QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN class

        Ok(packet)
    }

    fn parse_dns_response(&self, response: &[u8], expected_id: u16) -> Result<DnsAnswer> {
        if response.len() < 12 {
            return Err(anyhow::anyhow!("DNS response too short"));
        }

        // Check response ID
        let response_id = u16::from_be_bytes([response[0], response[1]]);
        if response_id != expected_id {
            return Err(anyhow::anyhow!("DNS response ID mismatch"));
        }

        // Check response flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        if (flags & 0x8000) == 0 {
            return Err(anyhow::anyhow!("Not a DNS response"));
        }

        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(anyhow::anyhow!("DNS server returned error code: {}", rcode));
        }

        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);

        let mut offset = 12;

        // Skip questions
        for _ in 0..qdcount {
            offset = self.skip_name(response, offset)?;
            offset += 4; // QTYPE + QCLASS
        }

        // Parse answers
        let mut ips = Vec::new();
        for _ in 0..ancount {
            offset = self.skip_name(response, offset)?;

            if offset + 10 > response.len() {
                break;
            }

            let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]);
            offset += 10;

            if offset + rdlength as usize > response.len() {
                break;
            }

            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = std::net::Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    );
                    ips.push(std::net::IpAddr::V4(ip));
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let mut ipv6_bytes = [0u8; 16];
                    ipv6_bytes.copy_from_slice(&response[offset..offset + 16]);
                    let ip = std::net::Ipv6Addr::from(ipv6_bytes);
                    ips.push(std::net::IpAddr::V6(ip));
                }
                _ => {}
            }

            offset += rdlength as usize;
        }

        Ok(DnsAnswer::new(
            ips,
            Duration::from_secs(300), // Default 5 minutes TTL
            crate::dns::cache::Source::Upstream,
            crate::dns::cache::Rcode::NoError,
        ))
    }

    fn skip_name(&self, data: &[u8], mut offset: usize) -> Result<usize> {
        loop {
            if offset >= data.len() {
                return Err(anyhow::anyhow!("Invalid name compression"));
            }

            let len = data[offset];
            if len == 0 {
                return Ok(offset + 1);
            }

            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                return Ok(offset + 2);
            }

            offset += 1 + len as usize;
        }
    }
}

/// DNS-over-HTTPS (DoH) 上游实现
pub struct DohUpstream {
    url: String,
    timeout: Duration,
    name: String,
    #[cfg(feature = "dns_doh")]
    client: std::sync::Arc<reqwest::Client>,
}

impl DohUpstream {
    /// 创建新的 DoH 上游
    pub fn new(url: String) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        #[cfg(feature = "dns_doh")]
        let client = {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;
            std::sync::Arc::new(client)
        };

        Ok(Self {
            url: url.clone(),
            timeout,
            name: format!("doh://{}", url),
            #[cfg(feature = "dns_doh")]
            client,
        })
    }
}

#[async_trait]
impl DnsUpstream for DohUpstream {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let _ = (&self.url, &self.timeout);
        #[cfg(feature = "dns_doh")]
        {
            self.query_doh(domain, record_type).await
        }
        #[cfg(not(feature = "dns_doh"))]
        {
            let _ = (domain, record_type);
            Err(anyhow::anyhow!("DoH support requires dns_doh feature"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "dns_doh")]
        {
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.query("dns.google", RecordType::A),
                )
                .await,
                Ok(Ok(_))
            )
        }
        #[cfg(not(feature = "dns_doh"))]
        {
            false
        }
    }
}

#[cfg(feature = "dns_doh")]
impl DohUpstream {
    async fn query_doh(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        // 构建 DNS 查询包
        let temp_upstream = {
            let addr = "0.0.0.0:53"
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid DoH bind address: {}", e))?;
            UdpUpstream::new(addr)
        };
        let query_packet = temp_upstream.build_query_packet(domain, record_type)?;

        // 发送 DoH 请求
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_packet)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("DoH request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH request failed with status: {}",
                response.status()
            ));
        }

        let response_body = response
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read DoH response: {}", e))?;

        // 解析响应
        temp_upstream.parse_response(&response_body, record_type)
    }
}

/// 系统解析器上游实现
pub struct SystemUpstream {
    default_ttl: Duration,
    name: String,
}

impl SystemUpstream {
    /// 创建新的系统解析器上游
    pub fn new() -> Self {
        let default_ttl = Duration::from_secs(
            std::env::var("SB_DNS_SYSTEM_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
        );

        Self {
            default_ttl,
            name: "system".to_string(),
        }
    }
}

impl Default for SystemUpstream {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsUpstream for SystemUpstream {
    async fn query(&self, domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
        // 使用系统解析器
        let addrs: Vec<std::net::IpAddr> = tokio::net::lookup_host((domain, 0))
            .await
            .map_err(|e| anyhow::anyhow!("System DNS resolution failed: {}", e))?
            .map(|addr| addr.ip())
            .collect();

        if addrs.is_empty() {
            return Err(anyhow::anyhow!(
                "No addresses resolved for domain: {}",
                domain
            ));
        }

        Ok(DnsAnswer::new(
            addrs,
            self.default_ttl,
            super::cache::Source::Upstream,
            super::cache::Rcode::NoError,
        ))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        // 系统解析器通常总是可用的
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_udp_upstream_creation() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        assert_eq!(upstream.name(), "udp://8.8.8.8:53");
        assert_eq!(upstream.server, server);
    }

    #[tokio::test]
    async fn test_system_upstream() {
        let upstream = SystemUpstream::new();
        assert_eq!(upstream.name(), "system");

        // 系统解析器应该总是健康的
        assert!(upstream.health_check().await);
    }

    #[test]
    fn test_query_packet_building() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        let packet = upstream
            .build_query_packet("example.com", RecordType::A)
            .unwrap();

        // 验证包的基本结构
        assert!(packet.len() > 12); // 至少包含 header
        assert_eq!(packet[4], 0x00); // QDCOUNT high byte
        assert_eq!(packet[5], 0x01); // QDCOUNT low byte (1 question)
    }
}
