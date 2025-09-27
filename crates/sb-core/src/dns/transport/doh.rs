//! DNS-over-HTTPS (DoH) 传输实现
//!
//! 提供基于 HTTPS 的安全 DNS 传输，支持：
//! - HTTP/2 和 HTTP/1.1
//! - RFC 8484 标准格式
//! - 连接复用和池化
//! - 超时和重试机制

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::DnsTransport;

/// DoH 传输实现
pub struct DohTransport {
    /// DoH 服务器 URL
    url: String,
    /// HTTP 客户端
    client: Arc<reqwest::Client>,
    /// 请求超时
    timeout: Duration,
}

impl DohTransport {
    /// 创建新的 DoH 传输
    pub fn new(url: String) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        // 创建 HTTP 客户端
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .tcp_keepalive(Duration::from_secs(60))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .user_agent("singbox-rust/1.0")
            .build()
            .context("Failed to create HTTP client for DoH")?;

        Ok(Self {
            url,
            client: Arc::new(client),
            timeout,
        })
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 使用 POST 方法发送 DoH 查询
    async fn query_post(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .header("Cache-Control", "no-cache")
            .body(packet.to_vec())
            .send()
            .await
            .context("DoH POST request failed")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH server returned error status: {} {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            ));
        }

        // 验证响应内容类型
        if let Some(content_type) = response.headers().get("content-type") {
            if !content_type
                .to_str()
                .unwrap_or("")
                .starts_with("application/dns-message")
            {
                return Err(anyhow::anyhow!(
                    "DoH server returned unexpected content type: {:?}",
                    content_type
                ));
            }
        }

        let response_body = response
            .bytes()
            .await
            .context("Failed to read DoH response body")?;

        Ok(response_body.to_vec())
    }

    /// 使用 GET 方法发送 DoH 查询（base64url 编码）
    async fn query_get(&self, packet: &[u8]) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let encoded_query = URL_SAFE_NO_PAD.encode(packet);
        let url = format!("{}?dns={}", self.url, encoded_query);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .header("Cache-Control", "no-cache")
            .send()
            .await
            .context("DoH GET request failed")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH server returned error status: {} {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            ));
        }

        let response_body = response
            .bytes()
            .await
            .context("Failed to read DoH response body")?;

        Ok(response_body.to_vec())
    }

    /// 选择最佳的查询方法
    async fn query_adaptive(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // 对于小查询包，优先使用 GET 方法（更好的缓存性能）
        // 对于大查询包，使用 POST 方法（避免 URL 长度限制）
        const GET_THRESHOLD: usize = 256;

        if packet.len() <= GET_THRESHOLD {
            // 先尝试 GET，失败则回退到 POST
            match self.query_get(packet).await {
                Ok(response) => Ok(response),
                Err(get_error) => {
                    tracing::debug!("DoH GET failed, falling back to POST: {}", get_error);
                    self.query_post(packet).await
                }
            }
        } else {
            // 直接使用 POST
            self.query_post(packet).await
        }
    }
}

#[async_trait]
impl DnsTransport for DohTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();

        let result = self.query_adaptive(packet).await;

        // 记录查询延迟
        #[cfg(feature = "metrics")]
        {
            let latency_ms = start_time.elapsed().as_millis() as f64;
            metrics::histogram!("dns_doh_query_duration_ms").record(latency_ms);

            match &result {
                Ok(_) => {
                    metrics::counter!("dns_doh_query_total", "result" => "success").increment(1);
                }
                Err(_) => {
                    metrics::counter!("dns_doh_query_total", "result" => "error").increment(1);
                }
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "doh"
    }
}

impl std::fmt::Debug for DohTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohTransport")
            .field("url", &self.url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// DoH 服务器配置
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// 服务器 URL
    pub url: String,
    /// 超时时间
    pub timeout: Duration,
    /// 是否优先使用 GET 方法
    pub prefer_get: bool,
    /// 最大查询大小（超过此大小强制使用 POST）
    pub max_get_size: usize,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            url: "https://cloudflare-dns.com/dns-query".to_string(),
            timeout: Duration::from_secs(5),
            prefer_get: true,
            max_get_size: 256,
        }
    }
}

impl DohConfig {
    /// 从配置创建 DoH 传输
    pub fn build(self) -> Result<DohTransport> {
        Ok(DohTransport::new(self.url)?.with_timeout(self.timeout))
    }
}

/// 常用的 DoH 服务器配置
pub struct DohServers;

impl DohServers {
    /// Cloudflare DoH
    pub fn cloudflare() -> DohConfig {
        DohConfig {
            url: "https://cloudflare-dns.com/dns-query".to_string(),
            ..Default::default()
        }
    }

    /// Google DoH
    pub fn google() -> DohConfig {
        DohConfig {
            url: "https://dns.google/dns-query".to_string(),
            ..Default::default()
        }
    }

    /// Quad9 DoH
    pub fn quad9() -> DohConfig {
        DohConfig {
            url: "https://dns.quad9.net/dns-query".to_string(),
            ..Default::default()
        }
    }

    /// AdGuard DoH
    pub fn adguard() -> DohConfig {
        DohConfig {
            url: "https://dns.adguard.com/dns-query".to_string(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_transport_creation() {
        let url = "https://cloudflare-dns.com/dns-query".to_string();
        let transport = DohTransport::new(url.clone()).unwrap();

        assert_eq!(transport.url, url);
        assert_eq!(transport.name(), "doh");
    }

    #[test]
    fn test_doh_config() {
        let config = DohServers::cloudflare();
        assert_eq!(config.url, "https://cloudflare-dns.com/dns-query");
        assert!(config.prefer_get);
        assert_eq!(config.max_get_size, 256);
    }

    #[test]
    fn test_doh_servers() {
        let cloudflare = DohServers::cloudflare();
        let google = DohServers::google();
        let quad9 = DohServers::quad9();
        let adguard = DohServers::adguard();

        assert!(cloudflare.url.contains("cloudflare"));
        assert!(google.url.contains("google"));
        assert!(quad9.url.contains("quad9"));
        assert!(adguard.url.contains("adguard"));
    }

    // 集成测试需要网络连接
    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_doh_query_integration() {
        let transport =
            DohTransport::new("https://cloudflare-dns.com/dns-query".to_string()).unwrap();

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
            "DoH query should succeed: {:?}",
            result.err()
        );

        let response = result.unwrap();
        assert!(
            response.len() > 12,
            "Response should contain DNS header and data"
        );
    }

    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_doh_get_vs_post() {
        let transport =
            DohTransport::new("https://cloudflare-dns.com/dns-query".to_string()).unwrap();

        // 小查询包
        let small_query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g',
            b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        // 测试 GET 方法
        let get_result = transport.query_get(&small_query).await;
        assert!(get_result.is_ok(), "DoH GET should succeed");

        // 测试 POST 方法
        let post_result = transport.query_post(&small_query).await;
        assert!(post_result.is_ok(), "DoH POST should succeed");

        // 两种方法应该返回相同的结果
        let get_response = get_result.unwrap();
        let post_response = post_result.unwrap();

        // 响应应该包含相同的 DNS 数据（可能除了事务 ID）
        assert_eq!(get_response.len(), post_response.len());
    }
}
