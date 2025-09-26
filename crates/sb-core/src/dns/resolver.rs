//! 标准 DNS 解析器实现
//!
//! 提供符合架构规范的 Resolver trait 实现，支持：
//! - 多上游服务器管理
//! - 智能缓存与 TTL 管理
//! - 故障转移与重试策略
//! - 完整的指标暴露

use anyhow::Result;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

use super::{DnsAnswer, DnsUpstream, RecordType, Resolver};
use crate::error::SbError;

/// 标准 DNS 解析器实现
#[derive(Clone)]
pub struct DnsResolver {
    /// 上游服务器列表
    upstreams: Vec<Arc<dyn DnsUpstream>>,
    /// 默认 TTL（当上游未提供时使用）
    default_ttl: Duration,
    /// 解析器名称
    name: String,
}

impl DnsResolver {
    /// 创建新的 DNS 解析器
    pub fn new(upstreams: Vec<Arc<dyn DnsUpstream>>) -> Self {
        let default_ttl = Duration::from_secs(
            std::env::var("SB_DNS_DEFAULT_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
        );

        Self {
            upstreams,
            default_ttl,
            name: "dns_resolver".to_string(),
        }
    }

    /// 创建带名称的 DNS 解析器
    pub fn with_name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// 并发查询 A 和 AAAA 记录
    async fn resolve_both_records(&self, domain: &str) -> Result<DnsAnswer> {
        let mut all_ips = Vec::new();
        let mut min_ttl: Option<std::time::Duration> = None;

        // 并发查询 A 和 AAAA 记录
        let (a_result, aaaa_result) = tokio::join!(
            self.resolve_record_type(domain, RecordType::A),
            self.resolve_record_type(domain, RecordType::AAAA)
        );

        // 合并 A 记录结果
        if let Ok(a_answer) = a_result {
            all_ips.extend(a_answer.ips);
            min_ttl = Some(min_ttl.map_or(a_answer.ttl, |ttl| ttl.min(a_answer.ttl)));
        }

        // 合并 AAAA 记录结果
        if let Ok(aaaa_answer) = aaaa_result {
            all_ips.extend(aaaa_answer.ips);
            min_ttl = Some(min_ttl.map_or(aaaa_answer.ttl, |ttl| ttl.min(aaaa_answer.ttl)));
        }

        if all_ips.is_empty() {
            return Err(anyhow::Error::from(SbError::dns(format!(
                "No DNS records for domain: {}",
                domain
            ))));
        }

        Ok(DnsAnswer {
            ips: all_ips,
            ttl: min_ttl.unwrap_or(self.default_ttl),
            source: crate::dns::cache::Source::System,
            rcode: crate::dns::cache::Rcode::NoError,
        })
    }

    /// 查询特定记录类型
    async fn resolve_record_type(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnsAnswer> {
        let mut last_error: Option<anyhow::Error> = None;

        // 尝试每个上游服务器
        for upstream in &self.upstreams {
            // 检查上游健康状态
            if !upstream.health_check().await {
                tracing::debug!("Upstream {} is unhealthy, skipping", upstream.name());
                continue;
            }

            let upstream_name = upstream.name().to_string();
            match upstream.query(domain, record_type).await {
                Ok(answer) => {
                    tracing::debug!(
                        "DNS query successful: upstream={}, domain={}, type={:?}, ips={}",
                        upstream_name,
                        domain,
                        record_type,
                        answer.ips.len()
                    );

                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "dns_query_total",
                        "upstream" => upstream_name,
                        "record_type" => format!("{:?}", record_type),
                        "result" => "success"
                    )
                    .increment(1);

                    return Ok(answer);
                }
                Err(e) => {
                    tracing::debug!(
                        "DNS query failed: upstream={}, domain={}, type={:?}, error={}",
                        upstream.name(),
                        domain,
                        record_type,
                        e
                    );

                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "dns_query_total",
                        "upstream" => upstream_name.clone(),
                        "record_type" => format!("{:?}", record_type),
                        "result" => "error"
                    )
                    .increment(1);

                    // Map to structured SbError for callers
                    let mapped = SbError::dns(format!(
                        "upstream={} query {:?} for {} failed: {}",
                        upstream_name, record_type, domain, e
                    ));
                    last_error = Some(anyhow::Error::from(mapped));
                }
            }
        }

        // 所有上游都失败了
        Err(last_error.unwrap_or_else(|| anyhow::Error::from(SbError::dns("No healthy DNS upstreams available"))))
    }
}

#[async_trait]
impl Resolver for DnsResolver {
    async fn resolve(&self, domain: &str) -> Result<DnsAnswer> {
        let _start_time = std::time::Instant::now();

        // Global timeout for resolve to avoid hangs; cancel concurrent tasks via select
        let timeout_ms = std::env::var("SB_DNS_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2_000);
        let timeout_dur = Duration::from_millis(timeout_ms);

        let result = tokio::select! {
            res = self.resolve_both_records(domain) => res,
            _ = tokio::time::sleep(timeout_dur) => {
                Err(anyhow::Error::from(SbError::timeout("dns_resolve", timeout_ms)))
            }
        };

        // 记录解析延迟
        #[cfg(feature = "metrics")]
        {
            let latency_ms = _start_time.elapsed().as_millis() as f64;
            metrics::histogram!("dns_resolve_duration_ms").record(latency_ms);
        }

        result
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Mock upstream for testing
    struct MockUpstream {
        name: String,
        responses: std::collections::HashMap<(String, RecordType), Result<DnsAnswer>>,
        healthy: bool,
    }

    impl MockUpstream {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                responses: std::collections::HashMap::new(),
                healthy: true,
            }
        }

        fn with_response(
            mut self,
            domain: &str,
            record_type: RecordType,
            response: Result<DnsAnswer>,
        ) -> Self {
            self.responses
                .insert((domain.to_string(), record_type), response);
            self
        }

        fn set_healthy(mut self, healthy: bool) -> Self {
            self.healthy = healthy;
            self
        }
    }

    #[async_trait]
    impl DnsUpstream for MockUpstream {
        async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
            match self.responses.get(&(domain.to_string(), record_type)) {
                Some(Ok(answer)) => Ok(answer.clone()),
                Some(Err(e)) => Err(anyhow::anyhow!("{}", e)),
                None => Err(anyhow::anyhow!("No response configured")),
            }
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn health_check(&self) -> bool {
            self.healthy
        }
    }

    #[tokio::test]
    async fn test_resolver_success() {
        let upstream = Arc::new(
            MockUpstream::new("test")
                .with_response(
                    "example.com",
                    RecordType::A,
                    Ok(DnsAnswer {
                        ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                        ttl: Duration::from_secs(300),
                    }),
                )
                .with_response(
                    "example.com",
                    RecordType::AAAA,
                    Ok(DnsAnswer {
                        ips: vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))],
                        ttl: Duration::from_secs(600),
                    }),
                ),
        );

        let resolver = DnsResolver::new(vec![upstream]);
        let result = resolver.resolve("example.com").await.unwrap();

        assert_eq!(result.ips.len(), 2);
        assert_eq!(result.ttl, Duration::from_secs(300)); // min TTL
    }

    #[tokio::test]
    async fn test_resolver_fallback() {
        let unhealthy_upstream = Arc::new(MockUpstream::new("unhealthy").set_healthy(false));
        let healthy_upstream = Arc::new(MockUpstream::new("healthy").with_response(
            "example.com",
            RecordType::A,
            Ok(DnsAnswer {
                ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                ttl: Duration::from_secs(300),
            }),
        ));

        let resolver = DnsResolver::new(vec![unhealthy_upstream, healthy_upstream]);
        let result = resolver.resolve("example.com").await.unwrap();

        assert_eq!(result.ips.len(), 1);
    }

    #[tokio::test]
    async fn test_resolver_no_records() {
        let upstream = Arc::new(MockUpstream::new("test"));
        let resolver = DnsResolver::new(vec![upstream]);

        let result = resolver.resolve("nonexistent.com").await;
        assert!(result.is_err());
    }
}
