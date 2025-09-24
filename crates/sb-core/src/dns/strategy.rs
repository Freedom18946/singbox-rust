//! DNS 查询策略实现
//!
//! 提供多种 DNS 查询策略：
//! - 故障转移策略
//! - 并发竞速策略
//! - 负载均衡策略
//! - 重试机制

use anyhow::Result;
use futures::future::{select_all, FutureExt};
use std::{sync::Arc, time::Duration};

use super::{DnsAnswer, DnsUpstream, RecordType};

/// DNS 查询策略
#[derive(Debug, Clone)]
pub enum QueryStrategy {
    /// 故障转移：按顺序尝试上游，直到成功
    Failover,
    /// 并发竞速：同时查询所有上游，返回最快的结果
    Race,
    /// 负载均衡：轮询选择上游
    RoundRobin,
    /// 随机选择上游
    Random,
}

/// 重试配置
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// 最大重试次数
    pub max_retries: usize,
    /// 重试间隔
    pub retry_delay: Duration,
    /// 重试间隔倍数（指数退避）
    pub backoff_multiplier: f64,
    /// 最大重试间隔
    pub max_retry_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            max_retry_delay: Duration::from_secs(5),
        }
    }
}

/// DNS 查询执行器
pub struct QueryExecutor {
    /// 上游服务器列表
    upstreams: Vec<Arc<dyn DnsUpstream>>,
    /// 查询策略
    strategy: QueryStrategy,
    /// 重试配置
    retry_config: RetryConfig,
    /// 查询超时
    query_timeout: Duration,
    /// 轮询计数器（用于负载均衡）
    round_robin_counter: std::sync::atomic::AtomicUsize,
}

impl QueryExecutor {
    /// 创建新的查询执行器
    pub fn new(upstreams: Vec<Arc<dyn DnsUpstream>>) -> Self {
        let strategy = match std::env::var("SB_DNS_STRATEGY").as_deref() {
            Ok("failover") => QueryStrategy::Failover,
            Ok("race") => QueryStrategy::Race,
            Ok("round_robin") => QueryStrategy::RoundRobin,
            Ok("random") => QueryStrategy::Random,
            _ => QueryStrategy::Failover,
        };

        let query_timeout = Duration::from_millis(
            std::env::var("SB_DNS_QUERY_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        Self {
            upstreams,
            strategy,
            retry_config: RetryConfig::default(),
            query_timeout,
            round_robin_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 设置查询策略
    pub fn with_strategy(mut self, strategy: QueryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 设置重试配置
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// 设置查询超时
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// 执行 DNS 查询
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        if self.upstreams.is_empty() {
            return Err(anyhow::anyhow!("No DNS upstreams configured"));
        }

        match self.strategy {
            QueryStrategy::Failover => self.query_failover(domain, record_type).await,
            QueryStrategy::Race => self.query_race(domain, record_type).await,
            QueryStrategy::RoundRobin => self.query_round_robin(domain, record_type).await,
            QueryStrategy::Random => self.query_random(domain, record_type).await,
        }
    }

    /// 故障转移查询
    async fn query_failover(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let mut last_error = None;

        for upstream in &self.upstreams {
            // 检查上游健康状态
            if !upstream.health_check().await {
                tracing::debug!("Upstream {} is unhealthy, skipping", upstream.name());
                continue;
            }

            let upstream_name = upstream.name().to_string();
            match self
                .query_with_retry(upstream.clone(), domain, record_type)
                .await
            {
                Ok(answer) => {
                    tracing::debug!(
                        "DNS query successful with failover: upstream={}, domain={}",
                        upstream_name,
                        domain
                    );

                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "dns_strategy_total",
                        "strategy" => "failover",
                        "upstream" => upstream_name,
                        "result" => "success"
                    )
                    .increment(1);

                    return Ok(answer);
                }
                Err(e) => {
                    tracing::debug!(
                        "DNS query failed with failover: upstream={}, domain={}, error={}",
                        upstream.name(),
                        domain,
                        e
                    );

                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "dns_strategy_total",
                        "strategy" => "failover",
                        "upstream" => upstream_name.clone(),
                        "result" => "error"
                    )
                    .increment(1);

                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("All DNS upstreams failed or are unhealthy")))
    }

    /// 并发竞速查询
    async fn query_race(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let healthy_upstreams: Vec<_> = {
            let mut healthy = Vec::new();
            for upstream in &self.upstreams {
                if upstream.health_check().await {
                    healthy.push(upstream.clone());
                }
            }
            healthy
        };

        if healthy_upstreams.is_empty() {
            return Err(anyhow::anyhow!("No healthy DNS upstreams available"));
        }

        // 创建所有查询的 Future
        let query_futures: Vec<_> = healthy_upstreams
            .into_iter()
            .map(|upstream| {
                let domain = domain.to_string();
                async move {
                    let result = tokio::time::timeout(
                        self.query_timeout,
                        self.query_with_retry(upstream.clone(), &domain, record_type),
                    )
                    .await;

                    match result {
                        Ok(Ok(answer)) => Ok((upstream.name().to_string(), answer)),
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err(anyhow::anyhow!("Query timeout")),
                    }
                }
                .boxed()
            })
            .collect();

        // 等待第一个成功的结果
        let (result, _index, _remaining) = select_all(query_futures).await;

        match result {
            Ok((upstream_name, answer)) => {
                tracing::debug!(
                    "DNS query successful with race: upstream={}, domain={}",
                    upstream_name,
                    domain
                );

                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "race",
                    "upstream" => upstream_name,
                    "result" => "success"
                )
                .increment(1);

                Ok(answer)
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "race",
                    "result" => "error"
                )
                .increment(1);

                Err(e)
            }
        }
    }

    /// 轮询查询
    async fn query_round_robin(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        let count = self
            .round_robin_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let index = count % self.upstreams.len();
        let upstream = &self.upstreams[index];

        // 如果选中的上游不健康，回退到故障转移
        if !upstream.health_check().await {
            return self.query_failover(domain, record_type).await;
        }

        let upstream_name = upstream.name().to_string();
        match self
            .query_with_retry(upstream.clone(), domain, record_type)
            .await
        {
            Ok(answer) => {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "round_robin",
                    "upstream" => upstream_name,
                    "result" => "success"
                )
                .increment(1);

                Ok(answer)
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "round_robin",
                    "upstream" => upstream_name.clone(),
                    "result" => "error"
                )
                .increment(1);

                // 回退到故障转移
                self.query_failover(domain, record_type).await
            }
        }
    }

    /// 随机选择查询
    async fn query_random(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        // 使用简单的伪随机选择（基于时间）
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let index = (now as usize) % self.upstreams.len();
        let upstream = &self.upstreams[index];

        // 如果选中的上游不健康，回退到故障转移
        if !upstream.health_check().await {
            return self.query_failover(domain, record_type).await;
        }

        let upstream_name = upstream.name().to_string();
        match self
            .query_with_retry(upstream.clone(), domain, record_type)
            .await
        {
            Ok(answer) => {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "random",
                    "upstream" => upstream_name,
                    "result" => "success"
                )
                .increment(1);

                Ok(answer)
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_strategy_total",
                    "strategy" => "random",
                    "upstream" => upstream_name.clone(),
                    "result" => "error"
                )
                .increment(1);

                // 回退到故障转移
                self.query_failover(domain, record_type).await
            }
        }
    }

    /// 带重试的查询
    async fn query_with_retry(
        &self,
        upstream: Arc<dyn DnsUpstream>,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnsAnswer> {
        let upstream_name = upstream.name().to_string();
        let mut delay = self.retry_config.retry_delay;
        let mut last_error = None;

        for attempt in 0..=self.retry_config.max_retries {
            match upstream.query(domain, record_type).await {
                Ok(answer) => {
                    if attempt > 0 {
                        tracing::debug!(
                            "DNS query succeeded after {} retries: upstream={}, domain={}",
                            attempt,
                            upstream.name(),
                            domain
                        );

                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "dns_retry_total",
                            "upstream" => upstream_name.clone(),
                            "result" => "success_after_retry"
                        )
                        .increment(1);
                    }

                    return Ok(answer);
                }
                Err(e) => {
                    last_error = Some(e);

                    if attempt < self.retry_config.max_retries {
                        tracing::debug!(
                            "DNS query failed, retrying in {:?}: upstream={}, domain={}, attempt={}, error={}",
                            delay,
                            upstream.name(),
                            domain,
                            attempt,
                            last_error.as_ref().unwrap()
                        );

                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "dns_retry_total",
                            "upstream" => upstream_name.clone(),
                            "result" => "retry"
                        )
                        .increment(1);

                        // 等待重试间隔
                        tokio::time::sleep(delay).await;

                        // 指数退避
                        delay = Duration::from_millis(
                            (delay.as_millis() as f64 * self.retry_config.backoff_multiplier)
                                as u64,
                        )
                        .min(self.retry_config.max_retry_delay);
                    }
                }
            }
        }

        #[cfg(feature = "metrics")]
        metrics::counter!(
            "dns_retry_total",
            "upstream" => upstream_name,
            "result" => "failed_after_retries"
        )
        .increment(1);

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "DNS query failed after {} retries",
                self.retry_config.max_retries
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Mock upstream for testing
    struct MockUpstream {
        name: String,
        responses: std::collections::HashMap<(String, RecordType), Result<DnsAnswer>>,
        healthy: bool,
        call_count: Arc<AtomicUsize>,
    }

    impl MockUpstream {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                responses: std::collections::HashMap::new(),
                healthy: true,
                call_count: Arc::new(AtomicUsize::new(0)),
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

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl DnsUpstream for MockUpstream {
        async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
            self.call_count.fetch_add(1, Ordering::Relaxed);

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
    async fn test_failover_strategy() {
        let failing_upstream = Arc::new(MockUpstream::new("failing").with_response(
            "example.com",
            RecordType::A,
            Err(anyhow::anyhow!("DNS error")),
        ));

        let working_upstream = Arc::new(MockUpstream::new("working").with_response(
            "example.com",
            RecordType::A,
            Ok(DnsAnswer {
                ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                ttl: Duration::from_secs(300),
                source: crate::dns::cache::Source::System,
                rcode: crate::dns::cache::Rcode::NoError,
            }),
        ));

        let executor = QueryExecutor::new(vec![failing_upstream.clone(), working_upstream.clone()])
            .with_strategy(QueryStrategy::Failover)
            .with_retry_config(RetryConfig {
                max_retries: 0,
                retry_delay: Duration::from_millis(0),
                backoff_multiplier: 1.0,
                max_retry_delay: Duration::from_millis(0),
            });

        let result = executor.query("example.com", RecordType::A).await.unwrap();
        assert_eq!(result.ips.len(), 1);

        // 验证调用次数（无重试）
        assert_eq!(failing_upstream.call_count(), 1);
        assert_eq!(working_upstream.call_count(), 1);
    }

    #[tokio::test]
    async fn test_round_robin_strategy() {
        let upstream1 = Arc::new(MockUpstream::new("upstream1").with_response(
            "example.com",
            RecordType::A,
            Ok(DnsAnswer {
                ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                ttl: Duration::from_secs(300),
                source: crate::dns::cache::Source::System,
                rcode: crate::dns::cache::Rcode::NoError,
            }),
        ));

        let upstream2 = Arc::new(MockUpstream::new("upstream2").with_response(
            "example.com",
            RecordType::A,
            Ok(DnsAnswer {
                ips: vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
                ttl: Duration::from_secs(300),
                source: crate::dns::cache::Source::System,
                rcode: crate::dns::cache::Rcode::NoError,
            }),
        ));

        let executor = QueryExecutor::new(vec![upstream1.clone(), upstream2.clone()])
            .with_strategy(QueryStrategy::RoundRobin);

        // 第一次查询应该使用 upstream1
        let _result1 = executor.query("example.com", RecordType::A).await.unwrap();

        // 第二次查询应该使用 upstream2
        let _result2 = executor.query("example.com", RecordType::A).await.unwrap();

        // 验证轮询行为
        assert_eq!(upstream1.call_count(), 1);
        assert_eq!(upstream2.call_count(), 1);
    }

    #[tokio::test]
    async fn test_retry_mechanism() {
        let upstream = Arc::new(MockUpstream::new("flaky"));

        let executor = QueryExecutor::new(vec![upstream.clone()]).with_retry_config(RetryConfig {
            max_retries: 2,
            retry_delay: Duration::from_millis(10),
            backoff_multiplier: 1.0,
            max_retry_delay: Duration::from_secs(1),
        });

        // 查询不存在的域名（会失败）
        let result = executor.query("nonexistent.com", RecordType::A).await;
        assert!(result.is_err());

        // 应该重试了 3 次（初始 + 2 次重试）
        assert_eq!(upstream.call_count(), 3);
    }
}
