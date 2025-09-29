//! DNS 系统集成测试
//!
//! 测试 DNS 解析器、上游、缓存和策略的集成

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use crate::dns::{
        cache::DnsCache,
        resolver::DnsResolver,
        strategy::{QueryExecutor, QueryStrategy, RetryConfig},
        upstream::{SystemUpstream, UdpUpstream},
        DnsAnswer, DnsUpstream, RecordType, Resolver,
    };

    #[tokio::test]
    async fn test_dns_resolver_with_system_upstream() {
        let system_upstream = Arc::new(SystemUpstream::new());
        let resolver = DnsResolver::new(vec![system_upstream]);

        // 测试解析已知域名
        let result = resolver.resolve("google.com").await;
        assert!(
            result.is_ok(),
            "Should resolve google.com: {:?}",
            result.err()
        );

        let answer = result.unwrap();
        assert!(!answer.ips.is_empty(), "Should return at least one IP");
        assert!(answer.ttl > Duration::ZERO, "Should have positive TTL");
    }

    #[tokio::test]
    async fn test_dns_cache_integration() {
        let cache = Arc::new(DnsCache::new(100));

        // 测试缓存未命中
        assert!(cache.get("example.com").is_none());

        // 存入缓存
        let answer = DnsAnswer {
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            ttl: Duration::from_secs(300),
            source: crate::dns::cache::Source::System,
            rcode: crate::dns::cache::Rcode::NoError,
        };
        cache.put("example.com", answer.clone());

        // 测试缓存命中
        let cached = cache.get("example.com").unwrap();
        assert_eq!(cached.ips, answer.ips);
        assert!(cached.ttl <= answer.ttl); // TTL 应该减少或相等
    }

    #[tokio::test]
    async fn test_query_executor_failover() {
        let system_upstream = Arc::new(SystemUpstream::new());
        let executor = QueryExecutor::new(vec![system_upstream])
            .with_strategy(QueryStrategy::Failover)
            .with_timeout(Duration::from_secs(5));

        let result = executor.query("google.com", RecordType::A).await;
        assert!(
            result.is_ok(),
            "Failover query should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_udp_upstream_creation() {
        let server = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let upstream = UdpUpstream::new(server);

        assert_eq!(upstream.name(), "udp://8.8.8.8:53");

        // 健康检查应该能工作（可能会失败，取决于网络）
        let _health = upstream.health_check().await;
    }

    #[tokio::test]
    async fn test_dns_record_types() {
        assert_eq!(RecordType::A.as_u16(), 1);
        assert_eq!(RecordType::AAAA.as_u16(), 28);
        assert_eq!(RecordType::CNAME.as_u16(), 5);

        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_u16(999), None);
    }

    #[tokio::test]
    async fn test_retry_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_millis(100));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_dns_answer_creation() {
        let answer = DnsAnswer {
            ips: vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ],
            ttl: Duration::from_secs(300),
            source: crate::dns::cache::Source::System,
            rcode: crate::dns::cache::Rcode::NoError,
        };

        assert_eq!(answer.ips.len(), 2);
        assert_eq!(answer.ttl, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_resolver_name() {
        let system_upstream = Arc::new(SystemUpstream::new());
        let resolver =
            DnsResolver::new(vec![system_upstream]).with_name("test_resolver".to_string());

        assert_eq!(resolver.name(), "test_resolver");
    }

    // 性能测试（可选）
    #[tokio::test]
    #[ignore] // 需要网络连接且可能较慢
    async fn test_dns_performance() {
        let system_upstream = Arc::new(SystemUpstream::new());
        let resolver = DnsResolver::new(vec![system_upstream]);

        let start = std::time::Instant::now();
        let mut tasks = Vec::new();

        // 并发解析多个域名
        let domains = vec![
            "google.com",
            "github.com",
            "stackoverflow.com",
            "rust-lang.org",
        ];

        for domain in domains {
            let resolver = resolver.clone();
            let task = tokio::spawn(async move { resolver.resolve(domain).await });
            tasks.push(task);
        }

        // 等待所有任务完成
        let results = futures::future::join_all(tasks).await;
        let elapsed = start.elapsed();

        // 检查结果
        let mut success_count = 0;
        for result in results {
            if let Ok(Ok(_)) = result {
                success_count += 1;
            }
        }

        println!(
            "DNS performance test: {}/{} successful in {:?}",
            success_count, 4, elapsed
        );

        // 至少应该有一半成功
        assert!(
            success_count >= 2,
            "At least half of DNS queries should succeed"
        );

        // 总时间应该合理（并发执行）
        assert!(
            elapsed < Duration::from_secs(10),
            "Concurrent DNS queries should complete quickly"
        );
    }
}
