//! Comprehensive unit tests for selector group functionality

#[cfg(test)]
mod tests {
    use crate::adapter::OutboundConnector;
    use crate::outbound::selector_group::{
        parse_test_url, ProxyHealth, ProxyMember, SelectMode, SelectorGroup,
    };
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpStream;

    /// Mock connector for testing
    #[derive(Debug)]
    struct MockConnector {
        #[allow(dead_code)]
        name: String,
        delay_ms: u64,
        fail_count: Arc<AtomicUsize>,
        max_fails: usize,
    }

    impl MockConnector {
        fn new(name: &str, delay_ms: u64) -> Self {
            Self {
                name: name.to_string(),
                delay_ms,
                fail_count: Arc::new(AtomicUsize::new(0)),
                max_fails: 0,
            }
        }

        #[allow(dead_code)]
        fn with_failures(name: &str, delay_ms: u64, max_fails: usize) -> Self {
            Self {
                name: name.to_string(),
                delay_ms,
                fail_count: Arc::new(AtomicUsize::new(0)),
                max_fails,
            }
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for MockConnector {
        async fn connect(&self, _host: &str, _port: u16) -> io::Result<TcpStream> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;

            let count = self.fail_count.fetch_add(1, Ordering::SeqCst);
            if count < self.max_fails {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "mock failure",
                ));
            }

            // Can't create a real TcpStream in tests, so return error
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mock connector (test only)",
            ))
        }
    }

    fn create_test_member(tag: &str, delay_ms: u64) -> ProxyMember {
        ProxyMember {
            tag: tag.to_string(),
            connector: Arc::new(MockConnector::new(tag, delay_ms)),
            udp_factory: None,
            health: Arc::new(ProxyHealth::default()),
        }
    }

    #[tokio::test]
    async fn test_manual_selector_select_by_name() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 20),
            create_test_member("proxy3", 30),
        ];

        let selector = SelectorGroup::new_manual(
            "test-selector".to_string(),
            members,
            Some("proxy1".to_string()),
        );

        // Default should be proxy1
        assert_eq!(selector.get_selected().await, Some("proxy1".to_string()));

        // Select proxy2
        selector.select_by_name("proxy2").await.unwrap();
        assert_eq!(selector.get_selected().await, Some("proxy2".to_string()));

        // Try to select non-existent proxy
        let result = selector.select_by_name("proxy99").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manual_selector_fallback() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 20),
        ];

        let selector = SelectorGroup::new_manual(
            "test-selector".to_string(),
            members,
            Some("proxy1".to_string()),
        );

        // Should use default when nothing selected
        let selected = selector.select_best().await;
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().tag, "proxy1");
    }

    #[tokio::test]
    async fn test_urltest_selector_latency_based() {
        let members = vec![
            create_test_member("fast", 10),
            create_test_member("medium", 50),
            create_test_member("slow", 100),
        ];

        // Set different RTTs
        members[0].health.record_success(10);
        members[1].health.record_success(50);
        members[2].health.record_success(100);

        let selector = SelectorGroup::new_urltest(
            "test-urltest".to_string(),
            members,
            "http://www.gstatic.com/generate_204".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
            50,
        );

        // Should select the fastest
        let selected = selector.select_best().await;
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().tag, "fast");
    }

    #[tokio::test]
    async fn test_urltest_skips_unhealthy() {
        let members = vec![
            create_test_member("fast-but-dead", 10),
            create_test_member("healthy", 50),
        ];

        // Mark first as dead
        members[0].health.record_failure();
        members[0].health.record_failure();
        members[0].health.record_failure();
        assert!(!members[0].health.is_healthy());

        // Set RTT for healthy one
        members[1].health.record_success(50);

        let selector = SelectorGroup::new_urltest(
            "test-urltest".to_string(),
            members,
            "http://www.gstatic.com/generate_204".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
            50,
        );

        let selected = selector.select_best().await;
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().tag, "healthy");
    }

    #[tokio::test]
    async fn test_round_robin_selection() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 10),
            create_test_member("proxy3", 10),
        ];

        let selector = SelectorGroup::new_load_balancer(
            "test-rr".to_string(),
            members,
            SelectMode::RoundRobin,
        );

        // Should cycle through proxies
        let mut tags = Vec::new();
        for _ in 0..6 {
            tags.push(selector.select_best().await.unwrap().tag.clone());
        }

        // Should see pattern: proxy1, proxy2, proxy3, proxy1, proxy2, proxy3
        assert_eq!(tags[0], "proxy1");
        assert_eq!(tags[1], "proxy2");
        assert_eq!(tags[2], "proxy3");
        assert_eq!(tags[3], "proxy1");
        assert_eq!(tags[4], "proxy2");
        assert_eq!(tags[5], "proxy3");
    }

    #[tokio::test]
    async fn test_least_connections_selection() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 10),
            create_test_member("proxy3", 10),
        ];

        let selector = SelectorGroup::new_load_balancer(
            "test-lc".to_string(),
            members,
            SelectMode::LeastConnections,
        );

        // Simulate different connection counts
        selector.members[0]
            .health
            .active_connections
            .store(5, Ordering::Relaxed);
        selector.members[1]
            .health
            .active_connections
            .store(2, Ordering::Relaxed);
        selector.members[2]
            .health
            .active_connections
            .store(8, Ordering::Relaxed);

        // Should select proxy2 (least connections)
        let selected = selector.select_best().await;
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().tag, "proxy2");
    }

    #[tokio::test]
    async fn test_random_selection() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 10),
            create_test_member("proxy3", 10),
        ];

        let selector = SelectorGroup::new_load_balancer(
            "test-random".to_string(),
            members,
            SelectMode::Random,
        );

        // Select 100 times, should see variety
        let mut tags = std::collections::HashSet::new();
        for _ in 0..100 {
            let selected = selector.select_best().await.unwrap();
            tags.insert(selected.tag.clone());
        }

        // Should have selected at least 2 different proxies
        assert!(tags.len() >= 2, "Random selection should vary");
    }

    #[test]
    fn test_proxy_health_tracking() {
        let health = ProxyHealth::default();

        // Initially healthy
        assert!(health.is_healthy());
        assert_eq!(health.consecutive_fails.load(Ordering::Relaxed), 0);

        // Record success
        health.record_success(100);
        assert!(health.is_healthy());
        assert_eq!(health.get_rtt_ms(), 100);

        // Record failures
        health.record_failure();
        assert!(health.is_healthy()); // Still healthy after 1 failure
        assert_eq!(health.consecutive_fails.load(Ordering::Relaxed), 1);

        health.record_failure();
        assert!(health.is_healthy()); // Still healthy after 2 failures

        health.record_failure();
        assert!(!health.is_healthy()); // Unhealthy after 3 failures

        // Recovery
        health.record_success(50);
        assert!(health.is_healthy());
        assert_eq!(health.consecutive_fails.load(Ordering::Relaxed), 0);
        assert_eq!(health.get_rtt_ms(), 50);
    }

    #[tokio::test]
    async fn test_graceful_degradation_all_dead() {
        let mut members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 10),
        ];

        // Mark all as dead
        for member in &mut members {
            member.health.record_failure();
            member.health.record_failure();
            member.health.record_failure();
        }

        let selector = SelectorGroup::new_urltest(
            "test-degradation".to_string(),
            members,
            "http://www.gstatic.com/generate_204".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
            50,
        );

        // Should still return something (fallback to first)
        let selected = selector.select_best().await;
        assert!(selected.is_some());
    }

    #[test]
    fn test_parse_test_url() {
        // HTTP
        let (host, port, https, _) = parse_test_url("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!(host, "www.gstatic.com");
        assert_eq!(port, 80);
        assert!(!https);

        // HTTPS
        let (host, port, https, _) = parse_test_url("https://www.google.com/").unwrap();
        assert_eq!(host, "www.google.com");
        assert_eq!(port, 443);
        assert!(https);

        // Custom port
        let (host, port, _, _) = parse_test_url("http://example.com:8080/test").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[tokio::test]
    async fn test_get_members_status() {
        let members = vec![
            create_test_member("proxy1", 10),
            create_test_member("proxy2", 20),
        ];

        members[0].health.record_success(100);
        members[1].health.record_failure();
        members[1].health.record_failure();
        members[1].health.record_failure();

        let selector =
            SelectorGroup::new_manual("test".to_string(), members, Some("proxy1".to_string()));

        let status = selector.get_members();
        assert_eq!(status.len(), 2);

        // proxy1 should be healthy
        let (tag, healthy, rtt) = &status[0];
        assert_eq!(tag, "proxy1");
        assert!(*healthy);
        assert_eq!(*rtt, 100);

        // proxy2 should be unhealthy
        let (tag, healthy, _rtt) = &status[1];
        assert_eq!(tag, "proxy2");
        assert!(!*healthy);
    }

    #[test]
    fn proxy_health_marks_permanent_failure() {
        use std::io;

        let health = ProxyHealth::default();
        assert!(health.is_healthy());

        let err = io::Error::new(io::ErrorKind::Unsupported, "stub");
        health.record_permanent_failure(&err);

        assert!(health.is_permanently_failed());
        assert!(!health.is_healthy());
    }
}
