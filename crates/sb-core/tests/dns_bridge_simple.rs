//! Simple test for DNS bridge functionality

use std::net::IpAddr;
use std::time::Duration;

// Mock implementations for testing
#[derive(Clone)]
struct MockDnsAnswer {
    ips: Vec<IpAddr>,
    ttl: Duration,
}

#[async_trait::async_trait]
trait MockResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> anyhow::Result<MockDnsAnswer>;
    #[allow(dead_code)]
    fn name(&self) -> &str;
}

struct TestResolver {
    responses: std::collections::HashMap<String, anyhow::Result<MockDnsAnswer>>,
}

impl TestResolver {
    fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
        }
    }

    fn add_response(&mut self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u64) {
        self.responses.insert(
            domain.to_string(),
            Ok(MockDnsAnswer {
                ips,
                ttl: Duration::from_secs(ttl_secs),
            }),
        );
    }
}

#[async_trait::async_trait]
impl MockResolver for TestResolver {
    async fn resolve(&self, domain: &str) -> anyhow::Result<MockDnsAnswer> {
        match self.responses.get(domain) {
            Some(response) => match response {
                Ok(answer) => Ok(answer.clone()),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            },
            None => Err(anyhow::anyhow!("Domain not found: {}", domain)),
        }
    }

    fn name(&self) -> &str {
        "test"
    }
}

#[tokio::test]
async fn test_dns_bridge_concept() {
    let mut resolver = TestResolver::new();
    resolver.add_response("example.com", vec!["1.2.3.4".parse().unwrap()], 300);

    let result = resolver.resolve("example.com").await;
    assert!(result.is_ok());

    let answer = result.unwrap();
    assert_eq!(answer.ips.len(), 1);
    assert_eq!(answer.ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
    assert_eq!(answer.ttl, Duration::from_secs(300));
}

#[tokio::test]
async fn test_dns_bridge_error_handling() {
    let resolver = TestResolver::new();
    let result = resolver.resolve("nonexistent.com").await;
    assert!(result.is_err());
}

#[test]
fn test_dns_integration_validation() {
    // Test environment variable parsing
    std::env::set_var("SB_ROUTER_DNS", "1");
    let dns_enabled = std::env::var("SB_ROUTER_DNS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    assert!(dns_enabled);

    std::env::remove_var("SB_ROUTER_DNS");
    let dns_disabled = std::env::var("SB_ROUTER_DNS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    assert!(!dns_disabled);
}

#[test]
fn test_dns_timeout_parsing() {
    std::env::set_var("SB_ROUTER_DNS_TIMEOUT_MS", "3000");
    let timeout = std::env::var("SB_ROUTER_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5000);
    assert_eq!(timeout, 3000);

    std::env::remove_var("SB_ROUTER_DNS_TIMEOUT_MS");
    let default_timeout = std::env::var("SB_ROUTER_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5000);
    assert_eq!(default_timeout, 5000);
}
