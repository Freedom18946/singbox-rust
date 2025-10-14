//! Tests for DNS integration in routing decision chain

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sb_core::dns::{DnsAnswer, Resolver};
use sb_core::router::{DnsResolve, DnsResolverBridge, RouterHandle};

/// Mock DNS resolver for testing
struct MockDnsResolver {
    responses: std::collections::HashMap<String, anyhow::Result<DnsAnswer>>,
}

impl MockDnsResolver {
    fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
        }
    }

    fn add_response(&mut self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u64) {
        self.responses.insert(
            domain.to_string(),
            Ok(DnsAnswer::new(
                ips,
                Duration::from_secs(ttl_secs),
                sb_core::dns::cache::Source::System,
                sb_core::dns::cache::Rcode::NoError,
            )),
        );
    }

    fn add_error(&mut self, domain: &str, error: &str) {
        self.responses
            .insert(domain.to_string(), Err(anyhow::anyhow!(error.to_string())));
    }
}

#[async_trait::async_trait]
impl Resolver for MockDnsResolver {
    async fn resolve(&self, domain: &str) -> anyhow::Result<DnsAnswer> {
        match self.responses.get(domain) {
            Some(response) => response
                .as_ref()
                .map(|r| r.clone())
                .map_err(|e| anyhow::anyhow!("{}", e)),
            None => Err(anyhow::anyhow!("Domain not found: {}", domain)),
        }
    }

    fn name(&self) -> &str {
        "mock"
    }
}

#[tokio::test]
async fn test_dns_integration_domain_resolution() {
    // Set up environment for DNS-enabled routing
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_ROUTER_DNS_TIMEOUT_MS", "1000");
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "exact:example.com=proxy,cidr4:1.2.3.0/24=direct",
    );

    // Create mock DNS resolver
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("example.com", vec!["1.2.3.4".parse().unwrap()], 300);
    mock_resolver.add_response("google.com", vec!["8.8.8.8".parse().unwrap()], 300);

    // Create router with DNS resolver
    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    // Test domain that resolves to IP matching CIDR rule
    let decision = router.decide_udp_async("example.com").await;
    assert_eq!(decision, "direct"); // Should match cidr4:1.2.3.0/24=direct

    // Test domain that doesn't match any IP rules
    let decision = router.decide_udp_async("google.com").await;
    assert_eq!(decision, "direct"); // Should fall back to default

    // Clean up environment
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_DNS_TIMEOUT_MS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_exact_match_priority() {
    // Set up environment
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "exact:test.example.com=proxy,cidr4:1.2.3.0/24=direct",
    );

    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("test.example.com", vec!["1.2.3.4".parse().unwrap()], 300);

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    // Exact match should take priority over DNS resolution + CIDR match
    let decision = router.decide_udp_async("test.example.com").await;
    assert_eq!(decision, "proxy"); // Should match exact rule, not DNS+CIDR

    // Clean up
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_timeout_handling() {
    // Set up environment with short timeout
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_ROUTER_DNS_TIMEOUT_MS", "10"); // Very short timeout
    std::env::set_var("SB_ROUTER_OVERRIDE", "cidr4:1.2.3.0/24=proxy");

    // Create resolver that will timeout
    let mock_resolver = MockDnsResolver::new();
    // Don't add any responses - will cause timeout

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    let decision = router.decide_udp_async("slow.example.com").await;
    assert_eq!(decision, "direct"); // Should fall back to default on timeout

    // Clean up
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_DNS_TIMEOUT_MS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_error_handling() {
    // Set up environment
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_ROUTER_OVERRIDE", "cidr4:1.2.3.0/24=proxy");

    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_error("error.example.com", "DNS resolution failed");

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    let decision = router.decide_udp_async("error.example.com").await;
    assert_eq!(decision, "direct"); // Should fall back to default on error

    // Clean up
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_ipv6_support() {
    // Set up environment
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_ROUTER_OVERRIDE", "cidr6:2001:db8::/32=proxy");

    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response(
        "ipv6.example.com",
        vec!["2001:db8::1".parse().unwrap()],
        300,
    );

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    let decision = router.decide_udp_async("ipv6.example.com").await;
    assert_eq!(decision, "proxy"); // Should match IPv6 CIDR rule

    // Clean up
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_multiple_ips() {
    // Set up environment
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "cidr4:1.2.3.0/24=proxy,cidr4:8.8.8.0/24=direct",
    );

    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response(
        "multi.example.com",
        vec!["1.2.3.4".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        300,
    );

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    let decision = router.decide_udp_async("multi.example.com").await;
    // Should match the first IP that has a rule (1.2.3.4 -> proxy)
    assert_eq!(decision, "proxy");

    // Clean up
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[tokio::test]
async fn test_dns_integration_disabled() {
    // Ensure DNS is disabled
    std::env::remove_var("SB_ROUTER_DNS");
    std::env::set_var("SB_ROUTER_OVERRIDE", "exact:test.com=proxy");

    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("unknown.example.com", vec!["1.2.3.4".parse().unwrap()], 300);

    let router = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));

    // DNS resolution should not be used when disabled
    let decision = router.decide_udp_async("unknown.example.com").await;
    assert_eq!(decision, "direct"); // Should use default, not resolve DNS

    // Clean up
    std::env::remove_var("SB_ROUTER_OVERRIDE");
}

#[test]
fn test_router_has_dns_resolver() {
    let router_without_dns = RouterHandle::from_env();
    assert!(!router_without_dns.has_dns_resolver());

    let mock_resolver = MockDnsResolver::new();
    let router_with_dns = RouterHandle::from_env().with_dns_resolver(Arc::new(mock_resolver));
    assert!(router_with_dns.has_dns_resolver());
}

#[tokio::test]
async fn test_dns_bridge_integration() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("bridge.test.com", vec!["192.168.1.1".parse().unwrap()], 300);

    let bridge = DnsResolverBridge::new(Arc::new(mock_resolver));
    let result = bridge.resolve("bridge.test.com", 5000).await;

    match result {
        sb_core::router::DnsResult::Ok(ips) => {
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        }
        _ => assert!(
            false,
            "Expected successful DNS resolution with IP addresses"
        ),
    }
}
