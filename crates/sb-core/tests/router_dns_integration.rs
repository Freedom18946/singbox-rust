#![allow(clippy::await_holding_lock)]
//! Tests for DNS integration in routing decision chain

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sb_core::dns::{DnsAnswer, Resolver};
use sb_core::router::{DnsResolve, DnsResolverBridge, RouterHandle};
use sb_core::runtime_options::RouterRuntimeOptions;

fn router_with_dns(
    resolver: MockDnsResolver,
    rules: &str,
    enabled: bool,
    timeout_ms: u64,
) -> RouterHandle {
    RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        dns_enabled: enabled,
        dns_timeout_ms: timeout_ms,
        ..Default::default()
    }))
    .with_dns_resolver(Arc::new(resolver))
}

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
    #[allow(clippy::useless_asref)]
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
    // Create mock DNS resolver
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("example.com", vec!["1.2.3.4".parse().unwrap()], 300);
    mock_resolver.add_response("google.com", vec!["8.8.8.8".parse().unwrap()], 300);

    // Create router with DNS resolver
    let router = router_with_dns(mock_resolver, "cidr4:1.2.3.0/24=direct", true, 1000);

    // Test domain that resolves to IP matching CIDR rule
    let decision = router.decide_udp_async("example.com").await;
    assert_eq!(decision, "direct"); // Should match cidr4:1.2.3.0/24=direct

    // Test domain that doesn't match any IP rules
    let decision = router.decide_udp_async("google.com").await;
    assert_eq!(decision, "unresolved"); // Should fall back to router default
}

#[tokio::test]
async fn test_dns_integration_exact_match_priority() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("test.example.com", vec!["1.2.3.4".parse().unwrap()], 300);

    let router = router_with_dns(
        mock_resolver,
        "exact:test.example.com=proxy\ncidr4:1.2.3.0/24=direct",
        true,
        300,
    );

    // Exact match should take priority over DNS resolution + CIDR match
    let decision = router.decide_udp_async("test.example.com").await;
    assert_eq!(decision, "proxy"); // Should match exact rule, not DNS+CIDR
}

#[tokio::test]
async fn test_dns_integration_timeout_handling() {
    // Create resolver that will timeout
    let mock_resolver = MockDnsResolver::new();
    // Don't add any responses - will cause timeout

    let router = router_with_dns(mock_resolver, "cidr4:1.2.3.0/24=proxy", true, 10);

    let decision = router.decide_udp_async("slow.example.com").await;
    assert_eq!(decision, "unresolved"); // Should fall back to router default on timeout
}

#[tokio::test]
async fn test_dns_integration_error_handling() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_error("error.example.com", "DNS resolution failed");

    let router = router_with_dns(mock_resolver, "cidr4:1.2.3.0/24=proxy", true, 300);

    let decision = router.decide_udp_async("error.example.com").await;
    assert_eq!(decision, "unresolved"); // Should fall back to router default on error
}

#[tokio::test]
async fn test_dns_integration_ipv6_support() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response(
        "ipv6.example.com",
        vec!["2001:db8::1".parse().unwrap()],
        300,
    );

    let router = router_with_dns(mock_resolver, "cidr6:2001:db8::/32=proxy", true, 300);

    let decision = router.decide_udp_async("ipv6.example.com").await;
    assert_eq!(decision, "proxy"); // Should match IPv6 CIDR rule
}

#[tokio::test]
async fn test_dns_integration_multiple_ips() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response(
        "multi.example.com",
        vec!["1.2.3.4".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        300,
    );

    let router = router_with_dns(
        mock_resolver,
        "cidr4:1.2.3.0/24=proxy\ncidr4:8.8.8.0/24=direct",
        true,
        300,
    );

    let decision = router.decide_udp_async("multi.example.com").await;
    // Should match the first IP that has a rule (1.2.3.4 -> proxy)
    assert_eq!(decision, "proxy");
}

#[tokio::test]
async fn test_dns_integration_disabled() {
    let mut mock_resolver = MockDnsResolver::new();
    mock_resolver.add_response("unknown.example.com", vec!["1.2.3.4".parse().unwrap()], 300);

    let router = router_with_dns(mock_resolver, "exact:test.com=proxy", false, 300);

    // DNS resolution should not be used when disabled
    let decision = router.decide_udp_async("unknown.example.com").await;
    assert_eq!(decision, "unresolved"); // Should use router default, not resolve DNS
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
        _ => panic!("Expected successful DNS resolution with IP addresses"),
    }
}
