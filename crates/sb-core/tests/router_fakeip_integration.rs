//! Integration tests for FakeIP routing
//!
//! Tests the integration of FakeIP with the routing decision engine, covering:
//! - FakeIP detection and original domain resolution
//! - Domain-based routing for FakeIP addresses
//! - GeoSite matching for FakeIP domains
//! - Fallback to IP routing when domain rules don't match
//! - Combined DNS + FakeIP + routing scenarios

use sb_core::dns::fakeip;
use sb_core::router::RouterHandle;

/// Clean up test environment variables
fn cleanup_env() {
    std::env::remove_var("SB_DNS_FAKEIP_ENABLE");
    std::env::remove_var("SB_FAKEIP_V4_BASE");
    std::env::remove_var("SB_FAKEIP_V4_MASK");
    std::env::remove_var("SB_ROUTER_OVERRIDE");
    std::env::remove_var("SB_ROUTER_DNS");
}

#[tokio::test]
async fn test_fakeip_routing_domain_exact_match() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules
    std::env::set_var("SB_ROUTER_OVERRIDE", "exact:google.com=proxy");

    // Allocate FakeIP for google.com
    let fake_ip = fakeip::allocate_v4("google.com");
    assert!(fakeip::is_fake_ip(&fake_ip));

    let router = RouterHandle::from_env();

    // Query with FakeIP should match domain rule
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "proxy",
        "FakeIP for google.com should match exact:google.com=proxy rule"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_domain_suffix_match() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules with suffix match
    std::env::set_var("SB_ROUTER_OVERRIDE", "suffix:.google.com=proxy");

    // Allocate FakeIP for subdomain
    let fake_ip = fakeip::allocate_v4("maps.google.com");
    assert!(fakeip::is_fake_ip(&fake_ip));

    let router = RouterHandle::from_env();

    // Query with FakeIP should match suffix rule
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "proxy",
        "FakeIP for maps.google.com should match suffix:.google.com=proxy rule"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_fallback_to_ip_rules() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules with only IP CIDR rule (matching FakeIP range)
    std::env::set_var("SB_ROUTER_OVERRIDE", "cidr4:198.18.0.0/16=block");

    // Allocate FakeIP for domain without domain rules
    let fake_ip = fakeip::allocate_v4("unknown.example.com");
    assert!(fakeip::is_fake_ip(&fake_ip));

    let router = RouterHandle::from_env();

    // Query with FakeIP should fallback to IP CIDR rule
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "block",
        "FakeIP for unknown domain should fallback to IP CIDR rule"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_domain_priority() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules with both domain and IP rules
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "exact:priority.test.com=proxy,cidr4:198.18.0.0/16=direct",
    );

    // Allocate FakeIP
    let fake_ip = fakeip::allocate_v4("priority.test.com");
    assert!(fakeip::is_fake_ip(&fake_ip));

    let router = RouterHandle::from_env();

    // Domain rule should have priority over IP rule
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "proxy",
        "Domain rule should take priority over IP CIDR rule"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_disabled() {
    cleanup_env();

    // FakeIP disabled
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "0");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "exact:test.com=proxy,cidr4:198.18.0.0/16=block",
    );

    // Allocate FakeIP (but FakeIP is disabled)
    let fake_ip = fakeip::allocate_v4("test.com");

    let router = RouterHandle::from_env();

    // When FakeIP is disabled, should use IP routing (CIDR rule)
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "block",
        "When FakeIP disabled, should use IP CIDR routing"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_ipv6() {
    cleanup_env();

    // Set up FakeIP for IPv6
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V6_BASE", "fd00::");
    std::env::set_var("SB_FAKEIP_V6_MASK", "8");

    // Set up routing rules
    std::env::set_var("SB_ROUTER_OVERRIDE", "exact:ipv6test.com=proxy");

    // Allocate FakeIP v6
    let fake_ip6 = fakeip::allocate_v6("ipv6test.com");
    assert!(fakeip::is_fake_ip(&fake_ip6));

    let router = RouterHandle::from_env();

    // IPv6 FakeIP should also resolve to original domain
    let decision = router.decide_udp_async(&fake_ip6.to_string()).await;
    assert_eq!(
        decision, "proxy",
        "IPv6 FakeIP should resolve to original domain and match rule"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_real_ip_no_false_positive() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules
    std::env::set_var(
        "SB_ROUTER_OVERRIDE",
        "exact:realip.com=proxy,cidr4:8.8.8.0/24=block",
    );

    let router = RouterHandle::from_env();

    // Real IP address (not FakeIP) should use IP routing
    let decision = router.decide_udp_async("8.8.8.8").await;
    assert_eq!(
        decision, "block",
        "Real IP should use IP CIDR routing, not domain routing"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_multiple_domains_same_rule() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules with suffix
    std::env::set_var("SB_ROUTER_OVERRIDE", "suffix:.cdn.com=proxy");

    let router = RouterHandle::from_env();

    // Test multiple subdomains
    let domains = vec!["img.cdn.com", "static.cdn.com", "api.cdn.com"];

    for domain in domains {
        let fake_ip = fakeip::allocate_v4(domain);
        assert!(fakeip::is_fake_ip(&fake_ip));

        let decision = router.decide_udp_async(&fake_ip.to_string()).await;
        assert_eq!(
            decision, "proxy",
            "FakeIP for {} should match suffix rule",
            domain
        );
    }

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_no_domain_rules_default() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // No routing rules configured

    // Allocate FakeIP
    let fake_ip = fakeip::allocate_v4("noroute.example.com");
    assert!(fakeip::is_fake_ip(&fake_ip));

    let router = RouterHandle::from_env();

    // Should fallback to default
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "direct",
        "FakeIP with no matching rules should use default (direct)"
    );

    cleanup_env();
}

#[tokio::test]
async fn test_fakeip_routing_case_insensitive() {
    cleanup_env();

    // Set up FakeIP
    std::env::set_var("SB_DNS_FAKEIP_ENABLE", "1");
    std::env::set_var("SB_FAKEIP_V4_BASE", "198.18.0.0");
    std::env::set_var("SB_FAKEIP_V4_MASK", "16");

    // Set up routing rules (lowercase)
    std::env::set_var("SB_ROUTER_OVERRIDE", "exact:example.com=proxy");

    let router = RouterHandle::from_env();

    // Allocate FakeIP with uppercase domain
    let fake_ip = fakeip::allocate_v4("EXAMPLE.COM");
    assert!(fakeip::is_fake_ip(&fake_ip));

    // Should match case-insensitively
    let decision = router.decide_udp_async(&fake_ip.to_string()).await;
    assert_eq!(
        decision, "proxy",
        "FakeIP routing should be case-insensitive"
    );

    cleanup_env();
}
