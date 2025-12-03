//! Integration tests for IP version matching
//!
//! Tests the routing engine's ability to route based on IP version (IPv4 vs IPv6).
//! This enables dual-stack routing policies, allowing different treatment of
//! IPv4 and IPv6 connections.
//!
//! Use cases:
//! - Route IPv6 traffic differently from IPv4 (e.g., direct IPv6, proxy IPv4)
//! - Implement IPv6-first or IPv4-first routing strategies
//! - Test dual-stack network configurations
//! - Handle IPv6 tunneling and translation scenarios

use sb_core::router::rules::{Decision, Engine, RouteCtx, Rule, RuleKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_ipversion_ipv4_match() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("ipv4_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match IPv4 address
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("ipv4_proxy".to_string()))
    );

    // Should not match IPv6 address
    let ctx_v6 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_v6), Decision::Direct);
}

#[test]
fn test_ipversion_ipv6_match() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpVersionV6,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Should match IPv6 address
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        ))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Direct);

    // Should not match IPv4 address
    let ctx_v4 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_v4), Decision::Proxy(None));
}

#[test]
fn test_ipversion_priority_after_query_type() {
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("example.com".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::ProcessName("firefox".to_string()),
            decision: Decision::Proxy(Some("browser_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("ipv4_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Domain rule should beat ipversion
    let ctx1 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // Process rule should beat ipversion
    let ctx2 = RouteCtx {
        domain: Some("other.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: Some("firefox"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("browser_proxy".to_string()))
    );

    // Ipversion rule should apply when no higher priority rules match
    let ctx3 = RouteCtx {
        domain: Some("other.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx3),
        Decision::Proxy(Some("ipv4_proxy".to_string()))
    );
}

#[test]
fn test_ipversion_no_ip_fallback() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Without IP address, should use default
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Direct);
}

#[test]
fn test_multiple_ipversion_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("ipv4_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::IpVersionV6,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // Test IPv4 routing
    let ctx_v4 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_v4),
        Decision::Proxy(Some("ipv4_proxy".to_string()))
    );

    // Test IPv6 routing
    let ctx_v6 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_v6), Decision::Direct);
}

#[test]
fn test_parse_rules_with_ipversion() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        ipversion:ipv4=proxy:ipv4_proxy
        ipversion:ipv6=direct
        ipversion:4=reject
        ipversion:6=proxy
        default=direct
    "#;

    let rules = parse_rules(rules_text);

    // Should have 5 rules (4 ipversion + 1 default)
    assert_eq!(rules.len(), 5);

    // Check ipv4 rules (both "ipv4" and "4" should work)
    let ipv4_rules: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r.kind, RuleKind::IpVersionV4))
        .collect();
    assert_eq!(ipv4_rules.len(), 2);

    // Check ipv6 rules (both "ipv6" and "6" should work)
    let ipv6_rules: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r.kind, RuleKind::IpVersionV6))
        .collect();
    assert_eq!(ipv6_rules.len(), 2);

    // Verify first ipv4 rule
    assert_eq!(
        ipv4_rules[0].decision,
        Decision::Proxy(Some("ipv4_proxy".to_string()))
    );

    // Verify first ipv6 rule
    assert_eq!(ipv6_rules[0].decision, Decision::Direct);
}

#[test]
fn test_ipversion_case_insensitive_parsing() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        ipversion:IPv4=direct
        ipversion:IPV6=proxy
        ipversion:IpV4=reject
    "#;

    let rules = parse_rules(rules_text);

    // All should be parsed correctly regardless of case
    assert_eq!(rules.len(), 3);

    assert!(
        rules
            .iter()
            .filter(|r| matches!(r.kind, RuleKind::IpVersionV4))
            .count()
            == 2
    );
    assert!(
        rules
            .iter()
            .filter(|r| matches!(r.kind, RuleKind::IpVersionV6))
            .count()
            == 1
    );
}

#[test]
fn test_ipversion_unknown_version_skipped() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        ipversion:ipv4=direct
        ipversion:ipv5=proxy
        ipversion:invalid=reject
        default=direct
    "#;

    let rules = parse_rules(rules_text);

    // Only ipv4 and default should be present, unknown versions skipped
    assert_eq!(rules.len(), 2);

    assert!(rules
        .iter()
        .any(|r| matches!(r.kind, RuleKind::IpVersionV4)));
    assert!(rules.iter().any(|r| matches!(r.kind, RuleKind::Default)));
}

#[test]
fn test_ipversion_combined_with_cidr_rules() {
    use std::net::Ipv4Addr;

    let rules = vec![
        Rule {
            kind: RuleKind::IpCidr("10.0.0.0/8".parse().unwrap()),
            decision: Decision::Direct, // Private network direct
        },
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("ipv4_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::IpVersionV6,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // CIDR rule should take precedence over ipversion
    let ctx1 = RouteCtx {
        domain: Some("internal.example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Direct);

    // Ipversion rule should apply for non-matching IPs
    let ctx2 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("ipv4_proxy".to_string()))
    );
}

#[test]
fn test_real_world_dual_stack_routing() {
    // Real-world scenario: Prefer IPv6 direct, proxy IPv4 through VPN
    let rules = vec![
        Rule {
            kind: RuleKind::IpVersionV6,
            decision: Decision::Direct, // IPv6 is fast and secure
        },
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("vpn_proxy".to_string())), // IPv4 through VPN
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // IPv6 connections go direct
    let ctx_v6 = RouteCtx {
        domain: Some("www.example.com"),
        ip: Some(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
        ))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_v6), Decision::Direct);

    // IPv4 connections go through VPN proxy
    let ctx_v4 = RouteCtx {
        domain: Some("www.example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_v4),
        Decision::Proxy(Some("vpn_proxy".to_string()))
    );
}
