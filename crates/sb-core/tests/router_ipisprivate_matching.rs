#![cfg(feature = "router")]
//! Integration tests for IP is-private detection
//!
//! Tests the routing engine's ability to route based on whether an IP address
//! is private (RFC 1918, RFC 4193, loopback, link-local).
//!
//! Use cases:
//! - Route LAN traffic directly (private IPs)
//! - Route internet traffic through proxy (public IPs)
//! - Implement split routing based on network scope
//! - Optimize routing for local vs remote destinations

use sb_core::router::rules::{Decision, Engine, RouteCtx, Rule, RuleKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_ipisprivate_ipv4_private_ranges() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // RFC 1918 private ranges

    // 10.0.0.0/8
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Direct);

    // 172.16.0.0/12
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);

    // 172.31.255.254 (end of range)
    let ctx3 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);

    // 192.168.0.0/16
    let ctx4 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx4), Decision::Direct);
}

#[test]
fn test_ipisprivate_ipv4_loopback_and_linklocal() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Loopback: 127.0.0.0/8
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Direct);

    // Link-local: 169.254.0.0/16
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);
}

#[test]
fn test_ipisprivate_ipv4_public_addresses() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Public IP: 8.8.8.8 (Google DNS)
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Proxy(None));

    // Public IP: 1.1.1.1 (Cloudflare DNS)
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Proxy(None));

    // Public IP: 93.184.216.34 (example.com)
    let ctx3 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Proxy(None));
}

#[test]
fn test_ipisprivate_ipv6_ula() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // ULA: fc00::/7
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Direct);

    // ULA: fd00::/8
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);
}

#[test]
fn test_ipisprivate_ipv6_linklocal_and_loopback() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Link-local: fe80::/10
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Direct);

    // Loopback: ::1
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);
}

#[test]
fn test_ipisprivate_ipv6_public_addresses() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Public IPv6: 2001:4860:4860::8888 (Google DNS)
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        ))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Proxy(None));

    // Public IPv6: 2606:2800:220:1:248:1893:25c8:1946 (example.com)
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
        ))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Proxy(None));
}

#[test]
fn test_ipisprivate_priority_after_ipversion() {
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("example.com".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::IpVersionV4,
            decision: Decision::Proxy(Some("ipv4_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Domain rule should beat ipisprivate
    let ctx1 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // IpVersion rule should beat ipisprivate
    let ctx2 = RouteCtx {
        domain: Some("other.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
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
fn test_ipisprivate_no_ip_fallback() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
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
    assert_eq!(engine.decide(&ctx), Decision::Proxy(None));
}

#[test]
fn test_parse_rules_with_ipisprivate() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        ip_is_private=direct
        default=proxy
    "#;

    let rules = parse_rules(rules_text);

    // Should have 2 rules (ip_is_private + default)
    assert_eq!(rules.len(), 2);

    // Check ip_is_private rule
    assert!(rules
        .iter()
        .any(|r| matches!(r.kind, RuleKind::IpIsPrivate)));

    let ipisprivate_rule = rules
        .iter()
        .find(|r| matches!(r.kind, RuleKind::IpIsPrivate))
        .expect("Should have ip_is_private rule");
    assert_eq!(ipisprivate_rule.decision, Decision::Direct);
}

#[test]
fn test_ipisprivate_combined_with_cidr_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpCidr("10.1.0.0/16".parse().unwrap()),
            decision: Decision::Reject, // Specific subnet blocked
        },
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct, // Other private IPs direct
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // CIDR rule should take precedence
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // Other private IPs should match ipisprivate
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);
}

#[test]
fn test_real_world_lan_routing() {
    // Real-world scenario: Direct route LAN traffic, proxy internet traffic
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(Some("internet_proxy".to_string())),
        },
    ];

    let engine = Engine::build(rules);

    // LAN traffic (private IPs) goes direct
    let lan_ips = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 10)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    ];

    for ip in lan_ips {
        let ctx = RouteCtx {
            domain: None,
            ip: Some(ip),
            transport_udp: false,
            port: Some(443),
            ..Default::default()
        };
        assert_eq!(
            engine.decide(&ctx),
            Decision::Direct,
            "{} should be routed direct",
            ip
        );
    }

    // Internet traffic (public IPs) goes through proxy
    let internet_ips = vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    ];

    for ip in internet_ips {
        let ctx = RouteCtx {
            domain: None,
            ip: Some(ip),
            transport_udp: false,
            port: Some(443),
            ..Default::default()
        };
        assert_eq!(
            engine.decide(&ctx),
            Decision::Proxy(Some("internet_proxy".to_string())),
            "{} should be routed through proxy",
            ip
        );
    }
}

#[test]
fn test_ipisprivate_edge_cases() {
    let rules = vec![
        Rule {
            kind: RuleKind::IpIsPrivate,
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Edge of 172.16.0.0/12 range
    // 172.15.255.255 (just before range) - should NOT match
    let ctx1 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Proxy(None));

    // 172.16.0.0 (start of range) - should match
    let ctx2 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);

    // 172.31.255.255 (end of range) - should match
    let ctx3 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);

    // 172.32.0.0 (just after range) - should NOT match
    let ctx4 = RouteCtx {
        domain: None,
        ip: Some(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))),
        transport_udp: false,
        port: Some(443),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx4), Decision::Proxy(None));
}
