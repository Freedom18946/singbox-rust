//! Integration tests for inbound/outbound tag matching
//!
//! Tests the routing engine's ability to route based on inbound/outbound adapter tags.
//! This allows for routing decisions based on:
//! - Which inbound adapter received the connection (e.g., http, socks5, tun)
//! - Which outbound adapter is being considered (e.g., direct, proxy, wireguard)
//!
//! Use cases:
//! - Route traffic from specific inbounds differently (e.g., all HTTP inbound → proxy)
//! - Block or allow traffic based on outbound selection
//! - Implement inbound-specific routing policies

use sb_core::router::rules::{Decision, Engine, RouteCtx, Rule, RuleKind};

#[test]
fn test_inbound_tag_exact_match() {
    let rules = vec![
        Rule {
            kind: RuleKind::InboundTag("http".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Match: inbound is "http"
    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Proxy(None));

    // No match: inbound is "socks5"
    let ctx2 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Direct);

    // No match: no inbound tag
    let ctx3 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);
}

#[test]
fn test_outbound_tag_exact_match() {
    let rules = vec![
        Rule {
            kind: RuleKind::OutboundTag("direct".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Match: outbound is "direct"
    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: Some("direct"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Reject);

    // No match: outbound is "proxy"
    let ctx2 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: Some("proxy"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Proxy(None));
}

#[test]
fn test_inbound_tag_case_insensitive() {
    let rules = vec![
        Rule {
            kind: RuleKind::InboundTag("HTTP".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Match with lowercase
    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Proxy(None));

    // Match with uppercase
    let ctx2 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("HTTP"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Proxy(None));

    // Match with mixed case
    let ctx3 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("HtTp"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Proxy(None));
}

#[test]
fn test_combined_inbound_and_domain_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("google.com".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::InboundTag("socks5".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Exact domain match takes priority
    let ctx = RouteCtx {
        domain: Some("google.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Proxy(None));

    // Inbound match when domain doesn't match
    let ctx2 = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Reject);

    // No match → default
    let ctx3 = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);
}

#[test]
fn test_inbound_and_outbound_together() {
    let rules = vec![
        Rule {
            kind: RuleKind::InboundTag("http".to_string()),
            decision: Decision::Proxy(Some("proxy1".to_string())),
        },
        Rule {
            kind: RuleKind::OutboundTag("wireguard".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Inbound match takes priority (checked first)
    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: Some("wireguard"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("proxy1".to_string()))
    );

    // Outbound match when inbound doesn't match
    let ctx2 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: Some("wireguard"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx2), Decision::Reject);

    // No match → default
    let ctx3 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("tun"),
        outbound_tag: Some("direct"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);
}

#[test]
fn test_priority_order_with_inbound_outbound() {
    // Test that priority order is: exact → suffix → keyword → inbound → outbound → ip → ...
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("priority.test".to_string()),
            decision: Decision::Proxy(Some("rule1".to_string())),
        },
        Rule {
            kind: RuleKind::InboundTag("http".to_string()),
            decision: Decision::Proxy(Some("rule2".to_string())),
        },
        Rule {
            kind: RuleKind::IpCidr("10.0.0.0/8".parse().unwrap()),
            decision: Decision::Proxy(Some("rule3".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Exact domain wins (highest priority)
    let ctx = RouteCtx {
        domain: Some("priority.test"),
        ip: Some("10.0.0.1".parse().unwrap()),
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("rule1".to_string()))
    );

    // Inbound wins (no exact match)
    let ctx2 = RouteCtx {
        domain: Some("other.test"),
        ip: Some("10.0.0.1".parse().unwrap()),
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("rule2".to_string()))
    );

    // IP wins (no exact or inbound match)
    let ctx3 = RouteCtx {
        domain: Some("other.test"),
        ip: Some("10.0.0.1".parse().unwrap()),
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx3),
        Decision::Proxy(Some("rule3".to_string()))
    );
}

#[test]
fn test_parse_rules_with_inbound_outbound() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
inbound:http=proxy
outbound:direct=reject
exact:google.com=proxy
default=direct
"#;

    let rules = parse_rules(rules_text);
    assert_eq!(rules.len(), 4);

    // Check that inbound rule was parsed correctly
    let inbound_rule = rules
        .iter()
        .find(|r| matches!(r.kind, RuleKind::InboundTag(_)));
    assert!(inbound_rule.is_some());
    if let Some(r) = inbound_rule {
        assert!(matches!(r.kind, RuleKind::InboundTag(ref tag) if tag == "http"));
        assert_eq!(r.decision, Decision::Proxy(None));
    }

    // Check that outbound rule was parsed correctly
    let outbound_rule = rules
        .iter()
        .find(|r| matches!(r.kind, RuleKind::OutboundTag(_)));
    assert!(outbound_rule.is_some());
    if let Some(r) = outbound_rule {
        assert!(matches!(r.kind, RuleKind::OutboundTag(ref tag) if tag == "direct"));
        assert_eq!(r.decision, Decision::Reject);
    }
}

#[test]
fn test_multiple_inbound_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::InboundTag("http".to_string()),
            decision: Decision::Proxy(Some("proxy1".to_string())),
        },
        Rule {
            kind: RuleKind::InboundTag("socks5".to_string()),
            decision: Decision::Proxy(Some("proxy2".to_string())),
        },
        Rule {
            kind: RuleKind::InboundTag("tun".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // HTTP inbound → proxy1
    let ctx1 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx1),
        Decision::Proxy(Some("proxy1".to_string()))
    );

    // SOCKS5 inbound → proxy2
    let ctx2 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("proxy2".to_string()))
    );

    // TUN inbound → direct
    let ctx3 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("tun"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx3), Decision::Direct);

    // Unknown inbound → default (reject)
    let ctx4 = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("unknown"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx4), Decision::Reject);
}

#[test]
fn test_real_world_scenario_selective_proxy() {
    // Scenario: Route all traffic from TUN to proxy, but HTTP/SOCKS inbound goes direct
    let rules = vec![
        Rule {
            kind: RuleKind::InboundTag("http".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::InboundTag("socks5".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::InboundTag("tun".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // TUN → proxy
    let ctx_tun = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("tun"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_tun), Decision::Proxy(None));

    // HTTP → direct
    let ctx_http = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("http"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_http), Decision::Direct);

    // SOCKS5 → direct
    let ctx_socks = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: Some("socks5"),
        outbound_tag: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_socks), Decision::Direct);
}
