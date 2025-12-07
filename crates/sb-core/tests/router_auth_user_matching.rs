#![cfg(feature = "router")]
//! Integration tests for Auth User matching
//!
//! Tests the routing engine's ability to route based on proxy authentication credentials.
//! This enables user-specific routing policies in multi-user proxy scenarios.
//!
//! Use cases:
//! - Multi-user proxy with different routing policies per user
//! - User-specific access control
//! - Enterprise proxy with department-specific routing
//! - Premium vs free user routing policies

use sb_core::router::rules::{Decision, Engine, RouteCtx, Rule, RuleKind};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_auth_user_exact_match() {
    let rules = vec![
        Rule {
            kind: RuleKind::AuthUser("alice".to_string()),
            decision: Decision::Proxy(Some("vip_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match user "alice"
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("vip_proxy".to_string()))
    );

    // Should not match user "bob"
    let ctx_bob = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("bob"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_bob), Decision::Direct);
}

#[test]
fn test_auth_user_case_insensitive() {
    let rules = vec![
        Rule {
            kind: RuleKind::AuthUser("Alice".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match case-insensitively
    let test_cases = vec!["alice", "ALICE", "Alice", "AlIcE"];
    for username in test_cases {
        let ctx = RouteCtx {
            domain: Some("example.com"),
            ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            transport_udp: false,
            port: Some(443),
            process_name: None,
            process_path: None,
            inbound_tag: None,
            outbound_tag: None,
            auth_user: Some(username),
            query_type: None,
            ..Default::default()
        };
        assert_eq!(
            engine.decide(&ctx),
            Decision::Proxy(None),
            "Username {} should match case-insensitively",
            username
        );
    }
}

#[test]
fn test_auth_user_priority_after_process() {
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("blocked.com".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::ProcessName("firefox".to_string()),
            decision: Decision::Proxy(Some("browser_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::AuthUser("alice".to_string()),
            decision: Decision::Proxy(Some("vip_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Domain rule should beat auth_user
    let ctx1 = RouteCtx {
        domain: Some("blocked.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // Process rule should beat auth_user
    let ctx2 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: Some("firefox"),
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("browser_proxy".to_string()))
    );

    // Auth_user rule should apply when no higher priority rules match
    let ctx3 = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx3),
        Decision::Proxy(Some("vip_proxy".to_string()))
    );
}

#[test]
fn test_auth_user_no_user_fallback() {
    let rules = vec![
        Rule {
            kind: RuleKind::AuthUser("alice".to_string()),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Without auth_user, should use default
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx), Decision::Direct);
}

#[test]
fn test_multiple_auth_user_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::AuthUser("alice".to_string()),
            decision: Decision::Proxy(Some("vip_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::AuthUser("bob".to_string()),
            decision: Decision::Proxy(Some("standard_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::AuthUser("charlie".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // Test alice routing
    let ctx_alice = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_alice),
        Decision::Proxy(Some("vip_proxy".to_string()))
    );

    // Test bob routing
    let ctx_bob = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("bob"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_bob),
        Decision::Proxy(Some("standard_proxy".to_string()))
    );

    // Test charlie routing
    let ctx_charlie = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("charlie"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_charlie), Decision::Direct);

    // Test unknown user
    let ctx_unknown = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("dave"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_unknown), Decision::Reject);
}

#[test]
fn test_parse_rules_with_auth_user() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        auth_user:alice=proxy:vip_proxy
        auth_user:bob=proxy:standard_proxy
        auth_user:charlie=direct
        default=reject
    "#;

    let rules = parse_rules(rules_text);

    // Should have 4 rules (3 auth_user + 1 default)
    assert_eq!(rules.len(), 4);

    // Check auth_user rules
    assert!(rules
        .iter()
        .any(|r| matches!(r.kind, RuleKind::AuthUser(_))));

    // Verify alice rule
    let alice_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::AuthUser(u) if u == "alice"))
        .expect("Should have alice rule");
    assert_eq!(
        alice_rule.decision,
        Decision::Proxy(Some("vip_proxy".to_string()))
    );

    // Verify bob rule
    let bob_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::AuthUser(u) if u == "bob"))
        .expect("Should have bob rule");
    assert_eq!(
        bob_rule.decision,
        Decision::Proxy(Some("standard_proxy".to_string()))
    );

    // Verify charlie rule
    let charlie_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::AuthUser(u) if u == "charlie"))
        .expect("Should have charlie rule");
    assert_eq!(charlie_rule.decision, Decision::Direct);
}

#[test]
fn test_real_world_multi_user_proxy() {
    // Real-world scenario: Enterprise proxy with department-specific routing
    let rules = vec![
        // VIP users get premium proxy
        Rule {
            kind: RuleKind::AuthUser("ceo".to_string()),
            decision: Decision::Proxy(Some("premium_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::AuthUser("cto".to_string()),
            decision: Decision::Proxy(Some("premium_proxy".to_string())),
        },
        // Engineering team gets dev proxy
        Rule {
            kind: RuleKind::AuthUser("alice_eng".to_string()),
            decision: Decision::Proxy(Some("dev_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::AuthUser("bob_eng".to_string()),
            decision: Decision::Proxy(Some("dev_proxy".to_string())),
        },
        // Sales team gets standard proxy
        Rule {
            kind: RuleKind::AuthUser("charlie_sales".to_string()),
            decision: Decision::Proxy(Some("standard_proxy".to_string())),
        },
        // Interns get limited direct access
        Rule {
            kind: RuleKind::AuthUser("intern1".to_string()),
            decision: Decision::Direct,
        },
        // Unknown users rejected
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Reject,
        },
    ];

    let engine = Engine::build(rules);

    // Test VIP routing
    let ctx_ceo = RouteCtx {
        domain: Some("www.example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("ceo"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_ceo),
        Decision::Proxy(Some("premium_proxy".to_string()))
    );

    // Test engineering routing
    let ctx_eng = RouteCtx {
        domain: Some("github.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("alice_eng"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_eng),
        Decision::Proxy(Some("dev_proxy".to_string()))
    );

    // Test sales routing
    let ctx_sales = RouteCtx {
        domain: Some("salesforce.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(13, 110, 54, 128))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("charlie_sales"),
        ..Default::default()
    };
    assert_eq!(
        engine.decide(&ctx_sales),
        Decision::Proxy(Some("standard_proxy".to_string()))
    );

    // Test intern routing (direct)
    let ctx_intern = RouteCtx {
        domain: Some("wikipedia.org"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(208, 80, 154, 224))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("intern1"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_intern), Decision::Direct);

    // Test unknown user (rejected)
    let ctx_unknown = RouteCtx {
        domain: Some("example.com"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: Some("hacker"),
        ..Default::default()
    };
    assert_eq!(engine.decide(&ctx_unknown), Decision::Reject);
}
