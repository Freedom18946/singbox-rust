//! Integration tests for DNS query type matching
//!
//! Tests the routing engine's ability to route based on DNS record types.
//! This enables DNS-specific routing policies, allowing different treatment
//! of A, AAAA, CNAME, MX, TXT, and other DNS query types.
//!
//! Use cases:
//! - Route IPv6 queries (AAAA) differently from IPv4 queries (A)
//! - Block or redirect MX queries for email server discovery
//! - Handle TXT record queries for verification/SPF differently
//! - Implement DNS-based routing strategies

use sb_core::router::rules::{Decision, DnsRecordType, Engine, RouteCtx, Rule, RuleKind};

#[test]
fn test_query_type_a_record() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::A),
            decision: Decision::Proxy(Some("ipv4_dns".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match A record query
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("ipv4_dns".to_string()))
    );

    // Should not match AAAA record query
    let ctx_aaaa = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(engine.decide(&ctx_aaaa), Decision::Direct);
}

#[test]
fn test_query_type_aaaa_record() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::AAAA),
            decision: Decision::Proxy(Some("ipv6_dns".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match AAAA record query
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("ipv6_dns".to_string()))
    );

    // Should not match A record query
    let ctx_a = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(engine.decide(&ctx_a), Decision::Direct);
}

#[test]
fn test_query_type_cname_record() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::CNAME),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Proxy(None),
        },
    ];

    let engine = Engine::build(rules);

    // Should match CNAME record query
    let ctx = RouteCtx {
        domain: Some("www.example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::CNAME),
    };
    assert_eq!(engine.decide(&ctx), Decision::Direct);
}

#[test]
fn test_query_type_mx_record() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::MX),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should block MX record queries
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::MX),
    };
    assert_eq!(engine.decide(&ctx), Decision::Reject);
}

#[test]
fn test_query_type_txt_record() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::TXT),
            decision: Decision::Proxy(Some("txt_dns".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Should match TXT record query
    let ctx = RouteCtx {
        domain: Some("_dmarc.example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::TXT),
    };
    assert_eq!(
        engine.decide(&ctx),
        Decision::Proxy(Some("txt_dns".to_string()))
    );
}

#[test]
fn test_query_type_priority_after_process() {
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
            kind: RuleKind::QueryType(DnsRecordType::A),
            decision: Decision::Proxy(Some("dns_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Domain rule should beat query type
    let ctx1 = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // Process rule should beat query type
    let ctx2 = RouteCtx {
        domain: Some("other.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: Some("firefox"),
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("browser_proxy".to_string()))
    );

    // Query type rule should apply when no higher priority rules match
    let ctx3 = RouteCtx {
        domain: Some("other.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(
        engine.decide(&ctx3),
        Decision::Proxy(Some("dns_proxy".to_string()))
    );
}

#[test]
fn test_query_type_no_query_type_fallback() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::A),
            decision: Decision::Proxy(None),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Without query_type, should use default
    let ctx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };
    assert_eq!(engine.decide(&ctx), Decision::Direct);
}

#[test]
fn test_multiple_query_type_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::A),
            decision: Decision::Proxy(Some("ipv4_dns".to_string())),
        },
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::AAAA),
            decision: Decision::Proxy(Some("ipv6_dns".to_string())),
        },
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::MX),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Test A record routing
    let ctx_a = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(
        engine.decide(&ctx_a),
        Decision::Proxy(Some("ipv4_dns".to_string()))
    );

    // Test AAAA record routing
    let ctx_aaaa = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(
        engine.decide(&ctx_aaaa),
        Decision::Proxy(Some("ipv6_dns".to_string()))
    );

    // Test MX record blocking
    let ctx_mx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::MX),
    };
    assert_eq!(engine.decide(&ctx_mx), Decision::Reject);

    // Test TXT record fallback to default
    let ctx_txt = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::TXT),
    };
    assert_eq!(engine.decide(&ctx_txt), Decision::Direct);
}

#[test]
fn test_parse_rules_with_query_type() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        query_type:A=proxy:ipv4_dns
        query_type:AAAA=proxy:ipv6_dns
        query_type:MX=reject
        query_type:TXT=direct
        query_type:CNAME=proxy
        default=direct
    "#;

    let rules = parse_rules(rules_text);

    // Should have 6 rules (5 query type + 1 default)
    assert_eq!(rules.len(), 6);

    // Check A record rule
    let a_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::A)))
        .expect("Should have A record rule");
    assert_eq!(
        a_rule.decision,
        Decision::Proxy(Some("ipv4_dns".to_string()))
    );

    // Check AAAA record rule
    let aaaa_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::AAAA)))
        .expect("Should have AAAA record rule");
    assert_eq!(
        aaaa_rule.decision,
        Decision::Proxy(Some("ipv6_dns".to_string()))
    );

    // Check MX record rule
    let mx_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::MX)))
        .expect("Should have MX record rule");
    assert_eq!(mx_rule.decision, Decision::Reject);

    // Check TXT record rule
    let txt_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::TXT)))
        .expect("Should have TXT record rule");
    assert_eq!(txt_rule.decision, Decision::Direct);

    // Check CNAME record rule
    let cname_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::CNAME)))
        .expect("Should have CNAME record rule");
    assert_eq!(cname_rule.decision, Decision::Proxy(None));
}

#[test]
fn test_query_type_case_insensitive_parsing() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        query_type:a=direct
        query_type:AAAA=proxy
        query_type:Mx=reject
        query_type:txt=direct
    "#;

    let rules = parse_rules(rules_text);

    // All query types should be parsed correctly regardless of case
    assert_eq!(rules.len(), 4);

    assert!(rules
        .iter()
        .any(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::A))));
    assert!(rules
        .iter()
        .any(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::AAAA))));
    assert!(rules
        .iter()
        .any(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::MX))));
    assert!(rules
        .iter()
        .any(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::TXT))));
}

#[test]
fn test_query_type_unknown_type_skipped() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        query_type:A=direct
        query_type:UNKNOWN=proxy
        query_type:INVALID=reject
        default=direct
    "#;

    let rules = parse_rules(rules_text);

    // Only A and default should be present, unknown types skipped
    assert_eq!(rules.len(), 2);

    assert!(rules
        .iter()
        .any(|r| matches!(&r.kind, RuleKind::QueryType(DnsRecordType::A))));
    assert!(rules.iter().any(|r| matches!(&r.kind, RuleKind::Default)));
}

#[test]
fn test_query_type_combined_with_domain_rules() {
    let rules = vec![
        Rule {
            kind: RuleKind::Exact("blocked.example.com".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Suffix(".internal".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::AAAA),
            decision: Decision::Proxy(Some("ipv6_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // Domain rule should take precedence over query type
    let ctx1 = RouteCtx {
        domain: Some("blocked.example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(engine.decide(&ctx1), Decision::Reject);

    // Query type rule should apply for non-matching domains
    let ctx2 = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(
        engine.decide(&ctx2),
        Decision::Proxy(Some("ipv6_proxy".to_string()))
    );
}

#[test]
fn test_real_world_ipv4_ipv6_routing() {
    let rules = vec![
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::A),
            decision: Decision::Proxy(Some("ipv4_dns".to_string())),
        },
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::AAAA),
            decision: Decision::Direct, // Use ISP DNS for IPv6
        },
        Rule {
            kind: RuleKind::QueryType(DnsRecordType::MX),
            decision: Decision::Reject, // Block email server discovery
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    // IPv4 queries routed through proxy DNS
    let ctx_ipv4 = RouteCtx {
        domain: Some("www.example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::A),
    };
    assert_eq!(
        engine.decide(&ctx_ipv4),
        Decision::Proxy(Some("ipv4_dns".to_string()))
    );

    // IPv6 queries go direct to ISP DNS
    let ctx_ipv6 = RouteCtx {
        domain: Some("www.example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::AAAA),
    };
    assert_eq!(engine.decide(&ctx_ipv6), Decision::Direct);

    // MX queries blocked for privacy
    let ctx_mx = RouteCtx {
        domain: Some("example.com"),
        ip: None,
        transport_udp: true,
        port: Some(53),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: Some(DnsRecordType::MX),
    };
    assert_eq!(engine.decide(&ctx_mx), Decision::Reject);
}
