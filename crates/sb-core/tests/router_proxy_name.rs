#![cfg(feature = "router")]
use sb_core::router::rules::{parse_rules, Decision};

#[test]
fn test_router_proxy_name_parsing() {
    let rules_text = r#"
        exact:example.com = proxy:poolA
        suffix:.internal = proxy:poolB
        keyword:ads = reject
        default = proxy
    "#;

    let rules = parse_rules(rules_text);

    // Should have 4 rules (3 specific + 1 default)
    assert_eq!(rules.len(), 4);

    // Check exact rule with named pool
    let exact_rule = rules.iter().find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Exact(domain) if domain == "example.com")).unwrap();
    match &exact_rule.decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "poolA"),
        _ => assert!(false, "Expected Proxy decision with pool name 'poolA'"),
    }

    // Check suffix rule with named pool
    let suffix_rule = rules.iter().find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Suffix(suffix) if suffix == ".internal")).unwrap();
    match &suffix_rule.decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "poolB"),
        _ => assert!(false, "Expected Proxy decision with pool name 'poolB'"),
    }

    // Check keyword rule with reject
    let keyword_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Keyword(kw) if kw == "ads"))
        .unwrap();
    match &keyword_rule.decision {
        Decision::Reject => {}
        _ => assert!(false, "Expected Reject decision for ads keyword"),
    }

    // Check default rule with generic proxy
    let default_rule = rules
        .iter()
        .find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Default))
        .unwrap();
    match &default_rule.decision {
        Decision::Proxy(None) => {}
        _ => assert!(false, "Expected Proxy decision with no specific pool name"),
    }
}

#[test]
fn test_router_proxy_name_decision_from_str() {
    use sb_core::router::rules::Decision;

    // Test parsing different decision strings
    assert_eq!(Decision::parse_decision("direct"), Some(Decision::Direct));
    assert_eq!(
        Decision::parse_decision("proxy"),
        Some(Decision::Proxy(None))
    );
    assert_eq!(
        Decision::parse_decision("proxy:poolA"),
        Some(Decision::Proxy(Some("poolA".to_string())))
    );
    assert_eq!(
        Decision::parse_decision("proxy:my-pool"),
        Some(Decision::Proxy(Some("my-pool".to_string())))
    );
    assert_eq!(Decision::parse_decision("reject"), Some(Decision::Reject));

    // Test case insensitive parsing
    assert_eq!(Decision::parse_decision("DIRECT"), Some(Decision::Direct));
    assert_eq!(
        Decision::parse_decision("PROXY"),
        Some(Decision::Proxy(None))
    );
    assert_eq!(Decision::parse_decision("REJECT"), Some(Decision::Reject));

    // Test invalid strings
    assert_eq!(Decision::parse_decision("invalid"), None);
    assert_eq!(Decision::parse_decision(""), None);
    assert_eq!(
        Decision::parse_decision("proxy:"),
        Some(Decision::Proxy(Some("".to_string())))
    ); // Edge case
}

#[test]
fn test_router_mixed_proxy_decisions() {
    let rules_text = r#"
        exact:direct.example.com = direct
        exact:proxy.example.com = proxy
        exact:pool1.example.com = proxy:pool1
        exact:pool2.example.com = proxy:pool2
        suffix:.reject = reject
        default = proxy:default_pool
    "#;

    let rules = parse_rules(rules_text);
    assert_eq!(rules.len(), 6);

    // Verify each rule has the correct decision type
    let decisions: std::collections::HashMap<String, Decision> = rules
        .into_iter()
        .filter_map(|rule| match &rule.kind {
            sb_core::router::rules::RuleKind::Exact(domain) => {
                Some((domain.clone(), rule.decision))
            }
            sb_core::router::rules::RuleKind::Suffix(suffix) => {
                Some((suffix.clone(), rule.decision))
            }
            sb_core::router::rules::RuleKind::Default => {
                Some(("default".to_string(), rule.decision))
            }
            _ => None,
        })
        .collect();

    assert_eq!(decisions.get("direct.example.com"), Some(&Decision::Direct));
    assert_eq!(
        decisions.get("proxy.example.com"),
        Some(&Decision::Proxy(None))
    );
    assert_eq!(
        decisions.get("pool1.example.com"),
        Some(&Decision::Proxy(Some("pool1".to_string())))
    );
    assert_eq!(
        decisions.get("pool2.example.com"),
        Some(&Decision::Proxy(Some("pool2".to_string())))
    );
    assert_eq!(decisions.get(".reject"), Some(&Decision::Reject));
    assert_eq!(
        decisions.get("default"),
        Some(&Decision::Proxy(Some("default_pool".to_string())))
    );
}

#[test]
fn test_router_proxy_name_with_whitespace() {
    let rules_text = r#"
        exact:example.com = proxy:poolA
        exact:test.com = proxy: pool-with-spaces
    "#;

    let rules = parse_rules(rules_text);

    // Should handle whitespace properly
    let pool_a_rule = rules.iter().find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Exact(domain) if domain == "example.com")).unwrap();
    match &pool_a_rule.decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "poolA"),
        _ => assert!(
            false,
            "Expected Proxy decision with pool name 'poolA' for example.com"
        ),
    }

    let pool_spaces_rule = rules.iter().find(|r| matches!(&r.kind, sb_core::router::rules::RuleKind::Exact(domain) if domain == "test.com")).unwrap();
    match &pool_spaces_rule.decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "pool-with-spaces"),
        _ => assert!(
            false,
            "Expected Proxy decision with pool name 'pool-with-spaces'"
        ),
    }
}

#[test]
fn test_router_engine_proxy_name_decisions() {
    use sb_core::router::rules::{Engine, RouteCtx};

    let rules_text = r#"
        exact:pool.example.com = proxy:specialPool
        suffix:.internal = proxy:internalPool
        default = direct
    "#;

    let rules = parse_rules(rules_text);
    let engine = Engine::build(rules);

    // Test exact match with named pool
    let ctx = RouteCtx {
        domain: Some("pool.example.com"),
        ip: None,
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };
    let decision = engine.decide(&ctx);
    match decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "specialPool"),
        _ => assert!(
            false,
            "Expected named proxy decision for exact domain match"
        ),
    }

    // Test suffix match with named pool
    let ctx = RouteCtx {
        domain: Some("service.internal"),
        ip: None,
        transport_udp: false,
        port: Some(80),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };
    let decision = engine.decide(&ctx);
    match decision {
        Decision::Proxy(Some(name)) => assert_eq!(name, "internalPool"),
        _ => assert!(
            false,
            "Expected named proxy decision for suffix domain match"
        ),
    }

    // Test default decision
    let ctx = RouteCtx {
        domain: Some("unknown.com"),
        ip: None,
        transport_udp: false,
        port: Some(443),
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };
    let decision = engine.decide(&ctx);
    assert_eq!(decision, Decision::Direct);
}
