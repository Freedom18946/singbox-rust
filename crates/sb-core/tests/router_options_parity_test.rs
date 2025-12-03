// Test for Config/Route Options Parity
use sb_config::ir::{ConfigIR, RouteIR, RuleIR};

#[test]
fn test_rule_ir_new_fields_serialization() {
    let json = r#"{
        "domain": ["example.com"],
        "domain_suffix": [".google.com", ".github.com"],
        "domain_keyword": ["google", "youtube"],
        "domain_regex": ["^api\\..*", "^stun\\..+"],
        "user_id": [1000, 1001, 1002],
        "user": ["alice", "bob"],
        "group_id": [100, 101],
        "group": ["staff", "admin"],
        "rule_set_ipcidr": ["geoip-cn", "geoip-private"],
        "outbound": "proxy"
    }"#;

    let rule: RuleIR = serde_json::from_str(json).unwrap();

    // Verify domain variants
    assert_eq!(rule.domain.len(), 1);
    assert_eq!(rule.domain_suffix.len(), 2);
    assert_eq!(rule.domain_suffix[0], ".google.com");
    assert_eq!(rule.domain_keyword.len(), 2);
    assert_eq!(rule.domain_keyword[0], "google");
    assert_eq!(rule.domain_regex.len(), 2);
    assert_eq!(rule.domain_regex[0], "^api\\..*");

    // Verify user/group matching
    assert_eq!(rule.user_id.len(), 3);
    assert_eq!(rule.user_id[0], 1000);
    assert_eq!(rule.user.len(), 2);
    assert_eq!(rule.user[0], "alice");
    assert_eq!(rule.group_id.len(), 2);
    assert_eq!(rule.group_id[0], 100);
    assert_eq!(rule.group.len(), 2);
    assert_eq!(rule.group[1], "admin");

    // Verify IP rule sets
    assert_eq!(rule.rule_set_ipcidr.len(), 2);
    assert_eq!(rule.rule_set_ipcidr[0], "geoip-cn");

    assert_eq!(rule.outbound.unwrap(), "proxy");
}

#[test]
fn test_rule_ir_negative_matches() {
    let json = r#"{
        "not_domain_suffix": [".cn"],
        "not_domain_keyword": ["ads"],
        "not_domain_regex": ["^tracker\\..*"],
        "not_user_id": [0],
        "not_group_id": [0],
        "not_rule_set_ipcidr": ["geoip-ir"],
        "outbound": "direct"
    }"#;

    let rule: RuleIR = serde_json::from_str(json).unwrap();

    assert_eq!(rule.not_domain_suffix.len(), 1);
    assert_eq!(rule.not_domain_keyword.len(), 1);
    assert_eq!(rule.not_domain_regex.len(), 1);
    assert_eq!(rule.not_user_id.len(), 1);
    assert_eq!(rule.not_group_id.len(), 1);
    assert_eq!(rule.not_rule_set_ipcidr.len(), 1);
}

#[test]
fn test_rule_ir_alias_support() {
    // Test uid/gid aliases
    let json = r#"{
        "uid": ["user1"],
        "gid": ["group1"],
        "outbound": "proxy"
    }"#;

    let rule: RuleIR = serde_json::from_str(json).unwrap();
    assert_eq!(rule.user.len(), 1);
    assert_eq!(rule.group.len(), 1);
}

#[test]
fn test_route_ir_with_new_fields() {
    let config = ConfigIR {
        route: RouteIR {
            rules: vec![
                RuleIR {
                    domain_regex: vec!["^api\\\\.example\\\\..*".into()],
                    user_id: vec![1000],
                    outbound: Some("proxy".into()),
                    ..Default::default()
                },
                RuleIR {
                    domain_suffix: vec![".cn".into()],
                    group_id: vec![100],
                    outbound: Some("direct".into()),
                    ..Default::default()
                },
            ],
            default: Some("block".into()),
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(config.route.rules.len(), 2);
    assert_eq!(config.route.rules[0].domain_regex.len(), 1);
    assert_eq!(config.route.rules[0].user_id.len(), 1);
    assert_eq!(config.route.rules[1].domain_suffix.len(), 1);
    assert_eq!(config.route.rules[1].group_id.len(), 1);
}

#[cfg(feature = "router")]
#[test]
fn test_router_parsing_new_fields() {
    use sb_core::adapter::bridge::build_bridge;
    use sb_core::context::Context;
    use sb_core::routing::engine::Engine;

    let config = ConfigIR {
        route: RouteIR {
            rules: vec![RuleIR {
                domain_suffix: vec![".google.com".into()],
                user_id: vec![1000],
                outbound: Some("proxy".into()),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    // Build engine and bridge to verify parsing doesn't crash
    let engine_result = Engine::from_ir(&config);
    assert!(
        engine_result.is_ok(),
        "Engine should build from IR with new fields"
    );

    let engine = engine_result.unwrap();
    let context = Context::new();
    let _bridge = build_bridge(&config, engine, context);

    // If we reach here, parsing succeeded
}
