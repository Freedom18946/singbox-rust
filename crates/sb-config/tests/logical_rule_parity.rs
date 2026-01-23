use sb_config::validator::v2::to_ir_v1;
use serde_json::json;

#[test]
fn test_logical_rule_parsing_sets_type_and_mode() {
    let config = json!({
        "route": {
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        { "domain_suffix": ["example.com"], "outbound": "direct" },
                        { "domain": ["example.org"], "outbound": "direct" }
                    ],
                    "outbound": "direct"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    assert_eq!(ir.route.rules.len(), 1);

    let rule = &ir.route.rules[0];
    assert_eq!(rule.rule_type.as_deref(), Some("logical"));
    assert_eq!(rule.mode.as_deref(), Some("and"));
    assert_eq!(rule.rules.len(), 2);
    assert_eq!(rule.outbound.as_deref(), Some("direct"));
    assert_eq!(rule.rules[0].domain_suffix, vec!["example.com"]);
    assert_eq!(rule.rules[1].domain, vec!["example.org"]);
}
