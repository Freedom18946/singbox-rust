use serde_json::json;
use sb_config::validator::v2::to_ir_v1;

#[test]
fn rule_domain_suffix_maps_correctly() {
    let doc = json!({
        "route": {
            "rules": [
                { "domain_suffix": [".example.com"], "outbound": "direct" }
            ]
        }
    });

    let ir = to_ir_v1(&doc);
    assert_eq!(ir.route.rules.len(), 1);
    let rule = &ir.route.rules[0];
    assert_eq!(rule.domain_suffix, vec![".example.com"]);
    assert!(rule.domain.is_empty());
}
