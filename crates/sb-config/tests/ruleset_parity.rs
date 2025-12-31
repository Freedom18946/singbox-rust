use serde_json::json;
use sb_config::validator::v2::to_ir_v1;

#[test]
fn test_ruleset_parity() {
    let config = json!({
        "route": {
            "rule_set": [
                {
                    "tag": "inline-set",
                    "type": "inline",
                    "rules": [
                        { "domain": "example.com", "action": "reject" }
                    ]
                },
                {
                    "tag": "remote-binary",
                    "type": "remote",
                    "url": "https://example.com/clean.srs"
                },
                {
                    "tag": "remote-source",
                    "type": "remote",
                    "url": "https://example.com/rules.json"
                },
                {
                    "tag": "local-source",
                    "type": "local",
                    "path": "/etc/sing-box/rules.json"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let rule_sets = ir.route.rule_set;

    assert_eq!(rule_sets.len(), 4);

    // Inline
    let r0 = &rule_sets[0];
    assert_eq!(r0.tag, "inline-set");
    assert_eq!(r0.ty, "inline");
    assert!(r0.rules.is_some());
    let r0_rules = r0.rules.as_ref().unwrap();
    assert_eq!(r0_rules.len(), 1);
    assert_eq!(r0_rules[0].domain, vec!["example.com"]);

    // Binary (default)
    let r1 = &rule_sets[1];
    assert_eq!(r1.format, "binary");

    // Remote Source (inference)
    let r2 = &rule_sets[2];
    assert_eq!(r2.format, "source");

    // Local Source (inference)
    let r3 = &rule_sets[3];
    assert_eq!(r3.format, "source");
}
