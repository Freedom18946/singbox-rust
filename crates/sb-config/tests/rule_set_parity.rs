use sb_config::validator::v2::{to_ir_v1, validate_v2};
use serde_json::json;

#[test]
fn test_rule_set_inline_defaults() {
    let config = json!({
        "route": {
            "rule_set": [
                {
                    "tag": "inline-default",
                    "rules": [
                        { "domain_suffix": ["example.com"], "outbound": "direct" }
                    ]
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let rule_set = &ir.route.rule_set[0];
    assert_eq!(rule_set.ty, "inline");
    assert_eq!(rule_set.format, "");
    assert!(rule_set.version.is_none());
    assert!(rule_set.rules.as_ref().is_some());
}

#[test]
fn test_rule_set_format_inference() {
    let config = json!({
        "route": {
            "rule_set": [
                { "tag": "local-src", "type": "local", "path": "rules.json" },
                { "tag": "remote-bin", "type": "remote", "url": "https://example.com/rules.srs" }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    assert_eq!(ir.route.rule_set[0].format, "source");
    assert_eq!(ir.route.rule_set[1].format, "binary");
}

#[test]
fn test_rule_set_missing_format_errors() {
    let config = json!({
        "schema_version": 2,
        "route": {
            "rule_set": [
                { "tag": "local-missing", "type": "local", "path": "rules.dat" }
            ]
        }
    });

    let issues = validate_v2(&config, false);
    assert!(issues.iter().any(|i| {
        i["kind"] == "error"
            && i["ptr"] == "/route/rule_set/0/format"
            && i["code"] == "MissingRequired"
    }));
}

#[test]
fn test_rule_set_invalid_version_errors() {
    let config = json!({
        "schema_version": 2,
        "route": {
            "rule_set": [
                { "tag": "remote-version", "type": "remote", "format": "source", "version": 99, "url": "https://example.com/rules.json" }
            ]
        }
    });

    let issues = validate_v2(&config, false);
    assert!(issues.iter().any(|i| {
        i["kind"] == "error"
            && i["ptr"] == "/route/rule_set/0/version"
            && i["code"] == "TypeMismatch"
    }));
}
