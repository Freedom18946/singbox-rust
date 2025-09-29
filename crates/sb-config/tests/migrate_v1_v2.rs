use serde_json::json;

#[test]
fn migrate_v1_to_v2_moves_rules_and_default() {
    let v1 = json!({
        "outbounds": [{"type":"direct","name":"direct"}],
        "rules": [{"domain_suffix":["example.com"],"outbound":"direct"}],
        "default_outbound":"direct"
    });
    let v2 = sb_config::compat::migrate_to_v2(&v1);
    assert_eq!(v2["schema_version"], 2);
    assert!(v2.get("rules").is_none());
    assert!(v2.get("default_outbound").is_none());
    assert!(v2["route"]["rules"].is_array());
    assert_eq!(v2["route"]["default"], "direct");
}

#[test]
fn migrate_normalizes_socks5_type() {
    let v1 = json!({
        "outbounds": [{"type":"socks5","name":"s","server":"127.0.0.1","port":1080}],
        "rules": [{"domain_suffix":["example.com"],"outbound":"s"}]
    });
    let v2 = sb_config::compat::migrate_to_v2(&v1);
    assert_eq!(v2["outbounds"][0]["type"], "socks");
}

#[test]
fn unknown_field_rejected_by_v2_validator_without_allow() {
    let mut v = json!({
        "inbounds":[],
        "outbounds": [{"type":"direct","name":"direct"}],
        "route": { "rules": [], "default":"direct" }
    });
    // inject unknown
    v["extra_unknown"] = json!(true);
    let issues = sb_config::validator::v2::validate_v2(&v);
    let has_unknown = issues
        .iter()
        .any(|i| i["code"].as_str() == Some("UnknownField"));
    assert!(has_unknown);
}
