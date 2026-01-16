use sb_config::validator::v2::to_ir_v1;
use serde_json::json;

#[test]
fn test_parse_dns_rule_match_fields() {
    let config = json!({
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "8.8.8.8"
                }
            ],
            "rules": [
                {
                    "ip_is_private": true,
                    "source_ip_is_private": true,
                    "ip_accept_any": true,
                    "rule_set_ip_cidr_match_source": true,
                    "rule_set_ip_cidr_accept_empty": true,
                    "clash_mode": "Global",
                    "network_is_expensive": true,
                    "network_is_constrained": true,
                    "server": "google"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let dns = ir.dns.expect("dns should be present");
    assert!(!dns.rules.is_empty());

    let rule = &dns.rules[0];
    assert_eq!(rule.ip_is_private, Some(true));
    assert_eq!(rule.source_ip_is_private, Some(true));
    assert_eq!(rule.ip_accept_any, Some(true));
    assert_eq!(rule.rule_set_ip_cidr_match_source, Some(true));
    assert_eq!(rule.rule_set_ip_cidr_accept_empty, Some(true));
    assert_eq!(rule.clash_mode, Some("Global".to_string()));
    assert_eq!(rule.network_is_expensive, Some(true));
    assert_eq!(rule.network_is_constrained, Some(true));
}

#[test]
fn test_parse_dns_rule_action_hijack() {
    let config = json!({
        "dns": {
            "servers": [],
            "rules": [
                {
                    "action": "hijack-dns",
                    "rcode": "NXDOMAIN",
                    "answer": ["1.1.1.1"],
                    "ns": ["ns1.example.com"],
                    "extra": ["extra-info"]
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let dns = ir.dns.expect("dns should be present");
    assert!(!dns.rules.is_empty());

    let rule = &dns.rules[0];
    assert_eq!(rule.action.as_deref(), Some("hijack-dns"));
    assert_eq!(rule.rcode.as_deref(), Some("NXDOMAIN"));

    let answer = rule.answer.as_ref().expect("answer should be present");
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0], "1.1.1.1");

    let ns = rule.ns.as_ref().expect("ns should be present");
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0], "ns1.example.com");

    let extra = rule.extra.as_ref().expect("extra should be present");
    assert_eq!(extra.len(), 1);
    assert_eq!(extra[0], "extra-info");
}
