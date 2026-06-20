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

#[test]
fn p1313_03_parse_go_dns_rule_fields_and_logical_rules() {
    let config = json!({
        "dns": {
            "servers": [
                {"tag": "dns-direct", "address": "8.8.8.8"}
            ],
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {
                            "domain": "example.com",
                            "inbound": ["tun-in"],
                            "ip_version": [4],
                            "query_type": ["A"],
                            "source_geoip": "cn",
                            "network": "udp",
                            "auth_user": "alice",
                            "protocol": "tls",
                            "source_port_range": "1000:2000",
                            "port_range": "53:853",
                            "process_path_regex": "/Applications/.+",
                            "user": "bob",
                            "user_id": [501],
                            "outbound": "proxy",
                            "network_type": "wifi",
                            "interface_address": {"en0": ["192.0.2.1"]},
                            "network_interface_address": {"wifi": ["192.0.2.2"]},
                            "default_interface_address": "192.0.2.3"
                        }
                    ],
                    "action": "route-options",
                    "strategy": "ipv4_only",
                    "rewrite_ttl": 30,
                    "disable_cache": true,
                    "client_subnet": "1.2.3.0/24",
                    "server": "dns-direct"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let dns = ir.dns.expect("dns should be present");
    let rule = &dns.rules[0];
    assert_eq!(rule.rule_type.as_deref(), Some("logical"));
    assert_eq!(rule.mode.as_deref(), Some("and"));
    assert_eq!(rule.strategy.as_deref(), Some("ipv4_only"));
    assert_eq!(rule.rules.len(), 1);

    let nested = &rule.rules[0];
    assert_eq!(nested.domain, vec!["example.com"]);
    assert_eq!(nested.inbound, vec!["tun-in"]);
    assert_eq!(nested.ip_version, vec!["4"]);
    assert_eq!(nested.source_geoip, vec!["cn"]);
    assert_eq!(nested.network, vec!["udp"]);
    assert_eq!(nested.auth_user, vec!["alice"]);
    assert_eq!(nested.protocol, vec!["tls"]);
    assert_eq!(nested.port_range, vec!["53:853"]);
    assert_eq!(nested.source_port_range, vec!["1000:2000"]);
    assert_eq!(nested.process_path_regex, vec!["/Applications/.+"]);
    assert_eq!(nested.user, vec!["bob"]);
    assert_eq!(nested.user_id, vec![501]);
    assert_eq!(nested.outbound, vec!["proxy"]);
    assert_eq!(nested.network_type, vec!["wifi"]);
    assert_eq!(
        nested.interface_address.get("en0").cloned(),
        Some(vec!["192.0.2.1".to_string()])
    );
}

#[test]
fn p1313_03_rejects_deprecated_rule_set_ipcidr_alias() {
    let config = json!({
        "dns": {
            "servers": [{"tag": "dns-direct", "address": "8.8.8.8"}],
            "rules": [
                {
                    "rule_set_ipcidr_match_source": true,
                    "server": "dns-direct"
                }
            ]
        }
    });

    let result = serde_json::from_value::<sb_config::ir::RawConfigRoot>(config);
    assert!(
        result.is_err(),
        "Raw DNS rule boundary must reject deprecated rule_set_ipcidr_match_source"
    );
}
