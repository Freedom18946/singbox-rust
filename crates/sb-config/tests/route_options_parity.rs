use sb_config::validator::v2::to_ir_v1;
use serde_json::json;

#[test]
fn test_route_options_parsing() {
    let config = json!({
        "route": {
            "override_android_vpn": true,
            "default_network_type": ["tcp", "udp"],
            "default_fallback_network_type": "tcp",
            "fallback_delay": "300ms",
            "default_domain_resolver": "local"
        }
    });

    let ir = to_ir_v1(&config);
    let route = ir.route;

    assert_eq!(route.override_android_vpn, Some(true));
    assert_eq!(
        route.default_network_type,
        Some(vec!["tcp".to_string(), "udp".to_string()])
    );
    assert_eq!(
        route.default_fallback_network_type,
        Some(vec!["tcp".to_string()])
    );
    assert_eq!(route.default_fallback_delay, Some("300ms".to_string()));

    // Updated verification for default_domain_resolver struct
    assert!(route.default_domain_resolver.is_some());
    let dr = route.default_domain_resolver.unwrap();
    assert_eq!(dr.server, "local");
}

#[test]
fn test_route_options_object_parsing() {
    let config = json!({
        "route": {
            "default_domain_resolver": {
                "server": "dns-remote",
                "strategy": "ipv4_only",
                "disable_cache": true,
                "rewrite_ttl": 60,
                "client_subnet": "1.2.3.0/24"
            }
        }
    });

    let ir = to_ir_v1(&config);
    let route = ir.route;

    assert!(route.default_domain_resolver.is_some());
    let dr = route.default_domain_resolver.unwrap();
    assert_eq!(dr.server, "dns-remote");
    assert_eq!(dr.strategy, Some("ipv4_only".to_string()));
    assert_eq!(dr.disable_cache, Some(true));
    assert_eq!(dr.rewrite_ttl, Some(60));
    assert_eq!(dr.client_subnet, Some("1.2.3.0/24".to_string()));
}

#[test]
fn test_rule_udp_route_action_options_parsing() {
    let config = json!({
        "route": {
            "rules": [
                {
                    "domain": "example.test",
                    "network": "udp",
                    "action": "route-options",
                    "outbound": "direct",
                    "udp_disable_domain_unmapping": true,
                    "udp_connect": true,
                    "udp_timeout": "45s"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let rule = ir.route.rules.first().expect("route rule");

    assert_eq!(rule.domain, vec!["example.test".to_string()]);
    assert_eq!(rule.network, vec!["udp".to_string()]);
    assert_eq!(rule.udp_disable_domain_unmapping, Some(true));
    assert_eq!(rule.udp_connect, Some(true));
    assert_eq!(rule.udp_timeout.as_deref(), Some("45s"));
}

#[test]
fn test_go_11313_route_rule_fields_parsing() {
    let config = json!({
        "route": {
            "rules": [
                {
                    "inbound": "mixed-in",
                    "ip_version": 4,
                    "ip_cidr": "198.51.100.0/24",
                    "ip_is_private": false,
                    "source_ip_cidr": "10.0.0.0/8",
                    "source_geoip": "private",
                    "source_ip_is_private": true,
                    "port_range": "8000-9000",
                    "source_port": 12345,
                    "source_port_range": "2000-3000",
                    "process_path_regex": "^/usr/bin/.+",
                    "auth_user": "alice",
                    "rule_set_ip_cidr": "src-private",
                    "rule_set_ip_cidr_match_source": true,
                    "interface_address": {"en0": "192.0.2.0/24"},
                    "network_interface_address": {"wifi": ["198.51.100.0/24"]},
                    "default_interface_address": "203.0.113.1",
                    "preferred_by": "selector-a",
                    "action": "direct"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let rule = ir.route.rules.first().expect("route rule");

    assert_eq!(rule.inbound, vec!["mixed-in".to_string()]);
    assert_eq!(rule.ip_version, vec!["4".to_string()]);
    assert_eq!(rule.ipcidr, vec!["198.51.100.0/24".to_string()]);
    assert_eq!(rule.ip_is_private, Some(false));
    assert_eq!(rule.source_ip_cidr, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(rule.source_geoip, vec!["private".to_string()]);
    assert_eq!(rule.source_ip_is_private, Some(true));
    assert_eq!(rule.port_range, vec!["8000-9000".to_string()]);
    assert_eq!(rule.source_port, vec!["12345".to_string()]);
    assert_eq!(rule.source_port_range, vec!["2000-3000".to_string()]);
    assert_eq!(rule.process_path_regex, vec!["^/usr/bin/.+".to_string()]);
    assert_eq!(rule.auth_user, vec!["alice".to_string()]);
    assert_eq!(rule.rule_set_ipcidr, vec!["src-private".to_string()]);
    assert_eq!(rule.rule_set_ip_cidr_match_source, Some(true));
    assert_eq!(
        rule.interface_address.get("en0").cloned(),
        Some(vec!["192.0.2.0/24".to_string()])
    );
    assert_eq!(
        rule.network_interface_address.get("wifi").cloned(),
        Some(vec!["198.51.100.0/24".to_string()])
    );
    assert_eq!(
        rule.default_interface_address,
        vec!["203.0.113.1".to_string()]
    );
    assert_eq!(rule.preferred_by, vec!["selector-a".to_string()]);
    assert_eq!(rule.action, sb_config::ir::RuleAction::Direct);
}

#[test]
fn test_go_11313_route_action_options_parsing() {
    let config = json!({
        "route": {
            "rules": [
                {
                    "domain_suffix": "example.test",
                    "action": "route-options",
                    "outbound": "proxy",
                    "override_address": "1.1.1.1",
                    "override_port": 8443,
                    "network_strategy": "prefer_ipv4",
                    "fallback_network_type": "wifi",
                    "fallback_delay": 250,
                    "tls_fragment": true,
                    "tls_fragment_fallback_delay": "50ms"
                }
            ]
        }
    });

    let ir = to_ir_v1(&config);
    let rule = ir.route.rules.first().expect("route rule");

    assert_eq!(rule.override_address.as_deref(), Some("1.1.1.1"));
    assert_eq!(rule.override_port, Some(8443));
    assert_eq!(rule.network_strategy.as_deref(), Some("prefer_ipv4"));
    assert_eq!(rule.fallback_network_type, Some(vec!["wifi".to_string()]));
    assert_eq!(rule.fallback_delay.as_deref(), Some("250ms"));
    assert_eq!(rule.tls_fragment, Some(true));
    assert_eq!(rule.tls_fragment_fallback_delay.as_deref(), Some("50ms"));
}

#[test]
fn test_route_raw_bridge_accepts_listable_interface_address_maps() {
    let rule: sb_config::ir::RuleIR = serde_json::from_value(json!({
        "interface_address": {"en0": "192.0.2.0/24"},
        "network_interface_address": {"wifi": ["198.51.100.1"]},
        "default_interface_address": "203.0.113.1"
    }))
    .expect("raw route rule should accept Go listable maps");

    assert_eq!(
        rule.interface_address.get("en0").cloned(),
        Some(vec!["192.0.2.0/24".to_string()])
    );
    assert_eq!(
        rule.network_interface_address.get("wifi").cloned(),
        Some(vec!["198.51.100.1".to_string()])
    );
    assert_eq!(
        rule.default_interface_address,
        vec!["203.0.113.1".to_string()]
    );
}
