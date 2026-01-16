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
