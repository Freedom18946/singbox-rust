//! End-to-end test for IR-driven DNS resolver


#[tokio::test]
async fn dns_ir_hosts_overlay_and_engine_presence() {
    // JSON config with dns.hosts and minimal servers/default
    let json = serde_json::json!({
        "dns": {
            "servers": [ {"tag": "system", "address": "system"} ],
            "default": "system",
            "hosts": { "unit.test.local": ["203.0.113.1", "2001:db8::1"] },
            "hosts_ttl": 123
        }
    });

    // Parse to IR
    let ir = sb_config::validator::v2::to_ir_v1(&json);
    let dns_ir = ir.dns.expect("dns ir expected");

    // Build resolver from IR
    let resolver = sb_core::dns::config_builder::resolver_from_ir(&dns_ir)
        .expect("build resolver from ir");

    // Hosts overlay should resolve without using network
    let ans = resolver.resolve("unit.test.local").await.expect("resolve host");
    assert!(ans.ips.iter().any(|ip| ip.is_ipv4()));
    assert_eq!(ans.ttl.as_secs(), 123);

    // Also verify that when rules exist, the resolver type becomes rule engine
    let json_rules = serde_json::json!({
        "dns": {
            "servers": [ {"tag": "system", "address": "system"} ],
            "default": "system",
            "rules": [ {"domain_suffix": ["example.com"], "server": "system"} ]
        }
    });
    let ir2 = sb_config::validator::v2::to_ir_v1(&json_rules);
    let dns_ir2 = ir2.dns.expect("dns ir expected");
    let resolver2 = sb_core::dns::config_builder::resolver_from_ir(&dns_ir2)
        .expect("build resolver from ir with rules");
    // name() should be "dns_rule_engine" per EngineResolver
    assert_eq!(resolver2.name(), "dns_rule_engine");
}
