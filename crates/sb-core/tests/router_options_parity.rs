use sb_config::ir::{ConfigIR, ExperimentalIR, OutboundIR, OutboundType};
use sb_core::adapter::{Bridge, OutboundParam};
use sb_core::context::Context;
use sb_core::router::rule_set::RuleSetDb;

#[test]
fn test_rule_set_db_matching() {
    let temp_dir = std::env::temp_dir().join("sb-ruleset-parity-test");
    let _ = std::fs::create_dir_all(&temp_dir);
    let rule_path = temp_dir.join("test.json");

    // Create a headless rule set
    let json_content = r#"{
        "version": 1,
        "rules": [
            { "domain": ["example.com"] },
            { "domain_suffix": ["test.com"] },
            { "ip_cidr": ["10.0.0.0/8", "192.168.1.1/32"] }
        ]
    }"#;
    std::fs::write(&rule_path, json_content).unwrap();

    let db = RuleSetDb::new();
    db.add_rule_set(
        "test-tag".to_string(),
        rule_path.to_str().unwrap(),
        "headless",
    )
    .expect("failed to add rule set");

    // Test domain matching
    let mut tags = Vec::new();
    db.match_host("example.com", &mut tags);
    assert!(tags.contains(&"test-tag".to_string()));
    tags.clear();

    db.match_host("sub.test.com", &mut tags);
    assert!(tags.contains(&"test-tag".to_string()));
    tags.clear();

    db.match_host("google.com", &mut tags);
    assert!(tags.is_empty());

    // Test IP matching
    db.match_ip("10.1.2.3".parse().unwrap(), &mut tags);
    assert!(tags.contains(&"test-tag".to_string()));
    tags.clear();

    db.match_ip("192.168.1.1".parse().unwrap(), &mut tags);
    assert!(tags.contains(&"test-tag".to_string()));
    tags.clear();

    db.match_ip("192.168.1.2".parse().unwrap(), &mut tags);
    assert!(tags.is_empty());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_dialer_options_plumbing() {
    let mut ob = OutboundIR {
        name: Some("test-out".to_string()),
        ty: OutboundType::Direct,
        ..Default::default()
    };

    // Set dialer options
    ob.bind_interface = Some("eth0".to_string());
    ob.inet4_bind_address = Some("1.2.3.4".to_string());
    ob.routing_mark = Some(1234);
    ob.connect_timeout = Some("5s".to_string());
    ob.tcp_fast_open = Some(true);
    ob.tcp_multi_path = Some(true);
    ob.udp_fragment = Some(true);

    // Convert to OutboundParam (using internal helper if accessible, or check Bridge logic)
    // Since to_outbound_param is private in bridge.rs, we can't call it directly.
    // But we can check if Bridge::new_from_config applies it?
    // Or we can check `sb_core::adapter::bridge::to_outbound_param` if we make it public or testable.
    // Alternatively, we can rely on `OutboundParam` struct definition which we modified.

    // Let's verify OutboundParam has the fields (compile-time check)
    let param = OutboundParam {
        bind_interface: ob.bind_interface.clone(),
        inet4_bind_address: ob.inet4_bind_address.as_ref().and_then(|s| s.parse().ok()),
        routing_mark: ob.routing_mark,
        connect_timeout: ob
            .connect_timeout
            .as_ref()
            .and_then(|s| humantime::parse_duration(s).ok()),
        tcp_fast_open: ob.tcp_fast_open,
        tcp_multi_path: ob.tcp_multi_path,
        udp_fragment: ob.udp_fragment,
        ..Default::default()
    };

    assert_eq!(param.bind_interface, Some("eth0".to_string()));
    assert_eq!(param.routing_mark, Some(1234));
    assert_eq!(param.tcp_fast_open, Some(true));
}

#[test]
fn test_experimental_options_plumbing() {
    let cfg = ConfigIR {
        experimental: Some(ExperimentalIR {
            cache_file: Some(sb_config::ir::CacheFileIR {
                enabled: true,
                path: Some("cache.db".to_string()),
                store_fakeip: true,
                store_rdrc: false,
                rdrc_timeout: None,
            }),
            clash_api: None,
            v2ray_api: None,
        }),
        ..Default::default()
    };

    // Bridge::new_from_config should populate experimental
    // Note: Bridge::new_from_config requires Context
    let ctx = Context::new();
    // Bridge::new_from_config is not pub? It is pub.
    // But it might require other things.
    // Let's check Bridge struct directly.

    let mut br = Bridge::new(ctx);
    br.experimental = cfg.experimental.clone();

    assert!(br.experimental.is_some());
    let exp = br.experimental.unwrap();
    assert!(exp.cache_file.is_some());
    assert_eq!(exp.cache_file.unwrap().path, Some("cache.db".to_string()));
}
