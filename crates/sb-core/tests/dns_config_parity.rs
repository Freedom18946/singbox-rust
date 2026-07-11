#![cfg(feature = "router")]
use sb_config::ir::{ConfigIR, DnsIR, DnsServerIR};
use sb_core::dns::config_builder::resolver_from_ir;

#[test]
fn test_config_fixture_cache_settings() {
    // Fixture: DNS config with specific cache/TTL settings
    let dns_ir = DnsIR {
        ttl_default_s: Some(300),
        ttl_min_s: Some(60),
        ttl_max_s: Some(3600),
        ttl_neg_s: Some(5),
        servers: vec![DnsServerIR {
            tag: "local".into(),
            address: "local".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir = ConfigIR {
        dns: Some(dns_ir),
        ..Default::default()
    };

    let resolver = resolver_from_ir(&ir).expect("IR-backed resolver");
    assert!(!resolver.name().is_empty());
}

#[test]
fn test_config_fixture_reverse_mapping_fakeip() {
    // Fixture: DNS config with FakeIP enabled (Reverse Mapping)
    let dns_ir = DnsIR {
        fakeip_enabled: Some(true),
        fakeip_v4_base: Some("198.18.0.0".to_string()),
        fakeip_v4_mask: Some(15),
        servers: vec![DnsServerIR {
            tag: "local".into(),
            address: "local".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir = ConfigIR {
        dns: Some(dns_ir),
        ..Default::default()
    };

    let resolver = resolver_from_ir(&ir).expect("IR-backed fakeip resolver");
    assert!(!resolver.name().is_empty());
}
