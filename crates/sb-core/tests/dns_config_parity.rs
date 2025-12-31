#![cfg(feature = "router")]
use sb_core::dns::config_builder::resolver_from_ir;
use sb_config::ir::{DnsIR, DnsServerIR};
use std::env;

#[test]
fn test_config_fixture_cache_settings() {
    // Fixture: DNS config with specific cache/TTL settings
    let mut ir = DnsIR::default();
    ir.ttl_default_s = Some(300);
    ir.ttl_min_s = Some(60);
    ir.ttl_max_s = Some(3600);
    ir.ttl_neg_s = Some(5);
    ir.servers.push(DnsServerIR {
        tag: "local".into(),
        address: "local".into(),
        ..Default::default()
    });

    // Clear env to ensure we are testing IR -> Env propagation
    env::remove_var("SB_DNS_DEFAULT_TTL_S");
    env::remove_var("SB_DNS_MIN_TTL_S");
    
    let _ = resolver_from_ir(&ir);

    // Verify side effects (env vars set by apply_env_from_ir)
    assert_eq!(env::var("SB_DNS_DEFAULT_TTL_S").unwrap(), "300");
    assert_eq!(env::var("SB_DNS_MIN_TTL_S").unwrap(), "60");
    assert_eq!(env::var("SB_DNS_MAX_TTL_S").unwrap(), "3600");
    assert_eq!(env::var("SB_DNS_NEG_TTL_S").unwrap(), "5");
}

#[test]
fn test_config_fixture_reverse_mapping_fakeip() {
    // Fixture: DNS config with FakeIP enabled (Reverse Mapping)
    let mut ir = DnsIR::default();
    ir.fakeip_enabled = Some(true);
    ir.fakeip_v4_base = Some("198.18.0.0".to_string());
    ir.fakeip_v4_mask = Some(15);
    ir.servers.push(DnsServerIR {
        tag: "local".into(),
        address: "local".into(),
        ..Default::default()
    });

    env::remove_var("SB_DNS_FAKEIP_ENABLE");
    env::remove_var("SB_FAKEIP_V4_BASE");

    let _ = resolver_from_ir(&ir);

    assert_eq!(env::var("SB_DNS_FAKEIP_ENABLE").unwrap(), "1");
    assert_eq!(env::var("SB_FAKEIP_V4_BASE").unwrap(), "198.18.0.0");
    assert_eq!(env::var("SB_FAKEIP_V4_MASK").unwrap(), "15");
}
