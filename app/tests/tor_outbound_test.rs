//! Test Tor outbound registration and configuration
//!
//! These tests verify that the Tor outbound adapter is correctly registered
//! and can be instantiated with proper configuration.

use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::registry;
use sb_core::adapter::OutboundParam;

fn create_outbound_param(kind: &str, name: &str) -> OutboundParam {
    OutboundParam {
        kind: kind.to_string(),
        name: Some(name.to_string()),
        server: None,
        port: None,
        credentials: None,
        uuid: None,
        token: None,
        password: None,
        congestion_control: None,
        alpn: None,
        skip_cert_verify: None,
        udp_relay_mode: None,
        udp_over_stream: None,
        ssh_private_key: None,
        ssh_private_key_passphrase: None,
        ssh_host_key_verification: None,
        ssh_known_hosts_path: None,
    }
}

#[test]
fn test_tor_outbound_registration() {
    // Register all adapters
    sb_adapters::register::register_all();

    // Try to build a Tor outbound
    let ir = OutboundIR {
        ty: OutboundType::Tor,
        name: Some("tor-out".to_string()),
        tor_proxy_addr: Some("127.0.0.1:9050".to_string()),
        ..Default::default()
    };

    let param = create_outbound_param("tor", "tor-out");

    // Verify that the builder is registered
    let builder = registry::get_outbound("tor");
    assert!(builder.is_some(), "Tor outbound builder should be registered");

    // Build the outbound
    let result = builder.unwrap()(&param, &ir);
    assert!(result.is_some(), "Tor outbound should be buildable");

    let (connector, udp_factory) = result.unwrap();
    // connector is Arc<dyn OutboundConnector>, not Option
    assert!(udp_factory.is_none(), "Tor outbound should not have UDP factory (not yet implemented)");

    // Verify debug format works
    let debug_str = format!("{:?}", connector);
    assert!(!debug_str.is_empty(), "Tor connector should have Debug implementation");
}

#[test]
fn test_tor_outbound_with_default_proxy() {
    // Register all adapters
    sb_adapters::register::register_all();

    // Test with default proxy address (should use 127.0.0.1:9050)
    let ir = OutboundIR {
        ty: OutboundType::Tor,
        name: Some("tor-default".to_string()),
        tor_proxy_addr: None,  // Should use default
        ..Default::default()
    };

    let param = create_outbound_param("tor", "tor-default");

    let builder = registry::get_outbound("tor");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir);
    assert!(result.is_some(), "Tor outbound should work with default proxy address");
}

#[test]
fn test_tor_outbound_with_custom_proxy() {
    // Register all adapters
    sb_adapters::register::register_all();

    // Test with custom proxy address
    let ir = OutboundIR {
        ty: OutboundType::Tor,
        name: Some("tor-custom".to_string()),
        tor_proxy_addr: Some("192.168.1.1:9150".to_string()),
        ..Default::default()
    };

    let param = create_outbound_param("tor", "tor-custom");

    let builder = registry::get_outbound("tor");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir);
    assert!(result.is_some(), "Tor outbound should work with custom proxy address");
}

#[test]
fn test_tor_outbound_debug_format() {
    // Register all adapters
    sb_adapters::register::register_all();

    let ir = OutboundIR {
        ty: OutboundType::Tor,
        name: Some("tor-debug".to_string()),
        ..Default::default()
    };

    let param = create_outbound_param("tor", "tor-debug");

    let builder = registry::get_outbound("tor");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir);
    assert!(result.is_some());

    let (connector, _) = result.unwrap();
    // Verify that Debug formatting works
    let debug_str = format!("{:?}", connector);
    assert!(!debug_str.is_empty(), "Tor connector should have Debug implementation");
}
