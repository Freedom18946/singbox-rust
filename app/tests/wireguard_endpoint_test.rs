//! Tests for WireGuard endpoint integration.

use sb_config::ir::{EndpointIR, EndpointType, WireGuardPeerIR};

#[test]
fn test_wireguard_endpoint_ir_serialization() {
    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg0".to_string()),
        network: Some(vec!["udp".to_string()]),
        wireguard_system: Some(false),
        wireguard_name: Some("wg0".to_string()),
        wireguard_mtu: Some(1420),
        wireguard_address: Some(vec!["10.0.0.2/24".to_string()]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(51820),
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: None,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string()]),
            address: Some("192.168.1.1".to_string()),
            port: Some(51820),
            persistent_keepalive_interval: Some(25),
            reserved: None,
        }]),
        wireguard_udp_timeout: None,
        wireguard_workers: None,
        tailscale_state_directory: None,
        tailscale_auth_key: None,
        tailscale_control_url: None,
        tailscale_ephemeral: None,
        tailscale_hostname: None,
        tailscale_accept_routes: None,
        tailscale_exit_node: None,
        tailscale_exit_node_allow_lan_access: None,
        tailscale_advertise_routes: None,
        tailscale_advertise_exit_node: None,
        tailscale_udp_timeout: None,
    };

    // Test that IR can be serialized and deserialized
    let json = serde_json::to_string_pretty(&ir).unwrap();
    println!("WireGuard Endpoint IR:\n{}", json);

    let deserialized: EndpointIR = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.ty, EndpointType::Wireguard);
    assert_eq!(deserialized.tag, Some("wg0".to_string()));
    assert_eq!(deserialized.wireguard_mtu, Some(1420));
}

#[cfg(feature = "adapter-wireguard-endpoint")]
#[test]
fn test_wireguard_endpoint_registration() {
    // Register all endpoints
    sb_adapters::register_all();

    let registry = sb_core::endpoint::endpoint_registry();

    // Verify WireGuard endpoint is registered
    let builder = registry.get(EndpointType::Wireguard);
    assert!(builder.is_some(), "WireGuard endpoint should be registered");
}

#[cfg(feature = "adapter-wireguard-endpoint")]
#[test]
fn test_wireguard_endpoint_instantiation() {
    use sb_core::endpoint::EndpointContext;

    // Register all endpoints
    sb_adapters::register_all();

    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_test".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_test".to_string()),
        wireguard_mtu: Some(1420),
        wireguard_address: Some(vec!["10.0.0.2/24".to_string()]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(0), // Random port
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: None,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string()]),
            address: Some("192.168.1.1".to_string()),
            port: Some(51820),
            persistent_keepalive_interval: Some(25),
            reserved: None,
        }]),
        wireguard_udp_timeout: None,
        wireguard_workers: None,
        tailscale_state_directory: None,
        tailscale_auth_key: None,
        tailscale_control_url: None,
        tailscale_ephemeral: None,
        tailscale_hostname: None,
        tailscale_accept_routes: None,
        tailscale_exit_node: None,
        tailscale_exit_node_allow_lan_access: None,
        tailscale_advertise_routes: None,
        tailscale_advertise_exit_node: None,
        tailscale_udp_timeout: None,
    };

    let ctx = EndpointContext::default();
    let registry = sb_core::endpoint::endpoint_registry();
    let endpoint = registry.build(&ir, &ctx);

    assert!(
        endpoint.is_some(),
        "Should be able to build WireGuard endpoint"
    );
    let endpoint = endpoint.unwrap();
    assert_eq!(endpoint.endpoint_type(), "wireguard");
    assert_eq!(endpoint.tag(), "wg_test");
}

#[cfg(not(feature = "adapter-wireguard-endpoint"))]
#[test]
fn test_wireguard_endpoint_stub_warning() {
    use sb_core::endpoint::{EndpointContext, StartStage};

    // Register all endpoints (including stubs)
    sb_adapters::register_all();

    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_stub".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: None,
        wireguard_mtu: None,
        wireguard_address: None,
        wireguard_private_key: None,
        wireguard_listen_port: None,
        wireguard_peers: None,
        wireguard_udp_timeout: None,
        wireguard_workers: None,
        tailscale_state_directory: None,
        tailscale_auth_key: None,
        tailscale_control_url: None,
        tailscale_ephemeral: None,
        tailscale_hostname: None,
        tailscale_accept_routes: None,
        tailscale_exit_node: None,
        tailscale_exit_node_allow_lan_access: None,
        tailscale_advertise_routes: None,
        tailscale_advertise_exit_node: None,
        tailscale_udp_timeout: None,
    };

    let ctx = EndpointContext::default();
    let registry = sb_core::endpoint::endpoint_registry();
    let endpoint = registry.build(&ir, &ctx);

    if sb_adapters::WIREGUARD_ENDPOINT_AVAILABLE {
        // Real endpoint should reject incomplete config.
        assert!(
            endpoint.is_none(),
            "WireGuard endpoint should reject missing config when enabled"
        );
        return;
    }

    // Stub should return an endpoint that fails on start().
    let endpoint = endpoint.expect("Stub should return an endpoint");
    assert!(
        endpoint.start(StartStage::Initialize).is_err(),
        "Stub endpoint should fail on start"
    );
}
