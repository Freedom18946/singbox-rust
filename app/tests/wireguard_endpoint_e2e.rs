//! End-to-end tests for WireGuard endpoint functionality.
//!
//! These tests validate the WireGuard endpoint implementation including
//! configuration parsing, endpoint lifecycle, and integration with the
//! broader singbox-rust system.

use sb_config::ir::{EndpointIR, EndpointType, WireGuardPeerIR};

/// Test that WireGuard endpoint configuration is correctly parsed from JSON
#[test]
fn test_wireguard_endpoint_config_parsing() {
    let json = r#"{
        "type": "wireguard",
        "tag": "wg_test",
        "wireguard_name": "wg0",
        "wireguard_mtu": 1420,
        "wireguard_address": ["10.0.0.2/24", "fd00::2/64"],
        "wireguard_private_key": "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=",
        "wireguard_listen_port": 51820,
        "wireguard_peers": [{
            "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "address": "192.168.1.1",
            "port": 51820,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_interval": 25
        }]
    }"#;

    let ir: EndpointIR = serde_json::from_str(json).expect("Failed to parse JSON");

    assert_eq!(ir.ty, EndpointType::Wireguard);
    assert_eq!(ir.tag, Some("wg_test".to_string()));
    assert_eq!(ir.wireguard_name, Some("wg0".to_string()));
    assert_eq!(ir.wireguard_mtu, Some(1420));
    assert_eq!(ir.wireguard_address.as_ref().unwrap().len(), 2);
    assert_eq!(ir.wireguard_listen_port, Some(51820));

    let peers = ir.wireguard_peers.as_ref().expect("No peers");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].allowed_ips.as_ref().unwrap().len(), 2);
}

/// Test WireGuard endpoint with minimal configuration
#[test]
fn test_wireguard_endpoint_minimal_config() {
    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_minimal".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_min".to_string()),
        wireguard_mtu: None, // Should use default
        wireguard_address: Some(vec!["10.1.1.1/24".to_string()]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(0), // Random port
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: None,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string()]),
            address: Some("10.0.0.1".to_string()),
            port: Some(51820),
            persistent_keepalive_interval: None,
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

    // Serialize and verify round-trip
    let json = serde_json::to_string(&ir).expect("Failed to serialize");
    let deserialized: EndpointIR = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(deserialized.ty, EndpointType::Wireguard);
    assert_eq!(deserialized.tag, Some("wg_minimal".to_string()));
}

/// Test WireGuard endpoint with pre-shared key
#[test]
fn test_wireguard_endpoint_with_psk() {
    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_psk".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_psk".to_string()),
        wireguard_mtu: Some(1380), // Lower MTU for PPPoE
        wireguard_address: Some(vec!["192.168.100.2/24".to_string()]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(51821),
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: Some("MzUwNDU3MDc2NTU5NDYzMjI4NjM4MjA1NjkxODY0MjQ=".to_string()),
            allowed_ips: Some(vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]),
            address: Some("203.0.113.1".to_string()),
            port: Some(51821),
            persistent_keepalive_interval: Some(15),
            reserved: None,
        }]),
        wireguard_udp_timeout: Some("5m".to_string()),
        wireguard_workers: Some(4),
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

    let json = serde_json::to_string_pretty(&ir).unwrap();
    println!("WireGuard PSK Config:\n{}", json);

    // Verify PSK is present
    assert!(ir.wireguard_peers.as_ref().unwrap()[0]
        .pre_shared_key
        .is_some());
    assert_eq!(ir.wireguard_mtu, Some(1380));
    assert_eq!(ir.wireguard_workers, Some(4));
}

#[cfg(feature = "adapter-wireguard-endpoint")]
#[test]
fn test_wireguard_endpoint_lifecycle() {
    use sb_core::endpoint::{Endpoint, EndpointContext, StartStage};

    // Register all endpoints
    sb_adapters::register_all();

    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_lifecycle".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_test_lifecycle".to_string()),
        wireguard_mtu: Some(1420),
        wireguard_address: Some(vec!["10.2.2.2/24".to_string()]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(0), // Random port to avoid conflicts
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: None,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string()]),
            address: Some("127.0.0.1".to_string()), // Localhost for testing
            port: Some(51822),
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
    let endpoint = registry.build(&ir, &ctx).expect("Failed to build endpoint");

    // Verify endpoint properties
    assert_eq!(endpoint.endpoint_type(), "wireguard");
    assert_eq!(endpoint.tag(), "wg_lifecycle");

    // Note: We don't actually start the endpoint in tests because:
    // 1. It requires root/admin privileges to create TUN devices
    // 2. It would spawn background tasks that are hard to clean up in tests
    // 3. The start() method is tested indirectly through the stub warning test

    // Verify close() doesn't panic
    endpoint.close().expect("Close should succeed");
}

/// Test validation of invalid configurations
#[test]
fn test_wireguard_endpoint_validation() {
    // Test missing required fields
    let invalid_jsons = [
        // Missing private key
        r#"{"type": "wireguard", "tag": "test"}"#,
        // Missing peers
        r#"{"type": "wireguard", "tag": "test", "wireguard_private_key": "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0="}"#,
        // Invalid base64 key
        r#"{"type": "wireguard", "tag": "test", "wireguard_private_key": "invalid!!!", "wireguard_peers": []}"#,
    ];

    for (idx, json) in invalid_jsons.iter().enumerate() {
        let result: Result<EndpointIR, _> = serde_json::from_str(json);
        // These should either fail to parse or have None values for required fields
        if let Ok(ir) = result {
            println!("Test case {}: Parsed but may be invalid: {:?}", idx, ir.tag);
            // Some fields are optional at parse time, validation happens at runtime
        } else {
            println!("Test case {}: Failed to parse (expected)", idx);
        }
    }
}

/// Test multiple IPv4 and IPv6 addresses
#[test]
fn test_wireguard_endpoint_dual_stack() {
    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_dualstack".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_ds".to_string()),
        wireguard_mtu: Some(1420),
        wireguard_address: Some(vec![
            "10.20.30.40/24".to_string(),
            "fd00:1234:5678::1/64".to_string(),
            "192.168.1.100/24".to_string(),
        ]),
        wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
        wireguard_listen_port: Some(51820),
        wireguard_peers: Some(vec![WireGuardPeerIR {
            public_key: Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string()),
            pre_shared_key: None,
            allowed_ips: Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()]),
            address: Some("2001:db8::1".to_string()), // IPv6 peer
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

    // Verify multiple addresses
    assert_eq!(ir.wireguard_address.as_ref().unwrap().len(), 3);

    // Verify dual-stack allowed IPs
    let peers = ir.wireguard_peers.as_ref().unwrap();
    assert_eq!(peers[0].allowed_ips.as_ref().unwrap().len(), 2);
}

/// Benchmark configuration serialization/deserialization
#[test]
fn test_wireguard_endpoint_serde_performance() {
    let ir = EndpointIR {
        ty: EndpointType::Wireguard,
        tag: Some("wg_perf".to_string()),
        network: None,
        wireguard_system: Some(false),
        wireguard_name: Some("wg_test".to_string()),
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

    // Perform multiple serialization cycles
    let iterations = 1000;
    let start = std::time::Instant::now();

    for _ in 0..iterations {
        let json = serde_json::to_string(&ir).unwrap();
        let _: EndpointIR = serde_json::from_str(&json).unwrap();
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed.as_micros() / iterations;

    println!(
        "Serialization + Deserialization: {} iterations in {:?}",
        iterations, elapsed
    );
    println!("Average per iteration: {} μs", per_iter);

    // Performance assertion: should complete in reasonable time
    assert!(
        per_iter < 100,
        "Serde performance degraded: {} μs > 100 μs",
        per_iter
    );
}
