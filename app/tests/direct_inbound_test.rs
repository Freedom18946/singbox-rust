//! Test for Direct inbound adapter registration and instantiation.

use sb_core::adapter::InboundParam;

#[test]
fn test_direct_inbound_instantiation() {
    // Create InboundParam for Direct inbound
    let param = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8080,
        basic_auth: None,
        sniff: false,
        udp: true,
        override_host: Some("1.1.1.1".to_string()),
        override_port: Some(53),
        network: Some("tcp,udp".to_string()),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    // Try to build the Direct inbound adapter directly
    #[cfg(feature = "adapters")]
    {
        use sb_adapters::inbound::direct::DirectInboundAdapter;

        let result = DirectInboundAdapter::new(&param);
        assert!(
            result.is_ok(),
            "Direct inbound should instantiate successfully with valid params"
        );

        let service = result.unwrap();
        println!("✓ Direct inbound successfully instantiated: {:?}", service);

        // Verify the service has expected properties
        assert!(service.active_connections().is_some());
        assert!(service.udp_sessions_estimate().is_some());
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping Direct inbound test: adapters feature not enabled");
    }
}

#[test]
fn test_direct_inbound_requires_override_host() {
    // Create InboundParam without override_host (should fail)
    let param = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8080,
        basic_auth: None,
        sniff: false,
        udp: true,
        override_host: None, // Missing!
        override_port: Some(53),
        network: Some("tcp".to_string()),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    #[cfg(feature = "adapters")]
    {
        use sb_adapters::inbound::direct::DirectInboundAdapter;

        let result = DirectInboundAdapter::new(&param);
        assert!(
            result.is_err(),
            "Direct inbound should fail without override_host"
        );

        println!("✓ Direct inbound correctly rejects missing override_host");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping Direct inbound validation test: adapters feature not enabled");
    }
}

#[test]
fn test_direct_inbound_requires_override_port() {
    // Create InboundParam without override_port (should fail)
    let param = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8080,
        basic_auth: None,
        sniff: false,
        udp: true,
        override_host: Some("1.1.1.1".to_string()),
        override_port: None, // Missing!
        network: Some("tcp".to_string()),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    #[cfg(feature = "adapters")]
    {
        use sb_adapters::inbound::direct::DirectInboundAdapter;

        let result = DirectInboundAdapter::new(&param);
        assert!(
            result.is_err(),
            "Direct inbound should fail without override_port"
        );

        println!("✓ Direct inbound correctly rejects missing override_port");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping Direct inbound validation test: adapters feature not enabled");
    }
}

#[test]
fn test_direct_inbound_network_modes() {
    // Test TCP only
    let param_tcp = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8080,
        basic_auth: None,
        sniff: false,
        udp: false,
        override_host: Some("1.1.1.1".to_string()),
        override_port: Some(53),
        network: Some("tcp".to_string()),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    // Test UDP only
    let param_udp = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8081,
        basic_auth: None,
        sniff: false,
        udp: true,
        override_host: Some("1.1.1.1".to_string()),
        override_port: Some(53),
        network: Some("udp".to_string()),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    // Test both TCP and UDP
    let param_both = InboundParam {
        kind: "direct".to_string(),
        listen: "127.0.0.1".to_string(),
        port: 8082,
        basic_auth: None,
        sniff: false,
        udp: true,
        override_host: Some("1.1.1.1".to_string()),
        override_port: Some(53),
        network: None, // Default to both
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        congestion_control: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_hysteria2: None,
        obfs: None,
        salamander: None,
        users_tuic: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
    };

    #[cfg(feature = "adapters")]
    {
        use sb_adapters::inbound::direct::DirectInboundAdapter;

        // All network modes should succeed
        assert!(
            DirectInboundAdapter::new(&param_tcp).is_ok(),
            "TCP-only Direct inbound should work"
        );
        assert!(
            DirectInboundAdapter::new(&param_udp).is_ok(),
            "UDP-only Direct inbound should work"
        );
        assert!(
            DirectInboundAdapter::new(&param_both).is_ok(),
            "TCP+UDP Direct inbound should work"
        );

        println!("✓ Direct inbound supports all network modes (tcp, udp, tcp+udp)");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping Direct inbound network modes test: adapters feature not enabled");
    }
}
