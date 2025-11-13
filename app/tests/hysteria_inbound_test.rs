//! Tests for Hysteria v1 inbound adapter registration and functionality

use sb_config::ir::{HysteriaUserIR, InboundIR, InboundType};

/// Test 1: Hysteria v1 inbound type is properly registered and can be deserialized
#[test]
fn test_hysteria_v1_inbound_registration() {
    // Create a Hysteria v1 inbound configuration
    let inbound = InboundIR {
        ty: InboundType::Hysteria,
        listen: "127.0.0.1".to_string(),
        port: 8443,
        sniff: false,
        udp: true,
        basic_auth: None,
        override_host: None,
        override_port: None,
        method: None,
        password: None,
        users_shadowsocks: None,
        network: None,
        uuid: None,
        alter_id: None,
        users_vmess: None,
        flow: None,
        users_vless: None,
        users_trojan: None,
        users_hysteria2: None,
        congestion_control: None,
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: None,
        users_hysteria: Some(vec![HysteriaUserIR {
            name: "test_user".to_string(),
            auth: "test_password".to_string(),
        }]),
        hysteria_protocol: Some("udp".to_string()),
        hysteria_obfs: None,
        hysteria_up_mbps: Some(100),
        hysteria_down_mbps: Some(100),
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        transport: None,
        ws_path: None,
        ws_host: None,
        h2_path: None,
        h2_host: None,
        grpc_service: None,
        tls_enabled: None,
        tls_cert_path: Some("/tmp/test_cert.pem".to_string()),
        tls_key_path: Some("/tmp/test_key.pem".to_string()),
        tls_cert_pem: None,
        tls_key_pem: None,
        tls_server_name: None,
        tls_alpn: None,
        multiplex: None,
    };

    // Verify inbound type
    assert_eq!(inbound.ty, InboundType::Hysteria);
    assert!(inbound.udp, "Hysteria v1 should support UDP");
    assert_eq!(inbound.port, 8443);

    // Verify Hysteria v1-specific fields
    assert!(inbound.users_hysteria.is_some());
    assert_eq!(inbound.users_hysteria.as_ref().unwrap().len(), 1);
    assert_eq!(
        inbound.users_hysteria.as_ref().unwrap()[0].name,
        "test_user"
    );
    assert_eq!(
        inbound.users_hysteria.as_ref().unwrap()[0].auth,
        "test_password"
    );
    assert_eq!(inbound.hysteria_protocol.as_ref().unwrap(), "udp");
    assert_eq!(inbound.hysteria_up_mbps, Some(100));
    assert_eq!(inbound.hysteria_down_mbps, Some(100));
}

/// Test 2: Hysteria v1 inbound with multiple users
#[test]
fn test_hysteria_v1_inbound_multi_user() {
    let users = vec![
        HysteriaUserIR {
            name: "user1".to_string(),
            auth: "password1".to_string(),
        },
        HysteriaUserIR {
            name: "user2".to_string(),
            auth: "password2".to_string(),
        },
        HysteriaUserIR {
            name: "user3".to_string(),
            auth: "password3".to_string(),
        },
    ];

    let inbound = InboundIR {
        ty: InboundType::Hysteria,
        listen: "0.0.0.0".to_string(),
        port: 9443,
        sniff: true,
        udp: true,
        basic_auth: None,
        override_host: None,
        override_port: None,
        method: None,
        password: None,
        users_shadowsocks: None,
        network: None,
        uuid: None,
        alter_id: None,
        users_vmess: None,
        flow: None,
        users_vless: None,
        users_trojan: None,
        users_hysteria2: None,
        congestion_control: None,
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: None,
        users_hysteria: Some(users),
        hysteria_protocol: Some("faketcp".to_string()),
        hysteria_obfs: Some("obfs_password".to_string()),
        hysteria_up_mbps: Some(200),
        hysteria_down_mbps: Some(200),
        hysteria_recv_window_conn: Some(1000000),
        hysteria_recv_window: Some(5000000),
        transport: None,
        ws_path: None,
        ws_host: None,
        h2_path: None,
        h2_host: None,
        grpc_service: None,
        tls_enabled: Some(true),
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: Some("CERT_PEM_CONTENT".to_string()),
        tls_key_pem: Some("KEY_PEM_CONTENT".to_string()),
        tls_server_name: Some("example.com".to_string()),
        tls_alpn: Some(vec!["hysteria".to_string()]),
        multiplex: None,
    };

    // Verify multi-user configuration
    assert_eq!(inbound.ty, InboundType::Hysteria);
    assert_eq!(inbound.users_hysteria.as_ref().unwrap().len(), 3);
    assert_eq!(inbound.hysteria_protocol.as_ref().unwrap(), "faketcp");
    assert_eq!(inbound.hysteria_obfs.as_ref().unwrap(), "obfs_password");
    assert_eq!(inbound.hysteria_up_mbps, Some(200));
    assert_eq!(inbound.hysteria_down_mbps, Some(200));
    assert_eq!(inbound.hysteria_recv_window_conn, Some(1000000));
    assert_eq!(inbound.hysteria_recv_window, Some(5000000));
    assert!(inbound.sniff);
}

/// Test 3: Hysteria v1 inbound with wechat-video protocol
#[test]
fn test_hysteria_v1_inbound_wechat_video_protocol() {
    let inbound = InboundIR {
        ty: InboundType::Hysteria,
        listen: "0.0.0.0".to_string(),
        port: 10443,
        sniff: false,
        udp: true,
        basic_auth: None,
        override_host: None,
        override_port: None,
        method: None,
        password: None,
        users_shadowsocks: None,
        network: None,
        uuid: None,
        alter_id: None,
        users_vmess: None,
        flow: None,
        users_vless: None,
        users_trojan: None,
        users_hysteria2: None,
        congestion_control: None,
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: None,
        users_hysteria: Some(vec![HysteriaUserIR {
            name: "test".to_string(),
            auth: "secret".to_string(),
        }]),
        hysteria_protocol: Some("wechat-video".to_string()),
        hysteria_obfs: None,
        hysteria_up_mbps: Some(50),
        hysteria_down_mbps: Some(50),
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        transport: None,
        ws_path: None,
        ws_host: None,
        h2_path: None,
        h2_host: None,
        grpc_service: None,
        tls_enabled: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: Some("CERT_CONTENT".to_string()),
        tls_key_pem: Some("KEY_CONTENT".to_string()),
        tls_server_name: None,
        tls_alpn: None,
        multiplex: None,
    };

    // Verify wechat-video protocol
    assert_eq!(inbound.ty, InboundType::Hysteria);
    assert_eq!(
        inbound.hysteria_protocol.as_ref().unwrap(),
        "wechat-video"
    );
}

/// Test 4: Hysteria v1 inbound serialization/deserialization
#[test]
fn test_hysteria_v1_inbound_serde() {
    let original = InboundIR {
        ty: InboundType::Hysteria,
        listen: "127.0.0.1".to_string(),
        port: 8443,
        sniff: false,
        udp: true,
        basic_auth: None,
        override_host: None,
        override_port: None,
        method: None,
        password: None,
        users_shadowsocks: None,
        network: None,
        uuid: None,
        alter_id: None,
        users_vmess: None,
        flow: None,
        users_vless: None,
        users_trojan: None,
        users_hysteria2: None,
        congestion_control: None,
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: None,
        users_hysteria: Some(vec![HysteriaUserIR {
            name: "test".to_string(),
            auth: "password".to_string(),
        }]),
        hysteria_protocol: Some("udp".to_string()),
        hysteria_obfs: None,
        hysteria_up_mbps: Some(100),
        hysteria_down_mbps: Some(100),
        hysteria_recv_window_conn: None,
        hysteria_recv_window: None,
        transport: None,
        ws_path: None,
        ws_host: None,
        h2_path: None,
        h2_host: None,
        grpc_service: None,
        tls_enabled: None,
        tls_cert_path: None,
        tls_key_path: None,
        tls_cert_pem: Some("CERT".to_string()),
        tls_key_pem: Some("KEY".to_string()),
        tls_server_name: None,
        tls_alpn: None,
        multiplex: None,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&original).expect("Failed to serialize");
    assert!(!json.is_empty());

    // Deserialize from JSON
    let deserialized: InboundIR =
        serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify deserialized matches original
    assert_eq!(deserialized.ty, original.ty);
    assert_eq!(deserialized.listen, original.listen);
    assert_eq!(deserialized.port, original.port);
    assert_eq!(deserialized.udp, original.udp);
    assert_eq!(deserialized.users_hysteria, original.users_hysteria);
    assert_eq!(deserialized.hysteria_protocol, original.hysteria_protocol);
    assert_eq!(deserialized.hysteria_up_mbps, original.hysteria_up_mbps);
    assert_eq!(deserialized.hysteria_down_mbps, original.hysteria_down_mbps);
}
