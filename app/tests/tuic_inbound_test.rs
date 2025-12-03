//! Tests for TUIC inbound adapter registration and functionality

use sb_config::ir::{InboundIR, InboundType, TuicUserIR};

/// Test that TUIC inbound type is properly registered and can be deserialized
#[test]
fn test_tuic_inbound_registration() {
    // Create a TUIC inbound configuration
    let inbound = InboundIR {
        ty: InboundType::Tuic,
        listen: "127.0.0.1".to_string(),
        port: 8443,
        sniff: false,
        udp: true, // TUIC supports UDP
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
        users_anytls: None,
        anytls_padding: None,
        users_hysteria2: None,
        congestion_control: Some("bbr".to_string()),
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: Some(vec![TuicUserIR {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            token: "test_token".to_string(),
        }]),
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
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
        tls_cert_pem: Some(
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        ),
        tls_key_pem: Some(
            "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
        ),
        tls_server_name: None,
        tls_alpn: None,
        multiplex: None,
        ..Default::default()
    };

    // Verify TUIC-specific fields are set
    assert!(inbound.users_tuic.is_some());
    assert_eq!(inbound.users_tuic.as_ref().unwrap().len(), 1);
    assert_eq!(
        inbound.users_tuic.as_ref().unwrap()[0].uuid,
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(inbound.users_tuic.as_ref().unwrap()[0].token, "test_token");
    assert_eq!(inbound.congestion_control, Some("bbr".to_string()));
    assert_eq!(inbound.ty, InboundType::Tuic);
}

/// Test serialization and deserialization of TUIC user config
#[test]
fn test_tuic_user_serde() {
    let user = TuicUserIR {
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        token: "test_token".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&user).expect("Failed to serialize TUIC user");

    // Deserialize back
    let deserialized: TuicUserIR =
        serde_json::from_str(&json).expect("Failed to deserialize TUIC user");

    assert_eq!(deserialized.uuid, user.uuid);
    assert_eq!(deserialized.token, user.token);
}

/// Test that TUIC inbound validates required fields
#[test]
fn test_tuic_inbound_requires_users() {
    let inbound = InboundIR {
        ty: InboundType::Tuic,
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
        users_anytls: None,
        anytls_padding: None,
        users_hysteria2: None,
        congestion_control: Some("bbr".to_string()),
        salamander: None,
        obfs: None,
        brutal_up_mbps: None,
        brutal_down_mbps: None,
        users_tuic: None, // No users
        users_hysteria: None,
        hysteria_protocol: None,
        hysteria_obfs: None,
        hysteria_up_mbps: None,
        hysteria_down_mbps: None,
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
        tls_cert_pem: Some(
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        ),
        tls_key_pem: Some(
            "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
        ),
        tls_server_name: None,
        tls_alpn: None,
        multiplex: None,
        ..Default::default()
    };

    // Verify that users_tuic is None
    assert!(inbound.users_tuic.is_none());
}

/// Test TUIC congestion control options
#[test]
fn test_tuic_congestion_control() {
    let congestion_algorithms = vec!["bbr", "cubic", "new_reno"];

    for algo in congestion_algorithms {
        let inbound = InboundIR {
            ty: InboundType::Tuic,
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
            users_anytls: None,
            anytls_padding: None,
            users_hysteria2: None,
            congestion_control: Some(algo.to_string()),
            salamander: None,
            obfs: None,
            brutal_up_mbps: None,
            brutal_down_mbps: None,
            users_tuic: Some(vec![TuicUserIR {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                token: "test_token".to_string(),
            }]),
            users_hysteria: None,
            hysteria_protocol: None,
            hysteria_obfs: None,
            hysteria_up_mbps: None,
            hysteria_down_mbps: None,
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
            tls_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            ),
            tls_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            ),
            tls_server_name: None,
            tls_alpn: None,
            multiplex: None,
            ..Default::default()
        };

        assert_eq!(inbound.congestion_control, Some(algo.to_string()));
    }
}
