//! Test VLESS configuration parsing and validation

use sb_config::Outbound;

#[test]
fn test_vless_config_parsing() {
    let json_config = r#"
    {
        "type": "vless",
        "name": "vless-out",
        "server": "example.com",
        "port": 443,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "flow": "xtls-rprx-vision",
        "network": "tcp",
        "packet_encoding": "xudp",
        "connect_timeout_sec": 30
    }
    "#;

    let outbound: Outbound = serde_json::from_str(json_config).unwrap();

    match outbound {
        Outbound::Vless {
            name,
            server,
            port,
            uuid,
            flow,
            network,
            packet_encoding,
            connect_timeout_sec,
        } => {
            assert_eq!(name, "vless-out");
            assert_eq!(server, "example.com");
            assert_eq!(port, 443);
            assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(flow, Some("xtls-rprx-vision".to_string()));
            assert_eq!(network, "tcp");
            assert_eq!(packet_encoding, Some("xudp".to_string()));
            assert_eq!(connect_timeout_sec, Some(30));
        }
        _ => assert!(false, "Expected VLESS outbound"),
    }
}

#[test]
fn test_vless_config_minimal() {
    let json_config = r#"
    {
        "type": "vless",
        "name": "vless-minimal",
        "server": "example.com",
        "port": 443,
        "uuid": "550e8400-e29b-41d4-a716-446655440000"
    }
    "#;

    let outbound: Outbound = serde_json::from_str(json_config).unwrap();

    match outbound {
        Outbound::Vless {
            name,
            server,
            port,
            uuid,
            flow,
            network,
            packet_encoding,
            connect_timeout_sec,
        } => {
            assert_eq!(name, "vless-minimal");
            assert_eq!(server, "example.com");
            assert_eq!(port, 443);
            assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(flow, None);
            assert_eq!(network, "tcp"); // Default value
            assert_eq!(packet_encoding, None);
            assert_eq!(connect_timeout_sec, None);
        }
        _ => assert!(false, "Expected VLESS outbound"),
    }
}

#[test]
fn test_vless_config_with_udp() {
    let json_config = r#"
    {
        "type": "vless",
        "name": "vless-udp",
        "server": "example.com",
        "port": 443,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "network": "udp",
        "packet_encoding": "packetaddr"
    }
    "#;

    let outbound: Outbound = serde_json::from_str(json_config).unwrap();

    match outbound {
        Outbound::Vless {
            name,
            server,
            port,
            uuid,
            flow,
            network,
            packet_encoding,
            connect_timeout_sec,
        } => {
            assert_eq!(name, "vless-udp");
            assert_eq!(server, "example.com");
            assert_eq!(port, 443);
            assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(flow, None);
            assert_eq!(network, "udp");
            assert_eq!(packet_encoding, Some("packetaddr".to_string()));
            assert_eq!(connect_timeout_sec, None);
        }
        _ => assert!(false, "Expected VLESS outbound"),
    }
}

#[test]
fn test_vless_config_invalid_json() {
    // Missing required fields should fail
    let invalid_configs = vec![
        r#"{"type": "vless"}"#,                 // Missing name, server, port, and uuid
        r#"{"type": "vless", "name": "test"}"#, // Missing server, port, and uuid
        r#"{"type": "vless", "name": "test", "server": "example.com"}"#, // Missing port and uuid
    ];

    for invalid_config in invalid_configs {
        let result: Result<Outbound, _> = serde_json::from_str(invalid_config);
        assert!(result.is_err(), "Should fail to parse: {}", invalid_config);
    }
}

#[test]
fn test_vless_config_serialization_roundtrip() {
    let outbound = Outbound::Vless {
        name: "vless-test".to_string(),
        server: "example.com".to_string(),
        port: 443,
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        packet_encoding: Some("xudp".to_string()),
        connect_timeout_sec: Some(15),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&outbound).unwrap();

    // Deserialize back
    let deserialized: Outbound = serde_json::from_str(&json).unwrap();

    // Verify it matches
    match (&outbound, &deserialized) {
        (
            Outbound::Vless {
                name: n1,
                server: s1,
                port: p1,
                uuid: u1,
                flow: f1,
                network: net1,
                packet_encoding: pe1,
                connect_timeout_sec: ct1,
            },
            Outbound::Vless {
                name: n2,
                server: s2,
                port: p2,
                uuid: u2,
                flow: f2,
                network: net2,
                packet_encoding: pe2,
                connect_timeout_sec: ct2,
            },
        ) => {
            assert_eq!(n1, n2);
            assert_eq!(s1, s2);
            assert_eq!(p1, p2);
            assert_eq!(u1, u2);
            assert_eq!(f1, f2);
            assert_eq!(net1, net2);
            assert_eq!(pe1, pe2);
            assert_eq!(ct1, ct2);
        }
        _ => assert!(false, "Expected VLESS outbound after deserialization"),
    }
}
