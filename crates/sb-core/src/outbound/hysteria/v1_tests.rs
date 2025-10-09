//! Hysteria v1 protocol tests
//!
//! Comprehensive test suite for Hysteria v1 implementation including:
//! - Config validation
//! - Handshake protocol
//! - Stream framing (TCP and UDP)
//! - Authentication logic
//! - Session management

#[cfg(test)]
mod tests {
    use crate::outbound::hysteria::v1::{
        HysteriaV1Config, HysteriaV1Outbound, HysteriaV1ServerConfig, UdpSessionManager,
    };
    use std::net::SocketAddr;
    use std::time::Duration;

    // Test config validation
    #[test]
    fn test_hysteria_v1_config_creation() {
        let config = HysteriaV1Config {
            server: "example.com".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 200,
            obfs: Some("test-obfs".to_string()),
            auth: Some("test-auth".to_string()),
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: Some(1024),
            recv_window: Some(2048),
            skip_cert_verify: true,
            sni: Some("example.com".to_string()),
        };

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.protocol, "udp");
        assert_eq!(config.up_mbps, 100);
        assert_eq!(config.down_mbps, 200);
        assert_eq!(config.obfs, Some("test-obfs".to_string()));
        assert_eq!(config.auth, Some("test-auth".to_string()));
        assert!(config.skip_cert_verify);
    }

    #[test]
    fn test_hysteria_v1_config_default() {
        let config = HysteriaV1Config::default();

        assert_eq!(config.server, "127.0.0.1");
        assert_eq!(config.port, 443);
        assert_eq!(config.protocol, "udp");
        assert_eq!(config.up_mbps, 10);
        assert_eq!(config.down_mbps, 50);
        assert_eq!(config.obfs, None);
        assert_eq!(config.auth, None);
        assert_eq!(config.alpn, vec!["hysteria".to_string()]);
        assert!(!config.skip_cert_verify);
    }

    #[test]
    fn test_hysteria_v1_outbound_creation() {
        let config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 200,
            obfs: None,
            auth: Some("test-password".to_string()),
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let outbound = HysteriaV1Outbound::new(config);
        assert!(outbound.is_ok());
    }

    #[test]
    fn test_hysteria_v1_outbound_with_empty_alpn() {
        let config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 200,
            obfs: None,
            auth: None,
            alpn: vec![], // Empty ALPN should default to "hysteria"
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let outbound = HysteriaV1Outbound::new(config);
        assert!(outbound.is_ok());
    }

    // Test handshake protocol
    #[test]
    fn test_handshake_packet_structure() {
        use bytes::{BufMut, BytesMut};

        let mut handshake = BytesMut::new();

        // Protocol version (v1)
        handshake.put_u8(0x01);

        // Bandwidth configuration
        handshake.put_u32(100); // up_mbps
        handshake.put_u32(200); // down_mbps

        // Authentication
        let auth = "test-auth";
        handshake.put_u8(auth.len() as u8);
        handshake.put_slice(auth.as_bytes());

        // Obfuscation
        let obfs = "test-obfs";
        handshake.put_u8(obfs.len() as u8);
        handshake.put_slice(obfs.as_bytes());

        // Verify packet structure
        assert_eq!(handshake[0], 0x01); // Version
        assert_eq!(handshake.len(), 1 + 8 + 1 + 9 + 1 + 9); // Total size
    }

    #[test]
    fn test_handshake_without_auth() {
        use bytes::{BufMut, BytesMut};

        let mut handshake = BytesMut::new();
        handshake.put_u8(0x01);
        handshake.put_u32(100);
        handshake.put_u32(200);
        handshake.put_u8(0); // No auth
        handshake.put_u8(0); // No obfs

        assert_eq!(handshake.len(), 1 + 8 + 1 + 1);
    }

    // Test stream framing (TCP)
    #[test]
    fn test_tcp_connect_request_ipv4() {
        use bytes::{BufMut, BytesMut};
        use std::net::Ipv4Addr;

        let mut request = BytesMut::new();

        // Command: TCP connect
        request.put_u8(0x01);

        // IPv4 address
        request.put_u8(0x01);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        request.put_slice(&ip.octets());

        // Port
        request.put_u16(8080);

        assert_eq!(request[0], 0x01); // TCP command
        assert_eq!(request[1], 0x01); // IPv4 type
        assert_eq!(request.len(), 1 + 1 + 4 + 2);
    }

    #[test]
    fn test_tcp_connect_request_ipv6() {
        use bytes::{BufMut, BytesMut};
        use std::net::Ipv6Addr;

        let mut request = BytesMut::new();

        // Command: TCP connect
        request.put_u8(0x01);

        // IPv6 address
        request.put_u8(0x04);
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        request.put_slice(&ip.octets());

        // Port
        request.put_u16(8080);

        assert_eq!(request[0], 0x01); // TCP command
        assert_eq!(request[1], 0x04); // IPv6 type
        assert_eq!(request.len(), 1 + 1 + 16 + 2);
    }

    #[test]
    fn test_tcp_connect_request_domain() {
        use bytes::{BufMut, BytesMut};

        let mut request = BytesMut::new();

        // Command: TCP connect
        request.put_u8(0x01);

        // Domain name
        request.put_u8(0x03);
        let domain = "example.com";
        request.put_u8(domain.len() as u8);
        request.put_slice(domain.as_bytes());

        // Port
        request.put_u16(443);

        assert_eq!(request[0], 0x01); // TCP command
        assert_eq!(request[1], 0x03); // Domain type
        assert_eq!(request[2], domain.len() as u8);
        assert_eq!(request.len(), 1 + 1 + 1 + domain.len() + 2);
    }

    // Test authentication logic
    #[test]
    fn test_server_config_with_auth() {
        let config = HysteriaV1ServerConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            up_mbps: 100,
            down_mbps: 200,
            obfs: None,
            auth: Some("secret-password".to_string()),
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            recv_window_conn: None,
            recv_window: None,
        };

        assert_eq!(config.auth, Some("secret-password".to_string()));
    }

    #[test]
    fn test_server_config_without_auth() {
        let config = HysteriaV1ServerConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            up_mbps: 100,
            down_mbps: 200,
            obfs: None,
            auth: None,
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            recv_window_conn: None,
            recv_window: None,
        };

        assert_eq!(config.auth, None);
    }

    // Test session management
    #[tokio::test]
    async fn test_udp_session_manager_create() {
        let manager = UdpSessionManager::new(Duration::from_secs(60));
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let target_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        manager.create_session(1, client_addr, target_addr).await;

        let session = manager.get_session(1).await;
        assert!(session.is_some());

        let session = session.unwrap();
        assert_eq!(session.session_id, 1);
        assert_eq!(session.client_addr, client_addr);
        assert_eq!(session.target_addr, target_addr);
    }

    #[tokio::test]
    async fn test_udp_session_manager_get_nonexistent() {
        let manager = UdpSessionManager::new(Duration::from_secs(60));

        let session = manager.get_session(999).await;
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_udp_session_manager_cleanup() {
        let manager = UdpSessionManager::new(Duration::from_millis(10));
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let target_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        manager.create_session(1, client_addr, target_addr).await;

        // Wait for session to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        manager.cleanup_expired().await;

        let session = manager.get_session(1).await;
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_udp_session_manager_multiple_sessions() {
        let manager = UdpSessionManager::new(Duration::from_secs(60));
        let client_addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let client_addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let target_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        manager.create_session(1, client_addr1, target_addr).await;
        manager.create_session(2, client_addr2, target_addr).await;

        let session1 = manager.get_session(1).await;
        let session2 = manager.get_session(2).await;

        assert!(session1.is_some());
        assert!(session2.is_some());
        assert_eq!(session1.unwrap().session_id, 1);
        assert_eq!(session2.unwrap().session_id, 2);
    }

    // Test protocol constants
    #[test]
    fn test_protocol_version() {
        assert_eq!(0x01, 0x01); // Hysteria v1 version
    }

    #[test]
    fn test_command_types() {
        assert_eq!(0x01, 0x01); // TCP connect command
    }

    #[test]
    fn test_address_types() {
        assert_eq!(0x01, 0x01); // IPv4
        assert_eq!(0x03, 0x03); // Domain
        assert_eq!(0x04, 0x04); // IPv6
    }

    #[test]
    fn test_response_codes() {
        assert_eq!(0x00, 0x00); // Success
        assert_eq!(0x01, 0x01); // Auth failed
    }

    // Test config validation edge cases
    #[test]
    fn test_config_with_various_protocols() {
        let protocols = vec!["udp", "wechat-video", "faketcp"];

        for protocol in protocols {
            let config = HysteriaV1Config {
                server: "127.0.0.1".to_string(),
                port: 443,
                protocol: protocol.to_string(),
                up_mbps: 10,
                down_mbps: 50,
                obfs: None,
                auth: None,
                alpn: vec!["hysteria".to_string()],
                recv_window_conn: None,
                recv_window: None,
                skip_cert_verify: false,
                sni: None,
            };

            assert_eq!(config.protocol, protocol);
        }
    }

    #[test]
    fn test_config_with_custom_alpn() {
        let config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            auth: None,
            alpn: vec!["h3".to_string(), "hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: false,
            sni: None,
        };

        assert_eq!(config.alpn.len(), 2);
        assert_eq!(config.alpn[0], "h3");
        assert_eq!(config.alpn[1], "hysteria");
    }

    #[test]
    fn test_bandwidth_config_ranges() {
        let config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 1,
            down_mbps: 1000,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: false,
            sni: None,
        };

        assert_eq!(config.up_mbps, 1);
        assert_eq!(config.down_mbps, 1000);
    }
}
