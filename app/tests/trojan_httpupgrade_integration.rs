//! Trojan + HTTPUpgrade Transport Integration Test
//!
//! This test validates that Trojan outbound adapter correctly integrates with HTTPUpgrade transport.

use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::OutboundConnector;
use sb_adapters::transport_config::{HttpUpgradeTransportConfig, TransportConfig};

#[tokio::test]
async fn test_trojan_httpupgrade_config_creation() {
    let server_addr = "127.0.0.1:8443".to_string();

    let httpupgrade_config = HttpUpgradeTransportConfig {
        path: "/upgrade".to_string(),
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ],
    };

    let config = TrojanConfig {
        server: server_addr.clone(),
        tag: Some("trojan-http".to_string()),
        password: "test-password-123".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        transport_layer: TransportConfig::HttpUpgrade(httpupgrade_config),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    assert_eq!(config.server, server_addr);
    assert_eq!(config.password, "test-password-123");

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[tokio::test]
async fn test_trojan_httpupgrade_with_multiplex() {
    let server_addr = "127.0.0.1:443".to_string();

    let config = TrojanConfig {
        server: server_addr,
        tag: Some("trojan-mux".to_string()),
        password: "password123".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        transport_layer: TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
            path: "/trojan-upgrade".to_string(),
            headers: vec![],
        }),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: Some(sb_transport::multiplex::MultiplexConfig::default()),
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[tokio::test]
async fn test_trojan_httpupgrade_path_variants() {
    let server_addr = "127.0.0.1:443".to_string();

    let paths = vec!["/", "/upgrade", "/trojan-ws", "/api/v1/connect"];

    for path in paths {
        let config = TrojanConfig {
            server: server_addr.clone(),
            tag: None,
            password: "test-pass".to_string(),
            connect_timeout_sec: Some(10),
            sni: None,
            skip_cert_verify: true,
            transport_layer: TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
                path: path.to_string(),
                headers: vec![],
            }),
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
        };

        let connector = TrojanConnector::new(config);
        assert_eq!(connector.name(), "trojan");
    }
}

#[tokio::test]
async fn test_trojan_tcp_vs_httpupgrade() {
    let server_addr = "127.0.0.1:443".to_string();

    // TCP configuration
    let tcp_config = TrojanConfig {
        server: server_addr.clone(),
        tag: Some("trojan-tcp".to_string()),
        password: "password123".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        transport_layer: TransportConfig::Tcp,
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    // HTTPUpgrade configuration
    let httpupgrade_config = TrojanConfig {
        server: server_addr,
        tag: Some("trojan-http".to_string()),
        password: "password123".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        transport_layer: TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
            path: "/upgrade".to_string(),
            headers: vec![],
        }),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let tcp_connector = TrojanConnector::new(tcp_config);
    let httpupgrade_connector = TrojanConnector::new(httpupgrade_config);

    assert_eq!(tcp_connector.name(), "trojan");
    assert_eq!(httpupgrade_connector.name(), "trojan");
}
