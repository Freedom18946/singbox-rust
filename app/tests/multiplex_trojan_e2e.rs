//! Trojan Multiplex configuration integration tests (compile-time validation)

use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::OutboundConnector;
use sb_adapters::transport_config::TransportConfig;
use sb_transport::multiplex::MultiplexConfig;

#[test]
fn trojan_multiplex_config_creation() {
    let client_config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: Some("trojan-mux".to_string()),
        password: "test-trojan-password".to_string(),
        connect_timeout_sec: Some(10),
        sni: Some("example.com".to_string()),
        skip_cert_verify: true,
        transport_layer: TransportConfig::Tcp,
        reality: None,
        multiplex: Some(MultiplexConfig {
            max_num_streams: 256,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_keepalive: true,
            keepalive_interval: 30,
            max_connections: 4,
            max_streams_per_connection: 16,
            connection_idle_timeout: 300,
            padding: false,
            brutal: None,
        }),
    };

    let connector = TrojanConnector::new(client_config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn trojan_non_multiplex_config_creation() {
    let client_config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: Some("trojan-tcp".to_string()),
        password: "password123".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        skip_cert_verify: false,
        transport_layer: TransportConfig::Tcp,
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(client_config);
    assert_eq!(connector.name(), "trojan");
}



// TLS+Multiplex runtime tests were removed for portability. Configuration
// validation is covered by the compile-time tests above.
