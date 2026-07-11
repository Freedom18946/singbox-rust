//! Hysteria2 integration coverage after protocol ownership moved to sb-adapters.
#![cfg(feature = "adapter-hysteria2")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::hysteria2::{
    Hysteria2AdapterConfig, Hysteria2BrutalConfig, Hysteria2Connector,
};
use sb_types::{NetworkKind, Outbound};

fn full_config() -> Hysteria2AdapterConfig {
    Hysteria2AdapterConfig {
        tag: Some("hy2-edge".to_string()),
        server: "hy2.example.com".to_string(),
        port: 8443,
        password: "test-password".to_string(),
        skip_cert_verify: false,
        sni: Some("hy2.example.com".to_string()),
        alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
        congestion_control: Some("brutal".to_string()),
        up_mbps: Some(100),
        down_mbps: Some(200),
        obfs: Some("obfs-key".to_string()),
        salamander: Some("salamander-key".to_string()),
        brutal: Some(Hysteria2BrutalConfig {
            up_mbps: 50,
            down_mbps: 100,
        }),
        tls_ca_paths: vec!["/tmp/custom-ca.pem".to_string()],
        tls_ca_pem: vec!["PEM".to_string()],
        zero_rtt_handshake: true,
    }
}

#[test]
fn canonical_contract_preserves_configured_identity_and_networks() {
    let connector = Hysteria2Connector::new(full_config());
    assert_eq!(connector.r#type(), "hysteria2");
    assert_eq!(connector.tag().as_str(), "hy2-edge");
    assert_eq!(connector.network(), &[NetworkKind::Tcp, NetworkKind::Udp]);
}

#[test]
fn full_transport_configuration_is_retained() {
    let config = full_config();
    assert_eq!(config.server, "hy2.example.com");
    assert_eq!(config.port, 8443);
    assert_eq!(config.sni.as_deref(), Some("hy2.example.com"));
    assert_eq!(config.tls_ca_paths, ["/tmp/custom-ca.pem"]);
    assert_eq!(config.tls_ca_pem, ["PEM"]);
    assert!(config.zero_rtt_handshake);
    assert_eq!(
        config.brutal,
        Some(Hysteria2BrutalConfig {
            up_mbps: 50,
            down_mbps: 100,
        })
    );
}

#[test]
fn default_configuration_keeps_legacy_defaults() {
    let config = Hysteria2AdapterConfig::default();
    assert_eq!(config.server, "127.0.0.1");
    assert_eq!(config.port, 443);
    assert!(config.skip_cert_verify);
    assert_eq!(config.congestion_control.as_deref(), Some("bbr"));
    assert!(!config.zero_rtt_handshake);
    assert!(config.tls_ca_paths.is_empty());
    assert!(config.tls_ca_pem.is_empty());
}
