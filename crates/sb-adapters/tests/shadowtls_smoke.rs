#![cfg(feature = "adapter-shadowtls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};

#[tokio::test]
#[ignore]
async fn shadowtls_dial_closed_port_returns_error() {
    // Intentionally dial a closed port to verify error path and linker integration
    let cfg = ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 1, // typically closed
        sni: "example.com".to_string(),
        alpn: Some("http/1.1".into()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    };
    let conn = ShadowTlsConnector::new(cfg);
    let target = Target::tcp("example.com", 443);
    let res = conn.dial(target, DialOpts::default()).await;
    assert!(res.is_err());
}
