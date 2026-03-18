#![cfg(feature = "adapter-shadowtls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};

#[tokio::test]
async fn shadowtls_standalone_leaf_dial_is_rejected() {
    // ShadowTLS is intentionally blocked as a standalone leaf until it is
    // reintroduced with transport-wrapper semantics.
    let cfg = ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 1, // typically closed
        version: 1,
        password: "interop-password".to_string(),
        sni: "example.com".to_string(),
        alpn: Some("http/1.1".into()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    };
    let conn = ShadowTlsConnector::new(cfg);
    let target = Target::tcp("example.com", 443);
    let res = conn.dial(target, DialOpts::default()).await;
    let err = match res {
        Ok(_) => panic!("shadowtls standalone leaf dial should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("standalone leaf dialing is disabled"));
}
