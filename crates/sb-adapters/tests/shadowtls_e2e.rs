#![cfg(feature = "adapter-shadowtls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};
use tokio::time::{timeout, Duration};

fn test_connector() -> ShadowTlsConnector {
    ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 443,
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    })
}

#[tokio::test]
async fn shadowtls_rejects_standalone_leaf_dialing() {
    let connector = test_connector();
    let err = timeout(
        Duration::from_secs(2),
        connector.dial(Target::tcp("127.0.0.1", 18080), DialOpts::default()),
    )
    .await
    .expect("shadowtls guardrail dial timed out");
    let err = match err {
        Ok(_) => panic!("shadowtls standalone leaf dial should be rejected"),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("standalone leaf dialing is disabled"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("transport-wrapper/detour model"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn shadowtls_standalone_rejection_happens_before_network_io() {
    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 1,
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: false,
        utls_fingerprint: None,
    });

    let err = timeout(
        Duration::from_secs(2),
        connector.dial(Target::tcp("198.51.100.10", 443), DialOpts::default()),
    )
    .await
    .expect("shadowtls guardrail dial timed out");
    let err = match err {
        Ok(_) => panic!("shadowtls standalone leaf dial should be rejected before connect"),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("standalone leaf dialing is disabled"),
        "unexpected error: {err}"
    );
}
