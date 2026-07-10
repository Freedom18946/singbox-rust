#![cfg(feature = "adapter-shadowtls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};
use sb_adapters::traits::Outbound;

#[tokio::test]
async fn shadowtls_canonical_contract_is_stream_only() {
    let cfg = ShadowTlsAdapterConfig {
        tag: None,
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
    assert_eq!(conn.network(), &[sb_types::NetworkKind::Tcp]);

    let session = sb_types::Session::outbound(sb_types::TargetAddr::domain("example.com", 443));
    let err = conn
        .listen_packet(&session)
        .await
        .expect_err("shadowtls must reject packet associations");
    assert!(matches!(
        err,
        sb_types::CoreError::Connect {
            kind: sb_types::ConnectErrorKind::Unsupported,
            ..
        }
    ));
}
