#![cfg(feature = "adapter-hysteria2")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sb_adapters::outbound::hysteria2::{Hysteria2AdapterConfig, Hysteria2Connector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};

#[tokio::test]
#[ignore]
async fn hysteria2_dial_closed_port_returns_error() {
    // Intentionally dial a closed port to verify error path and linker integration
    let cfg = Hysteria2AdapterConfig {
        server: "127.0.0.1".into(),
        port: 1,
        password: "test".into(),
        skip_cert_verify: true,
        sni: Some("example.com".into()),
        alpn: Some(vec!["h3".into(), "hysteria2".into()]),
        congestion_control: Some("bbr".into()),
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        salamander: None,
    };
    let conn = Hysteria2Connector::new(cfg);
    let target = Target::tcp("example.com", 443);
    let res = conn.dial(target, DialOpts::default()).await;
    assert!(res.is_err());
}
