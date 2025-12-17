#![cfg(feature = "net_e2e")]
//! E2E: Hysteria2 UDP session round-trip using core inbound server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[cfg(feature = "out_hysteria2")]
use sb_core::outbound::hysteria2::inbound::{
    Hysteria2Inbound, Hysteria2ServerConfig, Hysteria2User,
};

use sb_core::adapter::UdpOutboundFactory;
use sb_core::outbound::hysteria2::Hysteria2Config as OutCfg;
use sb_core::outbound::hysteria2::Hysteria2Outbound as Out;

async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn hysteria2_udp_roundtrip() {
    if std::env::var("SB_E2E_UDP").ok().as_deref() != Some("1") {
        eprintln!("SB_E2E_UDP not set; skipping hysteria2_udp_roundtrip");
        return;
    }
    // Skip if no TLS certs; use self-signed minimal files if present.
    // For CI environments, this test remains opt-in via net_e2e feature.
    let echo = start_udp_echo().await;

    let server_addr: SocketAddr = "127.0.0.1:44443".parse().unwrap();
    let server_cfg = Hysteria2ServerConfig {
        listen: server_addr,
        users: vec![Hysteria2User {
            password: "pwd".into(),
        }],
        cert: "tests/fixtures/cert.pem".into(),
        key: "tests/fixtures/key.pem".into(),
        congestion_control: Some("bbr".into()),
        salamander: None,
        obfs: None,
        masquerade: None,
    };
    let inbound = Hysteria2Inbound::new(server_cfg);
    inbound.start().await.expect("start hysteria2 inbound");

    // Create outbound and UDP session
    let ob_cfg = OutCfg {
        server: server_addr.ip().to_string(),
        port: server_addr.port(),
        password: "pwd".into(),
        congestion_control: Some("bbr".into()),
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        skip_cert_verify: true, // self-signed
        sni: None,
        alpn: None,
        salamander: None,
        brutal: None,
        tls_ca_paths: Vec::new(),
        tls_ca_pem: Vec::new(),
        zero_rtt_handshake: false,
    };
    let out = Arc::new(Out::new(ob_cfg).expect("outbound"));
    let factory = out.clone();
    let sess = factory.open_session().await.expect("open udp session");

    // Send to echo server and wait reply
    let payload = b"hy2-udp-e2e";
    sess.send_to(payload, &echo.ip().to_string(), echo.port())
        .await
        .expect("send");
    let (data, _src) = sess.recv_from().await.expect("recv");
    assert_eq!(&data, payload);
}
