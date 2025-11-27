#![cfg(all(feature = "net_e2e"))]
//! E2E: TUIC UDP session round-trip using adapters inbound server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uuid::Uuid;

use sb_adapters::inbound::tuic::{serve as tuic_serve, TuicInboundConfig, TuicUser};
use sb_core::outbound::OutboundRegistryHandle;
use sb_core::router;

fn self_signed_cert() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let cert = rcgen::Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

#[tokio::test]
async fn tuic_udp_roundtrip() {
    if std::env::var("SB_E2E_UDP").ok().as_deref() != Some("1") {
        eprintln!("SB_E2E_UDP not set; skipping tuic_udp_roundtrip");
        return;
    }
    // Start UDP echo server
    let echo = {
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
    };

    // Start TUIC inbound server
    let (cert_pem, key_pem) = self_signed_cert();
    let listen: SocketAddr = "127.0.0.1:48443".parse().unwrap();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let router = Arc::new(router::RouterHandle::from_env());
    let outbounds = Arc::new(OutboundRegistryHandle::default());
    let cfg = TuicInboundConfig {
        listen,
        users: vec![TuicUser {
            uuid: Uuid::new_v4(),
            token: "token".into(),
        }],
        cert: cert_pem,
        key: key_pem,
        congestion_control: Some("bbr".into()),
        router: router.clone(),
        outbounds: outbounds.clone(),
    };
    tokio::spawn(async move {
        let _ = tuic_serve(cfg, stop_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create TUIC outbound + UDP session
    use sb_core::outbound::tuic::{TuicConfig as OutCfg, TuicOutbound, UdpRelayMode};
    let out_cfg = OutCfg {
        server: listen.ip().to_string(),
        port: listen.port(),
        uuid: Uuid::new_v4(),
        token: "token".into(),
        password: None,
        congestion_control: Some("bbr".into()),
        alpn: Some("tuic".into()),
        skip_cert_verify: true,
        udp_relay_mode: UdpRelayMode::Native,
        udp_over_stream: true,
        zero_rtt_handshake: false,
    };
    let out = Arc::new(TuicOutbound::new(out_cfg).unwrap());
    let factory = out.clone();
    let sess = factory.open_session().await.expect("open udp session");

    // Send/recv
    let payload = b"tuic-udp-e2e";
    sess.send_to(payload, &echo.ip().to_string(), echo.port())
        .await
        .expect("send");
    let (data, _src) = sess.recv_from().await.expect("recv");
    assert_eq!(&data, payload);

    let _ = stop_tx.send(()).await;
}
