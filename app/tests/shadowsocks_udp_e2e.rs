#![cfg(feature = "net_e2e")]
//! E2E: Shadowsocks UDP session round-trip using adapters inbound server.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use sb_adapters::inbound::shadowsocks::{serve as ss_serve, ShadowsocksInboundConfig};
use sb_core::router::RouterHandle;

#[tokio::test]
async fn shadowsocks_udp_roundtrip() {
    if std::env::var("SB_E2E_UDP").ok().as_deref() != Some("1") {
        eprintln!("SB_E2E_UDP not set; skipping shadowsocks_udp_roundtrip");
        return;
    }
    // Start UDP echo server
    let echo = {
        let sock = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(sock) => sock,
            Err(err) => {
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
                ) {
                    eprintln!("Skipping shadowsocks_udp_roundtrip: cannot bind echo ({err})");
                    return;
                }
                panic!("bind echo: {err}");
            }
        };
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

    // Start Shadowsocks inbound server
    let ss_listen: SocketAddr = "127.0.0.1:8838".parse().unwrap();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let cfg = ShadowsocksInboundConfig {
        listen: ss_listen,
        method: "aes-256-gcm".into(),
        #[allow(deprecated)]
        password: None,
        users: vec![sb_adapters::inbound::shadowsocks::ShadowsocksUser::new(
            "test-user".to_string(),
            "test-password".to_string(),
        )],
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
        transport_layer: None,
    };
    tokio::spawn(async move {
        let _ = ss_serve(cfg, stop_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Use sb-core AEAD UDP socket against server
    use sb_core::outbound::ss::aead_udp::{SsAeadUdpConfig, SsAeadUdpSocket};
    let cli = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping shadowsocks_udp_roundtrip: cannot bind client ({err})");
                return;
            }
            panic!("bind client: {err}");
        }
    };
    cli.connect(ss_listen).await.expect("connect ss");
    let ss = SsAeadUdpSocket::new(
        cli,
        SsAeadUdpConfig {
            server: ss_listen.ip().to_string(),
            port: ss_listen.port(),
            cipher: sb_core::outbound::ss::aead_tcp::SsAeadCipher::Aes256Gcm,
            master_key: b"test-password".to_vec(),
        },
    )
    .expect("wrap ss udp");

    // Send to echo server
    let payload = b"ss-udp-e2e";
    let dst = sb_core::net::udp_nat::TargetAddr::Ip(echo);
    let _ = ss.send_to_target(payload, &dst).await.expect("send");
    let mut buf = [0u8; 4096];
    let (n, _src) = ss.recv_from_server(&mut buf).await.expect("recv");
    assert_eq!(&buf[..n], payload);

    let _ = stop_tx.send(()).await;
}
