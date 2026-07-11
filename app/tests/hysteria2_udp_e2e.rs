#![cfg(feature = "net_e2e")]
//! E2E: Hysteria2 UDP session round-trip using sb-adapters protocol ownership.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[cfg(feature = "adapter-hysteria2")]
use sb_adapters::inbound::hysteria2::{
    Hysteria2ServerConfig, Hysteria2User, ProtocolInbound as Hysteria2Inbound,
};
#[cfg(feature = "adapter-hysteria2")]
use sb_adapters::outbound::hysteria2::{Hysteria2AdapterConfig, Hysteria2Connector};
use sb_types::Outbound;

async fn start_udp_echo() -> Option<SocketAddr> {
    let sock = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(sock) => sock,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping hysteria2 udp test: cannot bind echo ({err})");
                return None;
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
    Some(addr)
}

#[cfg(feature = "adapter-hysteria2")]
#[tokio::test]
async fn hysteria2_udp_roundtrip() {
    if std::env::var("SB_E2E_UDP").ok().as_deref() != Some("1") {
        eprintln!("SB_E2E_UDP not set; skipping hysteria2_udp_roundtrip");
        return;
    }
    let Some(echo) = start_udp_echo().await else {
        return;
    };

    let server_addr: SocketAddr = "127.0.0.1:44443".parse().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate test certificate");
    let server_cfg = Hysteria2ServerConfig {
        listen: server_addr,
        users: vec![Hysteria2User {
            password: "pwd".into(),
        }],
        cert: certificate
            .serialize_pem()
            .expect("serialize test certificate"),
        key: certificate.serialize_private_key_pem(),
        congestion_control: Some("bbr".into()),
        salamander: None,
        obfs: None,
        masquerade: None,
    };
    let inbound = Arc::new(Hysteria2Inbound::new(server_cfg));
    inbound.start().await.expect("start hysteria2 inbound");
    let inbound_task = inbound.clone();
    let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel();
    let relay_task = tokio::spawn(async move {
        let association = inbound_task
            .accept_udp()
            .await
            .expect("accept udp association");
        let (payload, destination) = association
            .recv_from()
            .await
            .expect("receive relay request");
        let sb_types::TargetAddr::Socket(destination) = destination else {
            panic!("test destination must be a socket address");
        };
        let relay = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay socket");
        relay
            .send_to(&payload, destination)
            .await
            .expect("relay request");
        let mut response = [0u8; 4096];
        let (size, source) =
            tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut response))
                .await
                .expect("relay response timeout")
                .expect("relay response");
        association
            .send_to(&response[..size], &sb_types::TargetAddr::Socket(source))
            .expect("send relay response");
        let _ = relay_done_rx.await;
    });

    // Create outbound and UDP session
    let ob_cfg = Hysteria2AdapterConfig {
        tag: Some("hysteria2-udp-test".into()),
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
    let factory = Hysteria2Connector::new(ob_cfg);
    let session = sb_types::Session::new(
        0,
        sb_types::InboundTag::new("hysteria2-udp-test"),
        sb_types::TargetAddr::Socket(echo),
    );
    let sess = factory
        .listen_packet(&session)
        .await
        .expect("open udp packet connection");

    // Send to echo server and wait reply
    let payload = b"hy2-udp-e2e";
    sess.send_to(payload, &sb_types::TargetAddr::Socket(echo))
        .await
        .expect("send");
    let mut data = vec![0u8; 65_535];
    let (size, _src) = sess.recv_from(&mut data).await.expect("recv");
    assert_eq!(&data[..size], payload);
    relay_done_tx.send(()).expect("notify relay completion");
    relay_task.await.expect("relay task");
}
