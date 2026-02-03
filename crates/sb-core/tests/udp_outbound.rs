use sb_core::net::datagram::UdpTargetAddr;
use sb_core::outbound::udp::direct_sendto;
use tokio::net::UdpSocket;

fn is_permission_denied_io(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || err
            .to_string()
            .to_lowercase()
            .contains("operation not permitted")
}

fn is_permission_denied_any(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("operation not permitted") || msg.contains("permission denied")
}

async fn bind_socket_or_skip() -> Option<UdpSocket> {
    match UdpSocket::bind("127.0.0.1:0").await {
        Ok(sock) => Some(sock),
        Err(err) if is_permission_denied_io(&err) => {
            eprintln!("skipping direct_sendto_loopback_smoke: {err}");
            None
        }
        Err(err) => panic!("failed to bind udp socket: {err}"),
    }
}

#[tokio::test]
async fn direct_sendto_loopback_smoke() {
    // server on loopback
    let Some(server) = bind_socket_or_skip().await else {
        return;
    };
    let srv_addr = server.local_addr().unwrap();
    // client socket
    let Some(client) = bind_socket_or_skip().await else {
        return;
    };

    // spawn server recv
    let h = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, _peer) = server.recv_from(&mut buf).await.unwrap();
        n
    });

    // send via outbound helper
    let dst = UdpTargetAddr::Ip(srv_addr);
    let payload = b"ping-outbound";
    let n = match direct_sendto(&client, &dst, payload).await {
        Ok(n) => n,
        Err(err) if is_permission_denied_any(&err) => {
            eprintln!("skipping direct_sendto_loopback_smoke: {err}");
            return;
        }
        Err(err) => panic!("direct_sendto failed: {err}"),
    };
    assert_eq!(n, payload.len());

    let got = h.await.unwrap();
    assert_eq!(got, payload.len());
}
