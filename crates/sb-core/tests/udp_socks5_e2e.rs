#![cfg(feature = "scaffold")]

use sb_test_utils::socks5::start_mock_socks5;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

fn is_permission_denied_io(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(1)
        || err.raw_os_error() == Some(13)
}

fn is_permission_denied_any(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(is_permission_denied_io)
    }) || err.to_string().contains("Operation not permitted")
        || err.to_string().contains("Permission denied")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_udp_socks5_roundtrip() -> anyhow::Result<()> {
    let (proxy_tcp, _proxy_udp) = match start_mock_socks5().await {
        Ok(value) => value,
        Err(err) => {
            if is_permission_denied_any(&err) {
                eprintln!("Skipping: permission denied starting mock socks5");
                return Ok(());
            }
            return Err(err);
        }
    };
    // Configure env for our outbound
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var("SB_UDP_PROXY_ADDR", proxy_tcp.to_string());
    // Build a client UDP socket
    let sock = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(value) => value,
        Err(err) => {
            if is_permission_denied_io(&err) {
                eprintln!("Skipping: permission denied binding UDP socket");
                return Ok(());
            }
            return Err(err.into());
        }
    };
    let relay = match sb_core::outbound::udp_socks5::ensure_udp_relay().await {
        Ok(value) => value,
        Err(err) => {
            if is_permission_denied_any(&err) {
                eprintln!("Skipping: permission denied creating UDP relay");
                return Ok(());
            }
            return Err(err);
        }
    };
    // Destination (ignored by mock for routing, but must be well-formed)
    let dst: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let payload = b"hello-socks5-udp";
    // Send via socks5
    let n =
        sb_core::outbound::udp_socks5::sendto_via_socks5_on(&sock, payload, &dst, relay).await?;
    assert_eq!(n, 3 + 1 + 4 + 2 + payload.len()); // header + data
                                                  // Receive decoded reply
    let (dst2, p2) = sb_core::outbound::udp_socks5::recv_from_via_socks5(&sock).await?;
    assert_eq!(p2, payload);
    // mock sets reply dst to 127.0.0.1:<client-port>
    assert_eq!(dst2.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    Ok(())
}
