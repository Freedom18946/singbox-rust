#![cfg(feature = "socks-udp")]

use sb_adapters::outbound::socks5_udp::{strip_udp_reply, UpSocksSession, UpSocksSessionConfig};
use sb_core::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use sb_test_utils::socks5::start_mock_socks5;
use std::io;

#[test]
fn strip_udp_reply_rejects_invalid_packets() {
    assert!(strip_udp_reply(&[0x00]).is_err());
    assert!(strip_udp_reply(&[0x00, 0x00, 0x01]).is_err());
    assert!(strip_udp_reply(&[0x00, 0x00, 0x00, 0xff]).is_err());
}

#[test]
fn strip_udp_reply_parses_ipv4() {
    let payload = b"hello";
    let mut packet = vec![0x00, 0x00, 0x00, 0x01];
    packet.extend_from_slice(&[127, 0, 0, 1]);
    packet.extend_from_slice(&53u16.to_be_bytes());
    packet.extend_from_slice(payload);

    let (address, body) = strip_udp_reply(&packet).expect("decode ipv4");
    assert_eq!(address, "127.0.0.1:53".parse().unwrap());
    assert_eq!(body, payload);
}

#[test]
fn strip_udp_reply_preserves_legacy_domain_mapping() {
    let payload = b"domain";
    let mut packet = vec![0x00, 0x00, 0x00, 0x03, 12];
    packet.extend_from_slice(b"example.test");
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(payload);

    let (address, body) = strip_udp_reply(&packet).expect("decode domain");
    assert_eq!(address, "127.0.0.1:5353".parse().unwrap());
    assert_eq!(body, payload);
}

fn permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_error| io_error.kind() == io::ErrorKind::PermissionDenied)
    }) || error.to_string().contains("Operation not permitted")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_owned_session_preserves_wire_size_and_roundtrip() -> anyhow::Result<()> {
    let (proxy, _) = match start_mock_socks5().await {
        Ok(addresses) => addresses,
        Err(error) if permission_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let endpoint = ProxyEndpoint {
        kind: ProxyKind::Socks5,
        addr: proxy,
        auth: None,
        weight: 1,
        max_fail: 3,
        open_ms: 5_000,
        half_open_ms: 1_000,
    };
    let session = UpSocksSession::create(endpoint, 3_000, &UpSocksSessionConfig::default()).await?;
    let destination = "1.2.3.4:5353".parse()?;
    let payload = b"wp05-adapter-upstream";

    assert_eq!(
        session.send_to(destination, payload).await?,
        10 + payload.len()
    );
    let (source, reply) = session.recv_once(3_000).await?.expect("mock SOCKS5 reply");
    assert_eq!(source.ip(), "127.0.0.1".parse::<std::net::IpAddr>()?);
    assert_eq!(reply, payload);
    Ok(())
}
