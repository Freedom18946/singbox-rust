//! Product-profile SOCKS outbound UDP acceptance.

use sb_adapters::outbound::socks5::Socks5Connector;
use sb_test_utils::socks5::start_mock_socks5;
use sb_types::{Outbound, Session, TargetAddr};
use std::io;
use std::time::Duration;

fn permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_error| io_error.kind() == io::ErrorKind::PermissionDenied)
    }) || error.to_string().contains("Operation not permitted")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn product_profile_socks_outbound_udp_roundtrip() -> anyhow::Result<()> {
    let (proxy_tcp, _) = match start_mock_socks5().await {
        Ok(addresses) => addresses,
        Err(error) if permission_denied(&error) => {
            eprintln!("skipping product SOCKS UDP e2e: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    let connector = Socks5Connector::no_auth(proxy_tcp.to_string());
    let target = TargetAddr::ip("1.2.3.4".parse()?, 5353);
    let mut session = Session::outbound(target.clone());
    session.connect.connect_timeout = Duration::from_secs(3);
    session.packet.idle_timeout = Duration::from_secs(3);

    let packet = connector.listen_packet(&session).await?;
    let payload = b"wp05-product-socks-udp";
    assert_eq!(packet.send_to(payload, &target).await?, payload.len());

    let mut buffer = [0u8; 1500];
    let (size, source) = packet.recv_from(&mut buffer).await?;
    assert_eq!(&buffer[..size], payload);
    assert_eq!(source, TargetAddr::ip("127.0.0.1".parse()?, source.port()));
    packet.close().await?;
    Ok(())
}
