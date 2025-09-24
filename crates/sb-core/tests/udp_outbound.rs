use sb_core::net::datagram::UdpTargetAddr;
use sb_core::outbound::udp::direct_sendto;
use tokio::net::UdpSocket;

#[tokio::test]
async fn direct_sendto_loopback_smoke() {
    // server on loopback
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = server.local_addr().unwrap();
    // client socket
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // spawn server recv
    let h = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, _peer) = server.recv_from(&mut buf).await.unwrap();
        n
    });

    // send via outbound helper
    let dst = UdpTargetAddr::Ip(srv_addr);
    let payload = b"ping-outbound";
    let n = direct_sendto(&client, &dst, payload).await.unwrap();
    assert_eq!(n, payload.len());

    let got = h.await.unwrap();
    assert_eq!(got, payload.len());
}
