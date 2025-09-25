use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let addr = std::env::var("ECHO_ADDR").unwrap_or("127.0.0.1:19000".into());
    let sock = UdpSocket::bind(&addr)?;
    tracing::info!(target: "app::udp-echo", %addr, "listening");
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        let _ = sock.send_to(&buf[..n], peer);
    }
}
