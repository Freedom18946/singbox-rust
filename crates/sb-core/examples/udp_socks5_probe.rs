use std::net::ToSocketAddrs;
use tokio::net::UdpSocket;

#[cfg(feature = "scaffold")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Args: <dst-host> <dst-port> <hex-payload>
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!("Usage: udp_socks5_probe <host> <port> <hexpayload>");
        std::process::exit(2);
    }
    let host = args.remove(0);
    let port: u16 = args.remove(0).parse()?;
    let payload = decode_hex(&args.remove(0)).expect("bad hex");
    // Env:
    //   SB_UDP_PROXY_MODE=socks5
    //   SB_UDP_PROXY_ADDR=127.0.0.1:1080
    std::env::set_var("RUST_LOG", "info");
    let dst = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .unwrap();
    let listen = UdpSocket::bind("0.0.0.0:0").await?;
    let n = sb_core::outbound::udp_socks5::sendto_via_socks5(
        &listen,
        &payload,
        &sb_core::net::datagram::UdpTargetAddr::Ip(dst),
    )
    .await?;
    println!("sent {} bytes via SOCKS5 relay", n);
    Ok(())
}

#[cfg(not(feature = "scaffold"))]
fn main() {
    eprintln!("udp_socks5_probe requires the `scaffold` feature");
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}
fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
