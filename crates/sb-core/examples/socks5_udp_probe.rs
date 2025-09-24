use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

// --- Minimal DNS A query (ID=0x1234, RD=1) ---
fn build_dns_query_a(name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(512);
    q.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    q
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // args: <SOCKS_ADDR> <DNS_ADDR> <NAME>
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: socks5_udp_probe <socks_host:port> <dns_host:port> <name>");
        std::process::exit(2);
    }
    let socks: SocketAddr = args.remove(0).parse()?;
    let dns: SocketAddr = args.remove(0).parse()?;
    let name = args.remove(0);

    // TCP 控制通道：greet + UDP ASSOC
    let mut ctrl = TcpStream::connect(socks).await?;
    sb_core::socks5::greet_noauth(&mut ctrl).await?;
    let relay = sb_core::socks5::udp_associate(&mut ctrl, "0.0.0.0:0".parse()?).await?;

    // 通过中继发 DNS 查询
    let udp = UdpSocket::bind(("0.0.0.0", 0)).await?;
    let q = build_dns_query_a(&name);
    let pkt = sb_core::socks5::encode_udp_request(&dns, &q);
    udp.send_to(&pkt, relay).await?;

    // 收包并剥头
    let mut buf = [0u8; 2048];
    let (m, _) =
        tokio::time::timeout(std::time::Duration::from_secs(3), udp.recv_from(&mut buf)).await??;
    let (_dst, body) = sb_core::socks5::decode_udp_reply(&buf[..m])?;

    if body.len() < 12 || body[0..2] != 0x1234u16.to_be_bytes() {
        return Err(anyhow!("bad dns reply"));
    }
    println!("OK len={} id=0x{:04x}", body.len(), 0x1234u16);
    Ok(())
}
