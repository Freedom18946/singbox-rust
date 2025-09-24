use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 参数：<socks-udp-listen> <target-ip:port> [domain-for-dns]
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:11080".into())
        .parse::<SocketAddr>()?;
    let target = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1.1.1.1:53".into())
        .parse::<SocketAddr>()?;
    let qname = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "example.com".into());

    // 构造简单的 DNS A 记录查询
    let mut q = Vec::new();
    // DNS header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1, others=0
    q.extend_from_slice(&[0x12, 0x34]); // ID
    q.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

    // Question section: domain name + QTYPE(A) + QCLASS(IN)
    for part in qname.split('.') {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.push(0x00); // End of name
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE: A (1)
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (1)

    let sock = UdpSocket::bind(("0.0.0.0", 0)).await?;
    let mut pkt = Vec::with_capacity(q.len() + 32);

    // SOCKS5 UDP 请求头：RSV RSV FRAG ATYP ADDR PORT
    pkt.extend_from_slice(&[0, 0, 0]); // FRAG=0
    match target {
        SocketAddr::V4(sa) => {
            pkt.push(0x01);
            pkt.extend_from_slice(&sa.ip().octets());
            pkt.extend_from_slice(&sa.port().to_be_bytes());
        }
        SocketAddr::V6(sa) => {
            pkt.push(0x04);
            pkt.extend_from_slice(&sa.ip().octets());
            pkt.extend_from_slice(&sa.port().to_be_bytes());
        }
    }
    pkt.extend_from_slice(&q);

    sock.send_to(&pkt, listen).await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) =
        tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf)).await??;
    println!("got {} bytes via socks5-udp", n);
    Ok(())
}
