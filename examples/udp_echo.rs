//! 最小 UDP Echo 服务：用于本地 e2e 校验 SOCKS5 UDP 往返
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = std::env::args().nth(1).unwrap_or("127.0.0.1:19090".into()).parse()?;
    let s = UdpSocket::bind(addr).await?;
    println!("echo on {}", s.local_addr()?);
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = s.recv_from(&mut buf).await?;
        s.send_to(&buf[..n], from).await?;
    }
}
