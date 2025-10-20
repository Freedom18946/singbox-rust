use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = env::args().nth(1).unwrap_or("127.0.0.1".into());
    let port: u16 = env::args().nth(2).unwrap_or("11080".into()).parse().unwrap_or(11080);
    let n: usize = env::args().nth(3).unwrap_or("20".into()).parse().unwrap_or(20);

    let dst = format!("{}:{}", host, port);
    let sock = UdpSocket::bind(SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))).await?;

    let mut sent = 0usize;
    for i in 0..n {
        let payload = format!("hello-udp-{}", i).into_bytes();
        sock.send_to(&payload, &dst).await?;
        sent += 1;
        sleep(Duration::from_millis(10)).await;
    }

    eprintln!("sent {} packets to {}", sent, dst);
    Ok(())
}