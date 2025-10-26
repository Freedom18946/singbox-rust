#![cfg(feature = "e2e")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

struct Socks5Mock {
    tcp: TcpListener,
    udp_echo: UdpSocket,
    udp_addr: SocketAddr,
    healthy: bool,
}
impl Socks5Mock {
    async fn new(healthy: bool) -> anyhow::Result<Self> {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
        let udp_echo = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let udp_addr = udp_echo.local_addr()?;
        Ok(Self {
            tcp,
            udp_echo,
            udp_addr,
            healthy,
        })
    }
    fn tcp_addr(&self) -> SocketAddr {
        self.tcp.local_addr().unwrap()
    }
    fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }
    async fn serve(self: Arc<Self>) {
        let me = self.clone();
        // UDP echo only when healthy
        if me.healthy {
            let me2 = me.clone();
            tokio::spawn(async move {
                let sock = &me2.udp_echo;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match sock.recv_from(&mut buf).await {
                        Ok((n, peer)) => {
                            let _ = sock.send_to(&buf[..n], peer).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _peer)) = me.tcp.accept().await else {
                    break;
                };
                let me2 = me.clone();
                tokio::spawn(async move {
                    let healthy = me2.healthy;
                    // Socks5 greet
                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; head[1] as usize];
                    let _ = s.read_exact(&mut methods).await;
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut req = [0u8; 4];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    // Read dst address according to atyp
                    match req[3] {
                        0x01 => {
                            let mut a = [0u8; 6];
                            let _ = s.read_exact(&mut a).await;
                        }
                        0x03 => {
                            let mut l = [0u8; 1];
                            let _ = s.read_exact(&mut l).await;
                            let mut dom = vec![0u8; l[0] as usize + 2];
                            let _ = s.read_exact(&mut dom).await;
                        }
                        0x04 => {
                            let mut a = [0u8; 18];
                            let _ = s.read_exact(&mut a).await;
                        }
                        _ => {
                            let _ = s.write_all(&[0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0]).await;
                            return;
                        }
                    }
                    if req[1] != 0x03 {
                        let _ = s.write_all(&[0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    }
                    // Healthy: return UDP addr; Unhealthy: close abruptly
                    if !healthy {
                        let _ = s.shutdown().await;
                        return;
                    }
                    let p = me2.udp_addr.port().to_be_bytes();
                    let _ = s
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
                        .await;
                });
            }
        });
    }
}

fn encode_udp_datagram(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 32);
    out.extend_from_slice(&[0, 0, 0]);
    match dst {
        SocketAddr::V4(sa) => {
            out.push(0x01);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
        }
        SocketAddr::V6(sa) => {
            out.push(0x04);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_balancer_rr_with_failover() -> anyhow::Result<()> {
    // A healthy, B unhealthy
    let a = Arc::new(Socks5Mock::new(true).await?);
    let b = Arc::new(Socks5Mock::new(false).await?);
    a.clone().serve().await;
    b.clone().serve().await;

    // Env wiring
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "1");
    std::env::set_var("SB_SOCKS_UDP_LISTEN", "127.0.0.1:0");
    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var("SB_ROUTER_UDP_RULES", "default=proxy");
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var(
        "SB_UDP_SOCKS5_POOL",
        format!("{},{}", a.tcp_addr(), b.tcp_addr()),
    );
    std::env::set_var("SB_UDP_BALANCER_STRATEGY", "rr");
    std::env::set_var("SB_SOCKS_UDP_ALLOW_BALANCED_PROXY", "1");

    // Spawn inbound
    let inbound = sb_adapters::testsupport::spawn_socks_udp_inbound().await?;

    let cli = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let dst = a.udp_addr();
    let mut ok = 0usize;
    for i in 0..12 {
        let payload = format!("pkt-{}", i).into_bytes();
        let pkt = encode_udp_datagram(dst, &payload);
        let _ = cli.send_to(&pkt, inbound).await?;
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(800), cli.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                // strip reply header
                let off = 4 + 4 + 2; // v4 minimal
                if n >= off && &buf[off..n] == &payload {
                    ok += 1;
                }
            }
            _ => {}
        }
    }
    // should receive majority despite one backend failing
    assert!(ok >= 4);
    Ok(())
}
