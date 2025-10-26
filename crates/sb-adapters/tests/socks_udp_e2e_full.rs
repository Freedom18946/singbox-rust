#![cfg(feature = "e2e")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

// Reuse the simple SOCKS5 mock + UDP echo from the base test
struct Socks5Mock {
    tcp: TcpListener,
    udp_echo: UdpSocket,
    udp_addr: SocketAddr,
}
impl Socks5Mock {
    async fn new() -> anyhow::Result<Self> {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
        let udp_echo = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let udp_addr = udp_echo.local_addr()?;
        Ok(Self {
            tcp,
            udp_echo,
            udp_addr,
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
        tokio::spawn(async move {
            let sock = &me.udp_echo;
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
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _peer)) = me.tcp.accept().await else {
                    break;
                };
                let me2 = me.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_tcp(&mut s, me2.udp_addr).await {
                        eprintln!("[socks5-mock] {e:?}");
                    }
                });
            }
        });
    }
    async fn handle_tcp(s: &mut TcpStream, udp: SocketAddr) -> anyhow::Result<()> {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            anyhow::bail!("VER!=5")
        }
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await?;
        s.write_all(&[0x05, 0x00]).await?;
        let mut req = [0u8; 4];
        s.read_exact(&mut req).await?;
        if req[0] != 0x05 {
            anyhow::bail!("req VER!=5")
        }
        let cmd = req[1];
        let atyp = req[3];
        match atyp {
            0x01 => {
                let mut a = [0u8; 6];
                s.read_exact(&mut a).await?;
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                let mut dom = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut dom).await?;
            }
            0x04 => {
                let mut a = [0u8; 18];
                s.read_exact(&mut a).await?;
            }
            _ => anyhow::bail!("bad atyp"),
        }
        if cmd != 0x03 {
            s.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await?;
            anyhow::bail!("CMD!=UDP_ASSOC");
        }
        let p = udp.port().to_be_bytes();
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
            .await?;
        Ok(())
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
async fn socks5_udp_full_roundtrip_via_router_and_proxy() -> anyhow::Result<()> {
    // Mock SOCKS5 + UDP echo
    let mock = Arc::new(Socks5Mock::new().await?);
    let tcp_addr = mock.tcp_addr();
    mock.clone().serve().await;

    // Env wiring
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "1");
    std::env::set_var("SB_SOCKS_UDP_LISTEN", "127.0.0.1:0");
    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var("SB_ROUTER_UDP_RULES", "default=proxy");
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var("SB_UDP_PROXY_ADDR", tcp_addr.to_string());

    // Spawn inbound and get actual listen address
    let inbound = sb_adapters::testsupport::spawn_socks_udp_inbound().await?;

    // Client socket binds locally and sends a SOCKS5-UDP datagram to inbound
    let cli = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let dst = mock.udp_addr();
    let payload = b"m1-stage2-real-loop";
    let pkt = encode_udp_datagram(dst, payload);
    cli.send_to(&pkt, inbound).await?;

    let mut buf = [0u8; 2048];
    // Expect a reply carrying the same payload (REPLY header + payload)
    let n = tokio::time::timeout(Duration::from_secs(3), cli.recv(&mut buf)).await??;
    // Strip reply header: RSV RSV FRAG ATYP ... PORT
    // Minimal parse for IPv4
    assert!(n >= payload.len() + 4);
    let atyp = buf[3];
    let off = match atyp {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => 5 + (buf[4] as usize) + 2,
        _ => 0,
    };
    assert!(off <= n);
    assert_eq!(&buf[off..n], payload);
    Ok(())
}
