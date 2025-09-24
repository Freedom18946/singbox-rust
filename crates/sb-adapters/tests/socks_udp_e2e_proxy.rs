#![cfg(feature = "e2e")]
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_mock_udp_echo_roundtrip() -> anyhow::Result<()> {
    let mock = Arc::new(Socks5Mock::new().await?);
    mock.clone().serve().await;
    // not used yet but ensures tcp mock is bound
    let _tcp = mock.tcp_addr();
    let udp = mock.udp_addr();
    let cli = UdpSocket::bind(("127.0.0.1", 0)).await?;
    cli.connect(udp).await?;
    let payload = b"ping-udp";
    cli.send(payload).await?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), cli.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], payload);
    Ok(())
}
