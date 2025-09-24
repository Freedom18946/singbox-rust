use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// 复制 sb-core 测试里的最小 SOCKS5 mock（greet + UDP ASSOC；UDP 回显）
pub async fn start_mock_socks5() -> anyhow::Result<(SocketAddr, SocketAddr)> {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
    let tcp_addr = tcp.local_addr()?;
    let udp = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let udp_addr = udp.local_addr()?;
    {
        let udp = udp;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                if n < 3 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                    continue;
                }
                let mut i = 3usize;
                if i >= n {
                    continue;
                }
                match buf[i] {
                    0x01 => i += 1 + 4 + 2,
                    0x04 => i += 1 + 16 + 2,
                    0x03 => i += 2 + buf[i + 1] as usize + 2,
                    _ => continue,
                }
                let payload = &buf[i..n];
                let mut out = Vec::with_capacity(3 + 1 + 4 + 2 + payload.len());
                out.extend_from_slice(&[0, 0, 0, 0x01]);
                out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
                out.extend_from_slice(&from.port().to_be_bytes());
                out.extend_from_slice(payload);
                let _ = udp.send_to(&out, from).await;
            }
        });
    }
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = tcp.accept().await else {
                continue;
            };
            let udp_addr = udp_addr;
            tokio::spawn(async move {
                let mut h = [0u8; 2];
                if s.read_exact(&mut h).await.is_err() {
                    return;
                }
                if h != [0x05, 0x01] {
                    return;
                }
                let mut m = [0u8; 1];
                if s.read_exact(&mut m).await.is_err() {
                    return;
                }
                if m[0] != 0x00 {
                    return;
                }
                let _ = s.write_all(&[0x05, 0x00]).await;
                let mut r = [0u8; 3];
                if s.read_exact(&mut r).await.is_err() {
                    return;
                }
                if r[0] != 0x05 || r[1] != 0x03 {
                    return;
                }
                let mut atyp = [0u8; 1];
                if s.read_exact(&mut atyp).await.is_err() {
                    return;
                }
                match atyp[0] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        let _ = s.read_exact(&mut a).await;
                    }
                    0x04 => {
                        let mut a = [0u8; 16];
                        let _ = s.read_exact(&mut a).await;
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        let _ = s.read_exact(&mut l).await;
                        let mut d = vec![0u8; l[0] as usize];
                        let _ = s.read_exact(&mut d).await;
                    }
                    _ => return,
                }
                let mut p = [0u8; 2];
                let _ = s.read_exact(&mut p).await;
                let mut out = Vec::new();
                out.extend_from_slice(&[0x05, 0x00, 0x00, 0x01]);
                out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
                out.extend_from_slice(&udp_addr.port().to_be_bytes());
                let _ = s.write_all(&out).await;
            });
        }
    });
    Ok((tcp_addr, udp_addr))
}
