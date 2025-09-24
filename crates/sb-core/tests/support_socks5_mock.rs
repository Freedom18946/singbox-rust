use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// 启动一个最小可用的 SOCKS5 代理（支持 greet + UDP ASSOC；UDP 回显 payload）。
/// 返回：(TCP 控制地址, UDP 中继地址)
pub async fn start_mock_socks5() -> anyhow::Result<(SocketAddr, SocketAddr)> {
    // TCP 控制
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
    let tcp_addr = tcp.local_addr()?;
    // UDP 中继
    let udp = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let udp_addr = udp.local_addr()?;

    // UDP 回显循环（直接"move"掉 socket，无需 clone）
    {
        let udp = udp;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                // 解 SOCKS5 UDP REQUEST：RSV RSV FRAG ATYP DST... PORT... DATA
                if n < 3 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                    continue;
                }
                let mut i = 3usize;
                if i >= n {
                    continue;
                }
                let atyp = buf[i];
                i += 1;
                match atyp {
                    0x01 => {
                        if i + 4 + 2 > n {
                            continue;
                        }
                        i += 4;
                        i += 2;
                    } // IPv4
                    0x04 => {
                        if i + 16 + 2 > n {
                            continue;
                        }
                        i += 16;
                        i += 2;
                    } // IPv6
                    0x03 => {
                        if i >= n {
                            continue;
                        }
                        let l = buf[i] as usize;
                        i += 1;
                        if i + l + 2 > n {
                            continue;
                        }
                        i += l;
                        i += 2;
                    } // DOMAIN
                    _ => continue,
                }
                let payload = &buf[i..n];
                // 组 SOCKS5 UDP REPLY（127.0.0.1:from.port）
                let mut out = Vec::with_capacity(3 + 1 + 4 + 2 + payload.len());
                out.extend_from_slice(&[0, 0, 0]);
                out.push(0x01);
                out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
                out.extend_from_slice(&(from.port()).to_be_bytes());
                out.extend_from_slice(payload);
                let _ = udp.send_to(&out, from).await;
            }
        });
    }

    // 控制连接处理（greet + UDP ASSOC）
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _peer)) = tcp.accept().await else {
                continue;
            };
            let udp_addr = udp_addr;
            tokio::spawn(async move {
                // greet
                let mut head2 = [0u8; 2];
                if s.read_exact(&mut head2).await.is_err() {
                    return;
                }
                if head2 != [0x05, 0x01] {
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
                // request
                let mut head3 = [0u8; 3];
                if s.read_exact(&mut head3).await.is_err() {
                    return;
                }
                if head3[0] != 0x05 || head3[1] != 0x03 {
                    return;
                } // UDP ASSOC only
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
                // 响应成功（BND=127.0.0.1:udp_addr.port）
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
