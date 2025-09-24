use anyhow::Result;
use sb_core::socks5::{decode_udp_reply, encode_udp_request};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::main]
async fn main() -> Result<()> {
    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:29080".to_string())
        .parse()?;
    let relay: SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1.1.1.1:53".to_string())
        .parse()?;

    let listener = TcpListener::bind(listen).await?;
    eprintln!("[mock-socks5] listening on {listen}, relay->{relay}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let relay_addr = relay;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, relay_addr).await {
                eprintln!("[mock-socks5] client {peer} error: {e:?}");
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream, relay: SocketAddr) -> Result<()> {
    let mut greet = [0u8; 3];
    stream.read_exact(&mut greet).await?;
    stream.write_all(&[0x05, 0x00]).await?; // no-auth

    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x03 {
        anyhow::bail!("unsupported command");
    }
    let atyp = stream.read_u8().await?;
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; len as usize];
            stream.read_exact(&mut name).await?;
        }
        _ => anyhow::bail!("bad atyp"),
    }
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let _ = u16::from_be_bytes(port_bytes);

    let client_udp = UdpSocket::bind("0.0.0.0:0").await?;
    let bnd = client_udp.local_addr()?;
    let relay_udp = UdpSocket::bind("0.0.0.0:0").await?;
    relay_udp.connect(relay).await?;

    let mut resp = vec![0x05, 0x00, 0x00];
    match bnd {
        SocketAddr::V4(v4) => {
            resp.push(0x01);
            resp.extend_from_slice(&v4.ip().octets());
            resp.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            resp.push(0x04);
            resp.extend_from_slice(&v6.ip().octets());
            resp.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&resp).await?;

    let client_udp = std::sync::Arc::new(client_udp);
    let relay_udp = std::sync::Arc::new(relay_udp);
    let client_loop_udp = client_udp.clone();
    let relay_loop_udp = relay_udp.clone();

    let worker = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut resp_buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = client_loop_udp.recv_from(&mut buf).await else {
                break;
            };
            match decode_udp_reply(&buf[..n]) {
                Ok((_dst, payload)) => {
                    if relay_loop_udp.send(payload).await.is_ok() {
                        if let Ok(Ok(m)) = tokio::time::timeout(
                            Duration::from_millis(500),
                            relay_loop_udp.recv(&mut resp_buf),
                        )
                        .await
                        {
                            let pkt = encode_udp_request(&relay, &resp_buf[..m]);
                            let _ = client_loop_udp.send_to(&pkt, from).await;
                        }
                    }
                }
                Err(err) => {
                    eprintln!("[mock-socks5] decode request failed: {err:?}");
                }
            }
        }
    });

    let _ = worker.await;
    Ok(())
}
