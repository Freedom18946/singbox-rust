//! Shared TCP helpers for inbound routing and legacy proxy-pool endpoints.
//!
//! Protocol ownership lives in sb-adapters. These helpers intentionally return raw
//! Tokio streams because existing inbound copy loops use Tokio I/O directly.

use sb_core::telemetry::{err_kind, outbound_connect, outbound_handshake};
use socket2::{SockRef, TcpKeepalive};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpSocket, TcpStream},
    time::timeout,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default)]
pub struct ConnectOpts;

async fn connect_with_keepalive(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let _ = socket.set_nodelay(true);
    let _ = socket.set_keepalive(true);
    let stream = timeout(CONNECT_TIMEOUT, socket.connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))??;
    let socket_ref = SockRef::from(&stream);
    let _ = socket_ref.set_keepalive(true);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(30));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let keepalive = keepalive.with_retries(5);
    let _ = socket_ref.set_tcp_keepalive(&keepalive);
    Ok(stream)
}

async fn resolve_host(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Some(resolver) = sb_core::dns::global::get() {
        match resolver.resolve(host).await {
            Ok(answer) => {
                let addresses: Vec<_> = answer
                    .ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();
                if !addresses.is_empty() {
                    return Ok(addresses);
                }
                tracing::warn!(
                    host = %host,
                    "global dns resolver returned an empty answer for direct connect; falling back to system lookup"
                );
            }
            Err(error) => tracing::debug!(
                host = %host,
                %error,
                "global dns resolver failed for direct connect; falling back to system lookup"
            ),
        }
    }

    let addresses: Vec<_> = lookup_host((host, port)).await?.collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "resolve empty",
        ));
    }
    Ok(addresses)
}

pub async fn direct_connect_hostport(
    host: &str,
    port: u16,
    _options: &ConnectOpts,
) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in resolve_host(host, port).await? {
        match connect_with_keepalive(address).await {
            Ok(stream) => {
                outbound_connect("direct", "ok", None);
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address to connect"));
    let result = if error.kind() == io::ErrorKind::TimedOut {
        "timeout"
    } else {
        "error"
    };
    outbound_connect("direct", result, Some(err_kind(&error)));
    Err(error)
}

pub async fn http_proxy_connect_through_proxy(
    proxy_address: &str,
    target_host: &str,
    target_port: u16,
    _options: &ConnectOpts,
) -> io::Result<TcpStream> {
    let proxy_address: SocketAddr = proxy_address
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address"))?;
    let mut stream = match connect_with_keepalive(proxy_address).await {
        Ok(stream) => {
            outbound_connect("http", "ok", None);
            stream
        }
        Err(error) => {
            let result = if error.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "error"
            };
            outbound_connect("http", result, Some(err_kind(&error)));
            return Err(error);
        }
    };
    match timeout(HANDSHAKE_TIMEOUT, async {
        let authority = format!("{target_host}:{target_port}");
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::with_capacity(256);
        let mut chunk = [0u8; 128];
        loop {
            let size = stream.read(&mut chunk).await?;
            if size == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "proxy closed"));
            }
            response.extend_from_slice(&chunk[..size]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if response.len() > 8192 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy header too large",
                ));
            }
        }
        if response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200") {
            Ok(())
        } else {
            Err(io::Error::other("http connect failed"))
        }
    })
    .await
    {
        Err(_) => {
            outbound_handshake("http", "timeout", Some("timeout"));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "http handshake timeout",
            ));
        }
        Ok(Err(error)) => {
            outbound_handshake("http", "error", Some(err_kind(&error)));
            return Err(error);
        }
        Ok(Ok(())) => outbound_handshake("http", "ok", None),
    }
    Ok(stream)
}

pub async fn socks5_connect_through_socks5(
    proxy_address: &str,
    target_host: &str,
    target_port: u16,
    _options: &ConnectOpts,
) -> io::Result<TcpStream> {
    let proxy_address: SocketAddr = proxy_address
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address"))?;
    let mut stream = match connect_with_keepalive(proxy_address).await {
        Ok(stream) => {
            outbound_connect("socks5", "ok", None);
            stream
        }
        Err(error) => {
            let result = if error.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "error"
            };
            outbound_connect("socks5", result, Some(err_kind(&error)));
            return Err(error);
        }
    };
    match timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [0x05, 0x00] {
            return Err(io::Error::other("socks method not acceptable"));
        }

        let host = target_host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain too long",
            ));
        }
        let mut request = Vec::with_capacity(host.len() + 7);
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        request.extend_from_slice(host);
        request.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 || header[1] != 0x00 {
            return Err(io::Error::other("socks connect failed"));
        }
        match header[3] {
            0x01 => {
                let mut address = [0u8; 4];
                stream.read_exact(&mut address).await?;
            }
            0x03 => {
                let length = stream.read_u8().await? as usize;
                let mut address = vec![0u8; length];
                stream.read_exact(&mut address).await?;
            }
            0x04 => {
                let mut address = [0u8; 16];
                stream.read_exact(&mut address).await?;
            }
            _ => {}
        }
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok(())
    })
    .await
    {
        Err(_) => {
            outbound_handshake("socks5", "timeout", Some("timeout"));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "socks5 handshake timeout",
            ));
        }
        Ok(Err(error)) => {
            outbound_handshake("socks5", "error", Some(err_kind(&error)));
            return Err(error);
        }
        Ok(Ok(())) => outbound_handshake("socks5", "ok", None),
    }
    Ok(stream)
}
