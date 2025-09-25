use anyhow::{bail, Result};
use sb_core::error::SbError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::select_method;
use sb_config::SocksAuth;

pub struct Request {
    pub cmd: u8,
    pub dst_host: String,
    pub dst_port: u16,
}

/// 方法协商：读客户端方法列表 → 选择策略 → 回写选择
pub async fn negotiate_method(stream: &mut TcpStream, policy: &SocksAuth) -> Result<u8> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let ver = head[0];
    let nmethods = head[1] as usize;
    if ver != 0x05 {
        bail!(SbError::parse(format!("invalid SOCKS version: {}", ver)));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let selected = select_method(policy, &methods);
    stream.write_all(&[0x05, selected]).await?;
    stream.flush().await?;

    if selected == 0xFF {
        bail!(SbError::other("no acceptable authentication method"));
    }
    Ok(selected)
}

/// 读取请求（CONNECT/UDPASSOCIATE + 目标）
pub async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!(SbError::parse("invalid SOCKS version in request"));
    }
    let cmd = head[1];
    let atyp = head[3];

    let host = match atyp {
        0x01 => { // IPv4
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x03 => { // DOMAIN
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize];
            stream.read_exact(&mut b).await?;
            String::from_utf8_lossy(&b).to_string()
        }
        0x04 => { // IPv6
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => bail!(SbError::addr("address type not supported")),
    };

    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    Ok(Request { cmd, dst_host: host, dst_port: port })
}

/// 成功应答：返回绑定地址（未知则 0.0.0.0:0）
pub async fn write_success_reply(stream: &mut TcpStream, bnd: Option<&std::net::SocketAddr>) -> Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(0x05); // VER
    buf.push(0x00); // REP = succeeded
    buf.push(0x00); // RSV

    match bnd {
        Some(std::net::SocketAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
        }
        Some(std::net::SocketAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
        }
        None => {
            buf.push(0x01);
            buf.extend_from_slice(&[0, 0, 0, 0]);
        }
    }

    // 端口
    let port = bnd.map(|s| s.port()).unwrap_or(0);
    buf.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// 失败应答：用给定的 REP code（0x01..0x08），地址固定 0.0.0.0:0
pub async fn write_fail_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    let mut buf = Vec::with_capacity(10);
    buf.extend_from_slice(&[0x05, code, 0x00, 0x01]);
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}
