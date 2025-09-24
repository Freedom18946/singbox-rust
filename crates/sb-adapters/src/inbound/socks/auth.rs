use anyhow::{bail, Result};
use sb_config::SocksAuth;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 基于服务端策略与客户端宣告的方法集合，选择 0x00/0x02 或 0xFF（不可接受）
pub fn select_method(policy: &SocksAuth, methods: &[u8]) -> u8 {
    match policy {
        SocksAuth::None => {
            if methods.iter().any(|&m| m == 0x00) { 0x00 } else { 0xFF }
        }
        SocksAuth::Users(users) if users.is_empty() => {
            if methods.iter().any(|&m| m == 0x00) { 0x00 } else { 0xFF }
        }
        SocksAuth::Users(_) => {
            if methods.iter().any(|&m| m == 0x02) { 0x02 } else { 0xFF }
        }
    }
}

/// RFC1929 子协商（用户名/密码）
pub async fn negotiate_userpass(stream: &mut TcpStream, policy: &SocksAuth) -> Result<()> {
    let ver = read_u8(stream).await?;
    if ver != 0x01 {
        bail!("invalid RFC1929 version: {}", ver);
    }
    let ulen = read_u8(stream).await? as usize;
    let mut ubuf = vec![0u8; ulen];
    stream.read_exact(&mut ubuf).await?;
    let plen = read_u8(stream).await? as usize;
    let mut pbuf = vec![0u8; plen];
    stream.read_exact(&mut pbuf).await?;

    let username = String::from_utf8_lossy(&ubuf);
    let password = String::from_utf8_lossy(&pbuf);
    let ok = match policy {
        SocksAuth::None => true,
        SocksAuth::Users(users) => users.iter().any(|u| u.username == username && u.password == password),
    };

    let status = if ok { 0x00 } else { 0x01 };
    stream.write_all(&[0x01, status]).await?;
    stream.flush().await?;
    if ok { Ok(()) } else { bail!("invalid credentials") }
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8> {
    let mut b = [0u8; 1];
    stream.read_exact(&mut b).await?;
    Ok(b[0])
}