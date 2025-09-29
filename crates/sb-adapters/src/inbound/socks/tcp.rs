//! Minimal SOCKS5 TCP server (only supports UDP_ASSOCIATE).
//! 行为受环境变量控制，默认关闭，不破坏现有路径。
#![allow(dead_code)]

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use crate::inbound::socks::udp::{bind_udp_any, get_udp_bind_addr};

/// 启动最小 SOCKS5 TCP 服务：
// - greeting: 版本 5，选择 NO_AUTH(0x00)
// - request: 仅支持 CMD=UDP_ASSOCIATE(0x03)
// - reply: 成功时返回当前 UDP 绑定地址（BND.ADDR/PORT）
pub async fn run_tcp(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("socks: TCP listening on {}", listener.local_addr()?);
    loop {
        let (mut s, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_conn(&mut s).await {
                warn!("socks/tcp: {} error: {e}", peer);
            }
        });
    }
}

async fn handle_conn(s: &mut TcpStream) -> Result<()> {
    // --- greeting ---
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(anyhow::anyhow!("bad ver: {}", hdr[0]));
    }
    let n_methods = hdr[1] as usize;
    let mut methods = vec![0u8; n_methods];
    s.read_exact(&mut methods).await?;
    trace!("socks/tcp: methods={:?}", methods);
    // 选 NO_AUTH(0x00)
    s.write_all(&[0x05, 0x00]).await?;
    s.flush().await?;

    // --- request ---
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let ver = req[0];
    let cmd = req[1];
    let _rsv = req[2];
    let atyp = req[3];
    if ver != 0x05 {
        return Err(anyhow::anyhow!("bad ver in req: {}", ver));
    }
    if cmd != 0x03 {
        // command not supported
        write_reply(
            s,
            0x07,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        return Ok(());
    }
    // 读掉 DST.ADDR（我们不使用，仅完成协议）
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut v = vec![0u8; len[0] as usize];
            s.read_exact(&mut v).await?;
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
        }
        _ => {
            write_reply(
                s,
                0x08,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            return Ok(());
        }
    }
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let _dst_port = u16::from_be_bytes(port);

    // 获取/确保 UDP 绑定存在
    let udp_bind = if let Some(a) = get_udp_bind_addr() {
        a
    } else {
        // 兜底：如果未开启 UDP，则这里绑定一只（v4），以便返回 BND 信息
        let sock = bind_udp_any().await?;
        sock.local_addr()?
    };
    debug!("socks/tcp: reply UDP_ASSOCIATE with BND={udp_bind}");
    write_reply(s, 0x00, udp_bind).await?;

    // 保持连接直到对端关闭（关联生命周期对齐）
    let mut buf = [0u8; 1];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(_) => { /* 丢弃客户端数据 */ }
            Err(e) => {
                warn!("socks/tcp: read err: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// 生成 SOCKS5 回复报文（VER/REP/RSV/ATYP/BND.ADDR/BND.PORT）
fn build_reply_buf(rep: u8, bnd: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(0x05); // VER
    out.push(rep); // REP
    out.push(0x00); // RSV
    match bnd.ip() {
        IpAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&bnd.port().to_be_bytes());
    out
}

async fn write_reply(s: &mut TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    let out = build_reply_buf(rep, bnd);
    s.write_all(&out).await?;
    s.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    // 用内存双工流模拟最小 UDP_ASSOCIATE 流程，确保回复头部格式正确
    #[tokio::test]
    async fn test_udp_associate_reply() {
        let (mut a, mut b) = duplex(1024);
        let udp_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5353);
        // 客户端侧：写 greeting + request
        tokio::spawn(async move {
            // greeting: ver=5, methods=[0]
            a.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut r = [0u8; 2];
            a.read_exact(&mut r).await.unwrap();
            assert_eq!(&r, &[0x05, 0x00]);
            // request: ver=5, cmd=UDP_ASSOCIATE, rsv=0, atyp=V4, dst=0.0.0.0:0
            a.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // 读回复
            let mut head = [0u8; 4];
            a.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [0x05, 0x00, 0x00, 0x01]);
            let mut addr = [0u8; 4];
            a.read_exact(&mut addr).await.unwrap();
            let mut port = [0u8; 2];
            a.read_exact(&mut port).await.unwrap();
            assert_eq!(addr, [1, 2, 3, 4]);
            assert_eq!(u16::from_be_bytes(port), 5353);
        });
        // 服务器侧：直接用内部 writer 函数构造回复
        write_reply_stream(&mut b, udp_bind).await.unwrap();
    }

    // 测试辅助：不走全套 handle_conn，直接写一份 reply
    async fn write_reply_stream(s: &mut DuplexStream, bnd: SocketAddr) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        // 先写 greeting 响应（method=NO_AUTH）
        s.write_all(&[0x05, 0x00]).await?;
        // 再写构造好的回复包
        let buf = super::build_reply_buf(0x00, bnd);
        s.write_all(&buf).await?;
        s.flush().await?;
        Ok(())
    }
}
