//! tcp_local.rs - Localhost TCP Connector (127.0.0.1 / ::1 only), for offline alpha testing
//! tcp_local.rs - 本机 TCP 连接器（仅 127.0.0.1 / ::1），用于离线 α 测试
//!
//! Features: io_local_alpha + handshake_alpha
//! 特性：io_local_alpha + handshake_alpha
use crate::handshake::Handshake;
use crate::loopback::{Frame, FrameDir, SessionLog};
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio::time::timeout;

/// Chaos Injection Spec (All optional, default no side effects) / Chaos 注入规格（全部可选，默认无副作用）
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaosSpec {
    /// Additional delay before writing (ms) / 写入前的附加延迟（毫秒）
    pub delay_tx_ms: u64,
    /// Additional delay before reading (ms) / 读取前的附加延迟（毫秒）
    pub delay_rx_ms: u64,
    /// Drop first N bytes of read data (zeroed if insufficient) / 对读到的数据，丢弃前 N 个字节（不足则变 0）
    pub rx_drop: usize,
    /// Keep at most M bytes of read data (None=No truncation) / 对读到的数据，最多保留 M 个字节（None=不截断）
    pub rx_trim: Option<usize>,
    /// XOR mask for read data (None=No tampering) / 对读到的数据，按字节 XOR 的掩码（None=不篡改）
    pub rx_xor: Option<u8>,
}

/// Configuration for io_local operations
#[derive(Debug)]
pub struct IoLocalConfig<'a> {
    pub req_port: u16,
    pub seed: u64,
    pub log_path: &'a std::path::Path,
    pub read_max: usize,
    pub to_ms: u64,
    pub spawn_echo: bool,
    pub xor_key: Option<u8>,
}

fn is_localhost(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST,
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    }
}

/// 简单 XOR 回显（用于内置 echo 服务器，可选）
fn xor_inplace(buf: &mut [u8], key: u8) {
    for b in buf {
        *b ^= key;
    }
}

/// Local TCP Connector: Connect to 127.0.0.1/::1:port, send init, read reply, write JSONL frame
/// 本机 TCP 连接器：连接到 127.0.0.1/::1:port ，发送 init，读取回包片段，写 JSONL 帧
pub async fn io_local_once(
    proto: &dyn Handshake,
    target: SocketAddr,
    seed: u64,
    log_path: &std::path::Path,
    read_max: usize,
    to_ms: u64,
    chaos: Option<ChaosSpec>,
) -> Result<(usize, usize)> {
    if !is_localhost(&target) {
        return Err(anyhow!(
            "io_local_alpha only permits 127.0.0.1/::1; got {}",
            target
        ));
    }
    let logger = SessionLog::new(log_path);
    let mut stream = timeout(Duration::from_millis(to_ms), TcpStream::connect(target))
        .await
        .map_err(|_| anyhow!("connect timeout"))?
        .map_err(|e| anyhow!("connect error: {e}"))?;

    let init = proto.encode_init(seed);
    let chaos = chaos.unwrap_or_default();
    if chaos.delay_tx_ms > 0 {
        sleep(Duration::from_millis(chaos.delay_tx_ms)).await;
    }
    logger.log_frame(&Frame::new(FrameDir::Tx, &init))?;
    timeout(Duration::from_millis(to_ms), stream.write_all(&init))
        .await
        .map_err(|_| anyhow!("write timeout"))?
        .map_err(|e| anyhow!("write error: {e}"))?;

    if chaos.delay_rx_ms > 0 {
        sleep(Duration::from_millis(chaos.delay_rx_ms)).await;
    }
    let mut buf = vec![0u8; read_max];
    let n = timeout(Duration::from_millis(to_ms), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("read timeout"))?
        .map_err(|e| anyhow!("read error: {e}"))?;
    buf.truncate(n);
    // 注入：drop → trim → xor
    if chaos.rx_drop > 0 && chaos.rx_drop < buf.len() {
        buf.drain(0..chaos.rx_drop);
    } else if chaos.rx_drop >= buf.len() {
        buf.clear();
    }
    if let Some(m) = chaos.rx_trim {
        if buf.len() > m {
            buf.truncate(m);
        }
    }
    if let Some(k) = chaos.rx_xor {
        for b in &mut buf {
            *b ^= k;
        }
    }
    let actual_rx_len = buf.len(); // 记录 chaos 处理后的实际长度
    logger.log_frame(&Frame::new(FrameDir::Rx, &buf))?;

    // 仅形状校验
    proto.decode_ack(&buf)?;
    Ok((init.len(), actual_rx_len))
}

/// 内置 Echo 服务器（单连接，读后原样/异或回显）
pub async fn spawn_echo_once(bind: SocketAddr, xor_key: Option<u8>) -> Result<SocketAddr> {
    if !is_localhost(&bind) {
        return Err(anyhow!("echo must bind localhost only"));
    }
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    // 单连接即退
    tokio::spawn(async move {
        if let Ok((mut s, _peer)) = listener.accept().await {
            let mut buf = vec![0u8; 65536];
            if let Ok(n) = s.read(&mut buf).await {
                let mut out = buf[..n].to_vec();
                if let Some(k) = xor_key {
                    xor_inplace(&mut out, k);
                }
                let _ = s.write_all(&out).await;
            }
        }
    });
    Ok(addr)
}

/// 组合：如需内置 echo 则先起服，再执行 io_local_once
pub async fn io_local_with_optional_echo(
    proto: &dyn Handshake,
    config: IoLocalConfig<'_>,
) -> Result<(SocketAddr, usize, usize)> {
    let mut target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.req_port);
    if config.spawn_echo {
        // 允许 port=0 由系统分配
        target.set_port(config.req_port);
        let bound = spawn_echo_once(target, config.xor_key).await?;
        target = bound;
    }
    // IoLocal 主流程：允许 Chaos 注入由上层传入（此处保持无注入）
    let (tx, rx) = io_local_once(
        proto,
        target,
        config.seed,
        config.log_path,
        config.read_max,
        config.to_ms,
        None,
    )
    .await?;
    Ok((target, tx, rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::trojan::Trojan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::tempdir;
    #[tokio::test]
    async fn test_io_local_basic() {
        let hs = Trojan::new("example.com".into(), 443);
        let dir = tempdir().unwrap();
        let log = dir.path().join("hs.session.jsonl");
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let addr = spawn_echo_once(bind, Some(0xAA)).await.unwrap();
        let config = IoLocalConfig {
            req_port: addr.port(),
            seed: 42,
            log_path: &log,
            read_max: 64,
            to_ms: 200,
            spawn_echo: false,
            xor_key: None,
        };
        let (_addr, tx, rx) = io_local_with_optional_echo(&hs, config).await.unwrap();
        assert!(tx > 0 && rx > 0);
    }
}
