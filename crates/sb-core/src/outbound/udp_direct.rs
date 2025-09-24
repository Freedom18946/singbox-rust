use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// 建立到目标地址的"连接化"UDP socket（本质上是 bind + connect）
pub async fn connect_udp(dst: SocketAddr) -> Result<UdpSocket> {
    // 0.0.0.0:0 动态端口；若你项目已有统一 bind 策略，这里可接进来
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await?;
    sock.connect(dst).await?;
    Ok(sock)
}
