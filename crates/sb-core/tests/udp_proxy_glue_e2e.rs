#![cfg(feature = "scaffold")]

use sb_core::socks5::decode_udp_reply;
use sb_test_utils::socks5::start_mock_socks5;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn glue_per_client_roundtrip() -> anyhow::Result<()> {
    // 启动假代理
    let (proxy_tcp, _udp) = start_mock_socks5().await?;
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var("SB_UDP_PROXY_ADDR", proxy_tcp.to_string());
    // listen socket（模拟入站的 UDP server）
    let listen = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    // client socket（模拟下游客户端）
    let client = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let client_addr = client.local_addr()?;
    // 建立 per-client 关联（后台会拉起从 relay→listen→client_addr 的回传循环）
    sb_core::outbound::udp_proxy_glue::ensure_client_assoc(Arc::clone(&listen), client_addr)
        .await?;
    // 发一个包（通过 glue 走 SOCKS5 上游），目标随便
    let dst: SocketAddr = "9.9.9.9:5353".parse().unwrap();
    let payload = b"ppp-udp-proxy-glue";
    let n = sb_core::outbound::udp_proxy_glue::send_via_proxy_for_client(client_addr, payload, dst)
        .await?;
    assert!(n >= payload.len());
    // 客户端应该直接收到裸 payload
    let mut buf = [0u8; 1500];
    let (m, _from) = client.recv_from(&mut buf).await?;
    let (_dst, body) = decode_udp_reply(&buf[..m]).expect("decode udp reply");
    assert_eq!(body, payload);
    Ok(())
}
