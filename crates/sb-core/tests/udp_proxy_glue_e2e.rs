#![cfg(feature = "scaffold")]

use sb_core::socks5::decode_udp_reply;
use sb_test_utils::socks5::start_mock_socks5;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

fn is_permission_denied_io(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || err
            .to_string()
            .to_lowercase()
            .contains("operation not permitted")
}

fn is_permission_denied_any(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("operation not permitted") || msg.contains("permission denied")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn glue_per_client_roundtrip() -> anyhow::Result<()> {
    // 启动假代理
    let (proxy_tcp, _udp) = match start_mock_socks5().await {
        Ok(res) => res,
        Err(err) if is_permission_denied_any(&err) => {
            eprintln!("skipping glue_per_client_roundtrip: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var("SB_UDP_PROXY_ADDR", proxy_tcp.to_string());
    // listen socket（模拟入站的 UDP server）
    let listen = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(sock) => Arc::new(sock),
        Err(err) if is_permission_denied_io(&err) => {
            eprintln!("skipping glue_per_client_roundtrip: {err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    // client socket（模拟下游客户端）
    let client = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(sock) => sock,
        Err(err) if is_permission_denied_io(&err) => {
            eprintln!("skipping glue_per_client_roundtrip: {err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let client_addr = client.local_addr()?;
    // 建立 per-client 关联（后台会拉起从 relay→listen→client_addr 的回传循环）
    if let Err(err) =
        sb_core::outbound::udp_proxy_glue::ensure_client_assoc(Arc::clone(&listen), client_addr)
            .await
    {
        if is_permission_denied_any(&err) {
            eprintln!("skipping glue_per_client_roundtrip: {err}");
            return Ok(());
        }
        return Err(err);
    }
    // 发一个包（通过 glue 走 SOCKS5 上游），目标随便
    let dst: SocketAddr = "9.9.9.9:5353".parse().unwrap();
    let payload = b"ppp-udp-proxy-glue";
    let n = match sb_core::outbound::udp_proxy_glue::send_via_proxy_for_client(
        client_addr,
        payload,
        dst,
    )
    .await
    {
        Ok(n) => n,
        Err(err) if is_permission_denied_any(&err) => {
            eprintln!("skipping glue_per_client_roundtrip: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    assert!(n >= payload.len());
    // 客户端应该直接收到裸 payload
    let mut buf = [0u8; 1500];
    let (m, _from) = client.recv_from(&mut buf).await?;
    let (_dst, body) = decode_udp_reply(&buf[..m]).expect("decode udp reply");
    assert_eq!(body, payload);
    Ok(())
}
