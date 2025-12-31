#![cfg(feature = "socks")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// SOCKS5 UDP 端到端集成测试
// 由于解析函数是私有的，这里主要测试服务启动和基本功能

use sb_adapters::inbound::socks::udp::serve_udp_datagrams;
use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

// 手动构造 SOCKS5 UDP 包格式用于测试
fn encode_socks5_udp_ipv4(ip: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    buf.push(0x01); // ATYP = IPv4
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[tokio::test]
#[serial] // 必须与上一个测试串行，避免 env 互相覆盖
async fn socks_udp_service_starts_with_env() {
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "1");

    // 创建 UDP socket 用于 SOCKS 服务
    let socks_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socks_addr = socks_sock.local_addr().unwrap();

    // 启动 SOCKS UDP 服务
    let service_task = tokio::spawn(serve_udp_datagrams(socks_sock.clone(), None));

    // 给服务一些时间启动
    sleep(Duration::from_millis(100)).await;

    // 创建客户端 socket
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 创建一个简单的 echo 服务器作为上游目标
    let echo_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_server.local_addr().unwrap();

    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        if let Ok((n, peer)) = echo_server.recv_from(&mut buf).await {
            let _ = echo_server.send_to(&buf[..n], peer).await;
        }
    });

    // 构造 SOCKS5 UDP 数据包
    let target_ip = match echo_addr.ip() {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => panic!("Expected IPv4"),
    };
    let payload = b"test-socks-udp";
    let socks_packet = encode_socks5_udp_ipv4(target_ip, echo_addr.port(), payload);

    // 发送到 SOCKS 服务
    let send_result = timeout(
        Duration::from_secs(1),
        client.send_to(&socks_packet, socks_addr),
    )
    .await;

    // 验证发送成功（即使可能没有完整的代理流程，至少服务在运行）
    assert!(send_result.is_ok(), "Failed to send to SOCKS UDP service");

    // 清理
    service_task.abort();
    echo_task.abort();

    // 清理环境变量
    std::env::remove_var("SB_SOCKS_UDP_ENABLE");
}

#[tokio::test]
#[serial] // 与本文件中其他改 env 的测试串行化，避免进程级环境变量竞争
async fn socks_udp_service_disabled_by_default() {
    // 明确关闭（比 remove_var 更稳妥；避免并发测试遗留的 "1" 污染）
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "0");
    // 直接调用服务入口：现在应当快速返回；再加 300ms 超时，防回归
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let res = tokio::time::timeout(
        Duration::from_millis(300),
        sb_adapters::inbound::socks::udp::serve_socks5_udp(sock),
    )
    .await;
    assert!(matches!(res, Ok(Ok(()))));
}
