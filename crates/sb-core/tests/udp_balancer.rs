use sb_core::net::datagram::UdpTargetAddr;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

fn is_permission_denied(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("operation not permitted") || msg.contains("permission denied")
}

async fn start_udp_echo() -> anyhow::Result<SocketAddr> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let addr = sock.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            if let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], from).await;
            }
        }
    });
    Ok(addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balancer_direct_ok() -> anyhow::Result<()> {
    // 启本地 echo
    let echo = match start_udp_echo().await {
        Ok(addr) => addr,
        Err(err) if is_permission_denied(&err) => {
            eprintln!("skipping balancer_direct_ok: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    // 开启 balancer，仅 direct
    std::env::set_var("SB_UDP_BALANCER", "1");
    std::env::set_var("SB_UDP_BALANCER_BACKENDS", "direct:1");
    // 决策 direct
    let dst = UdpTargetAddr::Ip(echo);
    let payload = b"balancer-direct";
    let n = match sb_core::outbound::udp_balancer::send_balanced(payload, &dst, "direct").await {
        Ok(n) => n,
        Err(err) if is_permission_denied(&err) => {
            eprintln!("skipping balancer_direct_ok: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    assert!(n >= payload.len());
    Ok(())
}

use sb_test_utils::socks5::start_mock_socks5;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balancer_socks5_ok() -> anyhow::Result<()> {
    let (proxy_tcp, _udp) = match start_mock_socks5().await {
        Ok(res) => res,
        Err(err) if is_permission_denied(&err) => {
            eprintln!("skipping balancer_socks5_ok: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    std::env::set_var("SB_UDP_BALANCER", "1");
    std::env::set_var("SB_UDP_BALANCER_BACKENDS", "socks5:1");
    std::env::set_var("SB_UDP_PROXY_MODE", "socks5");
    std::env::set_var("SB_UDP_PROXY_ADDR", proxy_tcp.to_string());
    // 目标地址随意（mock 直接回显）
    let dst = UdpTargetAddr::Ip("1.2.3.4:7777".parse().unwrap());
    let payload = b"balancer-socks5";
    let n = match sb_core::outbound::udp_balancer::send_balanced(payload, &dst, "proxy").await {
        Ok(n) => n,
        Err(err) if is_permission_denied(&err) => {
            eprintln!("skipping balancer_socks5_ok: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    assert!(n >= payload.len());
    Ok(())
}
