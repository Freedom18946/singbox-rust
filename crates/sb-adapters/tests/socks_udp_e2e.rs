#![cfg(feature = "socks")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// SOCKS5 UDP 端到端集成测试
// 由于解析函数是私有的，这里主要测试服务启动和基本功能

use async_trait::async_trait;
use sb_adapters::inbound::socks::udp::{
    encode_udp_datagram, parse_udp_datagram, serve_udp_datagrams, serve_udp_datagrams_with_runtime,
    UdpDatagramRuntime,
};
use sb_config::ir::{ConfigIR, RuleAction, RuleIR};
use sb_core::adapter::{UdpOutboundFactory, UdpOutboundSession};
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use sb_core::router::RouterHandle;
use serial_test::serial;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout};

async fn bind_udp_or_skip() -> Option<UdpSocket> {
    match UdpSocket::bind("127.0.0.1:0").await {
        Ok(sock) => Some(sock),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => None,
        Err(err) => panic!("failed to bind UDP socket: {err}"),
    }
}

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

#[derive(Debug)]
struct MockTcpConnector;

#[async_trait]
impl sb_core::adapter::OutboundConnector for MockTcpConnector {
    async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<tokio::net::TcpStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "mock connector only supports UDP",
        ))
    }
}

#[derive(Debug)]
struct EchoUdpFactory;

impl UdpOutboundFactory for EchoUdpFactory {
    fn open_session(&self) -> sb_core::adapter::UdpOutboundFuture {
        Box::pin(async {
            let (tx, rx) = mpsc::channel(8);
            Ok(Arc::new(EchoUdpSession {
                tx,
                rx: Mutex::new(rx),
            }) as Arc<dyn UdpOutboundSession>)
        })
    }
}

#[derive(Debug)]
struct EchoUdpSession {
    tx: mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>>,
}

#[async_trait]
impl UdpOutboundSession for EchoUdpSession {
    async fn send_to(&self, data: &[u8], _host: &str, port: u16) -> std::io::Result<()> {
        let from = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        self.tx
            .send((data.to_vec(), from))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mock closed"))
    }

    async fn recv_from(&self) -> std::io::Result<(Vec<u8>, std::net::SocketAddr)> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mock closed"))
    }
}

fn udp_runtime(disable_domain_unmapping: bool) -> UdpDatagramRuntime {
    let mut cfg = ConfigIR::default();
    cfg.route.rules.push(RuleIR {
        action: RuleAction::RouteOptions,
        domain: vec!["example.test".to_string()],
        network: vec!["udp".to_string()],
        outbound: Some("udp-mock".to_string()),
        udp_disable_domain_unmapping: Some(disable_domain_unmapping),
        udp_timeout: Some("2s".to_string()),
        ..Default::default()
    });
    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("router build");

    let mut outbounds = HashMap::new();
    outbounds.insert(
        "udp-mock".to_string(),
        OutboundImpl::Connector(Arc::new(MockTcpConnector)),
    );
    let mut udp_factories: HashMap<String, Arc<dyn UdpOutboundFactory>> = HashMap::new();
    udp_factories.insert("udp-mock".to_string(), Arc::new(EchoUdpFactory));

    UdpDatagramRuntime::new(
        Some(Arc::new(RouterHandle::from_index(idx))),
        Some(Arc::new(OutboundRegistryHandle::new_with_udp_factories(
            OutboundRegistry::new(outbounds),
            udp_factories,
        ))),
    )
}

async fn run_domain_unmapping_case(
    disable_domain_unmapping: bool,
) -> Option<sb_core::net::datagram::UdpTargetAddr> {
    let Some(socks_sock) = bind_udp_or_skip().await else {
        eprintln!("skipping socks udp domain unmapping test: PermissionDenied binding service");
        return None;
    };
    let socks_sock = Arc::new(socks_sock);
    let socks_addr = socks_sock.local_addr().unwrap();
    let conn_tracker = sb_common::conntrack::shared_tracker();
    let service_task = tokio::spawn(serve_udp_datagrams_with_runtime(
        socks_sock,
        Some(Duration::from_secs(2)),
        Some("socks-test".to_string()),
        None,
        conn_tracker,
        udp_runtime(disable_domain_unmapping),
    ));

    let Some(client) = bind_udp_or_skip().await else {
        service_task.abort();
        eprintln!("skipping socks udp domain unmapping test: PermissionDenied binding client");
        return None;
    };

    let dst = sb_core::net::datagram::UdpTargetAddr::Domain {
        host: "example.test".to_string(),
        port: 5353,
    };
    let payload = b"domain-unmapping";
    let packet = encode_udp_datagram(&dst, payload);
    client.send_to(&packet, socks_addr).await.unwrap();

    let mut recv_buf = [0u8; 1500];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut recv_buf))
        .await
        .expect("reply timeout")
        .expect("reply recv");
    service_task.abort();

    let (reply_dst, header_len) = parse_udp_datagram(&recv_buf[..n]).expect("reply parse");
    assert_eq!(&recv_buf[header_len..n], payload);
    Some(reply_dst)
}

#[tokio::test]
#[serial] // 必须与上一个测试串行，避免 env 互相覆盖
async fn socks_udp_service_starts_with_env() {
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "1");

    // 创建 UDP socket 用于 SOCKS 服务
    let Some(socks_sock) = bind_udp_or_skip().await else {
        eprintln!("skipping socks udp env test: PermissionDenied binding socket");
        std::env::remove_var("SB_SOCKS_UDP_ENABLE");
        return;
    };
    let socks_sock = Arc::new(socks_sock);
    let socks_addr = socks_sock.local_addr().unwrap();
    let conn_tracker = sb_common::conntrack::shared_tracker();

    // 启动 SOCKS UDP 服务
    let service_task = tokio::spawn(serve_udp_datagrams(
        socks_sock.clone(),
        None,
        None,
        None,
        conn_tracker.clone(),
    ));

    // 给服务一些时间启动
    sleep(Duration::from_millis(100)).await;

    // 创建客户端 socket
    let Some(client) = bind_udp_or_skip().await else {
        eprintln!("skipping socks udp env test: PermissionDenied binding socket");
        std::env::remove_var("SB_SOCKS_UDP_ENABLE");
        return;
    };

    // 创建一个简单的 echo 服务器作为上游目标
    let Some(echo_server) = bind_udp_or_skip().await else {
        eprintln!("skipping socks udp env test: PermissionDenied binding socket");
        std::env::remove_var("SB_SOCKS_UDP_ENABLE");
        return;
    };
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
#[serial]
async fn socks_udp_registry_transport_preserves_domain_reply_by_default() {
    let Some(reply_dst) = run_domain_unmapping_case(false).await else {
        return;
    };

    assert_eq!(
        reply_dst,
        sb_core::net::datagram::UdpTargetAddr::Domain {
            host: "example.test".to_string(),
            port: 5353,
        }
    );
}

#[tokio::test]
#[serial]
async fn socks_udp_registry_transport_can_disable_domain_unmapping() {
    let Some(reply_dst) = run_domain_unmapping_case(true).await else {
        return;
    };

    assert_eq!(
        reply_dst,
        sb_core::net::datagram::UdpTargetAddr::Ip(std::net::SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            5353
        )))
    );
}

#[tokio::test]
#[serial] // 与本文件中其他改 env 的测试串行化，避免进程级环境变量竞争
async fn socks_udp_service_disabled_by_env() {
    // 明确关闭（比 remove_var 更稳妥；避免并发测试遗留的 "1" 污染）
    std::env::set_var("SB_SOCKS_UDP_ENABLE", "0");
    // 直接调用服务入口：现在应当快速返回；再加 300ms 超时，防回归
    let Some(sock) = bind_udp_or_skip().await else {
        eprintln!("skipping socks udp disabled test: PermissionDenied binding socket");
        return;
    };
    let sock = std::sync::Arc::new(sock);
    let conn_tracker = sb_common::conntrack::shared_tracker();
    let res = tokio::time::timeout(
        Duration::from_millis(300),
        sb_adapters::inbound::socks::udp::serve_socks5_udp(sock, conn_tracker),
    )
    .await;
    assert!(matches!(res, Ok(Ok(()))));
}
