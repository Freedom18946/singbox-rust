#![cfg(all(feature="http", feature="socks"))]
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::thread;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use sb_core::outbound::{OutboundRegistry, OutboundRegistryHandle, OutboundImpl, OutboundKind};
use sb_core::router::{Router, RouterHandle};
use sb_core::router::engine::Rule as RouteRule;
use sb_core::outbound::RouteTarget;

use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};
use tokio::sync::mpsc;

fn start_echo_server() -> Option<SocketAddr> {
    let listener = match StdListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable)
            {
                eprintln!("Skipping e2e_connect: cannot bind echo server ({err})");
                return None;
            }
            panic!("Failed to bind echo server: {err}");
        }
    };
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => { let _ = s.write_all(&buf[..n]); }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });
    Some(addr)
}

async fn start_http_inbound(listen: SocketAddr, router: RouterHandle, out: OutboundRegistryHandle) {
    let (tx, rx) = mpsc::channel(1);
    let cfg = HttpProxyConfig { listen, router, outbounds: out };
    tokio::spawn(async move { let _ = serve_http(cfg, rx).await; });
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(tx); // 不测试热更新
}

async fn start_socks_inbound(listen: SocketAddr, router: RouterHandle, out: OutboundRegistryHandle) {
    let (tx, rx) = mpsc::channel(1);
    let cfg = SocksInboundConfig { listen, udp_bind: None, router, outbounds: out, udp_nat_ttl: Duration::from_secs(60) };
    tokio::spawn(async move { let _ = serve_socks(cfg, rx).await; });
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(tx);
}

fn build_registry_and_router_direct() -> (OutboundRegistryHandle, RouterHandle) {
    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let reg = OutboundRegistry::new(map);
    let mut router = Router::with_default(OutboundKind::Direct);
    // 没有规则：默认直连
    router.set_rules(vec![]);
    (OutboundRegistryHandle::new(reg), RouterHandle::new(router))
}

#[tokio::test(flavor="multi_thread")]
async fn http_connect_roundtrip() {
    let Some(echo_addr) = start_echo_server() else {
        return;
    };
    let (out, router) = build_registry_and_router_direct();
    let http_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // 绑定 0 端口由 serve_http 自行监听：为了确定端口，这里固定改成 18081
    let http_addr: SocketAddr = "127.0.0.1:18081".parse().unwrap();
    start_http_inbound(http_addr, router.clone(), out.clone()).await;

    // 客户端：HTTP CONNECT
    let mut s = TcpStream::connect(http_addr).await.unwrap();
    let req = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n", echo_addr.ip(), echo_addr.port(), echo_addr.ip(), echo_addr.port());
    tokio::io::AsyncWriteExt::write_all(&mut s, req.as_bytes()).await.unwrap();
    // 读取响应
    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut s, &mut buf)).await.unwrap().unwrap();
    let hdr = String::from_utf8_lossy(&buf[..n]);
    assert!(hdr.starts_with("HTTP/1.1 200"));
    // 建立隧道后回环
    let payload = b"hello-http";
    tokio::io::AsyncWriteExt::write_all(&mut s, payload).await.unwrap();
    let mut back = [0u8; 32];
    let n2 = timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut s, &mut back)).await.unwrap().unwrap();
    assert_eq!(&back[..n2], payload);
}

#[tokio::test(flavor="multi_thread")]
async fn socks5_connect_roundtrip() {
    let Some(echo_addr) = start_echo_server() else {
        return;
    };
    let (out, router) = build_registry_and_router_direct();
    let socks_addr: SocketAddr = "127.0.0.1:1081".parse().unwrap();
    start_socks_inbound(socks_addr, router.clone(), out.clone()).await;

    // 客户端：SOCKS5 CONNECT（NO_AUTH）
    let mut s = TcpStream::connect(socks_addr).await.unwrap();
    // greeting
    tokio::io::AsyncWriteExt::write_all(&mut s, &[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    tokio::io::AsyncReadExt::read_exact(&mut s, &mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);
    // request connect echo_addr
    let ip = match echo_addr {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(_) => panic!("test uses v4 echo"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    tokio::io::AsyncWriteExt::write_all(&mut s, &req).await.unwrap();
    // read resp
    let mut resp = [0u8; 10];
    tokio::io::AsyncReadExt::read_exact(&mut s, &mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], 0x00);
    // 回环
    let payload = b"hello-socks";
    tokio::io::AsyncWriteExt::write_all(&mut s, payload).await.unwrap();
    let mut back = [0u8; 32];
    let n2 = timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut s, &mut back)).await.unwrap().unwrap();
    assert_eq!(&back[..n2], payload);
}
