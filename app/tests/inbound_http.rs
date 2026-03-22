#![allow(clippy::while_let_loop, clippy::field_reassign_with_default)]
use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_config::ir::Credentials;
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use sb_core::router::{Router, RouterHandle};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc, oneshot};

fn is_perm(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

fn spawn_backend_echo() -> std::net::SocketAddr {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                eprintln!(
                    "skipping inbound_http due to sandbox PermissionDenied on backend bind: {}",
                    e
                );
                return "127.0.0.1:0".parse().unwrap();
            } else {
                panic!("bind: {}", e);
            }
        }
    };
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || loop {
        if let Ok((mut s, _)) = listener.accept() {
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut s.try_clone().unwrap(), &mut s);
            });
        } else {
            break;
        }
    });
    addr
}

async fn start_http_inbound(
    listen: SocketAddr,
    users: Option<Vec<Credentials>>,
) -> mpsc::Sender<()> {
    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let registry = OutboundRegistry::new(map);
    let outbounds = Arc::new(OutboundRegistryHandle::new(registry));
    let router = Arc::new(RouterHandle::new(Router::with_default("direct")));

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let cfg = HttpProxyConfig {
        tag: None,
        listen,
        router,
        outbounds,
        tls: None,
        users,
        set_system_proxy: false,
        allow_private_network: true,
        stats: None,
        conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sniff: false,
        sniff_override_destination: false,
    };

    tokio::spawn(async move {
        let _ = serve_http(cfg, stop_rx, Some(ready_tx)).await;
    });
    ready_rx.await.expect("http inbound ready signal");
    stop_tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_no_auth() {
    let backend = spawn_backend_echo();

    // choose inbound port
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("probe bind: {}", e);
            }
        }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // start HTTP CONNECT inbound without auth
    let addr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let stop_tx = start_http_inbound(addr, None).await;

    // client: send CONNECT then data and expect echo
    let mut s = match tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await {
        Ok(s) => s,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("connect: {}", e);
            }
        }
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        backend.ip(),
        backend.port(),
        backend.ip(),
        backend.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 64];
    let n = s.read(&mut head).await.unwrap();
    let status = std::str::from_utf8(&head[..n]).unwrap();
    assert!(status.contains("200"), "status: {}", status);
    // now pipe data
    let msg = b"hello-http";
    s.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
    let _ = stop_tx.send(()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_basic_auth() {
    let backend = spawn_backend_echo();

    // choose inbound port
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("probe bind: {}", e);
            }
        }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // start HTTP CONNECT inbound with auth
    let addr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let stop_tx = start_http_inbound(
        addr,
        Some(vec![Credentials {
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            username_env: None,
            password_env: None,
        }]),
    )
    .await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 1) without auth should get 407
    let mut s = match tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await {
        Ok(s) => s,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("connect: {}", e);
            }
        }
    };
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        backend.ip(),
        backend.port(),
        backend.ip(),
        backend.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 128];
    let n = s.read(&mut head).await.unwrap();
    let status = std::str::from_utf8(&head[..n]).unwrap();
    assert!(status.contains("407"), "status: {}", status);

    // 2) with auth should get 200 and echo works
    let mut s2 = match tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await {
        Ok(s) => s,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("connect: {}", e);
            }
        }
    };
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"u:p");
    let req2 = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        backend.ip(),
        backend.port(),
        backend.ip(),
        backend.port(),
        token
    );
    s2.write_all(req2.as_bytes()).await.unwrap();
    let n2 = s2.read(&mut head).await.unwrap();
    let status2 = std::str::from_utf8(&head[..n2]).unwrap();
    assert!(status2.contains("200"), "status: {}", status2);
    let msg = b"auth-ok";
    s2.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    s2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
    let _ = stop_tx.send(()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_uses_connect_target() {
    let backend = spawn_backend_echo();

    // choose inbound port
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("probe bind: {}", e);
            }
        }
    };
    let inbound_port = probe.local_addr().unwrap().port();
    drop(probe);

    // start HTTP CONNECT inbound
    let addr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let stop_tx = start_http_inbound(addr, None).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // CONNECT target should be used regardless of Host header value.
    let mut s = match tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await {
        Ok(s) => s,
        Err(e) => {
            if is_perm(&e) {
                return;
            } else {
                panic!("connect: {}", e);
            }
        }
    };
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: invalid.invalid:65535\r\n\r\n",
        backend.ip(),
        backend.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 128];
    let n = s.read(&mut head).await.unwrap();
    let status = std::str::from_utf8(&head[..n]).unwrap();
    assert!(status.contains("200"), "status: {}", status);
    let _ = stop_tx.send(()).await;
}
