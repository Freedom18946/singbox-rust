#![allow(clippy::while_let_loop, clippy::field_reassign_with_default)]
use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_config::ir::Credentials;
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use sb_core::router::{Router, RouterHandle};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

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

struct CapturedOrigin {
    addr: SocketAddr,
    request_rx: std_mpsc::Receiver<String>,
}

fn spawn_http_origin(body: &'static str) -> CapturedOrigin {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                eprintln!(
                    "skipping inbound_http due to sandbox PermissionDenied on origin bind: {}",
                    e
                );
                let (_tx, rx) = std_mpsc::channel();
                return CapturedOrigin {
                    addr: "127.0.0.1:0".parse().unwrap(),
                    request_rx: rx,
                };
            }
            panic!("origin bind: {}", e);
        }
    };
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std_mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&req).to_string());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    CapturedOrigin {
        addr,
        request_rx: rx,
    }
}

fn reserve_loopback_addr() -> Option<SocketAddr> {
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if is_perm(&e) {
                return None;
            }
            panic!("probe bind: {}", e);
        }
    };
    let addr = probe.local_addr().unwrap();
    drop(probe);
    Some(addr)
}

async fn start_http_inbound(
    listen: SocketAddr,
    users: Option<Vec<Credentials>>,
) -> mpsc::Sender<()> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "direct".to_string(),
        OutboundImpl::Connector(std::sync::Arc::new(
            sb_adapters::outbound::direct::DirectOutbound::new(),
        )),
    );
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
    ready_rx
        .await
        .expect("http inbound ready signal")
        .expect("http inbound bind failed");
    stop_tx
}

async fn send_raw_http(addr: SocketAddr, request: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut s = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            if is_perm(&e) {
                return String::new();
            }
            panic!("connect: {}", e);
        }
    };
    s.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    timeout(Duration::from_secs(3), s.read_to_end(&mut buf))
        .await
        .expect("http response timed out")
        .expect("read http response");
    String::from_utf8_lossy(&buf).to_string()
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
async fn http_plain_forward_get_rewrites_and_strips_proxy_headers() {
    let origin = spawn_http_origin("plain-ok");
    if origin.addr.port() == 0 {
        return;
    }
    let Some(http_addr) = reserve_loopback_addr() else {
        return;
    };
    let stop_tx = start_http_inbound(http_addr, None).await;

    let req = format!(
        "GET http://{}:{}/alpha/beta?x=1 HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nX-Test: yes\r\nConnection: close\r\n\r\n",
        origin.addr.ip(),
        origin.addr.port(),
        origin.addr.ip(),
        origin.addr.port()
    );
    let response = send_raw_http(http_addr, req).await;
    assert!(response.contains("200 OK"), "response: {}", response);
    assert!(response.ends_with("plain-ok"), "response: {}", response);

    let seen = origin
        .request_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("origin captured request");
    assert!(
        seen.starts_with("GET /alpha/beta?x=1 HTTP/1.1\r\n"),
        "origin request: {}",
        seen
    );
    assert!(seen.contains("X-Test: yes"), "origin request: {}", seen);
    assert!(
        !seen.to_ascii_lowercase().contains("proxy-authorization:"),
        "origin request leaked Proxy-Authorization: {}",
        seen
    );
    assert!(
        !seen.to_ascii_lowercase().contains("proxy-connection:"),
        "origin request leaked Proxy-Connection: {}",
        seen
    );
    let _ = stop_tx.send(()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_plain_forward_basic_auth_required() {
    let Some(http_addr) = reserve_loopback_addr() else {
        return;
    };
    let stop_tx = start_http_inbound(
        http_addr,
        Some(vec![Credentials {
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            username_env: None,
            password_env: None,
        }]),
    )
    .await;

    let missing = send_raw_http(
        http_addr,
        "GET http://127.0.0.1:9/auth HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n".to_string(),
    )
    .await;
    assert!(missing.contains("407"), "response: {}", missing);

    let origin = spawn_http_origin("auth-plain-ok");
    if origin.addr.port() == 0 {
        let _ = stop_tx.send(()).await;
        return;
    }
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"u:p");
    let req = format!(
        "GET http://{}:{}/auth HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
        origin.addr.ip(),
        origin.addr.port(),
        origin.addr.ip(),
        origin.addr.port(),
        token
    );
    let response = send_raw_http(http_addr, req).await;
    assert!(response.contains("200 OK"), "response: {}", response);
    assert!(
        response.ends_with("auth-plain-ok"),
        "response: {}",
        response
    );
    let seen = origin
        .request_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("origin captured authed request");
    assert!(
        !seen.to_ascii_lowercase().contains("proxy-authorization:"),
        "origin request leaked auth: {}",
        seen
    );
    let _ = stop_tx.send(()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_plain_forward_rejects_relative_scheme_and_body_methods() {
    let Some(http_addr) = reserve_loopback_addr() else {
        return;
    };
    let stop_tx = start_http_inbound(http_addr, None).await;

    let relative = send_raw_http(
        http_addr,
        "GET /relative HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
    )
    .await;
    assert!(relative.contains("400"), "response: {}", relative);

    let https = send_raw_http(
        http_addr,
        "GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
    )
    .await;
    assert!(https.contains("400"), "response: {}", https);

    let post = send_raw_http(
        http_addr,
        "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"
            .to_string(),
    )
    .await;
    assert!(post.contains("405"), "response: {}", post);
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
