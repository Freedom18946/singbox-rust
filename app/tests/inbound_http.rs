use sb_core::adapter::InboundService;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

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
    thread::spawn(move || {
        let inbound = sb_core::inbound::http::HttpInboundService::new(addr);
        let _ = inbound.serve();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

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
    let user = "u".to_string();
    let pass = "p".to_string();
    thread::spawn(move || {
        let mut cfg = sb_core::inbound::http::HttpConfig::default();
        cfg.auth_enabled = true;
        cfg.username = Some(user);
        cfg.password = Some(pass);
        let inbound = sb_core::inbound::http::HttpInboundService::with_config(addr, cfg);
        let _ = inbound.serve();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_sniff_prefers_host_header() {
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

    // start HTTP CONNECT inbound with sniff enabled
    let addr = format!("127.0.0.1:{}", inbound_port).parse().unwrap();
    let sniff_enabled = true;
    thread::spawn(move || {
        let mut cfg = sb_core::inbound::http::HttpConfig::default();
        cfg.sniff_enabled = sniff_enabled;
        let inbound = sb_core::inbound::http::HttpInboundService::with_config(addr, cfg);
        let _ = inbound.serve();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Send CONNECT to an unreachable host:port, but with Host header of backend (should succeed)
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
        "CONNECT invalid.invalid:65535 HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        backend.ip(),
        backend.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 128];
    let n = s.read(&mut head).await.unwrap();
    let status = std::str::from_utf8(&head[..n]).unwrap();
    assert!(status.contains("200"), "status: {}", status);
}
