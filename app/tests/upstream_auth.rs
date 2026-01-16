#![allow(clippy::manual_flatten, clippy::clone_on_copy)]
//! Validate that scaffold upstreams receive credentials from IR.
use sb_config::ir::{
    ConfigIR, Credentials, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR,
};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use sb_core::runtime::Runtime;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn start_echo() -> Option<(std::net::SocketAddr, thread::JoinHandle<()>)> {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping upstream auth test: cannot bind echo server ({err})");
                return None;
            }
            panic!("Failed to bind echo server: {err}");
        }
    };
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]);
                            }
                        }
                    }
                });
            }
        }
    });
    Some((addr, h))
}

fn start_fake_http_up_with_auth(
    echo: std::net::SocketAddr,
) -> Option<(std::net::SocketAddr, thread::JoinHandle<()>)> {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping upstream auth test: cannot bind upstream listener ({err})");
                return None;
            }
            panic!("Failed to bind upstream listener: {err}");
        }
    };
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                let echo = echo.clone();
                thread::spawn(move || {
                    // read status line
                    let mut line = Vec::new();
                    let mut b = [0u8; 1];
                    let mut last_cr = false;
                    loop {
                        let n = s.read(&mut b).unwrap();
                        if n == 0 {
                            return;
                        }
                        line.push(b[0]);
                        if last_cr && b[0] == b'\n' {
                            break;
                        }
                        last_cr = b[0] == b'\r';
                        if line.len() > 8192 {
                            return;
                        }
                    }
                    // read headers; check Proxy-Authorization present
                    let mut has_auth = false;
                    let mut buf = [0u8; 1];
                    let mut hdr_line = Vec::new();
                    let mut last_cr = false;
                    loop {
                        let n = s.read(&mut buf).unwrap();
                        if n == 0 {
                            break;
                        }
                        hdr_line.push(buf[0]);
                        if last_cr && buf[0] == b'\n' {
                            let ls = String::from_utf8_lossy(&hdr_line).to_string();
                            if ls.trim().is_empty() {
                                break;
                            }
                            if ls
                                .to_ascii_lowercase()
                                .starts_with("proxy-authorization: basic ")
                            {
                                has_auth = true;
                            }
                            hdr_line.clear();
                        }
                        last_cr = buf[0] == b'\r';
                    }
                    if !has_auth {
                        let _ = s.write_all(b"HTTP/1.1 407\r\n\r\n");
                        return;
                    }
                    let _ = s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    let up = TcpStream::connect(echo).unwrap();
                    let (mut ra, mut wa) = (s.try_clone().unwrap(), s);
                    let (mut rb, mut wb) = (up.try_clone().unwrap(), up);
                    let t1 = thread::spawn(move || {
                        let _ = std::io::copy(&mut ra, &mut wb);
                        let _ = wb.shutdown(std::net::Shutdown::Write);
                    });
                    let t2 = thread::spawn(move || {
                        let _ = std::io::copy(&mut rb, &mut wa);
                        let _ = wa.shutdown(std::net::Shutdown::Write);
                    });
                    let _ = t1.join();
                    let _ = t2.join();
                });
            }
        }
    });
    Some((addr, h))
}

#[test]
fn upstream_http_basic_auth_sent() {
    sb_adapters::register_all();
    let Some((echo_addr, _eh)) = start_echo() else {
        return;
    };
    let Some((http_up_addr, _hh)) = start_fake_http_up_with_auth(echo_addr) else {
        return;
    };
    // http inbound listen
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping upstream auth test: cannot bind http inbound ({err})");
                return;
            }
            panic!("Failed to bind http inbound: {err}");
        }
    };
    let http_in = l.local_addr().unwrap();
    drop(l);
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Http,
            listen: http_in.ip().to_string(),
            port: http_in.port(),
            allow_private_network: true,
            ..Default::default()
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Http,
            name: Some("B".into()),
            server: Some(http_up_addr.ip().to_string()),
            port: Some(http_up_addr.port()),
            credentials: Some(Credentials {
                username: Some("u".into()),
                password: Some("p".into()),
                username_env: None,
                password_env: None,
            }),
            ..Default::default()
        }],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".into()],
                outbound: Some("P".into()),
                ..Default::default()
            }],
            default: Some("P".into()),
            ..Default::default()
        },
        ntp: None,
        dns: None,
        ..Default::default()
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng.clone(), sb_core::context::Context::default());
    let sb = sb_core::runtime::switchboard::SwitchboardBuilder::from_config_ir(&ir).unwrap();
    let rt = Runtime::new(eng, br, sb).start();
    thread::sleep(Duration::from_millis(120));
    // CONNECT via inbound → upstream with Proxy-Authorization
    let mut s = std::net::TcpStream::connect(http_in).unwrap();
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        echo_addr.ip(),
        echo_addr.port(),
        echo_addr.ip(),
        echo_addr.port()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut head = [0u8; 48];
    let _ = s.read(&mut head).unwrap();
    let text = String::from_utf8_lossy(&head);
    assert!(text.contains("200"));
    rt.shutdown();
}
