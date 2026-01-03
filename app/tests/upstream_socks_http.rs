#![allow(clippy::manual_flatten, clippy::clone_on_copy)]
//! Fake upstream proxy servers to validate scaffold outbound connectors.
use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
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
            if matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable)
            {
                eprintln!("Skipping upstream socks/http test: cannot bind echo ({err})");
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

fn start_fake_socks_up(
    echo: std::net::SocketAddr,
) -> Option<(std::net::SocketAddr, thread::JoinHandle<()>)> {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable)
            {
                eprintln!("Skipping upstream socks/http test: cannot bind socks ({err})");
                return None;
            }
            panic!("Failed to bind socks server: {err}");
        }
    };
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                thread::spawn({
                    let echo = echo.clone();
                    move || {
                        let mut b = [0u8; 2];
                        s.read_exact(&mut b).unwrap(); // ver, n_methods
                        let n = b[1] as usize;
                        let mut methods = vec![0u8; n];
                        s.read_exact(&mut methods).unwrap();
                        // no-auth
                        s.write_all(&[0x05, 0x00]).unwrap();
                        let mut h = [0u8; 4];
                        s.read_exact(&mut h).unwrap();
                        assert_eq!(h[0], 0x05);
                        assert_eq!(h[1], 0x01);
                        match h[3] {
                            0x01 => {
                                let mut _ip = [0u8; 4];
                                s.read_exact(&mut _ip).unwrap();
                            }
                            0x03 => {
                                let mut ln = [0u8; 1];
                                s.read_exact(&mut ln).unwrap();
                                let mut dom = vec![0u8; ln[0] as usize];
                                s.read_exact(&mut dom).unwrap();
                            }
                            0x04 => {
                                let mut _ip = [0u8; 16];
                                s.read_exact(&mut _ip).unwrap();
                            }
                            _ => {}
                        }
                        let mut _port = [0u8; 2];
                        s.read_exact(&mut _port).unwrap();
                        // reply success
                        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .unwrap();
                        // 作为中继：连接 echo 并转发
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
                    }
                });
            }
        }
    });
    Some((addr, h))
}

fn start_fake_http_up(
    echo: std::net::SocketAddr,
) -> Option<(std::net::SocketAddr, thread::JoinHandle<()>)> {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable)
            {
                eprintln!("Skipping upstream socks/http test: cannot bind http ({err})");
                return None;
            }
            panic!("Failed to bind http server: {err}");
        }
    };
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                thread::spawn({
                    let echo = echo.clone();
                    move || {
                        // 读取一行 CONNECT ...
                        let mut buf = Vec::new();
                        let mut b = [0u8; 1];
                        let mut last_cr = false;
                        loop {
                            let n = s.read(&mut b).unwrap();
                            if n == 0 {
                                return;
                            };
                            buf.push(b[0]);
                            if last_cr && b[0] == b'\n' {
                                break;
                            }
                            last_cr = b[0] == b'\r';
                            if buf.len() > 8192 {
                                return;
                            }
                        }
                        // 丢弃头
                        let mut blank = 0u8;
                        let mut pr = 0u8;
                        loop {
                            let n = s.read(&mut b).unwrap();
                            if n == 0 {
                                break;
                            };
                            let x = b[0];
                            if pr == b'\r' && x == b'\n' {
                                blank += 1;
                            } else if x != b'\r' {
                                blank = 0;
                            }
                            pr = x;
                            if blank >= 1 {
                                break;
                            }
                        }
                        // 返回 200
                        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .unwrap();
                        // 作为中继：连接 echo 并转发
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
                    }
                });
            }
        }
    });
    Some((addr, h))
}

#[test]
fn outbound_scaffold_socks_and_http_connect() {
    sb_adapters::register_all();
    let Some((echo_addr, _eh)) = start_echo() else {
        return;
    };
    let Some((socks_addr, _sh)) = start_fake_socks_up(echo_addr) else {
        return;
    };
    let Some((http_addr, _hh)) = start_fake_http_up(echo_addr) else {
        return;
    };
    // HTTP 入站监听随机端口
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping upstream socks/http test: cannot bind inbound ({err})");
                return;
            }
            panic!("Failed to bind inbound listener: {err}");
        }
    };
    let http_in = l.local_addr().unwrap();
    drop(l);
    // 两个上游（A=SOCKS, B=HTTP），选择器 S=[A,B]，规则导向 S
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Http,
            listen: http_in.ip().to_string(),
            port: http_in.port(),
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
            ..Default::default()
        }],
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Socks,
                name: Some("A".into()),
                server: Some(socks_addr.ip().to_string()),
                port: Some(socks_addr.port()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Http,
                name: Some("B".into()),
                server: Some(http_addr.ip().to_string()),
                port: Some(http_addr.port()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("S".into()),
                members: Some(vec!["A".into(), "B".into()]),
                ..Default::default()
            },
        ],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".into()],
                outbound: Some("S".into()),
                ..Default::default()
            }],
            default: Some("S".into()),
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
    // 客户端通过 HTTP CONNECT 入站访问 echo（将经由 Selector 选择 A 或 B）
    let mut s = TcpStream::connect(http_in).unwrap();
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        echo_addr.ip(),
        echo_addr.port(),
        echo_addr.ip(),
        echo_addr.port()
    );
    s.write_all(req.as_bytes()).unwrap();
    // 读取到空行
    let mut buf = [0u8; 1];
    let mut pr = 0u8;
    let mut blank = 0u8;
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        };
        let x = buf[0];
        if pr == b'\r' && x == b'\n' {
            blank += 1
        } else if x != b'\r' {
            blank = 0
        }
        pr = x;
        if blank >= 2 {
            break;
        }
    }
    s.write_all(b"hello upstream").unwrap();
    let mut out = [0u8; 14];
    s.read_exact(&mut out).unwrap();
    assert_eq!(&out, b"hello upstream");
    rt.shutdown();
}
