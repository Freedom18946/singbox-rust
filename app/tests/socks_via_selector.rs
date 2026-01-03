#![allow(clippy::manual_flatten)]
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
                eprintln!("Skipping socks selector test: cannot bind echo server ({err})");
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

fn socks_client_echo(
    socks: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = TcpStream::connect(socks).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep, [0x05, 0x00]);
    let ip = match target.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => [127, 0, 0, 1],
    };
    let port = target.port().to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port);
    s.write_all(&req).unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0x00);
    s.write_all(payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).unwrap();
    buf
}

#[test]
fn end2end_via_selector() {
    // Ensure adapter registry is populated for inbounds/outbounds.
    sb_adapters::register_all();
    let Some((echo_addr, _eh)) = start_echo() else {
        return;
    };
    // 准备 IR：SOCKS 入站 + directA/directB + selector S=[A,B]；规则默认导向 S
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable)
            {
                eprintln!("Skipping socks selector test: cannot bind socks listener ({err})");
                return;
            }
            panic!("Failed to bind socks listener: {err}");
        }
    };
    let socks_addr = l.local_addr().unwrap();
    drop(l);
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            listen: socks_addr.ip().to_string(),
            port: socks_addr.port(),
            ..Default::default()
        }],
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("A".into()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("B".into()),
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
        ..Default::default()
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng.clone(), sb_core::context::Context::default());
    let sb = sb_core::runtime::switchboard::SwitchboardBuilder::from_config_ir(&ir).unwrap();
    let rt = Runtime::new(eng, br, sb).start();
    std::thread::sleep(Duration::from_millis(100));
    let out = socks_client_echo(socks_addr, echo_addr, b"hello selector");
    assert_eq!(&out, b"hello selector");
    rt.shutdown();
}
