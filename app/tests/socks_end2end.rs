#![allow(clippy::manual_flatten)]
use sb_config::ir::ConfigIR;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use sb_core::runtime::switchboard::SwitchboardBuilder;
use sb_core::runtime::Runtime;
use serde_json::json;
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
                eprintln!("Skipping socks end-to-end test: cannot bind echo server ({err})");
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
    socks_addr: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    // Retry connect a few times to potential racing startup
    let mut s = {
        let mut conn = Err(std::io::Error::other("init"));
        for _ in 0..10 {
            match TcpStream::connect(socks_addr) {
                Ok(x) => {
                    conn = Ok(x);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
        conn.expect("failed to connect to socks server")
    };

    // greeting
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep, [0x05, 0x00], "SOCKS5 greeting failed");

    // request CONNECT ipv4
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
    assert_eq!(r[1], 0x00, "SOCKS5 connect failed (0x00=success)");

    // send/recv
    s.write_all(payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).unwrap();
    buf
}

#[test]
fn end_to_end_echo() {
    // Initialize registry
    sb_adapters::register_all();

    // Start echo server
    let Some((echo_addr, _h)) = start_echo() else {
        return;
    };

    // Reserve port for SOCKS
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping socks end-to-end test: cannot bind socks listener ({err})");
                return;
            }
            panic!("Failed to bind socks listener: {err}");
        }
    };
    let socks_addr = l.local_addr().unwrap();
    drop(l); // Release port
    thread::sleep(Duration::from_millis(100)); // Allow OS to clear

    // Config with Direct outbound
    let config = json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": socks_addr.ip().to_string(),
            "port": socks_addr.port()
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }]
    });

    let ir: ConfigIR = to_ir_v1(&config);
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng.clone(), sb_core::context::Context::default());
    let sb = SwitchboardBuilder::from_config_ir(&ir).unwrap();

    // Start Runtime (Full Stack)
    let rt = Runtime::new(eng, br, sb).start();

    // Run client verification
    let out = socks_client_echo(socks_addr, echo_addr, b"hello world");
    assert_eq!(&out, b"hello world");

    // Cleanup
    rt.shutdown();
}
