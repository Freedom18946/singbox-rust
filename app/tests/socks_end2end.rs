use sb_core::inbound::socks5::Socks5;
use sb_core::routing::engine::Engine;
use sb_config::ir::{ConfigIR, InboundIR, InboundType, RouteIR};
use sb_core::adapter::InboundService;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn start_echo() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
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
    (addr, h)
}

fn socks_client_echo(
    socks: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = TcpStream::connect(socks).unwrap();
    // greeting
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep, [0x05, 0x00]);
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
    assert_eq!(r[1], 0x00);
    // send/recv
    s.write_all(payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).unwrap();
    buf
}

#[test]
fn end_to_end_echo() {
    // 启 echo
    let (echo_addr, _h) = start_echo();
    // 启 socks inbound
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            listen: socks_addr.ip().to_string(),
            port: socks_addr.port(),
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
        }],
        ..Default::default()
    };
    let ir_static: &'static ConfigIR = Box::leak(Box::new(ir));
    let eng = Engine::new(ir_static);
    std::thread::spawn(move || {
        let srv = Socks5::new("127.0.0.1".into(), socks_addr.port()).with_engine(eng.clone_as_static());
        let _ = srv.serve();
    });
    std::thread::sleep(Duration::from_millis(100));
    // 客户端经 socks 访问 echo
    let out = socks_client_echo(socks_addr, echo_addr, b"hello world");
    assert_eq!(&out, b"hello world");
}
