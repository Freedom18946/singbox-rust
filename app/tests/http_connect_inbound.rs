use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use sb_core::runtime::Runtime;
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

fn http_connect(
    addr: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target.ip(),
        target.port(),
        target.ip(),
        target.port()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut line = String::new();
    // 读状态行与空行
    let mut buf = [0u8; 1];
    let mut last_cr = false;
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            assert!(false, "Unexpected EOF while reading HTTP CONNECT response status line");
        }
        line.push(buf[0] as char);
        if last_cr && buf[0] == b'\n' {
            break;
        }
        last_cr = buf[0] == b'\r';
    }
    // 跳过头直到空行
    let mut blank = 0;
    let mut prev = 0u8;
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let b = buf[0];
        if prev == b'\r' && b == b'\n' {
            blank += 1;
        } else if b != b'\r' {
            blank = 0;
        }
        prev = b;
        if blank >= 1 {
            break;
        }
    }
    s.write_all(payload).unwrap();
    let mut out = vec![0u8; payload.len()];
    s.read_exact(&mut out).unwrap();
    out
}

#[test]
fn http_connect_end2end_direct() {
    let (echo_addr, _h) = start_echo();
    // HTTP 入站监听随机端口
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_addr = l.local_addr().unwrap();
    drop(l);
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Http,
            listen: http_addr.ip().to_string(),
            port: http_addr.port(),
            sniff: false,
            udp: false,
            auth: None,
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".into()),
            server: None,
            port: None,
            udp: None,
            members: None,
            username: None,
            password: None,
        }],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            }],
            default: Some("direct".into()),
        },
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng);
    let rt = Runtime::new(eng, br).start();
    thread::sleep(Duration::from_millis(80));
    let out = http_connect(http_addr, echo_addr, b"hello http-connect");
    assert_eq!(&out, b"hello http-connect");
    rt.shutdown();
}
