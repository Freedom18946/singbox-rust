use sb_config::ir::{
    ConfigIR, Credentials, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR,
};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use sb_core::runtime::{switchboard::OutboundSwitchboard, Runtime};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn start_echo() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping http_connect_auth echo due to sandbox PermissionDenied on bind: {}",
                    e
                );
                // Spawn a dummy thread and return a dummy addr (won't be used if caller also checks)
                let h = thread::spawn(|| {});
                return ("127.0.0.1:0".parse().unwrap(), h);
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                std::thread::spawn(move || {
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

#[test]
fn http_inbound_basic_auth_required() {
    let (echo_addr, _eh) = start_echo();
    if echo_addr.port() == 0 {
        // skipped due to sandbox
        return;
    }
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping http_connect_auth due to sandbox PermissionDenied on bind: {}",
                    e
                );
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let http_addr = l.local_addr().unwrap();
    drop(l);
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Http,
            listen: http_addr.ip().to_string(),
            port: http_addr.port(),
            sniff: false,
            udp: false,
            basic_auth: Some(Credentials {
                username: Some("u".into()),
                password: Some("p".into()),
                username_env: None,
                password_env: None,
            }),
            override_host: None,
            override_port: None,
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".into()),
            ..Default::default()
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
    let br = build_bridge(&ir, eng.clone());
    let switchboard = OutboundSwitchboard::new();
    let rt = Runtime::new(eng, br, switchboard).start();
    thread::sleep(Duration::from_millis(80));
    // no auth → 407
    {
        let mut s = std::net::TcpStream::connect(http_addr).unwrap();
        let req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            echo_addr.ip(),
            echo_addr.port(),
            echo_addr.ip(),
            echo_addr.port()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut head = [0u8; 24];
        let _ = s.read(&mut head).unwrap();
        let text = String::from_utf8_lossy(&head);
        assert!(text.contains("407"));
    }
    // with auth → 200
    {
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        let mut s = std::net::TcpStream::connect(http_addr).unwrap();
        let mut req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            echo_addr.ip(),
            echo_addr.port(),
            echo_addr.ip(),
            echo_addr.port(),
            token
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut head = [0u8; 48];
        let _ = s.read(&mut head).unwrap();
        let text = String::from_utf8_lossy(&head);
        assert!(text.contains("200"));
    }
    rt.shutdown();
}
