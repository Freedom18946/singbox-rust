use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::admin::http::spawn_admin;
use sb_core::routing::engine::Engine;

fn get(host: &str, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(host).unwrap();
    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", path, host);
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

fn post_json(host: &str, path: &str, body: &str) -> String {
    let mut s = std::net::TcpStream::connect(host).unwrap();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        path, host, body.as_bytes().len(), body
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn admin_health_and_explain() {
    // pick free port for admin; skip if sandbox denies bind
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skipping admin_http test due to sandbox PermissionDenied on bind: {}", e);
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let addr = l.local_addr().unwrap();
    drop(l);
    let admin = format!("{}:{}", addr.ip(), addr.port());

    // minimal IR with socks inbound + direct outbound + rule
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            listen: "127.0.0.1".into(),
            port: 0,
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
        }],
        outbounds: vec![OutboundIR { ty: OutboundType::Direct, name: Some("direct".into()), ..Default::default() }],
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
    // Try to spawn admin server; sandboxed CI (macOS seatbelt) may deny binding
    let h = match spawn_admin(&admin, eng.clone_as_static(), std::sync::Arc::new(br), None, None, None) {
        Ok(h) => h,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skipping admin_http test due to sandbox PermissionDenied: {}", e);
                return; // skip in restricted environments
            } else {
                panic!("spawn_admin failed: {}", e);
            }
        }
    };
    // wait a bit
    thread::sleep(Duration::from_millis(80));

    // GET /healthz
    let resp = get(&admin, "/healthz");
    eprintln!("healthz resp=\n{}", resp);
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("\"ok\":true"));

    // GET /outbounds
    let resp = get(&admin, "/outbounds");
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("\"items\""));

    // POST /explain
    let resp = post_json(
        &admin,
        "/explain",
        r#"{"dest":"example.com:443","network":"tcp","protocol":"socks"}"#,
    );
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("\"outbound\""));

    // teardown admin thread by dropping process (test end)
    let _ = h.thread().id();
}
