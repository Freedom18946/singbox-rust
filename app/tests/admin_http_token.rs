#![cfg(feature = "admin_tests")]
use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::admin::http::spawn_admin;
use sb_core::context::Context;
use sb_core::routing::engine::Engine;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn get_with_token(host: &str, path: &str, tok: Option<&str>) -> String {
    let mut s = std::net::TcpStream::connect(host).unwrap();
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host);
    if let Some(t) = tok {
        req.push_str(&format!("X-Admin-Token: {}\r\n", t));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn admin_requires_token_when_configured() {
    // admin port
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping admin_http_token test due to sandbox PermissionDenied on bind: {}",
                    e
                );
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let addr = l.local_addr().unwrap();
    drop(l);
    let h = format!("{}:{}", addr.ip(), addr.port());
    // minimal IR
    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            listen: "127.0.0.1".into(),
            port: 0,
            ..Default::default()
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
            ..Default::default()
        },
        ..Default::default()
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng.clone(), Context::new());
    let th = match spawn_admin(
        &h,
        eng.clone_as_static(),
        std::sync::Arc::new(br),
        Some("sekret".into()),
        None,
        None,
    ) {
        Ok(h) => h,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping admin_http_token test due to sandbox PermissionDenied: {}",
                    e
                );
                return;
            } else {
                panic!("spawn_admin failed: {}", e);
            }
        }
    };
    thread::sleep(Duration::from_millis(60));
    // no token → 403
    let r = get_with_token(&h, "/healthz", None);
    assert!(r.contains("403"));
    // with token → 200
    let r = get_with_token(&h, "/healthz", Some("sekret"));
    assert!(r.contains("200 OK"));
    let _ = th.thread().id();
}
