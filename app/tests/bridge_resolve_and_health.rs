use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn rule_selects_named_outbound() {
    // echo upstream（用来证明 direct 可连通）
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skipping bridge_resolve_and_health due to sandbox PermissionDenied on bind: {}", e);
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let _echo_addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
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
    // ir：一个 socks 入站 + direct 出站（命名为 "direct"），规则 domain:* → outbound:"direct"
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
    let br = build_bridge(&ir, eng);
    // 桥里应该能找到 direct
    assert!(br.find_outbound("direct").is_some());
}
