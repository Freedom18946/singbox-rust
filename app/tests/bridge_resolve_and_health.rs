#![allow(clippy::manual_flatten)]
use sb_config::ir::ConfigIR;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn rule_selects_named_outbound() {
    sb_adapters::register_all();
    // echo upstream（用来证明 direct 可连通）
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "skipping bridge_resolve_and_health due to sandbox PermissionDenied on bind: {}",
                    e
                );
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
    let config = json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "rules": [{
                "domain": ["*"],
                "outbound": "direct"
            }],
            "default": "direct"
        }
    });
    let ir: ConfigIR = to_ir_v1(&config);
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng, sb_core::context::Context::default());
    // 桥里应该能找到 direct
    assert!(br.find_outbound("direct").is_some());
}
