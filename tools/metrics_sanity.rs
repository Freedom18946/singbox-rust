//! Read metrics text and check for required metric names and allowed labels.
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:19090".to_string());
    let mut s = TcpStream::connect(addr).expect("connect exporter");
    let req = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
    s.write_all(req).ok();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok();
    let text = String::from_utf8_lossy(&buf);
    // strip headers
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    let lines = body.lines().collect::<Vec<_>>();
    // required metrics
    let required = [
        "sb_build_info",
        "udp_upstream_map_size",
        "udp_evict_total",
        "udp_ttl_seconds",
        "udp_upstream_fail_total",
        "route_explain_total",
        "__PROM_HTTP_FAIL__",
    ];
    let names_in = lines.iter().filter_map(|l| {
        if l.starts_with('#') { return None; }
        Some(l.split_whitespace().next().unwrap_or(""))
    }).collect::<HashSet<_>>();
    for n in required {
        if !names_in.contains(n) {
            eprintln!("MISSING: {}", n);
            std::process::exit(2);
        }
    }
    // label whitelist (must match sb-metrics constants)
    let allowed = ["rule","reason","class","outbound"];
    for l in lines {
        if l.starts_with('#') { continue; }
        if let Some(kvs) = l.split('{').nth(1).and_then(|x| x.split('}').next()) {
            for kv in kvs.split(',') {
                if let Some((k,_)) = kv.split_once('=') {
                    if !allowed.contains(&k) {
                        eprintln!("DISALLOWED LABEL: {}", k);
                        std::process::exit(3);
                    }
                }
            }
        }
    }
    println!(r#"{{"ok":true}}"#);
}