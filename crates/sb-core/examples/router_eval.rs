use sb_core::router::rules::*;
use std::{env, fs};
fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "examples/rules/basic-router.rules".into());
    let txt = fs::read_to_string(&path).expect("read rules");
    let rs = parse_rules(&txt);
    let eng = Engine::build(rs);
    let samples = vec![
        ("download.example.com", None, false, Some(443)),
        ("www.example.com", None, false, Some(80)),
        ("cdn.tracker.net", None, false, Some(443)),
    ];
    for (dom, ip, udp, port) in samples {
        let d = eng.decide(&RouteCtx {
            domain: Some(dom),
            ip,
            transport_udp: udp,
            port,
            process_name: None,
            process_path: None,
            inbound_tag: None,
            outbound_tag: None,
            auth_user: None,
            query_type: None,
        });
        println!("{dom:25} udp={udp} port={:?} => {:?}", port, d);
    }
}
