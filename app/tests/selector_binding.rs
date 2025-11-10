use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;

#[test]
fn selector_is_bound_to_members() {
    // 构造 IR：directA/directB + selector S = [directA, directB]
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
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("directA".into()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("directB".into()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("S".into()),
                members: Some(vec!["directA".into(), "directB".into()]),
                ..Default::default()
            },
        ],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".into()],
                outbound: Some("S".into()),
                ..Default::default()
            }],
            default: Some("S".into()),
        },
        ntp: None,
        dns: None,
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng);
    // 选择器应已作为一个命名出站注册
    assert!(br.find_outbound("S").is_some());
}
