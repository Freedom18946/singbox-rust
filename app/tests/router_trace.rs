#![cfg(feature = "router")]
use sb_config::ir::{ConfigIR, OutboundIR, OutboundType, RouteIR, RuleIR};

#[test]
fn engine_trace_matches_domain_and_port() {
    // Config: rule for domain suffix, and specific port
    let ir = ConfigIR {
        inbounds: vec![],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".into()),
            ..Default::default()
        }],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["example.com".into()],
                port: vec!["443".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            }],
            default: Some("direct".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let eng = sb_core::routing::engine::Engine::new(&ir);
    let input = sb_core::routing::engine::Input {
        host: "sub.example.com",
        port: 443,
        network: "tcp",
        protocol: "http",
        sniff_host: None,
        sniff_alpn: None,
        ..Default::default()
    };
    let dec = eng.decide(&input, true);
    assert_eq!(dec.outbound, "direct");
    // When want_trace=true, trace should exist and contain steps
    let tr = dec.trace.expect("trace");
    // domain and port steps should be recorded as matched
    assert!(tr.steps.iter().any(|s| s.kind == "domain" && s.matched));
    assert!(tr.steps.iter().any(|s| s.kind == "port" && s.matched));
}

#[test]
fn engine_uses_sniff_host_over_original_host() {
    // Rule matches only the sniffed host, not the literal IP host
    let ir = ConfigIR {
        inbounds: vec![],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".into()),
            ..Default::default()
        }],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["sniff.example".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            }],
            default: Some("block".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let eng = sb_core::routing::engine::Engine::new(&ir);
    // original host is IP (won't match domain rule); sniff_host provides domain
    let input = sb_core::routing::engine::Input {
        host: "1.2.3.4",
        port: 443,
        network: "tcp",
        protocol: "tls",
        sniff_host: Some("sniff.example"),
        ..Default::default()
    };
    let dec = eng.decide(&input, false);
    assert_eq!(dec.outbound, "direct");
}
