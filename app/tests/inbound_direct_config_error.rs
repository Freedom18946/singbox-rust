use sb_core::adapter::Bridge;

#[test]
fn direct_inbound_missing_override_errors() {
    // Build IR with direct inbound missing override_host/override_port
    let ir = sb_config::ir::ConfigIR {
        inbounds: vec![sb_config::ir::InboundIR {
            ty: sb_config::ir::InboundType::Direct,
            listen: "127.0.0.1".into(),
            port: 12345,
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
        }],
        outbounds: vec![sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Direct,
            name: Some("direct".into()),
            ..Default::default()
        }],
        route: sb_config::ir::RouteIR { rules: vec![], default: Some("direct".into()) },
    };

    let res = Bridge::new_from_config(&ir);
    assert!(res.is_err(), "expected error for missing override fields");
}

