use sb_config::ir::{ConfigIR, InboundIR, InboundType};
// use sb_core::adapter::bridge::build_bridge;
// use sb_core::routing::engine::Engine;

#[allow(dead_code)]
fn base_ir() -> ConfigIR {
    let mut ir = ConfigIR::default();
    ir.inbounds.push(InboundIR {
        ty: InboundType::Socks,
        listen: "127.0.0.1".into(),
        port: 0,
        sniff: false,
        udp: true,
        basic_auth: None,
        override_port: None,
        ..Default::default()
    });
    ir
}

#[cfg(all(feature = "router", feature = "out_ss"))]
#[test]
fn registers_udp_factory_for_shadowsocks() {
    let mut ir = base_ir();
    // Shadowsocks outbound
    ir.outbounds.push(OutboundIR {
        ty: OutboundType::Shadowsocks,
        server: Some("127.0.0.1".into()),
        port: Some(8388),
        name: Some("ss".into()),
        method: Some("aes-256-gcm".into()),
        password: Some("test-password".into()),
        ..Default::default()
    });
    // Leak to 'static for Engine
    let ir_static: &'static ConfigIR = Box::leak(Box::new(ir));
    let eng = Engine::new(ir_static);

    let bridge = build_bridge(ir_static, eng, sb_core::context::Context::default());
    assert!(bridge.find_udp_factory("ss").is_some());
}

#[cfg(all(feature = "router", feature = "out_tuic"))]
#[test]
fn registers_udp_factory_for_tuic() {
    let mut ir = base_ir();
    // TUIC outbound
    ir.outbounds.push(OutboundIR {
        ty: OutboundType::Tuic,
        server: Some("127.0.0.1".into()),
        port: Some(4433),
        name: Some("tuic".into()),
        uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
        token: Some("test-token".into()),
        ..Default::default()
    });
    let ir_static: &'static ConfigIR = Box::leak(Box::new(ir));
    let eng = Engine::new(ir_static);
    let bridge = build_bridge(ir_static, eng, sb_core::context::Context::default());
    assert!(bridge.find_udp_factory("tuic").is_some());
}

#[cfg(all(feature = "router", feature = "out_hysteria2"))]
#[test]
fn registers_udp_factory_for_hysteria2() {
    let mut ir = base_ir();
    // Hysteria2 outbound
    ir.outbounds.push(OutboundIR {
        ty: OutboundType::Hysteria2,
        server: Some("127.0.0.1".into()),
        port: Some(4434),
        name: Some("hy2".into()),
        password: Some("pass".into()),
        ..Default::default()
    });
    let ir_static: &'static ConfigIR = Box::leak(Box::new(ir));
    let eng = Engine::new(ir_static);
    let bridge = build_bridge(ir_static, eng, sb_core::context::Context::default());
    assert!(bridge.find_udp_factory("hy2").is_some());
}
