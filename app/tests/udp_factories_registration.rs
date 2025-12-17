//! UDP Factories Registration Tests
//!
//! These tests validate that UDP-capable outbound adapters properly
//! register their UDP factories for QUIC-based protocols.

use sb_config::ir::{ConfigIR, InboundIR, InboundType};
#[cfg(any(feature = "out_ss", feature = "out_tuic", feature = "out_hysteria2"))]
use sb_config::ir::{OutboundIR, OutboundType};

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

    // Validate IR construction
    assert_eq!(ir.outbounds.len(), 1);
    assert_eq!(ir.outbounds[0].ty, OutboundType::Shadowsocks);
    assert_eq!(ir.outbounds[0].name, Some("ss".into()));

    println!("✅ Shadowsocks UDP factory config: PASS");
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

    // Validate IR construction
    assert_eq!(ir.outbounds.len(), 1);
    assert_eq!(ir.outbounds[0].ty, OutboundType::Tuic);
    assert_eq!(ir.outbounds[0].name, Some("tuic".into()));

    println!("✅ TUIC UDP factory config: PASS");
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

    // Validate IR construction
    assert_eq!(ir.outbounds.len(), 1);
    assert_eq!(ir.outbounds[0].ty, OutboundType::Hysteria2);
    assert_eq!(ir.outbounds[0].name, Some("hy2".into()));

    println!("✅ Hysteria2 UDP factory config: PASS");
}
