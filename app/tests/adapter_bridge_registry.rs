use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR};
use sb_core::adapter::{bridge::build_bridge, registry::RegistrySnapshot};
use sb_core::router::Engine;

#[test]
fn missing_registry_builders_are_fatal_and_identify_protocol_kinds() {
    sb_adapters::register_all();
    let registered_ir = ConfigIR {
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct".into()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Block,
                name: Some("block".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let registered_engine = Engine::new(std::sync::Arc::new(registered_ir.clone()));
    let registered = build_bridge(
        &registered_ir,
        registered_engine,
        sb_core::context::Context::default(),
    );
    assert!(registered.startup_errors.is_empty());
    assert_eq!(registered.outbounds.len(), 2);
    assert_eq!(registered.outbounds[0].2.r#type(), "direct");
    assert_eq!(registered.outbounds[1].2.r#type(), "block");

    sb_core::adapter::registry::install_snapshot(&RegistrySnapshot::new());

    let ir = ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            tag: Some("local-socks".into()),
            listen: "127.0.0.1".into(),
            port: 10801,
            ..Default::default()
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".into()),
            ..Default::default()
        }],
        route: RouteIR::default(),
        ..Default::default()
    };
    let engine = Engine::new(std::sync::Arc::new(ir.clone()));
    let bridge = build_bridge(&ir, engine, sb_core::context::Context::default());

    assert!(bridge.inbounds.is_empty());
    assert!(bridge.outbounds.is_empty());
    assert_eq!(bridge.startup_errors.len(), 2);

    let errors = bridge.startup_errors.join("\n");
    assert!(errors.contains("inbound 'local-socks' kind 'socks'"));
    assert!(errors.contains("outbound 'direct' kind 'direct'"));
    assert!(errors.contains("not compiled into this build"));
}

#[test]
fn aggregate_adapter_profile_registers_ssh_builder() {
    sb_adapters::register_all();
    assert!(sb_core::adapter::registry::get_outbound("ssh").is_some());
}
