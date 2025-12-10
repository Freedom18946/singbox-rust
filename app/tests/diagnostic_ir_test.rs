//! Diagnostic test to examine IR conversion for HTTP/SOCKS outbounds

#[test]
fn test_http_outbound_ir_conversion() {
    let config = serde_json::json!({
        "log": {
            "level": "error"
        },
        "outbounds": [{
            "type": "http",
            "tag": "http-proxy",
            "server": "127.0.0.1",
            "port": 8080
        }]
    });

    let ir = sb_config::validator::v2::to_ir_v1(&config);

    // Print the IR for inspection
    println!("IR: {:#?}", ir);

    // Check outbounds
    assert!(!ir.outbounds.is_empty(), "IR should have outbounds");
    let outbound = &ir.outbounds[0];

    println!("Outbound type: {:?}", outbound.ty);
    println!("Outbound server: {:?}", outbound.server);
    println!("Outbound port: {:?}", outbound.port);
    println!("Outbound name: {:?}", outbound.name);

    // These should be populated from the JSON
    assert!(outbound.server.is_some(), "Server should be present in IR");
    assert!(outbound.port.is_some(), "Port should be present in IR");
    assert_eq!(outbound.server.as_deref(), Some("127.0.0.1"));
    assert_eq!(outbound.port, Some(8080));
}

#[test]
fn test_socks_outbound_ir_conversion() {
    let config = serde_json::json!({
        "log": {
            "level": "error"
        },
        "outbounds": [{
            "type": "socks",
            "tag": "socks-proxy",
            "server": "127.0.0.1",
            "port": 1080
        }]
    });

    let ir = sb_config::validator::v2::to_ir_v1(&config);

    // Check outbounds
    assert!(!ir.outbounds.is_empty(), "IR should have outbounds");
    let outbound = &ir.outbounds[0];

    println!("Outbound type: {:?}", outbound.ty);
    println!("Outbound server: {:?}", outbound.server);
    println!("Outbound port: {:?}", outbound.port);
    println!("Outbound name: {:?}", outbound.name);

    // These should be populated from the JSON
    assert!(outbound.server.is_some(), "Server should be present in IR");
    assert!(outbound.port.is_some(), "Port should be present in IR");
    assert_eq!(outbound.server.as_deref(), Some("127.0.0.1"));
    assert_eq!(outbound.port, Some(1080));
}

#[test]
#[cfg(feature = "adapters")]
fn test_http_adapter_builder_with_ir() {
    use sb_config::ir::OutboundIR;
    use sb_config::ir::OutboundType;
    use sb_core::adapter::registry;
    use sb_core::adapter::Bridge;
    use sb_core::adapter::OutboundParam;
    use sb_core::context::{Context, ContextRegistry};
    use std::sync::Arc;

    // Register adapters
    sb_adapters::register_all();

    // Create IR manually with known values
    let ir = OutboundIR {
        ty: OutboundType::Http,
        server: Some("127.0.0.1".to_string()),
        port: Some(8080),
        name: Some("http-proxy".to_string()),
        credentials: None,
        ..Default::default()
    };

    // Create param with matching name/kind
    let param = OutboundParam {
        kind: "http".to_string(),
        name: Some("http-proxy".to_string()),
        server: None,
        port: None,
        credentials: None,
        ..Default::default()
    };

    // Try to get the adapter
    let builder = registry::get_outbound("http").expect("HTTP adapter should be registered");

    let ctx = registry::AdapterOutboundContext {
        bridge: Arc::new(Bridge::new(Context::new())),
        context: ContextRegistry::from(&Context::new()),
    };

    let result = builder(&param, &ir, &ctx);
    println!("Builder result: {:?}", result.is_some());

    assert!(
        result.is_some(),
        "HTTP adapter builder should return Some with valid IR"
    );
}
