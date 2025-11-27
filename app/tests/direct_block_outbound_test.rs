// Test for Direct and Block outbound adapter registration
use sb_adapters::register_all;
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::{registry, Bridge, OutboundParam};
use std::sync::Arc;

fn ctx() -> registry::AdapterOutboundContext {
    registry::AdapterOutboundContext {
        bridge: Arc::new(Bridge::new()),
    }
}

#[test]
fn test_direct_outbound_registration() {
    // Register all adapters
    register_all();

    // Create test IR
    let ir = OutboundIR {
        ty: OutboundType::Direct,
        name: Some("test-direct".to_string()),
        server: None,
        port: None,
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "direct".to_string(),
        name: Some("test-direct".to_string()),
        ..Default::default()
    };

    // Try to build the outbound
    let builder = registry::get_outbound("direct");
    assert!(
        builder.is_some(),
        "Direct outbound builder should be registered"
    );

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some(), "Direct outbound should be buildable");

    let (connector, udp_factory) = result.unwrap();
    // Connector is already Arc<dyn OutboundConnector>, not Option
    assert!(
        udp_factory.is_none(),
        "Direct outbound should not support UDP"
    );
}

#[test]
fn test_block_outbound_registration() {
    // Register all adapters
    register_all();

    // Create test IR
    let ir = OutboundIR {
        ty: OutboundType::Block,
        name: Some("test-block".to_string()),
        server: None,
        port: None,
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "block".to_string(),
        name: Some("test-block".to_string()),
        ..Default::default()
    };

    // Try to build the outbound
    let builder = registry::get_outbound("block");
    assert!(
        builder.is_some(),
        "Block outbound builder should be registered"
    );

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some(), "Block outbound should be buildable");

    let (connector, udp_factory) = result.unwrap();
    // Connector is already Arc<dyn OutboundConnector>, not Option
    assert!(
        udp_factory.is_none(),
        "Block outbound should not support UDP"
    );
}

#[tokio::test]
async fn test_direct_outbound_connect() {
    // Register all adapters
    register_all();

    // Create test IR
    let ir = OutboundIR {
        ty: OutboundType::Direct,
        name: Some("test-direct".to_string()),
        server: None,
        port: None,
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "direct".to_string(),
        name: Some("test-direct".to_string()),
        ..Default::default()
    };

    // Build the outbound
    let builder = registry::get_outbound("direct");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some());

    let (connector, _) = result.unwrap();
    // Connector is already Arc<dyn OutboundConnector>, ready to use

    // Try to connect to a public DNS server (should succeed or timeout)
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect("1.1.1.1", 53),
    )
    .await;

    // We just want to verify the connect method doesn't panic
    // It may succeed or timeout depending on network conditions
    match result {
        Ok(Ok(_stream)) => {
            // Connection succeeded
        }
        Ok(Err(_e)) => {
            // Connection failed (expected in some network environments)
        }
        Err(_) => {
            // Timeout (expected in some network environments)
        }
    }
}

#[tokio::test]
async fn test_block_outbound_always_fails() {
    // Register all adapters
    register_all();

    // Create test IR
    let ir = OutboundIR {
        ty: OutboundType::Block,
        name: Some("test-block".to_string()),
        server: None,
        port: None,
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "block".to_string(),
        name: Some("test-block".to_string()),
        ..Default::default()
    };

    // Build the outbound
    let builder = registry::get_outbound("block");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some());

    let (connector, _) = result.unwrap();
    // Connector is already Arc<dyn OutboundConnector>, ready to use

    // Try to connect - should always fail
    let result = connector.connect("1.1.1.1", 53).await;
    assert!(
        result.is_err(),
        "Block outbound should always fail to connect"
    );
}
