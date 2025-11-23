use anyhow::Result;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::Bridge;
use serde_json::json;

#[test]
fn test_service_instantiation() -> Result<()> {
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();

    let config = json!({
        "services": [{
            "type": "resolved",
            "tag": "resolved-dns",
            "resolved_listen": "127.0.0.53",
            "resolved_listen_port": 53
        }],
        "inbounds": [],
        "outbounds": [{
            "type": "direct",
            "tag": "direct-out"
        }]
    });

    let ir = to_ir_v1(&config);
    let bridge = Bridge::new_from_config(&ir)?;

    assert_eq!(bridge.services.len(), 1);
    let service = &bridge.services[0];
    assert_eq!(service.service_type(), "resolved");
    assert_eq!(service.tag(), "resolved-dns");

    Ok(())
}
