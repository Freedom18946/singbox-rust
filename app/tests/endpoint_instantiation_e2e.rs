use anyhow::Result;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::Bridge;
use serde_json::json;

#[test]
fn test_endpoint_instantiation() -> Result<()> {
    sb_adapters::register_all();

    let config = json!({
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg-ep",
            "system_interface": false,
            "address": ["10.0.0.1/24"],
            "private_key": "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=", // dummy base64 key
            "peers": []
        }],
        "inbounds": [],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }]
    });

    let ir = to_ir_v1(&config);
    let bridge = Bridge::new_from_config(&ir, sb_core::context::Context::default())?;

    assert_eq!(bridge.endpoints.len(), 1);
    let endpoint = &bridge.endpoints[0];
    assert_eq!(endpoint.tag(), "wg-ep");
    assert_eq!(endpoint.endpoint_type(), "wireguard");

    Ok(())
}
