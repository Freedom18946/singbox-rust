//! Additional bad-input tests to ensure the simple V2Ray API is not overly permissive

use std::net::SocketAddr;

#[test]
fn test_invalid_listen_addr_parse_fails() {
    // Illegal port (>= 65536) should not parse into SocketAddr
    let addr = "127.0.0.1:70000".parse::<SocketAddr>();
    assert!(addr.is_err(), "illegal port must fail to parse");
}

#[test]
fn test_missing_required_field_stats_request() {
    // Missing required field `name` should fail deserialization
    let json = r#"{ "reset": false }"#;
    let parsed: Result<sb_api::v2ray::simple::SimpleStatsRequest, _> = serde_json::from_str(json);
    assert!(parsed.is_err(), "missing required `name` must be an error");
}
