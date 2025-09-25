//! Contract tests for admin_debug schema and field order

#[test]
fn admin_config_field_order_locked() {
    // Serialize EnvConfig directly and inspect deterministic field order
    let cfg = app::admin_debug::reloadable::EnvConfig::from_env();
    let json = serde_json::to_string(&cfg).expect("serialize envconfig");
    // Expected order
    let keys = [
        "\"max_redirects\":",
        "\"timeout_ms\":",
        "\"max_bytes\":",
        "\"mime_allow\":",
        "\"mime_deny\":",
        "\"max_concurrency\":",
        "\"rps\":",
        "\"cache_capacity\":",
        "\"cache_ttl_ms\":",
        "\"breaker_window_ms\":",
        "\"breaker_open_ms\":",
        "\"breaker_failures\":",
        "\"breaker_ratio\":",
    ];
    let mut last = 0usize;
    for k in keys.iter() {
        let pos = json.find(k).expect("key present");
        assert!(pos >= last, "key order violated: {}", k);
        last = pos;
    }
}

#[test]
fn admin_reloadable_applyresult_field_order_locked() {
    let sample = app::admin_debug::reloadable::ApplyResult {
        ok: true,
        msg: "ok".to_string(),
        version: 7,
        changed: false,
        diff: serde_json::json!({"add":{},"remove":{},"replace":{}}),
    };
    let json = serde_json::to_string(&sample).expect("serialize applyresult");
    let keys = [
        "\"ok\":",
        "\"msg\":",
        "\"version\":",
        "\"changed\":",
        "\"diff\":",
    ];
    let mut last = 0usize;
    for k in keys.iter() {
        let pos = json.find(k).expect("key present");
        assert!(pos >= last, "key order violated: {}", k);
        last = pos;
    }
}

