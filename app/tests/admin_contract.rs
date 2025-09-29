//! Contract tests for admin_debug schema, field order, and unified response envelope

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

use sb_admin_contract::{ErrorBody, ErrorKind, ResponseEnvelope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Test data types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheStats {
    entries: u64,
    hit_rate: f64,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BreakerStatus {
    state: String,
    failure_count: u32,
    last_failure_time: Option<String>,
    next_attempt_time: Option<String>,
}

#[test]
fn response_envelope_success_case() {
    let cache_data = CacheStats {
        entries: 1024,
        hit_rate: 0.85,
        size_bytes: 2048576,
    };

    let envelope = ResponseEnvelope::ok(cache_data).with_request_id("test-req-001");

    let json = serde_json::to_string(&envelope).expect("serialize success envelope");

    // Verify required fields present
    assert!(json.contains("\"ok\":true"));
    assert!(json.contains("\"data\":"));
    assert!(json.contains("\"requestId\":\"test-req-001\""));

    // Verify error field is omitted when None
    assert!(!json.contains("\"error\":"));

    // Verify field order (note: sb-admin-contract uses camelCase)
    let keys = ["\"ok\":", "\"data\":", "\"requestId\":"];
    let mut last = 0usize;
    for k in keys.iter() {
        let pos = json.find(k).expect("key present");
        assert!(pos >= last, "key order violated: {}", k);
        last = pos;
    }
}

#[test]
fn response_envelope_error_case() {
    let envelope: ResponseEnvelope<()> =
        ResponseEnvelope::err(ErrorKind::NotFound, "Resource not found")
            .with_request_id("test-req-002");

    let json = serde_json::to_string(&envelope).expect("serialize error envelope");

    // Verify required fields present
    assert!(json.contains("\"ok\":false"));
    assert!(json.contains("\"error\":"));
    assert!(json.contains("\"requestId\":\"test-req-002\""));

    // Verify data field is omitted when None
    assert!(!json.contains("\"data\":"));

    // Verify error structure (note: sb-admin-contract uses different field names)
    assert!(json.contains("\"kind\":"));
    assert!(json.contains("\"msg\":\"Resource not found\""));
}

#[test]
fn response_envelope_field_order_locked() {
    let envelope: ResponseEnvelope<String> =
        ResponseEnvelope::ok("test".to_string()).with_request_id(Uuid::new_v4().to_string());

    let json = serde_json::to_string(&envelope).expect("serialize envelope");

    // Required field order: ok, data, error (if present), requestId
    let keys = ["\"ok\":", "\"data\":", "\"requestId\":"];
    let mut last = 0usize;
    for k in keys.iter() {
        let pos = json.find(k).expect("key present");
        assert!(pos >= last, "key order violated: {}", k);
        last = pos;
    }
}

#[test]
fn response_error_types_coverage() {
    let error_kinds = [
        (ErrorKind::NotFound, "Resource not found"),
        (ErrorKind::Conflict, "Resource conflict detected"),
        (ErrorKind::State, "Invalid state transition"),
        (ErrorKind::Auth, "Authentication required"),
        (ErrorKind::RateLimit, "Rate limit exceeded"),
        (ErrorKind::Internal, "Internal server error"),
    ];

    for (kind, message) in error_kinds.iter() {
        let envelope: ResponseEnvelope<()> = ResponseEnvelope::err(kind.clone(), *message)
            .with_request_id(format!("test-{:?}", kind));

        let json = serde_json::to_string(&envelope).expect("serialize error envelope");
        assert!(json.contains("\"msg\":"));
        assert!(json.contains(&format!("\"msg\":\"{}\"", message)));
        assert!(json.contains("\"ok\":false"));
    }
}

#[test]
fn cache_endpoint_contract() {
    // Simulate /admin/cache endpoint response
    let cache_data = CacheStats {
        entries: 512,
        hit_rate: 0.92,
        size_bytes: 1048576,
    };

    let success_envelope = ResponseEnvelope::ok(cache_data).with_request_id("cache-stats-001");

    let json = serde_json::to_string(&success_envelope).expect("serialize cache stats");

    // Verify JSON structure matches expected contract
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["entries"], 512);
    assert_eq!(parsed["data"]["hit_rate"], 0.92);
    assert_eq!(parsed["data"]["size_bytes"], 1048576);
    assert_eq!(parsed["requestId"], "cache-stats-001");

    // Test error case for cache endpoint
    let error_envelope: ResponseEnvelope<CacheStats> =
        ResponseEnvelope::err(ErrorKind::State, "Cache is in maintenance mode")
            .with_request_id("cache-stats-002");

    let error_json = serde_json::to_string(&error_envelope).expect("serialize cache error");
    let parsed_error: serde_json::Value =
        serde_json::from_str(&error_json).expect("parse error json");
    assert_eq!(parsed_error["ok"], false);
    assert!(parsed_error["error"]["msg"]
        .as_str()
        .unwrap()
        .contains("maintenance mode"));
}

#[test]
fn breaker_endpoint_contract() {
    // Simulate /admin/breaker endpoint response
    let breaker_data = BreakerStatus {
        state: "open".to_string(),
        failure_count: 5,
        last_failure_time: Some("2024-01-15T10:30:00Z".to_string()),
        next_attempt_time: Some("2024-01-15T10:35:00Z".to_string()),
    };

    let envelope = ResponseEnvelope::ok(breaker_data).with_request_id("breaker-status-001");

    let json = serde_json::to_string(&envelope).expect("serialize breaker status");

    // Verify JSON structure
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["state"], "open");
    assert_eq!(parsed["data"]["failure_count"], 5);
    assert!(parsed["data"]["last_failure_time"].is_string());
    assert!(parsed["data"]["next_attempt_time"].is_string());

    // Test closed breaker state
    let closed_breaker = BreakerStatus {
        state: "closed".to_string(),
        failure_count: 0,
        last_failure_time: None,
        next_attempt_time: None,
    };

    let closed_envelope =
        ResponseEnvelope::ok(closed_breaker).with_request_id("breaker-status-002");

    let closed_json = serde_json::to_string(&closed_envelope).expect("serialize closed breaker");
    let parsed_closed: serde_json::Value =
        serde_json::from_str(&closed_json).expect("parse closed json");
    assert_eq!(parsed_closed["data"]["state"], "closed");
    assert_eq!(parsed_closed["data"]["failure_count"], 0);
    // Optional fields should be omitted when None
    assert!(!closed_json.contains("\"last_failure_time\""));
    assert!(!closed_json.contains("\"next_attempt_time\""));
}

#[test]
fn request_id_uniqueness() {
    let mut request_ids = std::collections::HashSet::new();

    // Generate multiple envelopes and verify unique request IDs
    for i in 0..100 {
        let envelope: ResponseEnvelope<i32> =
            ResponseEnvelope::ok(i).with_request_id(Uuid::new_v4().to_string());

        let request_id = envelope.request_id.clone().unwrap();
        assert!(
            request_ids.insert(request_id.clone()),
            "Duplicate request_id: {}",
            request_id
        );

        // Verify UUID format (basic check)
        assert_eq!(request_id.len(), 36);
        assert_eq!(request_id.chars().filter(|&c| c == '-').count(), 4);
    }
}
