//! Integration tests for admin authentication contract compliance
//!
//! Tests the admin debug server authentication and rate limiting with
//! contract-compliant ResponseEnvelope responses.
//!
//! Scenarios covered:
//! 1. Correct credentials → 200 + {ok:true, request_id non-empty}
//! 2. Missing/wrong credentials → 401 + {ok:false, error.kind=="Auth"}
//! 3. High-frequency requests → 429 + {ok:false, error.kind=="RateLimit"}

#![cfg(feature = "admin_debug")]

use reqwest::Client;
use sb_admin_contract::{ErrorKind, ResponseEnvelope};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

/// Test configuration for admin server
struct TestConfig {
    port: u16,
    auth_token: String,
    rate_limit_max: u32,
}

impl TestConfig {
    fn new() -> Self {
        Self {
            port: 0, // Will be set by the server
            auth_token: "test-token-12345".to_string(),
            rate_limit_max: 3, // Low limit for testing
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn auth_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", self.auth_token),
        );
        headers.insert("x-request-id".to_string(), "test-req-001".to_string());
        headers
    }

    fn no_auth_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "test-req-002".to_string());
        headers
    }

    fn wrong_auth_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer wrong-token".to_string(),
        );
        headers.insert("x-request-id".to_string(), "test-req-003".to_string());
        headers
    }
}

/// Start admin debug server in background with test configuration
async fn start_test_server(config: &mut TestConfig) -> tokio::task::JoinHandle<()> {
    // Set environment variables for the test
    std::env::set_var("SB_ADMIN_TOKEN", &config.auth_token);
    std::env::set_var("SB_ADMIN_RATE_LIMIT_ENABLED", "1");
    std::env::set_var("SB_ADMIN_RATE_LIMIT_MAX", config.rate_limit_max.to_string());
    std::env::set_var("SB_ADMIN_RATE_LIMIT_WINDOW_SEC", "60");
    std::env::set_var("SB_ADMIN_RATE_LIMIT_STRATEGY", "global");

    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut tx = Some(tx);

    let handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Send the port back to the test
        if let Some(sender) = tx.take() {
            let _ = sender.send(addr.port());
        }

        // Create auth and TLS configuration
        let _auth_conf = app::admin_debug::http_server::AuthConf::from_env();
        let _tls_conf: Option<app::admin_debug::http_server::TlsConf> = None;

        // Start the server using public API
        if let Err(e) = app::admin_debug::http_server::serve_plain(&addr.to_string()).await {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for the port to be available
    config.port = rx.await.expect("Failed to get server port");

    // Give the server a moment to fully start
    sleep(Duration::from_millis(100)).await;

    handle
}

/// Make HTTP request and parse response as ResponseEnvelope
async fn make_request(
    client: &Client,
    url: &str,
    headers: &HashMap<String, String>,
) -> Result<(u16, ResponseEnvelope<Value>), Box<dyn std::error::Error>> {
    let mut req = client.get(url);

    for (key, value) in headers {
        req = req.header(key, value);
    }

    let response = req.send().await?;
    let status = response.status().as_u16();
    let body_text = response.text().await?;

    // Parse as ResponseEnvelope
    let envelope: ResponseEnvelope<Value> = serde_json::from_str(&body_text).map_err(|e| {
        format!(
            "Failed to parse response as ResponseEnvelope: {} (body: {})",
            e, body_text
        )
    })?;

    Ok((status, envelope))
}

#[tokio::test]
async fn test_auth_success_scenario() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    let (status, envelope) = make_request(&client, &url, &config.auth_headers())
        .await
        .expect("Request should succeed");

    // Scenario 1: Correct credentials → 200 + {ok:true, request_id non-empty}
    assert_eq!(status, 200, "Should return 200 for valid auth");
    assert!(envelope.ok, "Response should have ok=true");
    assert!(envelope.data.is_some(), "Response should have data");
    assert!(envelope.error.is_none(), "Response should not have error");
    assert!(
        envelope.request_id.is_some(),
        "Response should have request_id"
    );
    assert!(
        !envelope.request_id.as_ref().unwrap().is_empty(),
        "Request ID should not be empty"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}

#[tokio::test]
async fn test_auth_missing_credentials() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    let (status, envelope) = make_request(&client, &url, &config.no_auth_headers())
        .await
        .expect("Request should complete");

    // Scenario 2a: Missing credentials → 401 + {ok:false, error.kind=="Auth"}
    assert_eq!(status, 401, "Should return 401 for missing auth");
    assert!(!envelope.ok, "Response should have ok=false");
    assert!(envelope.data.is_none(), "Response should not have data");
    assert!(envelope.error.is_some(), "Response should have error");

    let error = envelope.error.unwrap();
    assert_eq!(error.kind, ErrorKind::Auth, "Error kind should be Auth");
    assert!(!error.msg.is_empty(), "Error message should not be empty");
    assert!(
        envelope.request_id.is_some(),
        "Response should have request_id"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}

#[tokio::test]
async fn test_auth_wrong_credentials() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    let (status, envelope) = make_request(&client, &url, &config.wrong_auth_headers())
        .await
        .expect("Request should complete");

    // Scenario 2b: Wrong credentials → 401 + {ok:false, error.kind=="Auth"}
    assert_eq!(status, 401, "Should return 401 for wrong auth");
    assert!(!envelope.ok, "Response should have ok=false");
    assert!(envelope.data.is_none(), "Response should not have data");
    assert!(envelope.error.is_some(), "Response should have error");

    let error = envelope.error.unwrap();
    assert_eq!(error.kind, ErrorKind::Auth, "Error kind should be Auth");
    assert!(!error.msg.is_empty(), "Error message should not be empty");
    assert!(
        envelope.request_id.is_some(),
        "Response should have request_id"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}

#[tokio::test]
async fn test_rate_limit_scenario() {
    let mut config = TestConfig::new();
    config.rate_limit_max = 2; // Very low limit for testing
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    // First few requests should succeed
    for i in 0..config.rate_limit_max {
        let mut headers = config.auth_headers();
        headers.insert("x-request-id".to_string(), format!("test-req-{:03}", i));

        let (status, envelope) = make_request(&client, &url, &headers)
            .await
            .expect("Request should complete");

        assert_eq!(status, 200, "Request {} should succeed", i + 1);
        assert!(envelope.ok, "Response {} should have ok=true", i + 1);
    }

    // Next request should hit rate limit
    let mut headers = config.auth_headers();
    headers.insert("x-request-id".to_string(), "test-req-ratelimit".to_string());

    let (status, envelope) = make_request(&client, &url, &headers)
        .await
        .expect("Request should complete");

    // Scenario 3: High-frequency requests → 429 + {ok:false, error.kind=="RateLimit"}
    assert_eq!(status, 429, "Should return 429 for rate limit");
    assert!(!envelope.ok, "Response should have ok=false");
    assert!(envelope.data.is_none(), "Response should not have data");
    assert!(envelope.error.is_some(), "Response should have error");

    let error = envelope.error.unwrap();
    assert_eq!(
        error.kind,
        ErrorKind::RateLimit,
        "Error kind should be RateLimit"
    );
    assert!(!error.msg.is_empty(), "Error message should not be empty");
    assert!(
        envelope.request_id.is_some(),
        "Response should have request_id"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_MAX");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_WINDOW_SEC");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_STRATEGY");
}

#[tokio::test]
async fn test_request_id_propagation() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    let custom_request_id = "custom-req-id-12345";
    let mut headers = config.auth_headers();
    headers.insert("x-request-id".to_string(), custom_request_id.to_string());

    let (status, envelope) = make_request(&client, &url, &headers)
        .await
        .expect("Request should succeed");

    assert_eq!(status, 200, "Request should succeed");
    assert!(envelope.ok, "Response should have ok=true");
    assert_eq!(
        envelope.request_id.as_ref().unwrap(),
        custom_request_id,
        "Request ID should be propagated from request headers"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}

#[tokio::test]
async fn test_response_envelope_schema_compliance() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let url = format!("{}/admin/__health", config.base_url());

    // Test success case schema
    let (_, success_envelope) = make_request(&client, &url, &config.auth_headers())
        .await
        .expect("Request should succeed");

    // Verify success response schema
    assert!(success_envelope.ok, "Success response must have ok=true");
    assert!(
        success_envelope.data.is_some(),
        "Success response must have data"
    );
    assert!(
        success_envelope.error.is_none(),
        "Success response must not have error"
    );
    assert!(
        success_envelope.request_id.is_some(),
        "Success response must have request_id"
    );

    // Test error case schema
    let (_, error_envelope) = make_request(&client, &url, &config.no_auth_headers())
        .await
        .expect("Request should complete");

    // Verify error response schema
    assert!(!error_envelope.ok, "Error response must have ok=false");
    assert!(
        error_envelope.data.is_none(),
        "Error response must not have data"
    );
    assert!(
        error_envelope.error.is_some(),
        "Error response must have error"
    );
    assert!(
        error_envelope.request_id.is_some(),
        "Error response must have request_id"
    );

    let error = error_envelope.error.unwrap();
    assert!(!error.msg.is_empty(), "Error message must not be empty");
    assert!(
        matches!(
            error.kind,
            ErrorKind::Auth | ErrorKind::RateLimit | ErrorKind::Internal
        ),
        "Error kind must be valid"
    );

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}

/// Test that different endpoints behave consistently
#[tokio::test]
async fn test_multiple_endpoints_consistency() {
    let mut config = TestConfig::new();
    let _server_handle = start_test_server(&mut config).await;

    let client = Client::new();
    let endpoints = vec!["/__health", "/__metrics"];

    for endpoint in endpoints {
        let url = format!("{}/admin{}", config.base_url(), endpoint);

        // Test success case
        let (status, envelope) = make_request(&client, &url, &config.auth_headers())
            .await
            .expect("Request should succeed");

        assert_eq!(status, 200, "Endpoint {} should return 200", endpoint);
        assert!(envelope.ok, "Endpoint {} should have ok=true", endpoint);
        assert!(
            envelope.request_id.is_some(),
            "Endpoint {} should have request_id",
            endpoint
        );

        // Test auth failure case
        let (status, envelope) = make_request(&client, &url, &config.no_auth_headers())
            .await
            .expect("Request should complete");

        assert_eq!(
            status, 401,
            "Endpoint {} should return 401 for no auth",
            endpoint
        );
        assert!(
            !envelope.ok,
            "Endpoint {} should have ok=false for no auth",
            endpoint
        );
        assert!(
            envelope.error.is_some(),
            "Endpoint {} should have error for no auth",
            endpoint
        );

        let error = envelope.error.unwrap();
        assert_eq!(
            error.kind,
            ErrorKind::Auth,
            "Endpoint {} should have Auth error",
            endpoint
        );
    }

    // Cleanup
    std::env::remove_var("SB_ADMIN_TOKEN");
    std::env::remove_var("SB_ADMIN_RATE_LIMIT_ENABLED");
}
