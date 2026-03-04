//! L19 GUI contract suite for fixed Clash API request set.
//!
//! This suite validates response shape compatibility for GUI-critical endpoints,
//! including the L19 `/capabilities` contract endpoint.

use reqwest::{Client, StatusCode};
use sb_api::{clash::ClashApiServer, types::ApiConfig};
use serde_json::Value;
use std::io::ErrorKind;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

struct TestServer {
    base_url: String,
    client: Client,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start() -> anyhow::Result<Option<Self>> {
        let config = ApiConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            enable_cors: true,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: true,
            enable_logs_ws: true,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = ClashApiServer::new(config)?;
        let listener =
            match tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
                Ok(listener) => listener,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    eprintln!("skipping capabilities contract: PermissionDenied binding listener");
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let app = server.create_app();
            let _ = axum::serve(listener, app).await;
        });
        sleep(Duration::from_millis(100)).await;
        Ok(Some(Self {
            base_url: format!("http://127.0.0.1:{}", addr.port()),
            client: Client::new(),
            _handle: handle,
        }))
    }

    async fn get_json(&self, path: &str) -> anyhow::Result<(StatusCode, Value)> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await?;
        let status = response.status();
        let payload = response.json::<Value>().await?;
        Ok((status, payload))
    }
}

fn require_object<'a>(
    value: &'a Value,
    label: &str,
) -> anyhow::Result<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{label} must be a JSON object"))
}

fn require_key<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> anyhow::Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("{label} missing key '{key}'"))
}

#[tokio::test]
async fn capabilities_contract_suite() -> anyhow::Result<()> {
    let Some(server) = TestServer::start().await? else {
        return Ok(());
    };

    let request_cases = [
        ("status", "/"),
        ("version", "/version"),
        ("capabilities", "/capabilities"),
        ("proxies", "/proxies"),
        ("connections", "/connections"),
        ("providers", "/providers/proxies"),
    ];

    let mut failures = Vec::<String>::new();
    for (id, path) in request_cases {
        let (status, payload) = match server.get_json(path).await {
            Ok(v) => v,
            Err(err) => {
                failures.push(format!("[{id}] request failed: {err}"));
                continue;
            }
        };
        if status != StatusCode::OK {
            failures.push(format!("[{id}] expected HTTP 200, got {status}"));
            continue;
        }
        if !payload.is_object() {
            failures.push(format!("[{id}] response must be JSON object"));
        }
    }

    let (_, status_payload) = server.get_json("/").await?;
    let status_obj = require_object(&status_payload, "GET /")?;
    if require_key(status_obj, "hello", "GET /").is_err() {
        failures.push("[status] GET / missing key 'hello'".to_string());
    }

    let (_, version_payload) = server.get_json("/version").await?;
    let version_obj = require_object(&version_payload, "GET /version")?;
    for key in ["version", "premium", "meta"] {
        if require_key(version_obj, key, "GET /version").is_err() {
            failures.push(format!("[version] GET /version missing key '{key}'"));
        }
    }

    let (_, capabilities_payload) = server.get_json("/capabilities").await?;
    let cap_obj = require_object(&capabilities_payload, "GET /capabilities")?;
    for key in [
        "schema_version",
        "compat_version",
        "clash_api_compat_version",
        "feature_flags",
        "source",
        "tls_provider",
        "capability_matrix",
    ] {
        if require_key(cap_obj, key, "GET /capabilities").is_err() {
            failures.push(format!("[capabilities] missing key '{key}'"));
        }
    }

    let matrix = cap_obj
        .get("capability_matrix")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("[capabilities] capability_matrix must be array"))?;
    if matrix.is_empty() {
        failures.push("[capabilities] capability_matrix must not be empty".to_string());
    } else {
        for (idx, row) in matrix.iter().take(3).enumerate() {
            let row_obj = match row.as_object() {
                Some(v) => v,
                None => {
                    failures.push(format!("[capabilities] matrix row #{idx} must be object"));
                    continue;
                }
            };
            for key in [
                "id",
                "name",
                "compile_state",
                "runtime_state",
                "verification_state",
                "overall_state",
                "accepted_limitation",
            ] {
                if !row_obj.contains_key(key) {
                    failures.push(format!(
                        "[capabilities] matrix row #{idx} missing key '{key}'"
                    ));
                }
            }
        }
    }

    let tls_provider = cap_obj
        .get("tls_provider")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("[capabilities] tls_provider must be object"))?;
    for key in [
        "status",
        "requested",
        "effective",
        "source",
        "install",
        "evidence_capability_ids",
    ] {
        if !tls_provider.contains_key(key) {
            failures.push(format!("[capabilities] tls_provider missing key '{key}'"));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "contract failures:\n{}",
            failures.join("\n")
        ))
    }
}
