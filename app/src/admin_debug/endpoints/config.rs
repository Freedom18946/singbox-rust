use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt};
use crate::admin_debug::{http_util::{respond, respond_json_ok, respond_json_error}, reloadable, audit};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize)]
pub struct ConfigView {
    pub cfg: reloadable::EnvConfig,
}

#[derive(Deserialize, Serialize, Default)]
pub struct ConfigDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_redirects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker_window_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker_open_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker_failures: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker_ratio: Option<f32>,
}

pub async fn handle_get(sock: &mut (impl AsyncWrite + Unpin)) -> std::io::Result<()> {
    let cfg = reloadable::get();
    let view = ConfigView { cfg };
    let body = serde_json::to_string(&view).unwrap_or_else(|_| "{}".to_string());
    respond(sock, 200, "application/json", &body).await
}

pub async fn handle_put(
    sock: &mut (impl AsyncRead + AsyncWrite + Unpin),
    body: bytes::Bytes,
    headers: &HashMap<String, String>,
) -> std::io::Result<()> {
    // Check RBAC - X-Role header should be admin
    let role = headers.get("x-role").map(|s| s.as_str()).unwrap_or("");
    if role != "admin" {
        return respond_json_error(sock, 403, "Access denied", Some("X-Role: admin required")).await;
    }

    // Parse the delta
    let delta: ConfigDelta = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return respond_json_error(sock, 400, "Invalid JSON in request body", Some(&e.to_string())).await;
        }
    };

    // Apply delta using reloadable module
    let result = reloadable::apply(&delta);
    let (success, message) = match result {
        Ok(msg) => (true, msg),
        Err(e) => (false, e.to_string()),
    };

    // Create audit entry
    let delta_json = serde_json::to_value(&delta).unwrap_or(serde_json::json!({}));
    let actor = headers.get("authorization")
        .and_then(|auth| {
            if auth.starts_with("SB-HMAC ") {
                auth.strip_prefix("SB-HMAC ").and_then(|s| s.split(':').next())
            } else if auth.starts_with("Bearer ") {
                Some("bearer_user")
            } else {
                None
            }
        })
        .unwrap_or("unknown");

    let entry = audit::create_entry(
        actor,
        "config.put",
        delta_json.clone(),
        success,
        &message,
    );
    audit::log(entry);

    if success {
        let response = serde_json::json!({
            "status": "applied",
            "delta": delta_json,
            "message": message
        });
        respond(sock, 200, "application/json", &serde_json::to_string(&response).unwrap()).await
    } else {
        respond_json_error(sock, 500, "Failed to apply configuration", Some(&message)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_delta_deserialization() {
        let json = r#"{"max_redirects": 5, "timeout_ms": 6000}"#;
        let delta: ConfigDelta = serde_json::from_str(json).unwrap();
        assert_eq!(delta.max_redirects, Some(5));
        assert_eq!(delta.timeout_ms, Some(6000));
        assert_eq!(delta.max_bytes, None);
    }

    #[test]
    fn test_config_delta_empty() {
        let json = r#"{}"#;
        let delta: ConfigDelta = serde_json::from_str(json).unwrap();
        assert_eq!(delta.max_redirects, None);
        assert_eq!(delta.timeout_ms, None);
    }
}