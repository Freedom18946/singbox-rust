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
) -> std::io::Result<()>
{
    // Check RBAC - X-Role header should be admin
    let role = headers.get("x-role").map(|s| s.as_str()).unwrap_or("");
    if role != "admin" {
        return respond_json_error(sock, 403, "Access denied", Some("X-Role: admin required")).await;
    }

    // Dry-run toggle
    let dry = headers
        .get("x-config-dryrun")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Parse the delta
    let delta: ConfigDelta = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return respond_json_error(sock, 400, "Invalid JSON in request body", Some(&e.to_string())).await;
        }
    };

    // Apply (or simulate) the delta
    match reloadable::apply_with_dryrun(&delta, dry) {
        Ok(app) => {
            // Audit with changed field
            let entry = audit::create_entry(
                "admin",
                if dry { "config_dryrun" } else { "config_apply" },
                serde_json::to_value(&delta).unwrap_or(serde_json::json!({})),
                app.ok,
                &app.msg,
            ).with_changed(app.changed);
            audit::log(entry);

            // Respond with full result including changed field
            #[derive(serde::Serialize)]
            struct Resp<'a> { ok: bool, msg: &'a str, changed: bool, version: u64, diff: serde_json::Value }
            let resp = Resp { ok: app.ok, msg: &app.msg, changed: app.changed, version: app.version, diff: app.diff };
            respond_json_ok(sock, &resp).await
        }
        Err(e) => {
            let entry = audit::create_entry(
                "admin",
                if dry { "config_dryrun" } else { "config_apply" },
                serde_json::to_value(&delta).unwrap_or(serde_json::json!({})),
                false,
                &e,
            ).with_changed(false);
            audit::log(entry);
            respond_json_error(sock, 400, "apply failed", Some(&e)).await
        }
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