use crate::admin_debug::{
    audit,
    http_util::{respond, respond_json_error, respond_json_ok},
    reloadable,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Serialize)]
pub struct ConfigView {
    pub cfg: reloadable::EnvConfig,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
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
    let t_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let t0 = tokio::time::Instant::now();
    // Check RBAC - X-Role header should be admin
    let role = headers.get("x-role").map(|s| s.as_str()).unwrap_or("");
    if role != "admin" {
        // Stable error schema
        #[derive(serde::Serialize)]
        struct Resp<'a> {
            status: &'a str,
            applied: bool,
            errors: Vec<&'a str>,
            start_ms: u128,
            dur_ms: u128,
        }
        let resp = Resp {
            status: "error",
            applied: false,
            errors: vec!["X-Role: admin required"],
            start_ms: t_start,
            dur_ms: t0.elapsed().as_millis(),
        };
        return crate::admin_debug::http_util::respond(
            sock,
            403,
            "application/json",
            &serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()),
        )
        .await;
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
            return respond_json_error(
                sock,
                400,
                "Invalid JSON in request body",
                Some(&e.to_string()),
            )
            .await;
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
            )
            .with_changed(app.changed);
            audit::log(entry);

            // Respond with fixed schema and stable field order
            #[derive(serde::Serialize)]
            struct Resp<'a> {
                status: &'a str,
                applied: bool,
                errors: &'a [&'a str],
                start_ms: u128,
                dur_ms: u128,
            }
            let status = if app.ok { "ok" } else { "error" };
            let applied = app.ok && !dry && app.changed;
            let resp = Resp {
                status,
                applied,
                errors: &[],
                start_ms: t_start,
                dur_ms: t0.elapsed().as_millis(),
            };
            respond_json_ok(sock, &resp).await
        }
        Err(e) => {
            let entry = audit::create_entry(
                "admin",
                if dry { "config_dryrun" } else { "config_apply" },
                serde_json::to_value(&delta).unwrap_or(serde_json::json!({})),
                false,
                &e,
            )
            .with_changed(false);
            audit::log(entry);
            // Fixed schema error
            #[derive(serde::Serialize)]
            struct Resp<'a> {
                status: &'a str,
                applied: bool,
                errors: [&'a str; 1],
                start_ms: u128,
                dur_ms: u128,
            }
            let resp = Resp {
                status: "error",
                applied: false,
                errors: [&*e],
                start_ms: t_start,
                dur_ms: t0.elapsed().as_millis(),
            };
            crate::admin_debug::http_util::respond(
                sock,
                400,
                "application/json",
                &serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()),
            )
            .await
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
