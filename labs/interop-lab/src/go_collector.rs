// L10.1.1 — Go Snapshot passive collector.
//
// Reads from the running Go sing-box Clash API without interrupting the
// Go+GUI+TUN baseline.  Produces a `NormalizedSnapshot` that can be diffed
// against the Rust snapshot produced by the same case run.

use crate::snapshot::{
    HttpResult, MemoryPoint, NormalizedError, NormalizedSnapshot, TrafficCounters, WsFrameCapture,
};
use crate::util::sha256_hex;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Default WS sample duration (seconds).
const WS_SAMPLE_SECS: u64 = 3;
/// Maximum WS frames per stream before stopping.
const WS_MAX_FRAMES: usize = 50;
/// HTTP endpoints to snapshot (method, path, name).
const HTTP_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("GET", "/configs", "go_configs"),
    ("GET", "/proxies", "go_proxies"),
    ("GET", "/connections", "go_connections"),
];
/// WS endpoints to sample (path, name).
const WS_ENDPOINTS: &[(&str, &str)] = &[
    ("/traffic", "go_traffic"),
    ("/memory", "go_memory"),
    ("/connections", "go_ws_connections"),
    ("/logs", "go_logs"),
];

/// Collect a read-only snapshot from the running Go Clash API.
pub async fn collect_go_snapshot(
    api_base: &str,
    token: Option<&str>,
    case_id: &str,
) -> Result<NormalizedSnapshot> {
    let run_id = Uuid::new_v4().to_string();
    let started_at = Utc::now();
    let mut snapshot = NormalizedSnapshot::new(
        run_id,
        case_id.to_string(),
        crate::snapshot::KernelKind::Go,
        started_at,
    );

    // --- HTTP endpoints ---
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .with_context(|| "building go collector HTTP client")?;

    for &(method, path, name) in HTTP_ENDPOINTS {
        let url = format!("{}{}", api_base.trim_end_matches('/'), path);
        let mut req = client.request(method.parse().unwrap_or(reqwest::Method::GET), &url);
        if let Some(secret) = token {
            req = req.bearer_auth(secret);
        }

        match req.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let bytes = response.bytes().await.unwrap_or_default();
                let parsed = serde_json::from_slice::<Value>(&bytes).ok();
                let body_hash = if bytes.is_empty() {
                    None
                } else {
                    Some(sha256_hex(&bytes))
                };

                // Extract connections summary for the snapshot.
                if path == "/connections" {
                    snapshot.conn_summary = parsed.clone();
                }

                snapshot.http_results.push(HttpResult {
                    name: name.to_string(),
                    method: method.to_string(),
                    path: path.to_string(),
                    status,
                    body: parsed,
                    body_hash,
                });
            }
            Err(err) => {
                snapshot.errors.push(NormalizedError {
                    stage: format!("go_http:{name}"),
                    message: err.to_string(),
                });
            }
        }
    }

    // --- WS endpoints (sampled) ---
    for &(path, name) in WS_ENDPOINTS {
        let ws_url = build_ws_url(api_base, path, token);
        let mut frames = Vec::new();

        match tokio_tungstenite::connect_async(&ws_url).await {
            Ok((mut stream, _)) => {
                let deadline = Instant::now() + Duration::from_secs(WS_SAMPLE_SECS);
                while frames.len() < WS_MAX_FRAMES && Instant::now() < deadline {
                    let timeout = Duration::from_millis(200);
                    let next = tokio::time::timeout(timeout, stream.next()).await;
                    match next {
                        Ok(Some(Ok(msg))) => {
                            if let Some(value) = normalize_ws_message(msg) {
                                ingest_series(path, &value, &mut snapshot);
                                frames.push(value);
                            }
                        }
                        Ok(Some(Err(err))) => {
                            snapshot.errors.push(NormalizedError {
                                stage: format!("go_ws:{name}"),
                                message: err.to_string(),
                            });
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {} // timeout, try again
                    }
                }
                let _ = stream.close(None).await;
            }
            Err(err) => {
                snapshot.errors.push(NormalizedError {
                    stage: format!("go_ws:{name}"),
                    message: err.to_string(),
                });
            }
        }

        snapshot.ws_frames.push(WsFrameCapture {
            name: name.to_string(),
            path: path.to_string(),
            frames,
        });
    }

    snapshot.finished_at = Utc::now();
    Ok(snapshot)
}

/// Persist a Go snapshot to the artifacts directory.
pub fn save_go_snapshot(snapshot: &NormalizedSnapshot, artifacts_root: &Path) -> Result<PathBuf> {
    let dir = artifacts_root
        .join(&snapshot.case_id)
        .join(&snapshot.run_id);
    crate::util::ensure_dir(&dir)?;
    let file = dir.join("go_snapshot.json");
    let json = serde_json::to_string_pretty(snapshot).with_context(|| "serialising Go snapshot")?;
    std::fs::write(&file, json).with_context(|| format!("writing {}", file.display()))?;
    Ok(file)
}

/// Persist a Go snapshot directly to a specific directory (no subdirectory creation).
pub fn save_go_snapshot_to_dir(snapshot: &NormalizedSnapshot, dir: &Path) -> Result<PathBuf> {
    let file = dir.join("go_snapshot.json");
    let json = serde_json::to_string_pretty(snapshot).with_context(|| "serialising Go snapshot")?;
    std::fs::write(&file, json).with_context(|| format!("writing {}", file.display()))?;
    Ok(file)
}

// ---- helpers (mirrors gui_replay.rs patterns) ----

fn build_ws_url(api_base: &str, path: &str, token: Option<&str>) -> String {
    let base = api_base
        .trim_end_matches('/')
        .replace("https://", "wss://")
        .replace("http://", "ws://");
    match token {
        Some(secret) if !secret.is_empty() => {
            let delim = if path.contains('?') { '&' } else { '?' };
            format!("{base}{path}{delim}token={secret}")
        }
        _ => format!("{base}{path}"),
    }
}

fn normalize_ws_message(msg: Message) -> Option<Value> {
    match msg {
        Message::Text(text) => serde_json::from_str::<Value>(&text)
            .ok()
            .or_else(|| Some(json!({ "text": text }))),
        Message::Binary(data) => serde_json::from_slice::<Value>(&data)
            .ok()
            .or_else(|| Some(json!({ "binary_b64": STANDARD.encode(data) }))),
        Message::Ping(payload) => Some(json!({ "ping": STANDARD.encode(payload) })),
        Message::Pong(payload) => Some(json!({ "pong": STANDARD.encode(payload) })),
        Message::Close(frame) => Some(json!({ "close": frame.map(|f| f.code.to_string()) })),
        Message::Frame(_) => None,
    }
}

fn ingest_series(path: &str, frame: &Value, snapshot: &mut NormalizedSnapshot) {
    if path.contains("/memory") {
        let inuse = frame.get("inuse").and_then(Value::as_i64).unwrap_or(0);
        let oslimit = frame.get("oslimit").and_then(Value::as_i64).unwrap_or(0);
        snapshot.memory_series.push(MemoryPoint { inuse, oslimit });
    }
    if path.contains("/traffic") {
        let up = frame.get("up").and_then(Value::as_i64).unwrap_or(0);
        let down = frame.get("down").and_then(Value::as_i64).unwrap_or(0);
        snapshot.traffic_counters = Some(TrafficCounters {
            up,
            down,
            extra: Default::default(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn build_ws_url_with_token() {
        let url = build_ws_url("http://127.0.0.1:9090", "/traffic", Some("secret123"));
        assert_eq!(url, "ws://127.0.0.1:9090/traffic?token=secret123");
    }

    #[test]
    fn build_ws_url_without_token() {
        let url = build_ws_url("http://127.0.0.1:9090", "/memory", None);
        assert_eq!(url, "ws://127.0.0.1:9090/memory");
    }

    #[test]
    fn save_go_snapshot_creates_file() {
        let tmp = TempDir::new().unwrap();
        let snapshot = NormalizedSnapshot::new(
            "test-run".to_string(),
            "test-case".to_string(),
            crate::snapshot::KernelKind::Go,
            Utc::now(),
        );
        let path = save_go_snapshot(&snapshot, tmp.path()).unwrap();
        assert!(path.exists());
        assert!(path.ends_with("go_snapshot.json"));
    }

    #[test]
    fn normalize_text_frame() {
        let msg = Message::Text(r#"{"up":100,"down":200}"#.to_string());
        let val = normalize_ws_message(msg).unwrap();
        assert_eq!(val.get("up").unwrap().as_i64().unwrap(), 100);
    }
}
