use crate::case_spec::{ApiAccess, CaseSpec, GuiStep, WsStreamSpec};
use crate::snapshot::{
    HttpResult, MemoryPoint, NormalizedError, NormalizedSnapshot, TrafficCounters, WsFrameCapture,
};
use crate::subscription::parse_subscription;
use crate::util::{normalize_ws_message, resolve_with_env, sha256_hex};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::Method;
use serde_json::Value;
use std::time::Duration;
use tokio::time::Instant;

fn parse_http_method(method: &str) -> Method {
    match method.parse::<Method>() {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(method = ?method, error = %err, "invalid GUI replay HTTP method, defaulting to GET");
            Method::GET
        }
    }
}

pub async fn run_gui_sequence(
    case: &CaseSpec,
    api: &ApiAccess,
    snapshot: &mut NormalizedSnapshot,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .with_context(|| "building gui replay client")?;

    for step in &case.gui_sequence {
        match step {
            GuiStep::Http {
                name,
                method,
                path,
                body,
                no_auth,
                auth_secret,
                expect_status,
            } => {
                let status_expected = *expect_status;
                let method = parse_http_method(method);
                let url = format!("{}{}", api.base_url.trim_end_matches('/'), path);
                let mut req = client.request(method.clone(), url);
                let step_secret = if *no_auth {
                    None
                } else if let Some(secret) = auth_secret {
                    Some(resolve_with_env(secret))
                } else {
                    api.secret.clone()
                };
                if let Some(secret) = &step_secret {
                    req = req.bearer_auth(secret);
                }
                if let Some(body) = body {
                    req = req.json(body);
                }

                let response = req.send().await;
                match response {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let bytes = response.bytes().await.unwrap_or_default();
                        let parsed = match serde_json::from_slice::<Value>(&bytes) {
                            Ok(value) => Some(value),
                            Err(_) if bytes.is_empty() => None,
                            Err(err) => {
                                snapshot.errors.push(NormalizedError {
                                    stage: format!("http:{name}:parse"),
                                    message: err.to_string(),
                                });
                                None
                            }
                        };
                        let body_hash = if bytes.is_empty() {
                            None
                        } else {
                            Some(sha256_hex(&bytes))
                        };

                        snapshot.http_results.push(HttpResult {
                            name: name.clone(),
                            method: method.to_string(),
                            path: path.clone(),
                            status,
                            body: parsed,
                            body_hash,
                        });

                        if let Some(expected) = status_expected {
                            if status != expected {
                                snapshot.errors.push(NormalizedError {
                                    stage: format!("http:{name}"),
                                    message: format!(
                                        "status mismatch: expected {expected}, got {status}"
                                    ),
                                });
                            }
                        }
                    }
                    Err(err) => {
                        snapshot.errors.push(NormalizedError {
                            stage: format!("http:{name}"),
                            message: err.to_string(),
                        });
                    }
                }
            }
            GuiStep::WsCollect {
                name,
                path,
                no_auth,
                auth_secret,
                max_frames,
                duration_ms,
            } => {
                let step_secret = if *no_auth {
                    None
                } else if let Some(secret) = auth_secret {
                    Some(resolve_with_env(secret))
                } else {
                    api.secret.clone()
                };
                let ws_url = build_ws_url(api, path, step_secret.as_deref());
                let result = tokio_tungstenite::connect_async(ws_url.clone()).await;
                let mut frames = Vec::new();
                match result {
                    Ok((mut stream, _)) => {
                        let deadline = Instant::now() + Duration::from_millis(*duration_ms);
                        while frames.len() < *max_frames && Instant::now() < deadline {
                            let timeout = Duration::from_millis(200);
                            let next = tokio::time::timeout(timeout, stream.next()).await;
                            match next {
                                Ok(Some(Ok(msg))) => {
                                    if let Some(value) = normalize_ws_message(msg) {
                                        ingest_special_series(path, &value, snapshot);
                                        frames.push(value);
                                    }
                                }
                                Ok(Some(Err(err))) => {
                                    snapshot.errors.push(NormalizedError {
                                        stage: format!("ws:{name}"),
                                        message: err.to_string(),
                                    });
                                    break;
                                }
                                Ok(None) => break,
                                Err(_) => {}
                            }
                        }
                        if let Err(err) = stream.close(None).await {
                            snapshot.errors.push(NormalizedError {
                                stage: format!("ws:{name}:close"),
                                message: err.to_string(),
                            });
                        }
                    }
                    Err(err) => {
                        snapshot.errors.push(NormalizedError {
                            stage: format!("ws:{name}"),
                            message: err.to_string(),
                        });
                    }
                }

                snapshot.ws_frames.push(WsFrameCapture {
                    name: name.clone(),
                    path: path.clone(),
                    frames,
                });
            }
            GuiStep::Sleep { ms } => {
                tokio::time::sleep(Duration::from_millis(*ms)).await;
            }
            GuiStep::SubscriptionParse => {
                if let Some(input) = &case.subscription_input {
                    match parse_subscription(input).await {
                        Ok(result) => {
                            snapshot.subscription_result = Some(result);
                        }
                        Err(err) => {
                            snapshot.errors.push(NormalizedError {
                                stage: "subscription_parse".to_string(),
                                message: err.to_string(),
                            });
                        }
                    }
                }
            }
            GuiStep::WsParallel {
                name,
                streams,
                duration_ms,
            } => {
                run_ws_parallel(name, streams, *duration_ms, api, snapshot).await;
            }
        }
    }

    if let Some(conns) = request_json(api, "/connections").await {
        snapshot.conn_summary = Some(conns);
    }

    if let Some(proxies) = request_json(api, "/proxies").await {
        if snapshot.http_results.iter().all(|r| r.path != "/proxies") {
            snapshot.http_results.push(HttpResult {
                name: "auto_get_proxies".to_string(),
                method: "GET".to_string(),
                path: "/proxies".to_string(),
                status: 200,
                body: Some(proxies),
                body_hash: None,
            });
        }
    }

    Ok(())
}

async fn run_ws_parallel(
    name: &str,
    streams: &[WsStreamSpec],
    duration_ms: u64,
    api: &ApiAccess,
    snapshot: &mut NormalizedSnapshot,
) {
    use tokio::task::JoinSet;

    let mut set = JoinSet::new();
    for (idx, spec) in streams.iter().enumerate() {
        let ws_url = build_ws_url(api, &spec.path, api.secret.as_deref());
        let max_frames = spec.max_frames;
        let dur = duration_ms;
        let path = spec.path.clone();
        let stream_name = format!("{name}_{idx}_{}", spec.path.trim_start_matches('/'));

        set.spawn(async move {
            let mut frames = Vec::new();
            let result = tokio_tungstenite::connect_async(ws_url.clone()).await;
            match result {
                Ok((mut stream, _)) => {
                    let deadline = Instant::now() + Duration::from_millis(dur);
                    while frames.len() < max_frames && Instant::now() < deadline {
                        let timeout = Duration::from_millis(200);
                        let next = tokio::time::timeout(timeout, stream.next()).await;
                        match next {
                            Ok(Some(Ok(msg))) => {
                                if let Some(value) = normalize_ws_message(msg) {
                                    frames.push(value);
                                }
                            }
                            Ok(Some(Err(_))) | Ok(None) => break,
                            Err(_) => {}
                        }
                    }
                    if let Err(err) = stream.close(None).await {
                        tracing::debug!(stream_name = %stream_name, error = %err, "parallel websocket close failed");
                    }
                    (stream_name, path, frames, None)
                }
                Err(err) => (stream_name, path, frames, Some(err.to_string())),
            }
        });
    }

    while let Some(result) = set.join_next().await {
        match result {
            Ok((stream_name, path, frames, error)) => {
                for frame in &frames {
                    ingest_special_series(&path, frame, snapshot);
                }
                snapshot.ws_frames.push(WsFrameCapture {
                    name: stream_name.clone(),
                    path: path.clone(),
                    frames,
                });
                if let Some(err_msg) = error {
                    snapshot.errors.push(NormalizedError {
                        stage: format!("ws_parallel:{stream_name}"),
                        message: err_msg,
                    });
                }
            }
            Err(err) => {
                snapshot.errors.push(NormalizedError {
                    stage: format!("ws_parallel:{name}"),
                    message: format!("join error: {err}"),
                });
            }
        }
    }
}

async fn request_json(api: &ApiAccess, path: &str) -> Option<Value> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", api.base_url.trim_end_matches('/'), path);
    let mut req = client.get(url);
    if let Some(secret) = &api.secret {
        req = req.bearer_auth(secret);
    }

    let response = match req.send().await {
        Ok(response) => response,
        Err(err) => {
            tracing::debug!(path = %path, error = %err, "request_json send failed");
            return None;
        }
    };
    if !response.status().is_success() {
        return None;
    }
    match response.json::<Value>().await {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::debug!(path = %path, error = %err, "request_json decode failed");
            None
        }
    }
}

fn build_ws_url(api: &ApiAccess, path: &str, token_override: Option<&str>) -> String {
    let base = api
        .base_url
        .trim_end_matches('/')
        .replace("https://", "wss://")
        .replace("http://", "ws://");
    let token = token_override
        .map(|secret| format!("token={secret}"))
        .unwrap_or_default();
    if token.is_empty() {
        format!("{base}{path}")
    } else {
        let delimiter = if path.contains('?') { '&' } else { '?' };
        format!("{base}{path}{delimiter}{token}")
    }
}

fn ingest_special_series(path: &str, frame: &Value, snapshot: &mut NormalizedSnapshot) {
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
