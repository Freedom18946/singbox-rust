//! WebSocket handlers for real-time updates
//! 用于实时更新的 WebSocket 处理程序
//!
//! # Strategic Role / 战略角色
//!
//! Manages long-lived WebSocket connections for pushing real-time data (traffic stats, logs,
//! connections) to the dashboard. This avoids the need for polling and provides a responsive
//! UI experience.
//!
//! 管理用于向仪表盘推送实时数据（流量统计、日志、连接）的长连接 WebSocket。
//! 这避免了轮询的需要，并提供了响应式的 UI 体验。

use crate::{
    clash::server::ApiState,
    types::{LogEntry, WebSocketMessage},
};
use axum::{
    extract::{ws::WebSocket, ws::WebSocketUpgrade, State},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{sync::broadcast, time::interval};

// ===== Traffic WebSocket =====

/// Handle traffic WebSocket connections — pushes real traffic delta every second.
pub async fn traffic_websocket(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_traffic_websocket(socket, state))
}

/// Handle traffic WebSocket — pushes `{"up": delta, "down": delta}` every second
/// using real data from the global connection tracker.
async fn handle_traffic_websocket(socket: WebSocket, _state: ApiState) {
    let (mut sender, mut receiver) = socket.split();
    let mut tick = interval(Duration::from_secs(1));
    let tracker = sb_common::conntrack::global_tracker();

    let mut prev_up = tracker.total_upload();
    let mut prev_down = tracker.total_download();

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) | None => break,
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        let _ = sender.send(axum::extract::ws::Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                let cur_up = tracker.total_upload();
                let cur_down = tracker.total_download();
                let msg = json!({
                    "up": cur_up.saturating_sub(prev_up),
                    "down": cur_down.saturating_sub(prev_down)
                });
                prev_up = cur_up;
                prev_down = cur_down;
                if let Ok(text) = serde_json::to_string(&msg) {
                    if sender.send(axum::extract::ws::Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}

// ===== Connections WebSocket =====

/// Handle connections WebSocket — pushes full snapshot every second.
/// Public so handlers.rs can call it from the dual HTTP/WS pattern.
pub async fn handle_connections_websocket(socket: WebSocket, _state: ApiState) {
    let (mut sender, mut receiver) = socket.split();
    let mut tick = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) | None => break,
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        let _ = sender.send(axum::extract::ws::Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                let snapshot = build_connections_snapshot();
                if let Ok(text) = serde_json::to_string(&snapshot) {
                    if sender.send(axum::extract::ws::Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}

/// Build connections snapshot (shared between HTTP and WS).
/// Returns the Go-compatible Snapshot format:
/// `{downloadTotal, uploadTotal, connections[], memory}`
pub fn build_connections_snapshot() -> serde_json::Value {
    let tracker = sb_common::conntrack::global_tracker();
    let connections = tracker.list();
    let memory = get_process_memory();

    let conn_json: Vec<serde_json::Value> = connections
        .iter()
        .map(|c| {
            let start = SystemTime::now() - c.start_time.elapsed();
            let start_str = humantime::format_rfc3339(start).to_string();
            json!({
                "id": format!("{}", c.id.as_u64()),
                "metadata": {
                    "network": c.network.as_str(),
                    "type": c.inbound_type.as_deref().unwrap_or(""),
                    "sourceIP": c.source.ip().to_string(),
                    "sourcePort": c.source.port().to_string(),
                    "destinationIP": "",
                    "destinationPort": c.destination_port.to_string(),
                    "host": c.host.as_deref().unwrap_or(&c.destination),
                    "dnsMode": "normal",
                    "processPath": c.process_path.as_deref().unwrap_or("")
                },
                "upload": c.get_upload(),
                "download": c.get_download(),
                "start": start_str,
                "chains": c.chains,
                "rule": c.rule.as_deref().unwrap_or(""),
                "rulePayload": ""
            })
        })
        .collect();

    json!({
        "downloadTotal": tracker.total_download(),
        "uploadTotal": tracker.total_upload(),
        "connections": conn_json,
        "memory": memory
    })
}

// ===== Logs WebSocket =====

/// Handle logs WebSocket connections
pub async fn logs_websocket(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_logs_websocket(socket, state))
}

/// Handle logs WebSocket connection
async fn handle_logs_websocket(socket: WebSocket, state: ApiState) {
    let client_id = uuid::Uuid::new_v4();
    log::info!("Logs WebSocket client {} connected", client_id);

    let mut log_rx = state.log_tx.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // Send welcome message
    let welcome = WebSocketMessage::Log(LogEntry {
        r#type: "info".to_string(),
        payload: format!("Connected to logs stream (client: {})", client_id),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        source: "ClashAPI".to_string(),
        connection_id: None,
    });

    if let Ok(welcome_text) = serde_json::to_string(&welcome) {
        if sender
            .send(axum::extract::ws::Message::Text(welcome_text))
            .await
            .is_err()
        {
            return;
        }
    }

    let mut heartbeat = interval(Duration::from_secs(30));
    let mut error_count = 0;
    const MAX_ERRORS: usize = 5;
    let mut message_buffer: VecDeque<String> = VecDeque::with_capacity(100);
    const BUFFER_SIZE: usize = 100;

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) => break,
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        if sender.send(axum::extract::ws::Message::Pong(data)).await.is_err() {
                            error_count += 1;
                        }
                    }
                    Some(Ok(axum::extract::ws::Message::Text(text))) => {
                        if let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(action) = request.get("action").and_then(|a| a.as_str()) {
                                if action == "get_recent_logs" {
                                    for buffered_log in &message_buffer {
                                        let _ = sender
                                            .send(axum::extract::ws::Message::Text(buffered_log.clone()))
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        log::warn!("Logs WebSocket client {} error: {}", client_id, e);
                        error_count += 1;
                    }
                    None => break,
                }
            }

            _ = heartbeat.tick() => {
                let ping_msg = WebSocketMessage::Ping {
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                if let Ok(ping_text) = serde_json::to_string(&ping_msg) {
                    if sender.send(axum::extract::ws::Message::Text(ping_text)).await.is_err() {
                        error_count += 1;
                    }
                }
            }

            log_result = log_rx.recv() => {
                match log_result {
                    Ok(log_entry) => {
                        let log_msg = WebSocketMessage::Log(log_entry);
                        if let Ok(log_text) = serde_json::to_string(&log_msg) {
                            if message_buffer.len() == BUFFER_SIZE { message_buffer.pop_front(); }
                            message_buffer.push_back(log_text.clone());

                            if sender.send(axum::extract::ws::Message::Text(log_text)).await.is_err() {
                                error_count += 1;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Logs WebSocket client {} lagged, skipped {} messages", client_id, skipped);
                        log_rx = state.log_tx.subscribe();
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }

        if error_count >= MAX_ERRORS {
            break;
        }
    }

    for buffered_msg in message_buffer {
        let _ = sender
            .send(axum::extract::ws::Message::Text(buffered_msg))
            .await;
    }
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}

// ===== Memory WebSocket =====

/// Handle memory WebSocket connections — matches Go's memory() handler
///
/// Pushes `{"inuse": N, "oslimit": 0}` every second. First push has inuse=0.
pub async fn memory_websocket(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_memory_websocket_inner(socket, state))
}

/// Get process memory usage in bytes.
pub fn get_process_memory_pub() -> u64 {
    get_process_memory()
}

fn get_process_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(resident_pages) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = resident_pages.parse::<u64>() {
                    return pages * 4096;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Handle memory WebSocket — pushes `{"inuse": N, "oslimit": 0}` every second
/// Public so handlers.rs can call it for the dual HTTP/WS pattern.
pub async fn handle_memory_websocket_inner(socket: WebSocket, _state: ApiState) {
    let (mut sender, mut receiver) = socket.split();
    let mut tick = interval(Duration::from_secs(1));
    let mut first = true;

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) | None => break,
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        let _ = sender.send(axum::extract::ws::Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                let inuse = if first {
                    first = false;
                    0
                } else {
                    get_process_memory()
                };
                let msg = json!({"inuse": inuse, "oslimit": 0});
                if let Ok(text) = serde_json::to_string(&msg) {
                    if sender.send(axum::extract::ws::Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}
