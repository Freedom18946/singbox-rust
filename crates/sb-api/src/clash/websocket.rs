//! WebSocket handlers for real-time updates

use crate::{
    clash::server::ApiState,
    types::{LogEntry, TrafficStats, WebSocketMessage},
};
use axum::{
    extract::{ws::WebSocket, ws::WebSocketUpgrade, State},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{sync::broadcast, time::interval};

/// Handle traffic WebSocket connections
pub async fn traffic_websocket(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_traffic_websocket(socket, state))
}

/// Handle logs WebSocket connections
pub async fn logs_websocket(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_logs_websocket(socket, state))
}

/// Handle traffic WebSocket connection
async fn handle_traffic_websocket(socket: WebSocket, state: ApiState) {
    let client_id = uuid::Uuid::new_v4();
    log::info!("Traffic WebSocket client {} connected", client_id);

    // Subscribe to traffic updates
    let mut traffic_rx = state.traffic_tx.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // Send welcome message
    let welcome = WebSocketMessage::Response {
        request_id: "welcome".to_string(),
        data: json!({
            "message": "Connected to traffic stream",
            "client_id": client_id.to_string()
        }),
    };

    if let Ok(welcome_text) = serde_json::to_string(&welcome) {
        if sender
            .send(axum::extract::ws::Message::Text(welcome_text))
            .await
            .is_err()
        {
            log::warn!(
                "Failed to send welcome message to traffic client {}",
                client_id
            );
            return;
        }
    }

    // Setup heartbeat and error tracking
    let mut heartbeat = interval(Duration::from_secs(30));
    let mut error_count = 0;
    const MAX_ERRORS: usize = 5;

    // Mock traffic data generation for demonstration
    let mut mock_traffic_interval = interval(Duration::from_millis(1000));
    let mut total_up = 0u64;
    let mut total_down = 0u64;

    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) => {
                        log::info!("Traffic WebSocket client {} requested close", client_id);
                        break;
                    }
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        if sender.send(axum::extract::ws::Message::Pong(data)).await.is_err() {
                            error_count += 1;
                        }
                    }
                    Some(Ok(axum::extract::ws::Message::Text(text))) => {
                        // Handle client requests (e.g., getting current stats)
                        if let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(action) = request.get("action").and_then(|a| a.as_str()) {
                                match action {
                                    "get_stats" => {
                                        let response = WebSocketMessage::Response {
                                            request_id: request.get("id")
                                                .and_then(|id| id.as_str())
                                                .unwrap_or("unknown")
                                                .to_string(),
                                            data: json!({
                                                "up": total_up,
                                                "down": total_down,
                                                "timestamp": SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_millis()
                                            }),
                                        };
                                        if let Ok(response_text) = serde_json::to_string(&response) {
                                            let _ = sender.send(axum::extract::ws::Message::Text(response_text)).await;
                                        }
                                    }
                                    _ => {
                                        log::debug!("Unknown action: {}", action);
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {
                        // Ignore other message types
                    }
                    Some(Err(e)) => {
                        log::warn!("Traffic WebSocket client {} error: {}", client_id, e);
                        error_count += 1;
                    }
                    None => {
                        log::info!("Traffic WebSocket client {} disconnected", client_id);
                        break;
                    }
                }
            }

            // Send heartbeat
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

            // Generate mock traffic data
            _ = mock_traffic_interval.tick() => {
                total_up += 1000;
                total_down += 4000;

                let traffic_stats = TrafficStats {
                    up: total_up,
                    down: total_down,
                    up_speed: 1000,
                    down_speed: 4000,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };

                let traffic_msg = WebSocketMessage::Traffic(traffic_stats);
                if let Ok(traffic_text) = serde_json::to_string(&traffic_msg) {
                    if sender.send(axum::extract::ws::Message::Text(traffic_text)).await.is_err() {
                        error_count += 1;
                    }
                }
            }

            // Handle traffic broadcast updates
            traffic_result = traffic_rx.recv() => {
                match traffic_result {
                    Ok(traffic) => {
                        let traffic_msg = WebSocketMessage::Traffic(traffic);
                        if let Ok(traffic_text) = serde_json::to_string(&traffic_msg) {
                            if sender.send(axum::extract::ws::Message::Text(traffic_text)).await.is_err() {
                                error_count += 1;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Traffic WebSocket client {} lagged, skipped {} messages", client_id, skipped);
                        traffic_rx = state.traffic_tx.subscribe();
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Traffic broadcast channel closed, disconnecting client {}", client_id);
                        break;
                    }
                }
            }
        }

        // Check error threshold
        if error_count >= MAX_ERRORS {
            log::error!(
                "Traffic WebSocket client {} exceeded error threshold, disconnecting",
                client_id
            );
            break;
        }
    }

    log::info!("Traffic WebSocket client {} disconnected", client_id);
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}

/// Handle logs WebSocket connection
async fn handle_logs_websocket(socket: WebSocket, state: ApiState) {
    let client_id = uuid::Uuid::new_v4();
    log::info!("Logs WebSocket client {} connected", client_id);

    // Subscribe to log updates
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
            log::warn!(
                "Failed to send welcome message to logs client {}",
                client_id
            );
            return;
        }
    }

    // Setup heartbeat and error tracking
    let mut heartbeat = interval(Duration::from_secs(30));
    let mut error_count = 0;
    const MAX_ERRORS: usize = 5;
    let mut message_buffer: Vec<String> = Vec::new();
    const BUFFER_SIZE: usize = 100;

    // Mock log generation for demonstration
    let mut mock_log_interval = interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) => {
                        log::info!("Logs WebSocket client {} requested close", client_id);
                        break;
                    }
                    Some(Ok(axum::extract::ws::Message::Ping(data))) => {
                        if sender.send(axum::extract::ws::Message::Pong(data)).await.is_err() {
                            error_count += 1;
                        }
                    }
                    Some(Ok(axum::extract::ws::Message::Text(text))) => {
                        // Handle client requests
                        if let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(action) = request.get("action").and_then(|a| a.as_str()) {
                                match action {
                                    "get_recent_logs" => {
                                        // Send recent buffered logs
                                        for buffered_log in &message_buffer {
                                            let _ = sender.send(axum::extract::ws::Message::Text(buffered_log.clone())).await;
                                        }
                                    }
                                    _ => {
                                        log::debug!("Unknown log action: {}", action);
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {
                        // Ignore other message types
                    }
                    Some(Err(e)) => {
                        log::warn!("Logs WebSocket client {} error: {}", client_id, e);
                        error_count += 1;
                    }
                    None => {
                        log::info!("Logs WebSocket client {} disconnected", client_id);
                        break;
                    }
                }
            }

            // Send heartbeat
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

            // Generate mock log entries
            _ = mock_log_interval.tick() => {
                let mock_log = LogEntry {
                    r#type: "info".to_string(),
                    payload: "Mock log entry for demonstration".to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    source: "MockService".to_string(),
                    connection_id: None,
                };

                let log_msg = WebSocketMessage::Log(mock_log);
                if let Ok(log_text) = serde_json::to_string(&log_msg) {
                    message_buffer.push(log_text.clone());

                    // Keep buffer size under control
                    if message_buffer.len() > BUFFER_SIZE {
                        message_buffer.remove(0);
                    }

                    if sender.send(axum::extract::ws::Message::Text(log_text)).await.is_err() {
                        error_count += 1;
                    }
                }
            }

            // Handle log broadcast updates
            log_result = log_rx.recv() => {
                match log_result {
                    Ok(log_entry) => {
                        let log_msg = WebSocketMessage::Log(log_entry);
                        if let Ok(log_text) = serde_json::to_string(&log_msg) {
                            message_buffer.push(log_text.clone());

                            // Keep buffer size under control
                            if message_buffer.len() > BUFFER_SIZE {
                                message_buffer.remove(0);
                            }

                            if sender.send(axum::extract::ws::Message::Text(log_text)).await.is_err() {
                                error_count += 1;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Logs WebSocket client {} lagged, skipped {} messages", client_id, skipped);
                        log_rx = state.log_tx.subscribe();
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Logs broadcast channel closed, disconnecting client {}", client_id);
                        break;
                    }
                }
            }
        }

        // Check error threshold
        if error_count >= MAX_ERRORS {
            log::error!(
                "Logs WebSocket client {} exceeded error threshold, disconnecting",
                client_id
            );
            break;
        }
    }

    // Send any remaining buffered messages
    for buffered_msg in message_buffer {
        let _ = sender
            .send(axum::extract::ws::Message::Text(buffered_msg))
            .await;
    }

    log::info!("Logs WebSocket client {} disconnected", client_id);
    let _ = sender.send(axum::extract::ws::Message::Close(None)).await;
}
