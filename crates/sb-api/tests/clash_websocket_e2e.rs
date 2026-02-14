//! WebSocket E2E tests for Clash API.
//!
//! Focus: `/connections` stream stability under concurrent clients.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use sb_api::{clash::ClashApiServer, types::ApiConfig};
use serde_json::Value;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn required_success(total: usize, success_percent: usize) -> usize {
    (total * success_percent) / 100
}

struct TestServer {
    http_base: String,
    ws_base: String,
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
            traffic_broadcast_interval_ms: 1_000,
            log_buffer_size: 100,
        };

        let server = ClashApiServer::new(config)?;
        let listener =
            match tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
                Ok(listener) => listener,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    eprintln!("skipping websocket e2e: PermissionDenied binding listener");
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
        let addr = listener.local_addr()?;
        let port = addr.port();

        let handle = tokio::spawn(async move {
            let app = server.create_app();
            let _ = axum::serve(listener, app).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let http_base = format!("http://127.0.0.1:{port}");
        let ws_base = format!("ws://127.0.0.1:{port}");
        Ok(Some(Self {
            http_base,
            ws_base,
            _handle: handle,
        }))
    }
}

fn verify_connections_snapshot(value: &Value) -> bool {
    value.get("connections").is_some()
        && value.get("uploadTotal").is_some()
        && value.get("downloadTotal").is_some()
        && value.get("memory").is_some()
}

async fn receive_connections_frame(ws_url: &str) -> bool {
    let Ok((mut stream, _)) = connect_async(ws_url).await else {
        return false;
    };

    let next = timeout(Duration::from_secs(3), stream.next()).await;
    let ok = match next {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<Value>(&text) {
            Ok(value) => verify_connections_snapshot(&value),
            Err(_) => false,
        },
        Ok(Some(Ok(Message::Binary(data)))) => match serde_json::from_slice::<Value>(&data) {
            Ok(value) => verify_connections_snapshot(&value),
            Err(_) => false,
        },
        _ => false,
    };

    let _ = stream.send(Message::Close(None)).await;
    ok
}

#[tokio::test]
async fn test_connections_ws_single_client_snapshot() -> anyhow::Result<()> {
    let Some(server) = TestServer::start().await? else {
        return Ok(());
    };

    // Ensure HTTP endpoint is healthy before WS handshake.
    let status = Client::new()
        .get(format!("{}/connections", server.http_base))
        .send()
        .await?
        .status();
    assert!(
        status.is_success(),
        "expected /connections success, got {status}"
    );

    let ws_url = format!("{}/connections", server.ws_base);
    assert!(
        receive_connections_frame(&ws_url).await,
        "single websocket client should receive valid /connections snapshot"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connections_ws_high_concurrency_clients() -> anyhow::Result<()> {
    let Some(server) = TestServer::start().await? else {
        return Ok(());
    };

    let ws_url = format!("{}/connections", server.ws_base);
    let clients = env_usize("SB_WS_CONCURRENCY_CLIENTS", 64);
    let success_percent = env_usize("SB_WS_CONCURRENCY_SUCCESS_PERCENT", 95);

    let mut set = JoinSet::new();
    for _ in 0..clients {
        let ws_url = ws_url.clone();
        set.spawn(async move { receive_connections_frame(&ws_url).await });
    }

    let mut success = 0usize;
    while let Some(result) = set.join_next().await {
        if matches!(result, Ok(true)) {
            success += 1;
        }
    }

    assert!(
        success >= required_success(clients, success_percent),
        "/connections websocket concurrency too low: {success}/{clients}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connections_ws_multi_wave_stability() -> anyhow::Result<()> {
    let Some(server) = TestServer::start().await? else {
        return Ok(());
    };

    let ws_url = format!("{}/connections", server.ws_base);
    let clients_per_wave = env_usize("SB_WS_MULTI_WAVE_CLIENTS", 32);
    let waves = env_usize("SB_WS_MULTI_WAVE_WAVES", 8);
    let wave_delay_ms = env_u64("SB_WS_MULTI_WAVE_DELAY_MS", 100);
    let wave_success_percent = env_usize("SB_WS_MULTI_WAVE_SUCCESS_PERCENT", 95);
    let overall_success_percent = env_usize("SB_WS_MULTI_WAVE_OVERALL_SUCCESS_PERCENT", 97);
    let mut total_success = 0usize;

    for wave in 0..waves {
        let mut set = JoinSet::new();
        for _ in 0..clients_per_wave {
            let ws_url = ws_url.clone();
            set.spawn(async move { receive_connections_frame(&ws_url).await });
        }

        let mut wave_success = 0usize;
        while let Some(result) = set.join_next().await {
            if matches!(result, Ok(true)) {
                wave_success += 1;
            }
        }

        assert!(
            wave_success >= required_success(clients_per_wave, wave_success_percent),
            "wave {} websocket success too low: {wave_success}/{clients_per_wave}",
            wave + 1
        );
        total_success += wave_success;

        tokio::time::sleep(Duration::from_millis(wave_delay_ms)).await;
    }

    let total_clients = waves * clients_per_wave;
    assert!(
        total_success >= required_success(total_clients, overall_success_percent),
        "overall websocket stability too low: {total_success}/{total_clients}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak; run explicitly in interop/nightly"]
async fn test_connections_ws_long_running_soak() -> anyhow::Result<()> {
    let Some(server) = TestServer::start().await? else {
        return Ok(());
    };

    let ws_url = format!("{}/connections", server.ws_base);
    let clients_per_wave = env_usize("SB_WS_SOAK_CLIENTS_PER_WAVE", 32);
    let waves = env_usize("SB_WS_SOAK_WAVES", 40);
    let wave_delay_ms = env_u64("SB_WS_SOAK_WAVE_DELAY_MS", 150);
    let wave_success_percent = env_usize("SB_WS_SOAK_WAVE_SUCCESS_PERCENT", 95);
    let overall_success_percent = env_usize("SB_WS_SOAK_OVERALL_SUCCESS_PERCENT", 97);
    let mut total_success = 0usize;

    for wave in 0..waves {
        let mut set = JoinSet::new();
        for _ in 0..clients_per_wave {
            let ws_url = ws_url.clone();
            set.spawn(async move { receive_connections_frame(&ws_url).await });
        }

        let mut wave_success = 0usize;
        while let Some(result) = set.join_next().await {
            if matches!(result, Ok(true)) {
                wave_success += 1;
            }
        }

        assert!(
            wave_success >= required_success(clients_per_wave, wave_success_percent),
            "soak wave {} websocket success too low: {wave_success}/{clients_per_wave}",
            wave + 1
        );
        total_success += wave_success;
        tokio::time::sleep(Duration::from_millis(wave_delay_ms)).await;
    }

    let total_clients = waves * clients_per_wave;
    assert!(
        total_success >= required_success(total_clients, overall_success_percent),
        "soak overall websocket stability too low: {total_success}/{total_clients}"
    );
    Ok(())
}
