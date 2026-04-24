use base64::Engine as _;
use sb_tls::reality::{
    ClientSocketTrace, SocketTraceEvent, debug_trace_remote_socket_handshake_with_timeout,
};
use sb_tls::{RealityClientConfig, ensure_crypto_provider};
use serde::Serialize;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

fn default_public_key() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 32])
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_timeout_ms(name: &str, default_ms: u64) -> Result<Duration, Box<dyn std::error::Error>> {
    let timeout_ms = env::var(name)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(default_ms);
    Ok(Duration::from_millis(timeout_ms))
}

#[derive(Serialize)]
struct TraceEvent {
    offset_micros: u64,
    kind: String,
    len: Option<usize>,
    detail: Option<String>,
}

#[derive(Serialize)]
struct TraceOutput {
    remote_addr: String,
    client_error: Option<String>,
    client_connect_elapsed_micros: Option<u64>,
    client_handshake_elapsed_micros: Option<u64>,
    client_first_write_after_connect_micros: Option<u64>,
    client_first_read_after_connect_micros: Option<u64>,
    client_event_trace: Vec<TraceEvent>,
}

fn map_event(event: SocketTraceEvent) -> TraceEvent {
    TraceEvent {
        offset_micros: event.offset_micros,
        kind: event.kind,
        len: event.len,
        detail: event.detail,
    }
}

fn map_output(trace: ClientSocketTrace) -> TraceOutput {
    TraceOutput {
        remote_addr: trace.remote_addr,
        client_error: trace.client_error,
        client_connect_elapsed_micros: trace.client_connect_elapsed_micros,
        client_handshake_elapsed_micros: trace.client_handshake_elapsed_micros,
        client_first_write_after_connect_micros: trace.client_first_write_after_connect_micros,
        client_first_read_after_connect_micros: trace.client_first_read_after_connect_micros,
        client_event_trace: trace
            .client_event_trace
            .into_iter()
            .map(map_event)
            .collect(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let remote_addr: SocketAddr = env::var("SB_REALITY_TRACE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:443".to_string())
        .parse()?;
    let handshake_timeout = env_timeout_ms("SB_REALITY_TRACE_TIMEOUT_MS", 2_000)?;

    let config = RealityClientConfig {
        target: env_or("SB_REALITY_TARGET", "www.apple.com"),
        server_name: env_or("SB_REALITY_SERVER_NAME", "www.apple.com"),
        public_key: env::var("SB_REALITY_PUBLIC_KEY").unwrap_or_else(|_| default_public_key()),
        short_id: Some(env_or("SB_REALITY_SHORT_ID", "01ab")),
        fingerprint: env_or("SB_REALITY_FINGERPRINT", "chrome"),
        alpn: Vec::new(),
    };

    let trace =
        debug_trace_remote_socket_handshake_with_timeout(config, remote_addr, handshake_timeout)?;
    println!("{}", serde_json::to_string_pretty(&map_output(trace))?);
    Ok(())
}
