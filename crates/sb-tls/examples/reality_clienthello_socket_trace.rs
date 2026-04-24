use base64::Engine as _;
use sb_tls::reality::{
    LocalSocketTrace, SocketTraceChunk, SocketTraceEvent, debug_trace_local_socket_handshake,
};
use sb_tls::{RealityClientConfig, ensure_crypto_provider};
use serde::Serialize;
use std::env;

fn default_public_key() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 32])
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

#[derive(Serialize)]
struct TraceChunk {
    index: usize,
    len: usize,
    offset_micros: u64,
    record_type: Option<String>,
    record_version: Option<String>,
    hex: String,
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
    listener_addr: String,
    client_error: Option<String>,
    client_connect_elapsed_micros: Option<u64>,
    client_handshake_elapsed_micros: Option<u64>,
    client_first_write_after_connect_micros: Option<u64>,
    client_first_read_after_connect_micros: Option<u64>,
    client_event_trace: Vec<TraceEvent>,
    server_read_count: usize,
    server_total_len: usize,
    server_first_read_delay_micros: Option<u64>,
    server_trace_elapsed_micros: u64,
    server_first_read_to_end_micros: Option<u64>,
    server_end_reason: String,
    server_timed_out_waiting_for_more: bool,
    server_chunks: Vec<TraceChunk>,
}

fn map_chunk(chunk: SocketTraceChunk) -> TraceChunk {
    TraceChunk {
        index: chunk.index,
        len: chunk.len,
        offset_micros: chunk.offset_micros,
        record_type: chunk.record_type,
        record_version: chunk.record_version,
        hex: chunk.hex,
    }
}

fn map_event(event: SocketTraceEvent) -> TraceEvent {
    TraceEvent {
        offset_micros: event.offset_micros,
        kind: event.kind,
        len: event.len,
        detail: event.detail,
    }
}

fn map_output(trace: LocalSocketTrace) -> TraceOutput {
    TraceOutput {
        listener_addr: trace.listener_addr,
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
        server_read_count: trace.server_read_count,
        server_total_len: trace.server_total_len,
        server_first_read_delay_micros: trace.server_first_read_delay_micros,
        server_trace_elapsed_micros: trace.server_trace_elapsed_micros,
        server_first_read_to_end_micros: trace.server_first_read_to_end_micros,
        server_end_reason: trace.server_end_reason,
        server_timed_out_waiting_for_more: trace.server_timed_out_waiting_for_more,
        server_chunks: trace.server_chunks.into_iter().map(map_chunk).collect(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let config = RealityClientConfig {
        target: env_or("SB_REALITY_TARGET", "www.apple.com"),
        server_name: env_or("SB_REALITY_SERVER_NAME", "www.apple.com"),
        public_key: env::var("SB_REALITY_PUBLIC_KEY").unwrap_or_else(|_| default_public_key()),
        short_id: Some(env_or("SB_REALITY_SHORT_ID", "01ab")),
        fingerprint: env_or("SB_REALITY_FINGERPRINT", "chrome"),
        alpn: Vec::new(),
    };

    let trace = debug_trace_local_socket_handshake(config)?;
    println!("{}", serde_json::to_string_pretty(&map_output(trace))?);
    Ok(())
}
