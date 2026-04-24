use base64::Engine as _;
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
    record_type: Option<String>,
    record_version: Option<String>,
    hex: String,
}

#[derive(Serialize)]
struct TraceOutput {
    write_count: usize,
    total_len: usize,
    writes: Vec<TraceChunk>,
    combined_hex: String,
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

    let writes = sb_tls::reality::debug_trace_client_hello_writes(config)?;
    let chunks = writes
        .iter()
        .enumerate()
        .map(|(index, chunk)| TraceChunk {
            index,
            len: chunk.len(),
            record_type: chunk.first().map(|value| format!("0x{value:02x}")),
            record_version: (chunk.len() >= 3)
                .then(|| format!("0x{:02x}{:02x}", chunk[1], chunk[2])),
            hex: hex::encode(chunk),
        })
        .collect::<Vec<_>>();
    let combined = writes.concat();
    let output = TraceOutput {
        write_count: chunks.len(),
        total_len: combined.len(),
        writes: chunks,
        combined_hex: hex::encode(combined),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
