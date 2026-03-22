use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

pub fn resolve_with_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            let _ = chars.next();
            let mut key = String::new();
            while let Some(&next) = chars.peek() {
                let _ = chars.next();
                if next == '}' {
                    break;
                }
                key.push(next);
            }
            if key.is_empty() {
                continue;
            }
            if let Ok(value) = env::var(&key) {
                out.push_str(&value);
            }
            continue;
        }
        out.push(ch);
    }

    out
}

pub fn resolve_command_with_fallback(input: &str) -> String {
    let resolved = resolve_with_env(input);
    if !looks_like_legacy_debug_app(&resolved) {
        return resolved;
    }
    if let Some(override_cmd) = find_rust_runtime_env_override() {
        return override_cmd;
    }
    if Path::new(&resolved).exists() {
        return resolved;
    }
    find_rust_runtime_fallback().unwrap_or(resolved)
}

fn looks_like_legacy_debug_app(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized == "./target/debug/app"
        || normalized == "target/debug/app"
        || normalized.ends_with("/target/debug/app")
}

fn find_rust_runtime_fallback() -> Option<String> {
    if let Some(value) = find_rust_runtime_env_override() {
        return Some(value);
    }

    for candidate in [
        "./target/release/app",
        "target/release/app",
        "./target/release/run",
        "target/release/run",
        "./target/debug/run",
        "target/debug/run",
    ] {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn find_rust_runtime_env_override() -> Option<String> {
    for key in ["INTEROP_RUST_BIN", "L18_RUST_BIN", "RUST_APP"] {
        if let Ok(value) = env::var(key) {
            if !value.is_empty() && Path::new(&value).exists() {
                return Some(value);
            }
        }
    }
    None
}

pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating directory {}", path.display()))
}

pub fn canonicalize_or(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Normalize a WebSocket message into a JSON `Value` for snapshot storage.
///
/// Shared by gui_replay and go_collector.
pub fn normalize_ws_message(
    msg: tokio_tungstenite::tungstenite::Message,
) -> Option<serde_json::Value> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::json;
    use tokio_tungstenite::tungstenite::Message;

    match msg {
        Message::Text(text) => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .or_else(|| Some(json!({ "text": text }))),
        Message::Binary(data) => serde_json::from_slice::<serde_json::Value>(&data)
            .ok()
            .or_else(|| Some(json!({ "binary_b64": STANDARD.encode(data) }))),
        Message::Ping(payload) => Some(json!({ "ping": STANDARD.encode(payload) })),
        Message::Pong(payload) => Some(json!({ "pong": STANDARD.encode(payload) })),
        Message::Close(frame) => Some(json!({ "close": frame.map(|f| f.code.to_string()) })),
        Message::Frame(_) => None,
    }
}

/// Compute the given percentile from a slice of microsecond samples.
///
/// Shared by orchestrator and upstream.
pub fn percentile_us(samples: &[u64], percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() * percentile).saturating_add(99) / 100).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}
