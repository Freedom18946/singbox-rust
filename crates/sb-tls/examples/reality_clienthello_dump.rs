use base64::Engine as _;
use sb_tls::{RealityClientConfig, ensure_crypto_provider};
use std::env;

fn default_public_key() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 32])
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
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

    let wire = sb_tls::reality::debug_emit_client_hello_record(config)?;
    println!("{}", hex::encode(wire));
    Ok(())
}
