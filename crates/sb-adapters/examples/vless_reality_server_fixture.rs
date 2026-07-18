//! Local-fixture VLESS+REALITY server used by the bidirectional interop gate.

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use sb_adapters::inbound::vless::{self, VlessInboundConfig};
use sb_core::router::RouterHandle;
use sb_tls::RealityServerConfig;
use tokio::sync::mpsc;
use uuid::Uuid;

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}

fn csv(name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(required(name)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sb_tls::ensure_crypto_provider();

    let listen = required("SB_REALITY_SERVER_LISTEN")?.parse::<SocketAddr>()?;
    let reality = RealityServerConfig {
        target: required("SB_REALITY_SERVER_TARGET")?,
        server_names: csv("SB_REALITY_SERVER_NAMES")?,
        private_key: required("SB_REALITY_SERVER_PRIVATE_KEY_HEX")?,
        short_ids: csv("SB_REALITY_SERVER_SHORT_IDS")?,
        handshake_timeout: 5,
        enable_fallback: true,
    };
    reality.validate()?;

    let config = VlessInboundConfig {
        listen,
        uuid: Uuid::parse_str(&required("SB_VLESS_UUID")?)?,
        router: Arc::new(RouterHandle::new_mock()),
        tag: Some("fixture-rust-reality-in".to_string()),
        stats: None,
        conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
        reality: Some(reality),
        multiplex: None,
        transport_layer: None,
        fallback: None,
        fallback_for_alpn: HashMap::new(),
        flow: None,
    };

    let (_stop_tx, stop_rx) = mpsc::channel(1);
    println!("STARTING {listen}");
    vless::serve(config, stop_rx).await?;
    Ok(())
}
