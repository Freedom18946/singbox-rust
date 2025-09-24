#![cfg(any(test, feature = "e2e"))]

#[cfg(feature = "socks")]
use anyhow::Result;
#[cfg(feature = "socks")]
use std::net::SocketAddr;
#[cfg(feature = "socks")]
use std::sync::Arc;

/// Spawn the SOCKS/UDP inbound using current environment and return the actual bound address.
/// Expects SB_SOCKS_UDP_ENABLE=1 and SB_SOCKS_UDP_LISTEN set (e.g., 127.0.0.1:0).
#[cfg(feature = "socks")]
pub async fn spawn_socks_udp_inbound() -> Result<SocketAddr> {
    use crate::inbound::socks::udp::{bind_udp_from_env_or_any, serve_udp_datagrams};

    let socks = bind_udp_from_env_or_any().await?;
    anyhow::ensure!(!socks.is_empty(), "no UDP listens configured");
    let first = Arc::clone(&socks[0]);
    let addr = first.local_addr()?;
    for s in socks.into_iter() {
        tokio::spawn(async move {
            let _ = serve_udp_datagrams(s).await;
        });
    }
    Ok(addr)
}
