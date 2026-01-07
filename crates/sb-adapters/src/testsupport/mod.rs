#![cfg(any(test, feature = "e2e"))]

//! Testing support utilities for adapter integration and E2E tests.

#[cfg(feature = "socks")]
use anyhow::Result;
#[cfg(feature = "socks")]
use std::net::SocketAddr;
#[cfg(feature = "socks")]
use std::sync::Arc;

/// Spawns a SOCKS/UDP inbound server for testing.
///
/// Reads configuration from environment variables:
/// - `SB_SOCKS_UDP_ENABLE=1`: Enables SOCKS UDP
/// - `SB_SOCKS_UDP_LISTEN`: Listen address (e.g., `127.0.0.1:0`)
///
/// Returns the actual bound socket address after spawning the server.
///
/// # Errors
///
/// Returns an error if:
/// - Environment configuration is missing or invalid
/// - No UDP listeners could be configured
/// - Binding to the socket address fails
///
/// # Examples
///
/// ```rust,ignore
/// std::env::set_var("SB_SOCKS_UDP_ENABLE", "1");
/// std::env::set_var("SB_SOCKS_UDP_LISTEN", "127.0.0.1:0");
/// let addr = spawn_socks_udp_inbound().await?;
/// println!("SOCKS UDP server listening on {}", addr);
/// ```
#[cfg(feature = "socks")]
pub async fn spawn_socks_udp_inbound() -> Result<SocketAddr> {
    use crate::inbound::socks::udp::{bind_udp_from_env_or_any, serve_udp_datagrams};

    let socks = bind_udp_from_env_or_any().await?;
    anyhow::ensure!(!socks.is_empty(), "no UDP listens configured");
    let first = Arc::clone(&socks[0]);
    let addr = first.local_addr()?;
    for s in socks {
        tokio::spawn(async move {
            let _ = serve_udp_datagrams(s, None, None, None).await;
        });
    }
    Ok(addr)
}
