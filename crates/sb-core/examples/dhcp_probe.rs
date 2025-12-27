//! DHCP Probe Validation Tool

use sb_core::dns::transport::{DhcpTransport, DnsStartStage, DnsTransport};
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("debug,sb_core=debug")
        .init();

    info!("Starting DHCP Probe...");

    // Create transport (auto interface by default, or specify e.g. Some("eth0".to_string()))
    // For local test, we trigger broadcast on default route usually.
    let transport = DhcpTransport::new(None);

    info!("Starting transport...");
    transport.start(DnsStartStage::Start).await?;

    info!("Waiting for probe (10s)...");

    // Wait for a few seconds to let probe finish
    for i in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let servers = transport.servers();
        if !servers.is_empty() {
            info!("Discovered DNS servers: {:?}", servers);
            break;
        }
        info!("Waiting... ({}/10)", i + 1);
    }

    let servers = transport.servers();
    if servers.is_empty() {
        info!("No servers discovered via DHCP (expected if no DHCP server on LAN replying to this machine)");
    } else {
        info!("SUCCESS: Found servers: {:?}", servers);
    }

    Ok(())
}
