//! TUN inbound service
//!
//! Provides TUN (network TUNnel) interface capabilities for transparent proxying.
//! This implementation handles incoming packets from the TUN device and routes them
//! through the appropriate outbound connections.

use crate::adapter::InboundService;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

/// TUN interface configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (platform specific)
    pub name: String,
    /// Maximum transmission unit
    pub mtu: u32,
    /// Interface IPv4 address
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Interface IPv6 address
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Enable auto-route configuration
    pub auto_route: bool,
    /// Stack type (system, gvisor, etc.)
    pub stack: String,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "tun-sb".to_string(),
            mtu: 1500,
            ipv4: Some(std::net::Ipv4Addr::new(192, 168, 53, 1)),
            ipv6: None,
            auto_route: false,
            stack: "system".to_string(),
        }
    }
}

/// TUN interface inbound service
#[derive(Debug)]
pub struct TunInboundService {
    config: TunConfig,
    shutdown: Arc<AtomicBool>,
    sniff_enabled: bool,
}

impl Default for TunInboundService {
    fn default() -> Self {
        Self::new()
    }
}

impl TunInboundService {
    /// Create new TUN inbound service with default configuration
    pub fn new() -> Self {
        Self::with_config(TunConfig::default())
    }

    /// Create new TUN inbound service with custom configuration
    pub fn with_config(config: TunConfig) -> Self {
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            sniff_enabled: false,
        }
    }

    /// Get TUN configuration
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Request graceful shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Enable/disable inbound sniff features (TLS SNI, QUIC ALPN, etc.)
    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Initialize TUN device (platform specific)
    fn init_device(&self) -> io::Result<()> {
        info!(
            "Initializing TUN device: name={}, mtu={}, stack={}",
            self.config.name, self.config.mtu, self.config.stack
        );

        // For now, we simulate device initialization
        // In a real implementation, this would:
        // 1. Create platform-specific TUN device handle
        // 2. Configure IP addresses and routes
        // 3. Set up packet capture/injection interfaces

        debug!("TUN device initialized successfully");
        Ok(())
    }

    /// Main packet processing loop
    async fn process_packets(&self) -> io::Result<()> {
        let mut packet_count = 0u64;

        loop {
            if self.is_shutdown() {
                info!("TUN service shutdown requested, stopping packet processing");
                break;
            }

            // Simulate packet processing delay
            tokio::time::sleep(Duration::from_millis(100)).await;

            // In a real implementation, this would:
            // 1. Read packet from TUN device
            // 2. Parse IP headers and extract destination
            // 3. Optionally peek first bytes of streams for TLS SNI/HTTP Host when sniff is enabled
            if self.sniff_enabled {
                // Placeholder: demonstrate that sniff path can be activated safely
                // Real implementation should extract SNI/ALPN from TCP ClientHello packets.
                tracing::trace!("tun: sniff enabled (stage1) - no-op");
            }
            // 4. Query router for routing decision
            // 4. Forward packet to appropriate outbound
            // 5. Handle return traffic

            packet_count += 1;
            if packet_count.is_multiple_of(100) {
                debug!("Processed {} packets", packet_count);
            }
        }

        info!("TUN packet processing loop ended");
        Ok(())
    }
}

impl InboundService for TunInboundService {
    fn serve(&self) -> std::io::Result<()> {
        info!("Starting TUN inbound service");

        // Initialize TUN device
        self.init_device()?;

        // Create async runtime for packet processing
        let rt = tokio::runtime::Runtime::new()
            .map_err(io::Error::other)?;

        // Run packet processing loop
        rt.block_on(async {
            if let Err(e) = self.process_packets().await {
                error!("TUN packet processing failed: {}", e);
                return Err(e);
            }
            Ok(())
        })
    }
}
