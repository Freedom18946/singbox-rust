//! TUN inbound service
//!
//! Provides TUN (network TUNnel) interface capabilities for transparent proxying.
//! This implementation handles incoming packets from the TUN device and routes them
//! through the appropriate outbound connections.

use crate::adapter::InboundService;
use sb_platform::tun::{AsyncTunDevice, TunConfig as PlatformTunConfig};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

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
    /// Stack type (system, gvisor, mixed)
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

    /// Main packet processing loop using smoltcp
    async fn process_packets(&self) -> io::Result<()> {
        let platform_config = PlatformTunConfig {
            name: self.config.name.clone(),
            mtu: self.config.mtu,
            ipv4: self.config.ipv4.map(Into::into),
            ipv6: self.config.ipv6.map(Into::into),
            auto_route: self.config.auto_route,
            table: None,
        };

        let mut device = AsyncTunDevice::new(&platform_config).map_err(io::Error::other)?;
        info!("TUN device {} initialized", device.name());

        // Initialize smoltcp interface
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut TunPhy::new(device.mtu()), Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            if let Some(ipv4) = self.config.ipv4 {
                let _ = ip_addrs.push(IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&ipv4.octets())),
                    24,
                ));
            }
        });

        let mut sockets = SocketSet::new(vec![]);
        let mut buf = vec![0u8; self.config.mtu as usize];

        loop {
            if self.is_shutdown() {
                info!("TUN service shutdown requested");
                break;
            }

            // Read packet from TUN
            match device.read(&mut buf) {
                Ok(len) => {
                    if len == 0 {
                        continue;
                    }
                    let packet = &mut buf[..len];

                    // Feed to smoltcp
                    let timestamp = Instant::now();
                    let mut phy = TunPhy::new(device.mtu());
                    phy.rx_buf = Some(packet.to_vec()); // Simple buffering for demo

                    iface.poll(timestamp, &mut phy, &mut sockets);
                    // Check for outgoing packets in phy.tx_buf and write to device
                    if let Some(tx_packet) = phy.tx_buf {
                        if let Err(e) = device.write(&tx_packet) {
                            warn!("Failed to write to TUN: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from TUN: {}", e);
                    break;
                }
            }
        }

        let _ = device.close();
        Ok(())
    }
}

/// A simple PHY device for smoltcp that buffers a single packet
struct TunPhy {
    mtu: u32,
    rx_buf: Option<Vec<u8>>,
    tx_buf: Option<Vec<u8>>,
}

impl TunPhy {
    fn new(mtu: u32) -> Self {
        Self {
            mtu,
            rx_buf: None,
            tx_buf: None,
        }
    }
}

impl Device for TunPhy {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_buf
            .take()
            .map(|buf| (TunRxToken(buf), TunTxToken(self)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu as usize;
        caps.medium = Medium::Ip;
        caps
    }
}

struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct TunTxToken<'a>(&'a mut TunPhy);

impl<'a> TxToken for TunTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.tx_buf = Some(buf);
        result
    }
}

impl InboundService for TunInboundService {
    fn serve(&self) -> std::io::Result<()> {
        info!("Starting TUN inbound service");
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        rt.block_on(self.process_packets())
    }

    fn request_shutdown(&self) {
        self.shutdown();
    }
}
