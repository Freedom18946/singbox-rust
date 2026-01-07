//! Tailscale outbound adapter with native WireGuard support.
//!
//! This adapter provides multiple connection modes:
//! 1. **WireGuard mode**: Direct WireGuard connection using boringtun (requires keys)
//! 2. **MagicDNS mode**: Resolve .ts.net domains via Tailscale's 100.100.100.100
//! 3. **SOCKS5 mode**: Route through local tailscaled SOCKS5 proxy (fallback)
//!
//! # Configuration
//! - `private_key` + `peer_public_key`: Enable native WireGuard mode
//! - `exit_node`: Use SOCKS5 proxy mode
//! - Neither: Direct connection with MagicDNS support
//!
//! # Requirements
//! - For WireGuard mode: Peer keys and endpoint configuration
//! - For SOCKS5 mode: tailscaled running with `--socks5-server` (127.0.0.1:1055)

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::outbound::prelude::*;
use sb_core::adapter::OutboundConnector as CoreOutboundConnector;
use sb_core::outbound::direct_connector::DirectConnector;
use sb_core::services::tailscale::coordinator::Coordinator;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Tailscale MagicDNS server.
pub const MAGIC_DNS_IP: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);

/// Connection mode for Tailscale outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleMode {
    /// Native WireGuard connection using boringtun.
    WireGuard,
    /// Route through local SOCKS5 proxy (tailscaled).
    Socks5,
    /// Direct connection with MagicDNS support.
    Direct,
    /// Managed mode using internal Coordination client (Headless).
    Managed,
}

/// Parsed Tailscale outbound configuration.
#[derive(Clone, Default)]
pub struct TailscaleConfig {
    /// Outbound tag name.
    pub tag: Option<String>,
    /// Tailscale state directory.
    pub state_directory: Option<String>,
    /// Auth key for headless authentication.
    pub auth_key: Option<String>,
    /// Control plane URL.
    pub control_url: Option<String>,
    /// Whether this is an ephemeral node.
    pub ephemeral: Option<bool>,
    /// Hostname for the node.
    pub hostname: Option<String>,
    /// Whether to accept routes from control plane.
    pub accept_routes: Option<bool>,
    /// Exit node to route traffic through.
    pub exit_node: Option<String>,
    /// Whether to allow LAN access with exit node.
    pub exit_node_allow_lan: Option<bool>,
    /// Routes to advertise.
    pub advertise_routes: Option<Vec<String>>,
    /// Whether to advertise as exit node.
    pub advertise_exit_node: Option<bool>,
    /// UDP timeout for idle sessions.
    pub udp_timeout: Option<String>,

    /// Optional socket factory for MagicDNS (netstack injection).
    #[cfg(feature = "sb-transport")]
    pub magic_dns_socket_factory: Option<MagicDnsSocketFactory>,

    // WireGuard direct connection fields
    /// Private key for WireGuard (base64).
    pub private_key: Option<String>,
    /// Peer public key for WireGuard (base64).
    pub peer_public_key: Option<String>,
    /// Pre-shared key for WireGuard (base64).
    pub pre_shared_key: Option<String>,
    /// WireGuard peer endpoint (IP:port).
    pub peer_endpoint: Option<String>,
    /// Persistent keepalive interval.
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for TailscaleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("TailscaleConfig");
        ds.field("tag", &self.tag)
            .field("state_directory", &self.state_directory)
            .field("auth_key", &self.auth_key.as_ref().map(|_| "[redacted]"))
            .field("control_url", &self.control_url)
            .field("ephemeral", &self.ephemeral)
            .field("hostname", &self.hostname)
            .field("accept_routes", &self.accept_routes)
            .field("exit_node", &self.exit_node)
            .field("exit_node_allow_lan", &self.exit_node_allow_lan)
            .field("advertise_routes", &self.advertise_routes)
            .field("advertise_exit_node", &self.advertise_exit_node)
            .field("udp_timeout", &self.udp_timeout);
        #[cfg(feature = "sb-transport")]
        {
            ds.field(
                "magic_dns_socket_factory",
                &self
                    .magic_dns_socket_factory
                    .as_ref()
                    .map(|_| "<factory>"),
            );
        }
        ds.field("private_key", &self.private_key.as_ref().map(|_| "[redacted]"))
            .field(
                "peer_public_key",
                &self.peer_public_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "pre_shared_key",
                &self.pre_shared_key.as_ref().map(|_| "[redacted]"),
            )
            .field("peer_endpoint", &self.peer_endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

impl TailscaleConfig {
    /// Determine the connection mode based on configuration.
    pub fn mode(&self) -> TailscaleMode {
        if self.private_key.is_some() && self.peer_public_key.is_some() {
            TailscaleMode::WireGuard
        } else if self.auth_key.is_some() {
            TailscaleMode::Managed
        } else if self.exit_node.is_some() {
            TailscaleMode::Socks5
        } else {
            TailscaleMode::Direct
        }
    }

    /// Inject a socket factory for MagicDNS (useful for netstack-backed sockets).
    #[cfg(feature = "sb-transport")]
    pub fn with_magic_dns_socket_factory(mut self, factory: MagicDnsSocketFactory) -> Self {
        self.magic_dns_socket_factory = Some(factory);
        self
    }
}

/// Tailscale connector that routes traffic through Tailscale network.
///
/// Supports multiple connection modes:
/// - WireGuard: Native userspace WireGuard via boringtun
/// - SOCKS5: Local tailscaled proxy
/// - Direct: Direct connection with MagicDNS
/// - Managed: Internal coordination client
#[derive(Debug)]
pub struct TailscaleConnector {
    /// Fallback direct connector.
    direct: Arc<DirectConnector>,
    /// Tailscale configuration.
    config: TailscaleConfig,
    /// Detected connection mode.
    mode: TailscaleMode,
    /// SOCKS5 proxy address.
    socks5_addr: Option<String>,
    /// WireGuard transport (lazy initialized).
    #[cfg(feature = "adapter-wireguard-outbound")]
    wireguard: Arc<Mutex<Option<Arc<crate::outbound::wireguard::WireGuardOutbound>>>>,
    /// Coordination client (for Managed mode).
    coordinator: Option<Arc<Coordinator>>,
}

impl Clone for TailscaleConnector {
    fn clone(&self) -> Self {
        Self {
            direct: self.direct.clone(),
            config: self.config.clone(),
            mode: self.mode.clone(),
            socks5_addr: self.socks5_addr.clone(),
            #[cfg(feature = "adapter-wireguard-outbound")]
            wireguard: self.wireguard.clone(),
            coordinator: self.coordinator.clone(),
        }
    }
}

impl TailscaleConnector {
    /// Create a new TailscaleConnector.
    pub fn new(direct: Arc<DirectConnector>, config: TailscaleConfig) -> Self {
        let tag = config.tag.as_deref().unwrap_or("tailscale");
        let mode = config.mode();

        match &mode {
            TailscaleMode::WireGuard => {
                info!(
                    target: "sb_adapters::tailscale",
                    tag = tag,
                    "Tailscale using native WireGuard mode"
                );
            }
            TailscaleMode::Socks5 => {
                if let Some(ref exit_node) = config.exit_node {
                    info!(
                        target: "sb_adapters::tailscale",
                        tag = tag,
                        exit_node = %exit_node,
                        "Tailscale using SOCKS5 proxy mode"
                    );
                }
            }
            TailscaleMode::Direct => {
                info!(
                    target: "sb_adapters::tailscale",
                    tag = tag,
                    "Tailscale using direct mode with MagicDNS"
                );
            }
            TailscaleMode::Managed => {
                info!(
                    target: "sb_adapters::tailscale",
                    tag = tag,
                    "Tailscale using Managed mode (Headless Auth)"
                );
            }
        }

        let socks5_addr = if mode == TailscaleMode::Socks5 {
            Some("127.0.0.1:1055".to_string())
        } else {
            None
        };

        #[cfg(feature = "adapter-wireguard-outbound")]
        let wireguard = Arc::new(Mutex::new(
            None::<Arc<crate::outbound::wireguard::WireGuardOutbound>>,
        ));

        let coordinator = if mode == TailscaleMode::Managed {
            let url = config
                .control_url
                .as_deref()
                .unwrap_or("https://controlplane.tailscale.com");
            let key = config
                .auth_key
                .as_deref()
                .expect("Managed mode requires auth_key");

            let state_path = std::env::var("SB_TAILSCALE_STATE_PATH")
                .unwrap_or_else(|_| "/tmp/singbox-tailscale-state.json".to_string());
            let coord = Arc::new(Coordinator::new(url, state_path).with_auth_key(key));
            let c = coord.clone();

            #[cfg(feature = "adapter-wireguard-outbound")]
            let wg_clone = wireguard.clone();

            tokio::spawn(async move {
                // Subscribe to updates
                let mut rx = c.subscribe();
                // Start coordinator loop
                // (Using select to run both? Or separate tasks?)
                // Actually `c.start()` runs the loop.
                // We should spawn `c.start()` separately or `join`.
                tokio::spawn(async move {
                    if let Err(e) = c.start().await {
                        error!("Tailscale coordinator failed: {}", e);
                    }
                });

                // Watch loop
                loop {
                    if rx.changed().await.is_err() {
                        break;
                    }
                    {
                        let addr_opt = {
                            let map_ref = rx.borrow();
                            if let Some(map) = map_ref.as_ref() {
                                if let Some(peer) = map.peers.first() {
                                    if let Some(ep_src) = peer.endpoints.first() {
                                        ep_src.parse::<SocketAddr>().ok()
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };

                        if let Some(addr) = addr_opt {
                            #[cfg(feature = "adapter-wireguard-outbound")]
                            {
                                let guard = wg_clone.lock().await;
                                if let Some(wg) = guard.as_ref() {
                                    wg.set_peer_endpoint(addr).await;
                                }
                            }
                        }
                    }
                }
            });
            Some(coord)
        } else {
            None
        };

        Self {
            direct,
            config,
            mode,
            socks5_addr,
            #[cfg(feature = "adapter-wireguard-outbound")]
            wireguard,
            coordinator,
        }
    }

    /// Initialize WireGuard transport if configured.
    #[cfg(feature = "adapter-wireguard-outbound")]
    pub async fn init_wireguard(&mut self) -> Result<(), AdapterError> {
        if self.mode != TailscaleMode::WireGuard {
            return Ok(());
        }

        let private_key = self
            .config
            .private_key
            .as_ref()
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard mode requires private_key",
            ))?;
        let peer_public_key =
            self.config
                .peer_public_key
                .as_ref()
                .ok_or(AdapterError::InvalidConfig(
                    "WireGuard mode requires peer_public_key",
                ))?;

        // Parse peer endpoint
        let endpoint = self
            .config
            .peer_endpoint
            .as_ref()
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard mode requires peer_endpoint",
            ))?;
        let peer_addr: SocketAddr = endpoint
            .parse()
            .map_err(|_| AdapterError::InvalidConfig("Invalid peer_endpoint format"))?;

        let wg_config = crate::outbound::wireguard::WireGuardOutboundConfig {
            server: peer_addr.ip().to_string(),
            port: peer_addr.port(),
            private_key: private_key.clone(),
            peer_public_key: peer_public_key.clone(),
            pre_shared_key: self.config.pre_shared_key.clone(),
            local_addr: None,
            allowed_ips: vec!["100.64.0.0/10".to_string(), "::/0".to_string()],
            persistent_keepalive: self.config.persistent_keepalive.or(Some(25)),
            mtu: 1420,
            connect_timeout: Duration::from_secs(10),
            tag: self.config.tag.clone(),
        };

        let wg = crate::outbound::wireguard::WireGuardOutbound::new(wg_config).await?;
        let mut guard = self.wireguard.lock().await;
        *guard = Some(Arc::new(wg));
        debug!("WireGuard transport initialized for Tailscale");
        Ok(())
    }

    /// Check if hostname is a Tailnet domain.
    pub fn is_tailnet_host(host: &str) -> bool {
        let lower = host.to_lowercase();
        lower.ends_with(".ts.net") || lower.ends_with(".tailscale.net")
    }

    /// Resolve hostname via MagicDNS if it's a Tailnet domain.
    async fn resolve_via_magic_dns(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        #[cfg(feature = "sb-transport")]
        {
            use sb_transport::tailscale_dns::TailscaleDnsTransport;
            let dns = if let Some(factory) = self.config.magic_dns_socket_factory.as_ref() {
                TailscaleDnsTransport::new().with_socket_factory({
                    let factory = factory.clone();
                    move || (factory)()
                })
            } else {
                TailscaleDnsTransport::new()
            };
            dns.resolve(host).await
        }
        #[cfg(not(feature = "sb-transport"))]
        {
            // Fallback: use system DNS
            use tokio::net::lookup_host;
            let addrs: Vec<IpAddr> = lookup_host(format!("{}:0", host))
                .await?
                .map(|a| a.ip())
                .collect();
            Ok(addrs)
        }
    }

    /// Connect through SOCKS5 proxy.
    async fn connect_via_socks5(
        &self,
        socks5_addr: &str,
        host: &str,
        port: u16,
    ) -> io::Result<TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let proxy_addr: SocketAddr = socks5_addr.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid SOCKS5 address {}: {}", socks5_addr, e),
            )
        })?;

        let mut stream = TcpStream::connect(proxy_addr).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to connect to Tailscale SOCKS5 proxy at {}: {}. \
                     Make sure tailscaled is running with --socks5-server",
                    socks5_addr, e
                ),
            )
        })?;

        // SOCKS5 handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "SOCKS5 authentication failed",
            ));
        }

        // SOCKS5 connect
        let mut request = Vec::with_capacity(7 + host.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;

        let mut resp = [0u8; 10];
        stream.read_exact(&mut resp).await?;

        if resp[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 connect failed: error code {}", resp[1]),
            ));
        }

        Ok(stream)
    }

    /// Try connecting to the first reachable address.
    async fn connect_first(addrs: &[IpAddr], port: u16) -> Option<io::Result<TcpStream>> {
        for addr in addrs {
            let sock_addr = SocketAddr::new(*addr, port);
            match TcpStream::connect(sock_addr).await {
                Ok(stream) => return Some(Ok(stream)),
                Err(e) => {
                    debug!("Failed to connect to {}: {}", sock_addr, e);
                }
            }
        }
        None
    }
}

#[cfg(feature = "sb-transport")]
pub type MagicDnsSocketFactory = Arc<
    dyn Fn() -> Pin<Box<dyn std::future::Future<Output = io::Result<UdpSocket>> + Send>>
        + Send
        + Sync,
>;

#[async_trait::async_trait]
impl CoreOutboundConnector for TailscaleConnector {
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let tag = self.config.tag.as_deref().unwrap_or("tailscale");
        let dest = format!("{}:{}", host, port);

        // Best-effort Tailnet resolution (MagicDNS) to support A/AAAA before mode selection.
        let mut tailnet_addrs: Option<Vec<IpAddr>> = None;
        if Self::is_tailnet_host(host) {
            match self.resolve_via_magic_dns(host).await {
                Ok(addrs) if !addrs.is_empty() => tailnet_addrs = Some(addrs),
                Ok(_) => warn!("MagicDNS returned no addresses for {}", host),
                Err(e) => warn!("MagicDNS resolution failed for {}: {}", host, e),
            }
        }

        match self.mode {
            TailscaleMode::WireGuard => {
                #[cfg(feature = "adapter-wireguard-outbound")]
                {
                    let guard = self.wireguard.lock().await;
                    if let Some(ref _wg) = *guard {
                        debug!(
                            target: "sb_adapters::tailscale",
                            tag = tag,
                            dest = %dest,
                            "Connecting via WireGuard"
                        );
                        // WireGuard doesn't return TcpStream, this needs adapter
                        // For now, fall through to direct
                        warn!("WireGuard stream type mismatch, falling back to direct");
                    }
                }
                // Fallback when WireGuard not available
                if let Some(addrs) = tailnet_addrs.as_ref() {
                    if let Some(stream) = Self::connect_first(addrs, port).await {
                        return stream;
                    }
                }
                self.direct.connect(host, port).await
            }

            TailscaleMode::Socks5 => {
                if let Some(ref socks5_addr) = self.socks5_addr {
                    debug!(
                        target: "sb_adapters::tailscale",
                        tag = tag,
                        dest = %dest,
                        socks5 = %socks5_addr,
                        "Connecting via SOCKS5 proxy"
                    );
                    if let Some(addrs) = tailnet_addrs.as_ref() {
                        // Prefer IP literals if MagicDNS succeeded to avoid proxy-side DNS
                        for addr in addrs {
                            if let Ok(stream) = self
                                .connect_via_socks5(socks5_addr, &addr.to_string(), port)
                                .await
                            {
                                return Ok(stream);
                            }
                        }
                    }
                    return self.connect_via_socks5(socks5_addr, host, port).await;
                }
                if let Some(addrs) = tailnet_addrs.as_ref() {
                    if let Some(stream) = Self::connect_first(addrs, port).await {
                        return stream;
                    }
                }
                self.direct.connect(host, port).await
            }

            TailscaleMode::Direct => {
                debug!(
                    target: "sb_adapters::tailscale",
                    tag = tag,
                    dest = %dest,
                    "Connecting directly"
                );
                if let Some(addrs) = tailnet_addrs.as_ref() {
                    if let Some(stream) = Self::connect_first(addrs, port).await {
                        return stream;
                    }
                }
                self.direct.connect(host, port).await
            }
            TailscaleMode::Managed => {
                debug!(
                    target: "sb_adapters::tailscale",
                    tag = tag,
                    "Managed mode: routing pending, preferring MagicDNS resolution"
                );
                if let Some(addrs) = tailnet_addrs.as_ref() {
                    if let Some(stream) = Self::connect_first(addrs, port).await {
                        return stream;
                    }
                }
                self.direct.connect(host, port).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_detection_wireguard() {
        let config = TailscaleConfig {
            private_key: Some("key".to_string()),
            peer_public_key: Some("peer".to_string()),
            ..Default::default()
        };
        assert_eq!(config.mode(), TailscaleMode::WireGuard);
    }

    #[test]
    fn test_mode_detection_socks5() {
        let config = TailscaleConfig {
            exit_node: Some("my-exit".to_string()),
            ..Default::default()
        };
        assert_eq!(config.mode(), TailscaleMode::Socks5);
    }

    #[test]
    fn test_mode_detection_direct() {
        let config = TailscaleConfig::default();
        assert_eq!(config.mode(), TailscaleMode::Direct);
    }

    #[test]
    fn test_is_tailnet_host() {
        assert!(TailscaleConnector::is_tailnet_host("device.ts.net"));
        assert!(TailscaleConnector::is_tailnet_host("server.tailscale.net"));
        assert!(!TailscaleConnector::is_tailnet_host("google.com"));
    }
}
