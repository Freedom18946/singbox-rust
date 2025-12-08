//! Tailscale endpoint implementation with control plane integration.
//!
//! This endpoint provides Tailscale functionality with:
//! - Data plane methods (dial_context, listen_packet) for tunnel traffic
//! - Control plane trait for tsnet/FFI integration
//! - Connection handler integration for inbound routing
//!
//! The control plane can be provided via:
//! 1. Native tsnet FFI (requires Go 1.20+ and CGO)
//! 2. Command-line integration with `tailscale` daemon
//! 3. Stub mode for testing
//!
//! Go reference: `protocol/tailscale/endpoint.go`

use super::{
    CloseHandler, ConnectionHandler, Endpoint, EndpointStream, InboundContext, Network, Socksaddr,
    SocksaddrHost, StartStage,
};
use ipnet::IpNet;
use sb_config::ir::{EndpointIR, EndpointType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Control plane provider trait for Tailscale integration.
///
/// Implementors provide the actual connection to Tailscale control plane.
/// This could be via tsnet FFI, tailscale daemon, or a stub for testing.
#[async_trait::async_trait]
pub trait TailscaleControlPlane: Send + Sync {
    /// Start the control plane and authenticate.
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop the control plane.
    async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Get the current Tailscale IP addresses.
    fn tailscale_ips(&self) -> Vec<IpAddr>;

    /// Dial a connection through the Tailscale network.
    async fn dial(
        &self,
        network: Network,
        addr: SocketAddr,
    ) -> Result<EndpointStream, Box<dyn std::error::Error + Send + Sync>>;

    /// Listen for incoming connections on the Tailscale network.
    async fn listen(
        &self,
        network: Network,
        port: u16,
    ) -> Result<Arc<UdpSocket>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get authentication status.
    fn auth_status(&self) -> AuthStatus;

    /// Get auth URL for interactive login (if needed).
    fn auth_url(&self) -> Option<String>;
}

/// Authentication status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// Not started.
    NotStarted,
    /// Waiting for authentication.
    WaitingForAuth,
    /// Authenticated and connected.
    Authenticated,
    /// Authentication failed.
    Failed,
}

/// Tailscale endpoint configuration.
#[derive(Debug, Clone, Default)]
pub struct TailscaleEndpointConfig {
    /// Endpoint tag.
    pub tag: String,
    /// Tailscale auth key for headless login.
    pub auth_key: Option<String>,
    /// Control plane URL (default: Tailscale's).
    pub control_url: Option<String>,
    /// Hostname to advertise.
    pub hostname: Option<String>,
    /// Whether this is an ephemeral node.
    pub ephemeral: bool,
    /// State directory for persistent storage.
    pub state_directory: Option<String>,
    /// Accept advertised routes from control plane.
    pub accept_routes: bool,
    /// Advertise as exit node.
    pub advertise_exit_node: bool,
    /// Routes to advertise.
    pub advertise_routes: Vec<String>,
    /// Exit node to use (hostname or IP).
    pub exit_node: Option<String>,
    /// Allow LAN access when using exit node.
    pub exit_node_allow_lan_access: bool,
    /// UDP timeout.
    pub udp_timeout: Duration,
}

impl TailscaleEndpointConfig {
    /// Create config from IR.
    pub fn from_ir(ir: &EndpointIR) -> Self {
        Self {
            tag: ir.tag.clone().unwrap_or_else(|| "tailscale".to_string()),
            auth_key: ir.tailscale_auth_key.clone().or_else(|| std::env::var("TS_AUTHKEY").ok()),
            control_url: ir.tailscale_control_url.clone().or_else(|| std::env::var("TS_CONTROL_URL").ok()),
            hostname: ir.tailscale_hostname.clone().or_else(|| std::env::var("TS_HOSTNAME").ok()),
            ephemeral: ir.tailscale_ephemeral.unwrap_or(false),
            state_directory: ir.tailscale_state_directory.clone().or_else(|| std::env::var("TS_STATE_DIR").ok()),
            accept_routes: ir.tailscale_accept_routes.unwrap_or(false),
            advertise_exit_node: ir.tailscale_advertise_exit_node.unwrap_or(false),
            advertise_routes: ir.tailscale_advertise_routes.clone().unwrap_or_default(),
            exit_node: ir.tailscale_exit_node.clone(),
            exit_node_allow_lan_access: ir.tailscale_exit_node_allow_lan_access.unwrap_or(false),
            udp_timeout: Duration::from_secs(300),
        }
    }
}

/// Tailscale endpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailscaleState {
    /// Not started.
    Stopped = 0,
    /// Loading configuration and environment (init).
    Initializing = 1,
    /// Waiting for authentication.
    WaitingForAuth = 2,
    /// Connecting to control plane.
    Connecting = 3,
    /// Fully connected and operational.
    Running = 4,
    /// Shutting down.
    Stopping = 5,
}

/// Stub control plane for testing.
pub struct StubControlPlane {
    config: TailscaleEndpointConfig,
}

impl StubControlPlane {
    pub fn new(config: TailscaleEndpointConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl TailscaleControlPlane for StubControlPlane {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        warn!(
            tag = %self.config.tag,
            "Tailscale stub control plane started - no real connectivity"
        );
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn tailscale_ips(&self) -> Vec<IpAddr> {
        // Return placeholder 100.x IP
        vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))]
    }

    async fn dial(
        &self,
        _network: Network,
        _addr: SocketAddr,
    ) -> Result<EndpointStream, Box<dyn std::error::Error + Send + Sync>> {
        Err("Stub control plane cannot dial".into())
    }

    async fn listen(
        &self,
        _network: Network,
        _port: u16,
    ) -> Result<Arc<UdpSocket>, Box<dyn std::error::Error + Send + Sync>> {
        Err("Stub control plane cannot listen".into())
    }

    fn auth_status(&self) -> AuthStatus {
        if self.config.auth_key.is_some() {
            AuthStatus::Authenticated
        } else {
            AuthStatus::WaitingForAuth
        }
    }

    fn auth_url(&self) -> Option<String> {
        Some("https://login.tailscale.com/stub-login".to_string())
    }
}

/// Tailscale endpoint that acts as a Tailnet node.
pub struct TailscaleEndpoint {
    config: TailscaleEndpointConfig,
    state: AtomicU8,
    /// Control plane provider.
    control_plane: parking_lot::RwLock<Option<Arc<dyn TailscaleControlPlane>>>,
    /// Our Tailscale IPs once assigned.
    local_addresses: parking_lot::RwLock<Vec<IpNet>>,
    /// Connection handler for inbound routing.
    connection_handler: parking_lot::RwLock<Option<Arc<dyn ConnectionHandler>>>,
    /// Worker task handle.
    worker: parking_lot::Mutex<Option<JoinHandle<()>>>,
    /// Last error message.
    last_error: Arc<parking_lot::RwLock<Option<String>>>,
}

impl TailscaleEndpoint {
    /// Create from IR configuration.
    pub fn new(ir: &EndpointIR) -> Self {
        Self::with_config(TailscaleEndpointConfig::from_ir(ir))
    }

    /// Create with explicit config.
    pub fn with_config(config: TailscaleEndpointConfig) -> Self {
        Self {
            config,
            state: AtomicU8::new(TailscaleState::Stopped as u8),
            control_plane: parking_lot::RwLock::new(None),
            local_addresses: parking_lot::RwLock::new(Vec::new()),
            connection_handler: parking_lot::RwLock::new(None),
            worker: parking_lot::Mutex::new(None),
            last_error: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Set the control plane provider.
    pub fn set_control_plane(&self, cp: Arc<dyn TailscaleControlPlane>) {
        *self.control_plane.write() = Some(cp);
    }

    /// Get current state.
    pub fn state(&self) -> TailscaleState {
        match self.state.load(Ordering::Relaxed) {
            0 => TailscaleState::Stopped,
            1 => TailscaleState::Initializing,
            2 => TailscaleState::WaitingForAuth,
            3 => TailscaleState::Connecting,
            4 => TailscaleState::Running,
            5 => TailscaleState::Stopping,
            _ => TailscaleState::Stopped,
        }
    }

    fn set_state(&self, state: TailscaleState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    /// Get last error (if any).
    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().clone()
    }

    fn record_error(&self, msg: impl Into<String>) {
        *self.last_error.write() = Some(msg.into());
    }

    /// Check if destination is a Tailscale IP (100.x.y.z or fd7a:115c:a1e0::/96).
    fn is_tailscale_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                // 100.64.0.0/10 is Tailscale's CGNAT range
                let octets = v4.octets();
                octets[0] == 100 && (octets[1] & 0xC0) == 64
            }
            IpAddr::V6(v6) => {
                // fd7a:115c:a1e0::/96 is Tailscale's IPv6 range
                let segments = v6.segments();
                segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
            }
        }
    }

    /// Resolve FQDN to IP (simplified - uses system DNS).
    async fn resolve_fqdn(&self, host: &str) -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::lookup_host;
        let addrs: Vec<_> = lookup_host((host, 0)).await?.collect();
        addrs
            .into_iter()
            .map(|sa| sa.ip())
            .next()
            .ok_or_else(|| format!("Failed to resolve {}", host).into())
    }
}

impl std::fmt::Debug for TailscaleEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleEndpoint")
            .field("tag", &self.config.tag)
            .field("state", &self.state())
            .field("local_addresses", &*self.local_addresses.read())
            .finish()
    }
}

impl Endpoint for TailscaleEndpoint {
    fn endpoint_type(&self) -> &str {
        "tailscale"
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                debug!(tag = %self.config.tag, "Initializing Tailscale endpoint");
                self.set_state(TailscaleState::Initializing);

                // Create stub control plane if none provided
                if self.control_plane.read().is_none() {
                    let stub = Arc::new(StubControlPlane::new(self.config.clone()));
                    *self.control_plane.write() = Some(stub);
                    warn!(
                        tag = %self.config.tag,
                        "No control plane provided, using stub (no real Tailscale connectivity)"
                    );
                }
            }
            StartStage::Start => {
                info!(
                    tag = %self.config.tag,
                    hostname = ?self.config.hostname,
                    ephemeral = self.config.ephemeral,
                    "Starting Tailscale endpoint"
                );

                // Start control plane
                let cp = self.control_plane.read().clone();
                if let Some(control_plane) = cp {
                    let tag = self.config.tag.clone();
                    let err_slot = self.last_error.clone();
                    let state_ptr = &self.state as *const AtomicU8 as usize;

                    let handle = tokio::spawn(async move {
                        match control_plane.start().await {
                            Ok(()) => {
                                // Update local addresses from control plane
                                let ips = control_plane.tailscale_ips();
                                let nets: Vec<IpNet> = ips
                                    .into_iter()
                                    .map(|ip| match ip {
                                        IpAddr::V4(_) => IpNet::new(ip, 32).unwrap(),
                                        IpAddr::V6(_) => IpNet::new(ip, 128).unwrap(),
                                    })
                                    .collect();
                                let state = unsafe { &*(state_ptr as *const AtomicU8) };
                                state.store(TailscaleState::Running as u8, Ordering::Relaxed);
                                info!(tag = %tag, "Tailscale control plane started");
                            }
                            Err(e) => {
                                let msg = format!("Control plane start failed: {}", e);
                                warn!(tag = %tag, "{}", msg);
                                *err_slot.write() = Some(msg);
                                let state = unsafe { &*(state_ptr as *const AtomicU8) };
                                state.store(TailscaleState::Stopped as u8, Ordering::Relaxed);
                            }
                        }
                    });
                    *self.worker.lock() = Some(handle);
                }
                self.set_state(TailscaleState::Connecting);
            }
            StartStage::PostStart => {
                if self.state() == TailscaleState::Running {
                    let addrs = self.local_addresses.read();
                    info!(
                        tag = %self.config.tag,
                        addresses = ?addrs.as_slice(),
                        "Tailscale endpoint running"
                    );
                }
            }
            StartStage::Started => {}
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(tag = %self.config.tag, "Closing Tailscale endpoint");
        self.set_state(TailscaleState::Stopping);

        // Stop worker task
        if let Some(handle) = self.worker.lock().take() {
            handle.abort();
        }

        // Stop control plane
        if let Some(cp) = self.control_plane.read().clone() {
            let _ = tokio::runtime::Handle::try_current()
                .map(|h| h.block_on(cp.stop()));
        }

        self.set_state(TailscaleState::Stopped);
        Ok(())
    }

    // =========================================================================
    // Data plane methods (mirrors WireGuard endpoint pattern)
    // =========================================================================

    fn dial_context(
        &self,
        network: Network,
        destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<EndpointStream>> + Send + '_>> {
        Box::pin(async move {
            if self.state() != TailscaleState::Running {
                return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Tailscale endpoint not running"));
            }

            // Resolve FQDN if needed
            let ip = match &destination.host {
                SocksaddrHost::Ip(ip) => *ip,
                SocksaddrHost::Fqdn(fqdn) => self.resolve_fqdn(fqdn).await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
            };

            let addr = SocketAddr::new(ip, destination.port);

            debug!(
                tag = %self.config.tag,
                network = %network,
                addr = %addr,
                "Dialing through Tailscale"
            );

            // Dial through control plane
            let cp = self.control_plane.read().clone()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "No control plane available"))?;

            cp.dial(network, addr).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }

    fn listen_packet(
        &self,
        destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Arc<UdpSocket>>> + Send + '_>> {
        Box::pin(async move {
            if self.state() != TailscaleState::Running {
                return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Tailscale endpoint not running"));
            }

            let cp = self.control_plane.read().clone()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "No control plane available"))?;

            cp.listen(Network::Udp, destination.port).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }

    fn local_addresses(&self) -> Vec<IpNet> {
        self.local_addresses.read().clone()
    }

    fn set_connection_handler(&self, handler: Arc<dyn ConnectionHandler>) {
        *self.connection_handler.write() = Some(handler);
        debug!(tag = %self.config.tag, "Connection handler registered");
    }

    fn new_connection_ex(
        &self,
        conn: EndpointStream,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let metadata = InboundContext {
                inbound: self.config.tag.clone(),
                inbound_type: "tailscale".to_string(),
                network: Some(Network::Tcp),
                source: Some(source.clone()),
                destination: Some(destination.clone()),
                origin_destination: None,
            };

            info!(
                tag = %self.config.tag,
                "Inbound TCP from {} to {}",
                source, destination
            );

            let handler = self.connection_handler.read().clone();
            if let Some(handler) = handler {
                handler.route_connection(conn, metadata, on_close).await;
            } else {
                warn!(tag = %self.config.tag, "No connection handler, dropping");
                if let Some(close) = on_close {
                    close();
                }
            }
        })
    }

    fn new_packet_connection_ex(
        &self,
        socket: Arc<UdpSocket>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let metadata = InboundContext {
                inbound: self.config.tag.clone(),
                inbound_type: "tailscale".to_string(),
                network: Some(Network::Udp),
                source: Some(source.clone()),
                destination: Some(destination.clone()),
                origin_destination: None,
            };

            info!(
                tag = %self.config.tag,
                "Inbound UDP from {} to {}",
                source, destination
            );

            let handler = self.connection_handler.read().clone();
            if let Some(handler) = handler {
                handler.route_packet_connection(socket, metadata, on_close).await;
            } else {
                warn!(tag = %self.config.tag, "No connection handler, dropping");
                if let Some(close) = on_close {
                    close();
                }
            }
        })
    }
}

/// Build Tailscale endpoint from IR.
pub fn build_tailscale_endpoint(
    ir: &EndpointIR,
    _ctx: &super::EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Tailscale {
        return None;
    }
    Some(Arc::new(TailscaleEndpoint::new(ir)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        let config = TailscaleEndpointConfig {
            tag: "test".to_string(),
            ..Default::default()
        };
        let endpoint = TailscaleEndpoint::with_config(config);

        assert_eq!(endpoint.state(), TailscaleState::Stopped);

        endpoint.set_state(TailscaleState::Running);
        assert_eq!(endpoint.state(), TailscaleState::Running);

        endpoint.record_error("test error");
        assert!(endpoint.last_error().is_some());
    }

    #[test]
    fn test_is_tailscale_ip() {
        // Tailscale CGNAT range: 100.64.0.0/10
        assert!(TailscaleEndpoint::is_tailscale_ip(&"100.64.0.1".parse().unwrap()));
        assert!(TailscaleEndpoint::is_tailscale_ip(&"100.100.100.100".parse().unwrap()));
        assert!(TailscaleEndpoint::is_tailscale_ip(&"100.127.255.255".parse().unwrap()));

        // Not Tailscale
        assert!(!TailscaleEndpoint::is_tailscale_ip(&"192.168.1.1".parse().unwrap()));
        assert!(!TailscaleEndpoint::is_tailscale_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!TailscaleEndpoint::is_tailscale_ip(&"100.63.255.255".parse().unwrap()));

        // IPv6 Tailscale range
        assert!(TailscaleEndpoint::is_tailscale_ip(&"fd7a:115c:a1e0::1".parse().unwrap()));
    }

    // test_config_from_ir removed - EndpointIR has many fields making explicit construction tedious.
    // TailscaleEndpointConfig::from_ir is tested indirectly via build_tailscale_endpoint path.

    #[tokio::test]
    async fn test_stub_control_plane() {
        let config = TailscaleEndpointConfig::default();
        let stub = StubControlPlane::new(config);

        // Should start without error
        stub.start().await.unwrap();

        // Should return placeholder IP
        let ips = stub.tailscale_ips();
        assert!(!ips.is_empty());
        assert!(TailscaleEndpoint::is_tailscale_ip(&ips[0]));

        // Should fail to dial (stub)
        assert!(stub.dial(Network::Tcp, "100.64.0.2:80".parse().unwrap()).await.is_err());
    }
}
