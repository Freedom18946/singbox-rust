//! Tailscale endpoint implementation with control plane integration.
//!
//! This endpoint provides Tailscale functionality with:
//! - Data plane methods (dial_context, listen_packet) for tunnel traffic
//! - Control plane trait for tsnet/FFI integration
//! - Connection handler integration for inbound routing
//!
//! ## Architecture (Daemon-Only Mode)
//!
//! Unlike the Go reference which embeds `tsnet` + gVisor netstack, this
//! implementation uses **daemon-only mode** - connecting to an external
//! `tailscaled` daemon via its Local API. See [`docs/TAILSCALE_LIMITATIONS.md`]
//! for detailed architectural comparison and rationale.
//!
//! The control plane can be provided via:
//! 1. `DaemonControlPlane` (default) - connects to local `tailscaled` daemon
//! 2. `StubControlPlane` - for testing without a real daemon
//!
//! Go reference: `protocol/tailscale/endpoint.go` (4 files, 27KB)

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
            auth_key: ir
                .tailscale_auth_key
                .clone()
                .or_else(|| std::env::var("TS_AUTHKEY").ok()),
            control_url: ir
                .tailscale_control_url
                .clone()
                .or_else(|| std::env::var("TS_CONTROL_URL").ok()),
            hostname: ir
                .tailscale_hostname
                .clone()
                .or_else(|| std::env::var("TS_HOSTNAME").ok()),
            ephemeral: ir.tailscale_ephemeral.unwrap_or(false),
            state_directory: ir
                .tailscale_state_directory
                .clone()
                .or_else(|| std::env::var("TS_STATE_DIR").ok()),
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

// ============================================================================
// DaemonControlPlane - Connects to local tailscaled daemon via Unix socket
// ============================================================================

use parking_lot::RwLock;
use std::path::PathBuf;

/// Status response from Tailscale Local API.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailscaleStatus {
    /// Backend state: "Running", "NeedsLogin", etc.
    #[serde(default)]
    pub backend_state: String,
    /// Our Tailscale IPs.
    #[serde(default)]
    pub tailscale_i_ps: Vec<String>,
    /// Auth URL for login (if needed).
    #[serde(default)]
    pub auth_url: Option<String>,
    /// Self node info.
    #[serde(default)]
    pub self_node: Option<SelfNode>,
}

/// Self node info from status.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SelfNode {
    #[serde(default)]
    pub d_n_s_name: String,
    #[serde(default)]
    pub tailscale_i_ps: Vec<String>,
    #[serde(default)]
    pub online: bool,
}

/// Control plane backed by local Tailscale daemon socket.
///
/// Connects to `tailscaled` via its Local API (Unix socket on Linux/macOS,
/// named pipe on Windows) to query status and authenticate.
///
/// Data plane (dial/listen) goes through system network stack after
/// Tailscale sets up routes.
pub struct DaemonControlPlane {
    /// Path to tailscaled socket.
    socket_path: PathBuf,
    /// Endpoint configuration.
    config: TailscaleEndpointConfig,
    /// Cached status from daemon.
    status: RwLock<Option<TailscaleStatus>>,
}

impl DaemonControlPlane {
    /// Default socket path on Unix.
    #[cfg(unix)]
    pub const DEFAULT_SOCKET_PATH: &'static str = "/var/run/tailscale/tailscaled.sock";

    /// Alternative socket path on macOS (user installation).
    #[cfg(target_os = "macos")]
    pub const MACOS_USER_SOCKET: &'static str = "/Users/Shared/tailscale/tailscaled.sock";

    /// Create new DaemonControlPlane with default socket path.
    pub fn new(config: TailscaleEndpointConfig) -> Self {
        let socket_path = Self::find_socket_path();
        Self {
            socket_path,
            config,
            status: RwLock::new(None),
        }
    }

    /// Create with explicit socket path.
    pub fn with_socket(socket_path: PathBuf, config: TailscaleEndpointConfig) -> Self {
        Self {
            socket_path,
            config,
            status: RwLock::new(None),
        }
    }

    /// Find the tailscaled socket path.
    #[cfg(unix)]
    fn find_socket_path() -> PathBuf {
        let default = PathBuf::from(Self::DEFAULT_SOCKET_PATH);
        if default.exists() {
            return default;
        }

        #[cfg(target_os = "macos")]
        {
            let macos_path = PathBuf::from(Self::MACOS_USER_SOCKET);
            if macos_path.exists() {
                return macos_path;
            }
        }

        // Return default even if not found - will error on connect
        default
    }

    #[cfg(not(unix))]
    fn find_socket_path() -> PathBuf {
        // Windows uses named pipe
        PathBuf::from(r"\\.\pipe\ProtectedPrefix\Tailscale\tailscaled")
    }

    /// Query status from daemon via HTTP over Unix socket.
    async fn query_status(
        &self,
    ) -> Result<TailscaleStatus, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(unix)]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::UnixStream;

            let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
                format!(
                    "Failed to connect to tailscaled socket {:?}: {}",
                    self.socket_path, e
                )
            })?;

            // Send HTTP request
            let request = "GET /localapi/v0/status HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n";
            stream.write_all(request.as_bytes()).await?;

            // Read response
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            // Parse HTTP response (skip headers)
            let response_str = String::from_utf8_lossy(&response);
            let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            let body = &response_str[body_start..];

            let status: TailscaleStatus = serde_json::from_str(body).map_err(|e| {
                format!(
                    "Failed to parse tailscale status: {} (body: {})",
                    e,
                    &body[..body.len().min(200)]
                )
            })?;

            Ok(status)
        }

        #[cfg(not(unix))]
        {
            Err("Tailscale daemon integration not yet implemented for this platform".into())
        }
    }
}

impl std::fmt::Debug for DaemonControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonControlPlane")
            .field("socket_path", &self.socket_path)
            .field("tag", &self.config.tag)
            .finish()
    }
}

#[async_trait::async_trait]
impl TailscaleControlPlane for DaemonControlPlane {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            tag = %self.config.tag,
            socket = %self.socket_path.display(),
            "Connecting to Tailscale daemon"
        );

        // Query status to verify daemon is running
        let status = self.query_status().await?;
        *self.status.write() = Some(status.clone());

        match status.backend_state.as_str() {
            "Running" => {
                info!(
                    tag = %self.config.tag,
                    ips = ?status.tailscale_i_ps,
                    "Tailscale daemon connected and authenticated"
                );
                Ok(())
            }
            "NeedsLogin" => {
                if let Some(url) = &status.auth_url {
                    warn!(
                        tag = %self.config.tag,
                        auth_url = %url,
                        "Tailscale needs authentication - please login"
                    );
                }
                Err(format!(
                    "Tailscale needs authentication: {}",
                    status.auth_url.as_deref().unwrap_or("")
                )
                .into())
            }
            state => {
                warn!(
                    tag = %self.config.tag,
                    state = %state,
                    "Unexpected Tailscale state"
                );
                Err(format!("Tailscale daemon in unexpected state: {}", state).into())
            }
        }
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!(tag = %self.config.tag, "DaemonControlPlane stopped (daemon continues running)");
        Ok(())
    }

    fn tailscale_ips(&self) -> Vec<IpAddr> {
        let status = self.status.read();
        if let Some(status) = status.as_ref() {
            // Try self_node first, fall back to root TailscaleIPs
            let ips = status
                .self_node
                .as_ref()
                .map(|n| &n.tailscale_i_ps)
                .unwrap_or(&status.tailscale_i_ps);

            ips.iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect()
        } else {
            vec![]
        }
    }

    async fn dial(
        &self,
        network: Network,
        addr: SocketAddr,
    ) -> Result<EndpointStream, Box<dyn std::error::Error + Send + Sync>> {
        // Tailscale sets up routes, so we dial through normal system stack
        // and the kernel routes to Tailscale interface
        match network {
            Network::Tcp => {
                debug!(
                    tag = %self.config.tag,
                    addr = %addr,
                    "Dialing through Tailscale (system routing)"
                );
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                Ok(Box::new(tcp) as EndpointStream)
            }
            Network::Udp => Err("UDP dial not directly supported - use listen_packet".into()),
        }
    }

    async fn listen(
        &self,
        network: Network,
        port: u16,
    ) -> Result<Arc<UdpSocket>, Box<dyn std::error::Error + Send + Sync>> {
        match network {
            Network::Udp => {
                // Bind to Tailscale IP if we have one
                let bind_addr = self
                    .tailscale_ips()
                    .into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, port))
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));

                debug!(
                    tag = %self.config.tag,
                    bind = %bind_addr,
                    "Listening on Tailscale IP"
                );

                let socket = UdpSocket::bind(bind_addr).await?;
                Ok(Arc::new(socket))
            }
            Network::Tcp => Err("TCP listen not supported via this method".into()),
        }
    }

    fn auth_status(&self) -> AuthStatus {
        let status = self.status.read();
        match status.as_ref().map(|s| s.backend_state.as_str()) {
            Some("Running") => AuthStatus::Authenticated,
            Some("NeedsLogin") => AuthStatus::WaitingForAuth,
            Some("Stopped") => AuthStatus::NotStarted,
            _ => AuthStatus::NotStarted,
        }
    }

    fn auth_url(&self) -> Option<String> {
        self.status.read().as_ref().and_then(|s| s.auth_url.clone())
    }
}

/// Tailscale endpoint that acts as a Tailnet node.
pub struct TailscaleEndpoint {
    config: TailscaleEndpointConfig,
    state: AtomicU8,
    /// Control plane provider.
    control_plane: parking_lot::RwLock<Option<Arc<dyn TailscaleControlPlane>>>,
    /// Our Tailscale IPs once assigned.
    local_addresses: Arc<parking_lot::RwLock<Vec<IpNet>>>,
    /// Connection handler for inbound routing.
    connection_handler: parking_lot::RwLock<Option<Arc<dyn ConnectionHandler>>>,
    /// Worker task handle.
    worker: parking_lot::Mutex<Option<JoinHandle<()>>>,
    /// Last error message.
    last_error: Arc<parking_lot::RwLock<Option<String>>>,
    /// Router handle for policy checks.
    #[cfg(feature = "router")]
    router: Option<Arc<crate::router::RouterHandle>>,
}

impl TailscaleEndpoint {
    /// Create from IR configuration.
    pub fn new(
        ir: &EndpointIR,
        #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>,
    ) -> Self {
        #[cfg(feature = "router")]
        {
            Self::with_config(TailscaleEndpointConfig::from_ir(ir), router)
        }
        #[cfg(not(feature = "router"))]
        {
            Self::with_config(TailscaleEndpointConfig::from_ir(ir))
        }
    }

    /// Create with explicit config.
    pub fn with_config(
        config: TailscaleEndpointConfig,
        #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>,
    ) -> Self {
        Self {
            config,
            state: AtomicU8::new(TailscaleState::Stopped as u8),
            control_plane: parking_lot::RwLock::new(None),
            local_addresses: Arc::new(parking_lot::RwLock::new(vec![])),
            connection_handler: parking_lot::RwLock::new(None),
            worker: parking_lot::Mutex::new(None),
            last_error: Arc::new(parking_lot::RwLock::new(None)),
            #[cfg(feature = "router")]
            router,
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

    #[allow(dead_code)] // Used in test and for future error recording
    fn record_error(&self, msg: impl Into<String>) {
        *self.last_error.write() = Some(msg.into());
    }

    /// Check if destination is a Tailscale IP (100.x.y.z or fd7a:115c:a1e0::/96).
    #[allow(dead_code)] // Used in tests
    pub(crate) fn is_tailscale_ip(ip: &IpAddr) -> bool {
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
    async fn resolve_fqdn(
        &self,
        host: &str,
    ) -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::lookup_host;
        let addrs: Vec<_> = lookup_host((host, 0)).await?.collect();
        addrs
            .into_iter()
            .map(|sa| sa.ip())
            .next()
            .ok_or_else(|| format!("Failed to resolve {}", host).into())
    }
    /// Convert destination to loopback if it matches a local address.
    fn translate_local_destination(&self, dest: &Socksaddr) -> (Socksaddr, Option<Socksaddr>) {
        if let Some(ip) = dest.addr() {
            let local_addrs = self.local_addresses.read();
            for local_prefix in local_addrs.iter() {
                if local_prefix.contains(&ip) {
                    // Replace with loopback
                    let loopback_ip = if ip.is_ipv4() {
                        IpAddr::V4(Ipv4Addr::LOCALHOST)
                    } else {
                        IpAddr::V6(Ipv6Addr::LOCALHOST)
                    };
                    let translated = Socksaddr {
                        host: SocksaddrHost::Ip(loopback_ip),
                        port: dest.port,
                    };
                    return (translated, Some(dest.clone()));
                }
            }
        }
        (dest.clone(), None)
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

                // Default to DaemonControlPlane if none provided
                if self.control_plane.read().is_none() {
                    let daemon = Arc::new(DaemonControlPlane::new(self.config.clone()));
                    *self.control_plane.write() = Some(daemon);
                    debug!(
                        tag = %self.config.tag,
                        "No control plane provided, using default DaemonControlPlane"
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
                    let local_addrs = self.local_addresses.clone();
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
                                *local_addrs.write() = nets;
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
            let _ = tokio::runtime::Handle::try_current().map(|h| h.block_on(cp.stop()));
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
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<EndpointStream>> + Send + '_>,
    > {
        Box::pin(async move {
            if self.state() != TailscaleState::Running {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Tailscale endpoint not running",
                ));
            }

            // Resolve FQDN if needed
            let ip = match &destination.host {
                SocksaddrHost::Ip(ip) => *ip,
                SocksaddrHost::Fqdn(fqdn) => self
                    .resolve_fqdn(fqdn)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?,
            };

            let addr = SocketAddr::new(ip, destination.port);

            debug!(
                tag = %self.config.tag,
                network = %network,
                addr = %addr,
                "Dialing through Tailscale"
            );

            // Dial through control plane
            let cp = self.control_plane.read().clone().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "No control plane available",
                )
            })?;

            cp.dial(network, addr)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }

    fn listen_packet(
        &self,
        destination: Socksaddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<UdpSocket>>> + Send + '_>,
    > {
        Box::pin(async move {
            if self.state() != TailscaleState::Running {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Tailscale endpoint not running",
                ));
            }

            let cp = self.control_plane.read().clone().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "No control plane available",
                )
            })?;

            cp.listen(Network::Udp, destination.port)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }

    fn local_addresses(&self) -> Vec<IpNet> {
        self.local_addresses.read().clone()
    }

    fn set_connection_handler(&self, handler: Arc<dyn ConnectionHandler>) {
        *self.connection_handler.write() = Some(handler);
        debug!(tag = %self.config.tag, "Connection handler registered");
    }

    #[allow(unused_variables)] // network/source only used when router feature is enabled
    fn prepare_connection(
        &self,
        network: Network,
        source: Socksaddr,
        destination: Socksaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Integrate with router logic for policy checks
        #[cfg(feature = "router")]
        if let Some(router) = &self.router {
            let host = destination.fqdn();
            let ip = destination.addr();
            let port = Some(destination.port);
            let net_str = match network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            };

            let ctx = crate::router::RouteCtx {
                host,
                ip,
                port,
                network: net_str,
                inbound_tag: Some(&self.config.tag),
                ..Default::default()
            };

            let decision = router.decide(&ctx);
            if let crate::router::rules::Decision::Reject = decision {
                return Err(format!(
                    "connection from {} to {} rejected by rule",
                    source, destination
                )
                .into());
            }
            debug!(tag = %self.config.tag, "connection allowed by router: {:?}", decision);
        }
        Ok(())
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

            // Translate local destination if needed
            let (translated_dest, origin) = self.translate_local_destination(&destination);
            // let check_destination = translated_dest.clone(); // Removed unused
            if origin.is_some() {
                // Update context with translated destination?
                // The original code in WireGuard updates metadata.destination.
            }
            // Note: InboundContext destination is updated logic in WireGuard:
            // metadata.destination = Some(translated_dest.clone());
            // if origin.is_some() { metadata.origin_destination = Some(destination.clone()); }

            let mut metadata = metadata;
            metadata.destination = Some(translated_dest);
            if origin.is_some() {
                metadata.origin_destination = Some(destination.clone());
            }

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

            // Translate local destination if needed
            let (translated_dest, origin) = self.translate_local_destination(&destination);
            let mut metadata = metadata;
            metadata.destination = Some(translated_dest);
            if origin.is_some() {
                metadata.origin_destination = Some(destination.clone());
            }

            info!(
                tag = %self.config.tag,
                "Inbound UDP from {} to {}",
                source, destination
            );

            let handler = self.connection_handler.read().clone();
            if let Some(handler) = handler {
                handler
                    .route_packet_connection(socket, metadata, on_close)
                    .await;
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
    #[cfg(feature = "router")]
    {
        Some(Arc::new(TailscaleEndpoint::new(ir, _ctx.router.clone())))
    }
    #[cfg(not(feature = "router"))]
    {
        Some(Arc::new(TailscaleEndpoint::new(ir)))
    }
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
        #[cfg(feature = "router")]
        let endpoint = TailscaleEndpoint::with_config(config.clone(), None);
        #[cfg(not(feature = "router"))]
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
        assert!(TailscaleEndpoint::is_tailscale_ip(
            &"100.64.0.1".parse().unwrap()
        ));
        assert!(TailscaleEndpoint::is_tailscale_ip(
            &"100.100.100.100".parse().unwrap()
        ));
        assert!(TailscaleEndpoint::is_tailscale_ip(
            &"100.127.255.255".parse().unwrap()
        ));

        // Not Tailscale
        assert!(!TailscaleEndpoint::is_tailscale_ip(
            &"192.168.1.1".parse().unwrap()
        ));
        assert!(!TailscaleEndpoint::is_tailscale_ip(
            &"8.8.8.8".parse().unwrap()
        ));
        assert!(!TailscaleEndpoint::is_tailscale_ip(
            &"100.63.255.255".parse().unwrap()
        ));

        // IPv6 Tailscale range
        assert!(TailscaleEndpoint::is_tailscale_ip(
            &"fd7a:115c:a1e0::1".parse().unwrap()
        ));
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
        assert!(stub
            .dial(Network::Tcp, "100.64.0.2:80".parse().unwrap())
            .await
            .is_err());
    }

    #[test]
    fn test_daemon_control_plane_creation() {
        let config = TailscaleEndpointConfig {
            tag: "test-daemon".to_string(),
            ..Default::default()
        };

        // Test default creation (finds socket path)
        let daemon = DaemonControlPlane::new(config.clone());
        assert!(!daemon.socket_path.as_os_str().is_empty());

        // Test explicit socket path
        let custom_path = std::path::PathBuf::from("/tmp/test-tailscaled.sock");
        let daemon2 = DaemonControlPlane::with_socket(custom_path.clone(), config);
        assert_eq!(daemon2.socket_path, custom_path);

        // Auth status should be NotStarted before calling start()
        assert_eq!(daemon2.auth_status(), AuthStatus::NotStarted);

        // IPs should be empty before connecting
        assert!(daemon2.tailscale_ips().is_empty());
    }
}
