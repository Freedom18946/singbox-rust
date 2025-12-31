//! VPN endpoint management (WireGuard, Tailscale, etc.)
//!
//! Endpoints provide VPN tunnel functionality similar to outbounds but with
//! dedicated lifecycle management and integration with the routing system.

pub use crate::service::StartStage;
use sb_config::ir::{EndpointIR, EndpointType};
use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Tcp => write!(f, "tcp"),
            Network::Udp => write!(f, "udp"),
        }
    }
}

/// Socket address that can be either an IP address or FQDN with port.
#[derive(Debug, Clone)]
pub struct Socksaddr {
    /// The host (IP address or domain name).
    pub host: SocksaddrHost,
    /// The port number.
    pub port: u16,
}

/// Host component of a Socksaddr.
#[derive(Debug, Clone)]
pub enum SocksaddrHost {
    /// An IP address (v4 or v6).
    Ip(IpAddr),
    /// A fully qualified domain name.
    Fqdn(String),
}

impl Socksaddr {
    /// Create a new Socksaddr from an IP address and port.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self {
            host: SocksaddrHost::Ip(addr.ip()),
            port: addr.port(),
        }
    }

    /// Create a new Socksaddr from an FQDN and port.
    pub fn from_fqdn(fqdn: impl Into<String>, port: u16) -> Self {
        Self {
            host: SocksaddrHost::Fqdn(fqdn.into()),
            port,
        }
    }

    /// Check if this address is an FQDN.
    pub fn is_fqdn(&self) -> bool {
        matches!(self.host, SocksaddrHost::Fqdn(_))
    }

    /// Get the FQDN if this is a domain-based address.
    pub fn fqdn(&self) -> Option<&str> {
        match &self.host {
            SocksaddrHost::Fqdn(s) => Some(s),
            SocksaddrHost::Ip(_) => None,
        }
    }

    /// Get the IP address if this is an IP-based address.
    pub fn addr(&self) -> Option<IpAddr> {
        match &self.host {
            SocksaddrHost::Ip(ip) => Some(*ip),
            SocksaddrHost::Fqdn(_) => None,
        }
    }

    /// Convert to a SocketAddr (only valid for IP-based addresses).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl std::fmt::Display for Socksaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            SocksaddrHost::Ip(ip) => write!(f, "{}:{}", ip, self.port),
            SocksaddrHost::Fqdn(fqdn) => write!(f, "{}:{}", fqdn, self.port),
        }
    }
}

impl From<SocketAddr> for Socksaddr {
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(addr)
    }
}

/// A boxed async stream for TCP connections through endpoints.
/// This is re-exported from sb_transport for compatibility.
pub type EndpointStream = sb_transport::IoStream;

/// Inbound connection context for routing.
#[derive(Debug, Clone, Default)]
pub struct InboundContext {
    /// The inbound endpoint tag.
    pub inbound: String,
    /// The inbound endpoint type.
    pub inbound_type: String,
    /// Network protocol.
    pub network: Option<Network>,
    /// Source address.
    pub source: Option<Socksaddr>,
    /// Destination address.
    pub destination: Option<Socksaddr>,
    /// Original destination (before NAT).
    pub origin_destination: Option<Socksaddr>,
}

/// Close handler function type for connection cleanup.
pub type CloseHandler = Box<dyn FnOnce() + Send + 'static>;

/// Trait for routing inbound connections from endpoints.
///
/// This trait is implemented by the router/connection manager to handle
/// connections that arrive through VPN endpoints (WireGuard, Tailscale, etc.).
/// It mirrors Go's `adapter.Router.RouteConnectionEx` and `RoutePacketConnectionEx`.
#[async_trait::async_trait]
pub trait ConnectionHandler: Send + Sync {
    /// Route a TCP connection from an endpoint.
    ///
    /// Called when an inbound TCP connection arrives through a VPN tunnel.
    /// The handler should match the connection against routing rules and
    /// forward it to the appropriate outbound.
    async fn route_connection(
        &self,
        conn: EndpointStream,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    );

    /// Route a UDP packet connection from an endpoint.
    ///
    /// Called when inbound UDP packets arrive through a VPN tunnel.
    /// The handler should match the connection against routing rules and
    /// forward it to the appropriate outbound.
    async fn route_packet_connection(
        &self,
        socket: Arc<UdpSocket>,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    );
}

/// A no-op connection handler for testing or when routing is disabled.
pub struct NoOpConnectionHandler;

#[async_trait::async_trait]
impl ConnectionHandler for NoOpConnectionHandler {
    async fn route_connection(
        &self,
        _conn: EndpointStream,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    ) {
        tracing::debug!(
            inbound = %metadata.inbound,
            "NoOpConnectionHandler: dropping connection"
        );
        if let Some(handler) = on_close {
            handler();
        }
    }

    async fn route_packet_connection(
        &self,
        _socket: Arc<UdpSocket>,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    ) {
        tracing::debug!(
            inbound = %metadata.inbound,
            "NoOpConnectionHandler: dropping packet connection"
        );
        if let Some(handler) = on_close {
            handler();
        }
    }
}

/// Endpoint trait for VPN tunnel management.
///
/// Endpoints (like WireGuard/Tailscale) implement this trait to provide
/// VPN functionality with lifecycle management.
pub trait Endpoint: Send + Sync + Any {
    /// Return the endpoint type (e.g., "wireguard", "tailscale").
    fn endpoint_type(&self) -> &str;

    /// Return the endpoint tag/identifier.
    fn tag(&self) -> &str;

    /// Start the endpoint at a specific lifecycle stage.
    ///
    /// # Errors
    /// Returns an error if the endpoint fails to start.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up the endpoint.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    // =========================================================================
    // Data plane methods (optional, default implementations return errors)
    // =========================================================================

    /// Dial a connection through this endpoint.
    ///
    /// This is the primary method for outbound connections through the VPN tunnel.
    /// The implementation should handle DNS resolution for FQDNs.
    fn dial_context(
        &self,
        _network: Network,
        _destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<EndpointStream>> + Send + '_>>
    {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dial_context not implemented for this endpoint",
            ))
        })
    }

    /// Listen for UDP packets through this endpoint.
    ///
    /// Returns a UDP socket bound to the tunnel interface.
    fn listen_packet(
        &self,
        _destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Arc<UdpSocket>>> + Send + '_>>
    {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "listen_packet not implemented for this endpoint",
            ))
        })
    }

    /// Prepare a connection for routing (pre-match hook).
    ///
    /// Called before establishing a connection to allow the router to
    /// perform pre-matching and policy checks.
    fn prepare_connection(
        &self,
        _network: Network,
        _source: Socksaddr,
        _destination: Socksaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Get the local addresses assigned to this endpoint.
    ///
    /// These are used to detect traffic destined for the local VPN interface.
    fn local_addresses(&self) -> Vec<ipnet::IpNet> {
        Vec::new()
    }

    // =========================================================================
    // Inbound connection routing methods (optional, for VPN tunnel endpoints)
    // =========================================================================

    /// Set the connection handler for routing inbound connections.
    ///
    /// This is called during endpoint initialization to provide the router
    /// callback that will handle connections arriving through the tunnel.
    fn set_connection_handler(&self, _handler: Arc<dyn ConnectionHandler>) {
        // Default: no-op. Endpoints that support inbound routing should override.
    }

    /// Handle a new TCP connection from the tunnel.
    ///
    /// This is called when an inbound TCP connection arrives through the VPN tunnel.
    /// The endpoint should prepare the metadata (translate local addresses, etc.)
    /// and then call the connection handler to route it.
    ///
    /// Mirrors Go's `NewConnectionEx`.
    fn new_connection_ex(
        &self,
        _conn: EndpointStream,
        _source: Socksaddr,
        _destination: Socksaddr,
        _on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            tracing::warn!("new_connection_ex not implemented for this endpoint");
        })
    }

    /// Handle a new UDP packet connection from the tunnel.
    ///
    /// This is called when inbound UDP packets arrive through the VPN tunnel.
    /// The endpoint should prepare the metadata and call the connection handler.
    ///
    /// Mirrors Go's `NewPacketConnectionEx`.
    fn new_packet_connection_ex(
        &self,
        _socket: Arc<UdpSocket>,
        _source: Socksaddr,
        _destination: Socksaddr,
        _on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            tracing::warn!("new_packet_connection_ex not implemented for this endpoint");
        })
    }
}

#[derive(Default)]
pub struct EndpointContext {
    /// DNS resolver for internal name resolution (prevents DNS leaks).
    pub dns: Option<Arc<dyn crate::dns::Resolver>>,
    /// Router handle for policy checks.
    #[cfg(feature = "router")]
    pub router: Option<Arc<crate::router::RouterHandle>>,
    // pub bridge: Arc<Bridge>,
}

/// Builder function signature for creating endpoints.
pub type EndpointBuilder = fn(&EndpointIR, &EndpointContext) -> Option<Arc<dyn Endpoint>>;

/// Registry for endpoint builders.
pub struct EndpointRegistry {
    builders: parking_lot::RwLock<std::collections::HashMap<EndpointType, EndpointBuilder>>,
}

impl EndpointRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builders: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register an endpoint builder for a specific endpoint type.
    ///
    /// Returns `false` if a builder for this type already exists.
    pub fn register(&self, ty: EndpointType, builder: EndpointBuilder) -> bool {
        let mut g = self.builders.write();
        if g.contains_key(&ty) {
            return false;
        }
        g.insert(ty, builder);
        true
    }

    /// Look up an endpoint builder by type.
    pub fn get(&self, ty: EndpointType) -> Option<EndpointBuilder> {
        let g = self.builders.read();
        g.get(&ty).copied()
    }

    /// Build an endpoint from configuration.
    pub fn build(&self, ir: &EndpointIR, ctx: &EndpointContext) -> Option<Arc<dyn Endpoint>> {
        let builder = self.get(ir.ty)?;
        builder(ir, ctx)
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global endpoint registry instance.
static ENDPOINT_REGISTRY: once_cell::sync::Lazy<EndpointRegistry> =
    once_cell::sync::Lazy::new(EndpointRegistry::new);

/// Register an endpoint builder globally.
///
/// Returns `false` if a builder for this type already exists.
pub fn register_endpoint(ty: EndpointType, builder: EndpointBuilder) -> bool {
    ENDPOINT_REGISTRY.register(ty, builder)
}

/// Get the global endpoint registry.
#[must_use]
pub fn endpoint_registry() -> &'static EndpointRegistry {
    &ENDPOINT_REGISTRY
}

pub mod tailscale;
pub mod wireguard;

/// Register built-in endpoints.
pub fn register_builtins() {
    #[cfg(feature = "out_wireguard")]
    register_endpoint(
        sb_config::ir::EndpointType::Wireguard,
        wireguard::build_wireguard_endpoint,
    );
    #[cfg(feature = "out_tailscale")]
    register_endpoint(
        sb_config::ir::EndpointType::Tailscale,
        tailscale::build_tailscale_endpoint,
    );
}

/// Thread-safe manager for runtime endpoints.
#[derive(Clone)]
pub struct EndpointManager {
    endpoints: Arc<parking_lot::RwLock<HashMap<String, Arc<dyn Endpoint>>>>,
    stage: Arc<parking_lot::Mutex<Option<StartStage>>>,
}

impl std::fmt::Debug for EndpointManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointManager")
            .field("endpoints", &"<dyn Endpoint>")
            .finish()
    }
}

impl EndpointManager {
    /// Create a new empty endpoint manager.
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            stage: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    /// Register an endpoint by tag.
    pub async fn add_endpoint(&self, tag: String, endpoint: Arc<dyn Endpoint>) {
        let mut guard = self.endpoints.write();
        guard.insert(tag, endpoint);
    }

    /// Fetch an endpoint by tag.
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {
        let guard = self.endpoints.read();
        guard.get(tag).cloned()
    }

    /// Remove an endpoint by tag.
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {
        let mut guard = self.endpoints.write();
        guard.remove(tag)
    }

    /// List all registered endpoint tags.
    pub async fn list_tags(&self) -> Vec<String> {
        let guard = self.endpoints.read();
        guard.keys().cloned().collect()
    }

    /// Number of registered endpoints.
    pub async fn len(&self) -> usize {
        let guard = self.endpoints.read();
        guard.len()
    }

    /// Returns true when no endpoints are registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all endpoints.
    pub async fn clear(&self) {
        let mut guard = self.endpoints.write();
        guard.clear();
    }

    /// Start all registered endpoints for a given lifecycle stage.
    ///
    /// The manager is idempotent per stage; repeated calls with the same or
    /// earlier stage are no-ops. Later stages are invoked sequentially on
    /// all endpoints in registration order.
    pub fn run_stage(
        &self,
        stage: StartStage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Fast path: if we've already processed this stage or later, skip.
        {
            let guard = self.stage.lock();
            if let Some(prev) = *guard {
                if stage_rank(prev) >= stage_rank(stage) {
                    return Ok(());
                }
            }
            // Defer updating the stage until after endpoints succeed.
            drop(guard);
        }

        let endpoints: Vec<(String, Arc<dyn Endpoint>)> = {
            let guard = self.endpoints.read();
            guard
                .iter()
                .map(|(tag, ep)| (tag.clone(), ep.clone()))
                .collect()
        };

        for (tag, ep) in endpoints {
            ep.start(stage).map_err(|e| {
                let ctx = format!("failed to start endpoint/{tag} at stage {:?}", stage);
                let err = anyhow::anyhow!("{ctx}: {e}");
                Box::<dyn std::error::Error + Send + Sync>::from(err)
            })?;
        }

        let mut guard = self.stage.lock();
        *guard = Some(stage);
        Ok(())
    }

    /// Close all registered endpoints.
    pub fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let endpoints: Vec<Arc<dyn Endpoint>> = {
            let guard = self.endpoints.read();
            guard.values().cloned().collect()
        };

        let mut first_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for ep in endpoints {
            if let Err(e) = ep.close() {
                if first_err.is_none() {
                    first_err = Some(e);
                } else {
                    tracing::warn!(
                        target: "sb_core::endpoint",
                        endpoint = ep.tag(),
                        "additional error while closing endpoint: {}",
                        e
                    );
                }
            }
        }

        *self.stage.lock() = None;
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }

    /// Replace an endpoint, closing the old one if present (Go parity: close-on-replace).
    /// 替换端点，如果存在则关闭旧的（Go 对等：替换时关闭）。
    pub async fn replace(&self, tag: String, endpoint: Arc<dyn Endpoint>) {
        // Close old endpoint if exists
        if let Some(old) = self.get(&tag).await {
            tracing::debug!(tag = %tag, "endpoint: closing old endpoint before replace");
            if let Err(e) = old.close() {
                tracing::warn!(tag = %tag, error = %e, "endpoint: failed to close old endpoint during replace");
            }
        }
        
        let mut guard = self.endpoints.write();
        guard.insert(tag, endpoint);
    }

    /// Remove with validation (Go parity: ErrInvalid if tag is empty).
    /// 带验证的移除（Go 对等：标签为空时返回 ErrInvalid）。
    pub async fn remove_with_check(&self, tag: &str) -> Result<Option<Arc<dyn Endpoint>>, String> {
        if tag.is_empty() {
            return Err("empty tag invalid".to_string());
        }
        Ok(self.remove(tag).await)
    }

    /// Get an endpoint as an OutboundConnector (Go parity: Endpoint as Outbound).
    /// 获取端点作为出站连接器（Go 对等：端点作为出站）。
    pub async fn as_outbound_connector(&self, tag: &str) -> Option<Arc<dyn crate::adapter::OutboundConnector>> {
        let ep = self.get(tag).await?;
        Some(Arc::new(EndpointAsOutbound::new(tag.to_string(), ep)))
    }
}

/// Wrapper to expose an Endpoint as an OutboundConnector (Go parity: endpoint as outbound).
/// 将端点公开为出站连接器的包装器（Go 对等：端点作为出站）。
pub struct EndpointAsOutbound {
    tag: String,
    endpoint: Arc<dyn Endpoint>,
}

impl EndpointAsOutbound {
    pub fn new(tag: String, endpoint: Arc<dyn Endpoint>) -> Self {
        Self { tag, endpoint }
    }
    
    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl std::fmt::Debug for EndpointAsOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointAsOutbound")
            .field("tag", &self.tag)
            .field("endpoint_type", &self.endpoint.endpoint_type())
            .finish()
    }
}

#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for EndpointAsOutbound {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        // Use dial_context to establish connection through the endpoint
        let dest = Socksaddr::from_fqdn(host, port);
        let _stream = self.endpoint.dial_context(Network::Tcp, dest).await?;
        
        // Extract underlying TcpStream if possible, otherwise return error
        // For now, we return an error since IoStream is not directly a TcpStream
        // Endpoints need to be refactored to return TcpStream directly or use a different API
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("endpoint {} dial_context returns IoStream, use dial_context directly", self.tag),
        ))
    }
}

impl Default for EndpointManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_endpoint_registry() {
        let registry = EndpointRegistry::new();

        // Test empty registry
        assert!(registry.get(EndpointType::Wireguard).is_none());

        // Test registration
        fn stub_builder(_ir: &EndpointIR, _ctx: &EndpointContext) -> Option<Arc<dyn Endpoint>> {
            None
        }

        assert!(registry.register(EndpointType::Wireguard, stub_builder));
        assert!(!registry.register(EndpointType::Wireguard, stub_builder)); // duplicate

        // Test retrieval
        assert!(registry.get(EndpointType::Wireguard).is_some());
    }

    #[tokio::test]
    async fn endpoint_manager_tracks_entries() {
        let mgr = EndpointManager::new();
        assert!(mgr.is_empty().await);

        struct DummyEndpoint;
        impl Endpoint for DummyEndpoint {
            fn endpoint_type(&self) -> &str {
                "dummy"
            }
            fn tag(&self) -> &str {
                "ep"
            }
            fn start(
                &self,
                _stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let ep = Arc::new(DummyEndpoint);
        mgr.add_endpoint("ep".into(), ep.clone()).await;
        assert_eq!(mgr.len().await, 1);
        assert!(mgr.get("ep").await.is_some());

        mgr.remove("ep").await;
        assert!(mgr.is_empty().await);
    }

    #[test]
    fn endpoint_manager_runs_lifecycle_stages() {
        struct CountingEndpoint {
            tag: String,
            starts: Arc<AtomicUsize>,
            closes: Arc<AtomicUsize>,
        }

        impl Endpoint for CountingEndpoint {
            fn endpoint_type(&self) -> &str {
                "counting"
            }

            fn tag(&self) -> &str {
                &self.tag
            }

            fn start(
                &self,
                _stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                self.starts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let mgr = EndpointManager::new();
        let ep = Arc::new(CountingEndpoint {
            tag: "ep".to_string(),
            starts: Arc::new(AtomicUsize::new(0)),
            closes: Arc::new(AtomicUsize::new(0)),
        });

        // register
        futures::executor::block_on(mgr.add_endpoint("ep".into(), ep.clone()));
        assert_eq!(futures::executor::block_on(mgr.len()), 1);

        // lifecycle
        mgr.run_stage(StartStage::Initialize).unwrap();
        mgr.run_stage(StartStage::Initialize).unwrap(); // idempotent
        mgr.run_stage(StartStage::Start).unwrap();

        assert_eq!(ep.starts.load(Ordering::SeqCst), 2); // Initialize + Start

        mgr.shutdown().unwrap();
        assert_eq!(ep.closes.load(Ordering::SeqCst), 1);
    }
}

fn stage_rank(stage: StartStage) -> u8 {
    match stage {
        StartStage::Initialize => 0,
        StartStage::Start => 1,
        StartStage::PostStart => 2,
        StartStage::Started => 3,
    }
}
