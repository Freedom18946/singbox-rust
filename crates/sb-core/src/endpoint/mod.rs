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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
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

#[derive(Debug)]
pub(crate) struct EndpointUdpSocketPacketConn {
    socket: Arc<UdpSocket>,
    idle_timeout: Duration,
    deadlines: Mutex<(Option<Instant>, Option<Instant>)>,
    closed: AtomicBool,
}

impl EndpointUdpSocketPacketConn {
    pub(crate) fn new(socket: Arc<UdpSocket>, idle_timeout: Duration) -> Self {
        Self {
            socket,
            idle_timeout,
            deadlines: Mutex::new((None, None)),
            closed: AtomicBool::new(false),
        }
    }

    fn operation_timeout(&self, read: bool) -> (Instant, Duration) {
        let now = Instant::now();
        let deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let explicit = if read { deadlines.0 } else { deadlines.1 };
        let duration = explicit
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or(self.idle_timeout);
        (now + duration, duration)
    }

    fn ensure_open(&self) -> Result<(), sb_types::CoreError> {
        if self.closed.load(Ordering::Acquire) {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Reset,
                "packet connection closed",
            ))
        } else {
            Ok(())
        }
    }
}

async fn run_endpoint_packet_operation<T, F>(
    deadline: Instant,
    duration: Duration,
    operation: &'static str,
    future: F,
) -> Result<T, sb_types::CoreError>
where
    F: std::future::Future<Output = Result<T, sb_types::CoreError>>,
{
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| sb_types::CoreError::timeout(operation, duration))?
}

impl sb_types::PacketConn for EndpointUdpSocketPacketConn {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a sb_types::TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            self.ensure_open()?;
            let (deadline, duration) = self.operation_timeout(false);
            let operation = async {
                let address = match destination {
                    sb_types::TargetAddr::Socket(address) => *address,
                    sb_types::TargetAddr::Domain(host, port) => {
                        tokio::net::lookup_host((host.as_str(), *port))
                            .await
                            .map_err(|error| sb_types::CoreError::dns(error.to_string()))?
                            .next()
                            .ok_or_else(|| {
                                sb_types::CoreError::dns("no endpoint UDP address resolved")
                            })?
                    }
                };
                self.socket
                    .send_to(data, address)
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))
            };
            run_endpoint_packet_operation(deadline, duration, "packet-send", operation).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            self.ensure_open()?;
            let (deadline, duration) = self.operation_timeout(true);
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.socket.recv_from(buffer),
            )
            .await
            .map_err(|_| sb_types::CoreError::timeout("packet-recv", duration))?
            .map(|(size, source)| (size, sb_types::TargetAddr::Socket(source)))
            .map_err(|error| sb_types::CoreError::io(error.to_string()))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        self.closed.store(true, Ordering::Release);
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<sb_types::TargetAddr> {
        self.socket
            .local_addr()
            .ok()
            .map(sb_types::TargetAddr::Socket)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        *self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = (deadline, deadline);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0 = deadline;
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .1 = deadline;
        Ok(())
    }
}

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
    /// Returns the canonical packet connection owned by this endpoint.
    fn listen_packet(
        &self,
        _session: &sb_types::Session,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<sb_types::BoxedPacketConn>> + Send + '_>,
    > {
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

#[cfg(feature = "router")]
pub mod handler;
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

    /// Get an endpoint as the canonical outbound (Go parity: Endpoint as Outbound).
    /// 获取端点作为出站连接器（Go 对等：端点作为出站）。
    pub async fn as_outbound_connector(&self, tag: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        let ep = self.get(tag).await?;
        Some(Arc::new(EndpointAsOutbound::new(tag.to_string(), ep)))
    }
}

/// Wrapper to expose an Endpoint as the canonical outbound (Go parity: endpoint as outbound).
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

impl sb_types::Outbound for EndpointAsOutbound {
    fn r#type(&self) -> &str {
        self.endpoint.endpoint_type()
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(self.tag.clone())
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
    }

    fn dial<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;

            let destination = match &session.target {
                sb_types::TargetAddr::Socket(address) => Socksaddr::from_socket_addr(*address),
                sb_types::TargetAddr::Domain(host, port) => Socksaddr::from_fqdn(host, *port),
            };
            let stream = self
                .endpoint
                .dial_context(Network::Tcp, destination)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }

    fn listen_packet<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            self.endpoint
                .listen_packet(session)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))
        })
    }
}

impl Default for EndpointManager {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use super::*;
    use sb_types::Outbound;
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

    #[derive(Clone, Debug)]
    struct RecordedDial {
        network: Network,
        destination: Socksaddr,
    }

    #[derive(Debug)]
    struct RecordingEndpoint {
        tag: String,
        calls: Arc<parking_lot::Mutex<Vec<RecordedDial>>>,
    }

    impl RecordingEndpoint {
        fn new(tag: &str) -> (Self, Arc<parking_lot::Mutex<Vec<RecordedDial>>>) {
            let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
            (
                Self {
                    tag: tag.to_string(),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Endpoint for RecordingEndpoint {
        fn endpoint_type(&self) -> &str {
            "recording"
        }

        fn tag(&self) -> &str {
            &self.tag
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

        fn dial_context(
            &self,
            network: Network,
            destination: Socksaddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = io::Result<EndpointStream>> + Send + '_>,
        > {
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.lock().push(RecordedDial {
                    network,
                    destination,
                });
                let (stream, _peer) = tokio::io::duplex(64);
                let stream: EndpointStream = Box::new(stream);
                Ok(stream)
            })
        }
    }

    #[tokio::test]
    async fn endpoint_as_outbound_dial_delegates_to_endpoint_context() {
        let (endpoint, calls) = RecordingEndpoint::new("wg-ep");
        let connector = EndpointAsOutbound::new("wg-ep".to_string(), Arc::new(endpoint));

        let _stream = connector
            .dial(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::from_host_port("198.51.100.10", 443),
            ))
            .await
            .expect("canonical dial should expose endpoint streams");
        assert_eq!(calls.lock().len(), 1);
    }

    #[cfg(feature = "v2ray_transport")]
    #[tokio::test]
    async fn endpoint_as_outbound_canonical_dial_delegates_ip_to_dial_context() {
        let (endpoint, calls) = RecordingEndpoint::new("wg-ep");
        let connector = EndpointAsOutbound::new("wg-ep".to_string(), Arc::new(endpoint));

        let _stream = connector
            .dial(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::from_host_port("198.51.100.10", 443),
            ))
            .await
            .expect("canonical dial should expose endpoint dial_context streams");

        let calls = calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].network, Network::Tcp);
        assert_eq!(calls[0].destination.port, 443);
        assert_eq!(
            calls[0]
                .destination
                .addr()
                .map(|ip| ip.to_string())
                .as_deref(),
            Some("198.51.100.10")
        );
    }

    #[cfg(feature = "v2ray_transport")]
    #[tokio::test]
    async fn endpoint_as_outbound_canonical_dial_delegates_domain_to_dial_context() {
        let (endpoint, calls) = RecordingEndpoint::new("wg-ep");
        let connector = EndpointAsOutbound::new("wg-ep".to_string(), Arc::new(endpoint));

        let _stream = connector
            .dial(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::domain("example.test", 8443),
            ))
            .await
            .expect("canonical dial should pass domains through as FQDN destinations");

        let calls = calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].network, Network::Tcp);
        assert_eq!(calls[0].destination.port, 8443);
        assert_eq!(calls[0].destination.fqdn(), Some("example.test"));
    }

    #[tokio::test]
    async fn endpoint_as_outbound_delegates_canonical_packet_connection() {
        #[derive(Debug)]
        struct MockPacketConn;

        impl sb_types::PacketConn for MockPacketConn {
            fn send_to<'a>(
                &'a self,
                data: &'a [u8],
                _: &'a sb_types::TargetAddr,
            ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
                Box::pin(async move { Ok(data.len()) })
            }
            fn recv_from<'a>(
                &'a self,
                _: &'a mut [u8],
            ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>>
            {
                Box::pin(async {
                    Ok((
                        0,
                        sb_types::TargetAddr::socket("127.0.0.1:1".parse().unwrap()),
                    ))
                })
            }
            fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
                Box::pin(async { Ok(()) })
            }
            fn local_addr(&self) -> Option<sb_types::TargetAddr> {
                None
            }
            fn set_deadline(&self, _: Option<Instant>) -> Result<(), sb_types::CoreError> {
                Ok(())
            }
            fn set_read_deadline(&self, _: Option<Instant>) -> Result<(), sb_types::CoreError> {
                Ok(())
            }
            fn set_write_deadline(&self, _: Option<Instant>) -> Result<(), sb_types::CoreError> {
                Ok(())
            }
        }

        #[derive(Debug)]
        struct UdpEndpoint {
            opened: Arc<AtomicUsize>,
        }

        impl Endpoint for UdpEndpoint {
            fn endpoint_type(&self) -> &str {
                "udp"
            }

            fn tag(&self) -> &str {
                "udp-ep"
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

            fn listen_packet(
                &self,
                _session: &sb_types::Session,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = io::Result<sb_types::BoxedPacketConn>>
                        + Send
                        + '_,
                >,
            > {
                self.opened.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(Box::new(MockPacketConn) as sb_types::BoxedPacketConn) })
            }
        }

        let opened = Arc::new(AtomicUsize::new(0));
        let endpoint = Arc::new(UdpEndpoint {
            opened: opened.clone(),
        });
        let outbound = EndpointAsOutbound::new("udp-ep".to_string(), endpoint);
        let session = outbound
            .listen_packet(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::domain("127.0.0.1", 53),
            ))
            .await
            .expect("udp endpoint session");

        session
            .send_to(b"x", &sb_types::TargetAddr::domain("127.0.0.1", 53))
            .await
            .unwrap();
        assert_eq!(opened.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn endpoint_udp_packet_timeout_uses_idle_then_explicit_deadline() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let packet = EndpointUdpSocketPacketConn::new(socket, Duration::from_millis(30));
        let mut buffer = [0_u8; 1];

        let error = sb_types::PacketConn::recv_from(&packet, &mut buffer)
            .await
            .expect_err("idle timeout");
        assert!(
            matches!(error, sb_types::CoreError::Timeout { duration, .. } if duration == Duration::from_millis(30))
        );

        sb_types::PacketConn::set_read_deadline(
            &packet,
            Some(Instant::now() + Duration::from_millis(10)),
        )
        .unwrap();
        let error = sb_types::PacketConn::recv_from(&packet, &mut buffer)
            .await
            .expect_err("explicit timeout");
        assert!(
            matches!(error, sb_types::CoreError::Timeout { duration, .. } if duration <= Duration::from_millis(10) && duration < Duration::from_millis(30))
        );
    }

    #[tokio::test]
    async fn endpoint_udp_packet_close_rejects_later_io() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let packet = EndpointUdpSocketPacketConn::new(socket, Duration::from_secs(1));
        sb_types::PacketConn::close(&packet).await.unwrap();
        let error = sb_types::PacketConn::send_to(
            &packet,
            b"x",
            &sb_types::TargetAddr::socket("127.0.0.1:9".parse().unwrap()),
        )
        .await
        .expect_err("closed packet connection");
        assert!(matches!(
            error,
            sb_types::CoreError::Connect {
                kind: sb_types::ConnectErrorKind::Reset,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn endpoint_udp_timeout_wraps_entire_async_operation() {
        let duration = Duration::from_millis(5);
        let error = run_endpoint_packet_operation(
            Instant::now() + duration,
            duration,
            "packet-send",
            std::future::pending::<Result<(), sb_types::CoreError>>(),
        )
        .await
        .expect_err("pending resolution/send operation must time out");
        assert!(matches!(
            error,
            sb_types::CoreError::Timeout {
                operation,
                duration: reported,
            } if operation == "packet-send" && reported == duration
        ));
    }
}
