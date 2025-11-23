//! Adapter traits and factory interfaces.
//!
//! This module defines the core abstraction layer between configuration and runtime:
//! - [`InboundService`]: Trait for inbound protocol handlers (socks5, http, tun, etc.)
//! - [`OutboundConnector`]: Trait for outbound connection providers
//! - [`Bridge`]: Runtime container managing all inbound/outbound instances
//!
//! sb-adapters provides concrete implementations; sb-core defines interfaces and bridging logic.

use crate::endpoint::{endpoint_registry, Endpoint, EndpointContext};
use crate::service::{service_registry, Service, ServiceContext};
use sb_config::ir::Credentials;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub use crate::outbound::selector::Member as SelectorMember;
pub mod bridge;
pub mod registry;

/// Helper to parse socket address from listen and port
#[allow(dead_code)]
fn parse_socket_addr(listen: &str, port: u16) -> anyhow::Result<std::net::SocketAddr> {
    format!("{listen}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid inbound address: {e}"))
}

/// Helper to create a direct connector fallback
fn direct_connector_fallback() -> Arc<dyn OutboundConnector> {
    use crate::outbound::direct_connector::DirectConnector;
    Arc::new(DirectConnector::new())
}

/// Inbound service trait for protocol handlers (socks5/http/tun).
///
/// Implementers provide a blocking `serve()` method that internally spawns worker threads.
pub trait InboundService: Send + Sync + std::fmt::Debug + 'static {
    /// Blocking entry point to run the service (spawns internal workers).
    fn serve(&self) -> std::io::Result<()>;

    /// Request a graceful shutdown if supported by the implementation.
    /// Default implementation is a no-op for servers that don't support it.
    fn request_shutdown(&self) {
        // Default: do nothing
    }

    /// Optional: return current active connections if available.
    /// Implementers that track connection count can override this.
    fn active_connections(&self) -> Option<u64> {
        None
    }

    /// Optional: return current estimated UDP session count (for UDP-capable inbounds)
    fn udp_sessions_estimate(&self) -> Option<u64> {
        None
    }
}

/// Outbound connector trait for establishing TCP connections to targets.
///
/// Implementers handle protocol-specific handshakes (e.g., SOCKS5 upstream, HTTP CONNECT).
#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync + std::fmt::Debug + 'static {
    /// Establish a TCP connection to the specified host and port.
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream>;
}

/// UDP session for datagram-based outbound protocols (e.g. QUIC-based).
#[async_trait::async_trait]
pub trait UdpOutboundSession: Send + Sync + std::fmt::Debug + 'static {
    /// Send a UDP datagram to the specified host:port through this session
    async fn send_to(&self, data: &[u8], host: &str, port: u16) -> std::io::Result<()>;
    /// Receive the next UDP datagram from remote; returns payload and source address
    async fn recv_from(&self) -> std::io::Result<(Vec<u8>, SocketAddr)>;
}

/// Factory that creates UDP outbound sessions (per SOCKS UDP association).
pub trait UdpOutboundFactory: Send + Sync + std::fmt::Debug + 'static {
    fn open_session(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn UdpOutboundSession>>> + Send>,
    >;
}

/// Inbound construction parameters (derived from IR).
#[derive(Clone, Debug)]
pub struct InboundParam {
    /// Protocol kind: "socks", "http", "tun", etc.
    pub kind: String,
    pub listen: String,
    pub port: u16,
    pub basic_auth: Option<Credentials>,
    pub sniff: bool,
    /// Enable UDP on inbound (for protocols that support it)
    pub udp: bool,
    /// Optional fixed override destination (used by direct inbound)
    pub override_host: Option<String>,
    pub override_port: Option<u16>,
    /// Network mode: "tcp", "udp", or "tcp,udp" (both)
    pub network: Option<String>,
    /// AnyTLS users (multi-user configuration)
    pub users_anytls: Option<Vec<AnyTlsUserParam>>,
    /// Single user password (fallback)
    pub password: Option<String>,
    /// AnyTLS padding scheme rows.
    pub anytls_padding: Option<Vec<String>>,

    // TLS configuration (for inbounds that need TLS)
    /// Path to TLS certificate file (PEM format)
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file (PEM format)
    pub tls_key_path: Option<String>,
    /// Inline TLS certificate (PEM format)
    pub tls_cert_pem: Option<String>,
    /// Inline TLS private key (PEM format)
    pub tls_key_pem: Option<String>,
    /// TLS server name (SNI)
    pub tls_server_name: Option<String>,
    /// TLS ALPN protocols
    pub tls_alpn: Option<Vec<String>>,

    // Hysteria2-specific fields
    /// Hysteria2 multi-user authentication (JSON-encoded for now)
    pub users_hysteria2: Option<String>,
    /// Hysteria2 congestion control algorithm (e.g., "bbr", "cubic", "brutal")
    pub congestion_control: Option<String>,
    /// Hysteria2 Salamander obfuscation password
    pub salamander: Option<String>,
    /// Hysteria2 obfuscation key
    pub obfs: Option<String>,
    /// Hysteria2 Brutal upload limit (Mbps)
    pub brutal_up_mbps: Option<u32>,
    /// Hysteria2 Brutal download limit (Mbps)
    pub brutal_down_mbps: Option<u32>,

    // TUIC-specific fields
    /// TUIC multi-user authentication (JSON-encoded for now)
    pub users_tuic: Option<String>,

    // Hysteria v1-specific fields
    /// Hysteria v1 multi-user authentication (JSON-encoded for now)
    pub users_hysteria: Option<String>,
    /// Hysteria v1 protocol type ("udp", "wechat-video", "faketcp")
    pub hysteria_protocol: Option<String>,
    /// Hysteria v1 obfuscation password
    pub hysteria_obfs: Option<String>,
    /// Hysteria v1 upload bandwidth (Mbps)
    pub hysteria_up_mbps: Option<u32>,
    /// Hysteria v1 download bandwidth (Mbps)
    pub hysteria_down_mbps: Option<u32>,
    /// Hysteria v1 QUIC receive window for connection
    pub hysteria_recv_window_conn: Option<u64>,
    /// Hysteria v1 QUIC receive window for stream
    pub hysteria_recv_window: Option<u64>,
}

/// AnyTLS user parameters passed to the adapter layer.
#[derive(Clone, Debug)]
pub struct AnyTlsUserParam {
    pub name: Option<String>,
    pub password: String,
}

/// Outbound construction parameters (derived from IR).
#[derive(Clone, Debug)]
pub struct OutboundParam {
    /// Protocol kind: "direct", "socks", "http", "block", named protocols
    pub kind: String,
    pub name: Option<String>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub credentials: Option<Credentials>,
    pub uuid: Option<String>,
    pub token: Option<String>,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub udp_relay_mode: Option<String>,
    pub udp_over_stream: Option<bool>,
    // SSH-specific options
    pub ssh_private_key: Option<String>,
    pub ssh_private_key_passphrase: Option<String>,
    pub ssh_host_key_verification: Option<bool>,
    pub ssh_known_hosts_path: Option<String>,
}

impl Default for OutboundParam {
    fn default() -> Self {
        Self {
            kind: "direct".to_string(),
            name: None,
            server: None,
            port: None,
            credentials: None,
            uuid: None,
            token: None,
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: None,
            udp_relay_mode: None,
            udp_over_stream: None,
            ssh_private_key: None,
            ssh_private_key_passphrase: None,
            ssh_host_key_verification: None,
            ssh_known_hosts_path: None,
        }
    }
}

/// Factory interface for creating inbound services (implemented by sb-adapters).
pub trait InboundFactory: Send + Sync {
    fn create(&self, p: &InboundParam) -> Option<Arc<dyn InboundService>>;
}

/// Factory interface for creating outbound connectors (implemented by sb-adapters).
pub trait OutboundFactory: Send + Sync {
    fn create(&self, p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>>;
}

/// Runtime bridge: manages inbound services and outbound connectors.
///
/// The bridge is assembled from IR configuration and serves as the central registry
/// for all protocol handlers. It supports adapter-first fallback to scaffold implementations.
#[derive(Clone)]
pub struct Bridge {
    pub inbounds: Vec<Arc<dyn InboundService>>,
    /// Inbound protocol kinds aligned with `inbounds` indices
    pub inbound_kinds: Vec<String>,
    /// (name, kind, connector) tuples
    pub outbounds: Vec<(String, String, Arc<dyn OutboundConnector>)>,
    /// UDP outbound factories by name
    pub udp_factories: HashMap<String, Arc<dyn UdpOutboundFactory>>,
    /// Endpoints (WireGuard, Tailscale, etc.)
    pub endpoints: Vec<Arc<dyn Endpoint>>,
    /// Background services (Resolved, DERP, SSM API, etc.)
    pub services: Vec<Arc<dyn Service>>,
}

impl Bridge {
    /// Creates a new empty bridge.
    pub fn new() -> Self {
        Self {
            inbounds: vec![],
            inbound_kinds: vec![],
            outbounds: vec![],
            udp_factories: HashMap::new(),
            endpoints: vec![],
            services: vec![],
        }
    }

    /// Create bridge from IR configuration
    pub fn new_from_config(ir: &sb_config::ir::ConfigIR) -> anyhow::Result<Self> {
        let mut bridge = Self::new();

        // Build inbound services from IR
        #[cfg(feature = "scaffold")]
        {
            for inbound in &ir.inbounds {
                let inbound_service = match inbound.ty {
                    sb_config::ir::InboundType::Socks => {
                        // Create SOCKS5 inbound service
                        use crate::inbound::socks5::Socks5;

                        let addr = parse_socket_addr(&inbound.listen, inbound.port)?;
                        Arc::new(Socks5::new(addr.ip().to_string(), addr.port()))
                            as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Http => {
                        // Create HTTP CONNECT inbound service (optionally with Basic auth)
                        use crate::inbound::http::{HttpConfig, HttpInboundService};

                        let addr = parse_socket_addr(&inbound.listen, inbound.port)?;

                        let mut cfg = HttpConfig::default();
                        if let Some(creds) = &inbound.basic_auth {
                            // Enable basic auth if username/password both present
                            let user = creds
                                .username
                                .clone()
                                .or_else(|| creds.username_env.clone());
                            let pass = creds
                                .password
                                .clone()
                                .or_else(|| creds.password_env.clone());
                            if user.is_some() && pass.is_some() {
                                cfg.auth_enabled = true;
                                cfg.username = user;
                                cfg.password = pass;
                            }
                        }
                        cfg.sniff_enabled = inbound.sniff;

                        Arc::new(HttpInboundService::with_config(addr, cfg))
                            as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Mixed => {
                        use crate::inbound::mixed::MixedInbound;

                        let mut srv = MixedInbound::new(inbound.listen.clone(), inbound.port);
                        if let Some(creds) = &inbound.basic_auth {
                            let user = creds
                                .username
                                .clone()
                                .or_else(|| creds.username_env.clone());
                            let pass = creds
                                .password
                                .clone()
                                .or_else(|| creds.password_env.clone());
                            srv = srv.with_basic_auth(user, pass);
                        }
                        srv = srv.with_sniff(inbound.sniff);
                        Arc::new(srv) as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Tun => {
                        // TUN inbound service
                        use crate::inbound::tun::TunInboundService;

                        Arc::new(TunInboundService::new()) as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Direct => {
                        use crate::inbound::direct::DirectForward;

                        let addr = parse_socket_addr(&inbound.listen, inbound.port)?;
                        let host = inbound.override_host.clone().ok_or_else(|| {
                            anyhow::anyhow!(
                                "direct inbound requires override_address/override_host"
                            )
                        })?;
                        let dst_port = inbound.override_port.ok_or_else(|| {
                            anyhow::anyhow!("direct inbound requires override_port")
                        })?;
                        Arc::new(DirectForward::new(addr, host, dst_port, inbound.udp))
                            as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Redirect => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "redirect",
                            "requires Linux iptables REDIRECT and adapter integration",
                            Some(
                                "Use 'tun' inbound or SOCKS/HTTP inbound as a fallback".to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Tproxy => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "tproxy",
                            "requires Linux IP_TRANSPARENT and adapter integration",
                            Some(
                                "Use 'tun' inbound or SOCKS/HTTP inbound as a fallback".to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundService>
                    }
                    _ => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            inbound.ty.ty_str(),
                            "requires adapter implementation; build with adapters features enabled",
                            Some(
                                "Add sb-adapters adapters feature (e.g., via app feature 'adapters') to enable this inbound"
                                    .to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundService>
                    }
                };

                // Stage 1: acknowledge sniff flag without changing behavior
                if inbound.sniff {
                    tracing::info!(
                        kind = ?inbound.ty,
                        listen = %format!("{}:{}", inbound.listen, inbound.port),
                        "inbound sniff requested (stage1 noop)"
                    );
                }

                let kind = inbound.ty.ty_str();
                bridge.add_inbound_with_kind(kind, inbound_service);
            }
        }

        #[cfg(not(feature = "scaffold"))]
        {
            if !ir.inbounds.is_empty() {
                return Err(anyhow::anyhow!(
                    "Inbound services not available without scaffold feature"
                ));
            }
        }

        // Build outbound connectors from IR
        for outbound in &ir.outbounds {
            let name = outbound
                .name
                .clone()
                .unwrap_or(format!("outbound_{}", outbound.ty_str()));
            let kind = outbound.ty_str().to_string();

            let connector = match outbound.ty {
                sb_config::ir::OutboundType::Direct => direct_connector_fallback(),
                sb_config::ir::OutboundType::Block => {
                    #[cfg(feature = "scaffold")]
                    {
                        use crate::outbound::block_connector::BlockConnector;
                        Arc::new(BlockConnector::new()) as Arc<dyn OutboundConnector>
                    }
                    #[cfg(not(feature = "scaffold"))]
                    {
                        // Fall back to direct connector when scaffold is not available
                        use crate::outbound::direct_connector::DirectConnector;
                        Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                    }
                }
                sb_config::ir::OutboundType::Http => {
                    // HTTP upstream connector (scaffold implementation)
                    #[cfg(feature = "scaffold")]
                    {
                        use crate::outbound::http_upstream::HttpUp;
                        let (user, pass) = outbound
                            .credentials
                            .as_ref()
                            .map(|c| (c.username.clone(), c.password.clone()))
                            .unwrap_or((None, None));
                        let server = outbound.server.clone().unwrap_or_default();
                        let port = outbound.port.unwrap_or(8080);
                        Arc::new(HttpUp::new(server, port, user, pass))
                            as Arc<dyn OutboundConnector>
                    }
                    #[cfg(not(feature = "scaffold"))]
                    {
                        direct_connector_fallback()
                    }
                }
                sb_config::ir::OutboundType::Socks => {
                    // SOCKS5 upstream connector (scaffold implementation)
                    #[cfg(feature = "scaffold")]
                    {
                        use crate::outbound::socks_upstream::SocksUp;
                        let (user, pass) = outbound
                            .credentials
                            .as_ref()
                            .map(|c| (c.username.clone(), c.password.clone()))
                            .unwrap_or((None, None));
                        let server = outbound.server.clone().unwrap_or_default();
                        let port = outbound.port.unwrap_or(1080);
                        Arc::new(SocksUp::new(server, port, user, pass))
                            as Arc<dyn OutboundConnector>
                    }
                    #[cfg(not(feature = "scaffold"))]
                    {
                        direct_connector_fallback()
                    }
                }
                sb_config::ir::OutboundType::Vless => {
                    #[cfg(feature = "out_vless")]
                    {
                        use crate::outbound::vless::VlessConfig;
                        use crate::outbound::vless::VlessOutbound;

                        if let (Some(server), Some(port)) = (&outbound.server, outbound.port) {
                            let config = VlessConfig {
                                server: server.clone(),
                                port,
                                uuid: uuid::Uuid::new_v4(), // Would need to parse from IR
                                flow: None,
                                encryption: Some("none".to_string()),
                                ..Default::default()
                            };

                            match VlessOutbound::new(config) {
                                Ok(vless_outbound) => {
                                    Arc::new(vless_outbound) as Arc<dyn OutboundConnector>
                                }
                                Err(_) => {
                                    use crate::outbound::direct_connector::DirectConnector;
                                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                                }
                            }
                        } else {
                            use crate::outbound::direct_connector::DirectConnector;
                            Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                        }
                    }
                    #[cfg(not(feature = "out_vless"))]
                    {
                        use crate::outbound::direct_connector::DirectConnector;
                        Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                    }
                }
                sb_config::ir::OutboundType::Selector => {
                    // Selector outbound would be implemented here
                    // For now, fall back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Shadowsocks => direct_connector_fallback(),
                sb_config::ir::OutboundType::UrlTest => direct_connector_fallback(),
                sb_config::ir::OutboundType::Shadowtls => {
                    // Adapter-provided in sb-adapters; core bridge falls back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Hysteria2 => {
                    // Adapter-provided in sb-adapters; core bridge falls back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Tuic => {
                    #[cfg(feature = "out_tuic")]
                    {
                        use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};
                        let fallback = || {
                            use crate::outbound::direct_connector::DirectConnector;
                            Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                        };
                        match (
                            outbound.server.as_ref(),
                            outbound.port,
                            outbound.uuid.as_ref(),
                            outbound.token.as_ref(),
                        ) {
                            (Some(server), Some(port), Some(uuid_str), Some(token)) => {
                                match uuid::Uuid::parse_str(uuid_str) {
                                    Ok(uuid) => {
                                        let relay_mode = match outbound.udp_relay_mode.as_deref() {
                                            Some(mode) if mode.eq_ignore_ascii_case("quic") => {
                                                UdpRelayMode::Quic
                                            }
                                            _ => UdpRelayMode::Native,
                                        };
                                        let cfg = TuicConfig {
                                            server: server.clone(),
                                            port,
                                            uuid,
                                            token: token.clone(),
                                            password: outbound.password.clone(),
                                            congestion_control: outbound.congestion_control.clone(),
                                            alpn: outbound.tls_alpn.clone(),
                                            skip_cert_verify: outbound
                                                .skip_cert_verify
                                                .unwrap_or(false),
                                            sni: outbound.tls_sni.clone(),
                                            tls_ca_paths: outbound.tls_ca_paths.clone(),
                                            tls_ca_pem: outbound.tls_ca_pem.clone(),
                                            udp_relay_mode: relay_mode,
                                            udp_over_stream: outbound
                                                .udp_over_stream
                                                .unwrap_or(false),
                                            zero_rtt_handshake: outbound
                                                .zero_rtt_handshake
                                                .unwrap_or(false),
                                        };
                                        match TuicOutbound::new(cfg) {
                                            Ok(connector) => {
                                                Arc::new(connector) as Arc<dyn OutboundConnector>
                                            }
                                            Err(_) => fallback(),
                                        }
                                    }
                                    Err(_) => fallback(),
                                }
                            }
                            _ => fallback(),
                        }
                    }
                    #[cfg(not(feature = "out_tuic"))]
                    {
                        use crate::outbound::direct_connector::DirectConnector;
                        Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                    }
                }
                sb_config::ir::OutboundType::Vmess => {
                    // VMess connector not wired in adapter bridge yet; fall back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Trojan => {
                    // Trojan connector not wired in adapter bridge; fall back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Ssh => {
                    // Fallback to direct in this adapter path
                    direct_connector_fallback()
                }
                _ => direct_connector_fallback(),
            };

            bridge.add_outbound(name, kind, connector);
        }

        // Build endpoints from IR
        for endpoint_ir in &ir.endpoints {
            let ctx = EndpointContext::default();
            if let Some(endpoint) = endpoint_registry().build(endpoint_ir, &ctx) {
                bridge.add_endpoint(endpoint);
            } else {
                tracing::warn!(
                    "Failed to build endpoint: {}",
                    endpoint_ir.tag.as_deref().unwrap_or("unknown")
                );
            }
        }

        // Build services from IR
        for service_ir in &ir.services {
            let ctx = ServiceContext::default();
            if let Some(service) = service_registry().build(service_ir, &ctx) {
                bridge.add_service(service);
            } else {
                tracing::warn!(
                    "Failed to build service: {}",
                    service_ir.tag.as_deref().unwrap_or("unknown")
                );
            }
        }

        Ok(bridge)
    }
    /// Registers an inbound service.
    pub fn add_inbound(&mut self, ib: Arc<dyn InboundService>) {
        self.inbounds.push(ib);
        self.inbound_kinds.push("unknown".to_string());
    }

    /// Registers an inbound service with explicit kind label
    pub fn add_inbound_with_kind(&mut self, kind: &str, ib: Arc<dyn InboundService>) {
        self.inbounds.push(ib);
        self.inbound_kinds.push(kind.to_string());
    }

    /// Registers an outbound connector with name and kind.
    pub fn add_outbound(&mut self, name: String, kind: String, ob: Arc<dyn OutboundConnector>) {
        self.outbounds.push((name, kind, ob));
    }

    /// Registers a VPN endpoint instance.
    pub fn add_endpoint(&mut self, ep: Arc<dyn Endpoint>) {
        self.endpoints.push(ep);
    }

    /// Registers a background service instance.
    pub fn add_service(&mut self, svc: Arc<dyn Service>) {
        self.services.push(svc);
    }

    /// Registers an UDP outbound factory with name.
    pub fn add_outbound_udp_factory(&mut self, name: String, f: Arc<dyn UdpOutboundFactory>) {
        self.udp_factories.insert(name, f);
    }

    /// Finds an outbound connector by name.
    ///
    /// Returns `None` if no outbound with the given name exists.
    pub fn find_outbound(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.outbounds
            .iter()
            .find_map(|(n, _k, ob)| (n == name).then(|| Arc::clone(ob)))
    }

    /// Finds an UDP factory by name
    pub fn find_udp_factory(&self, name: &str) -> Option<Arc<dyn UdpOutboundFactory>> {
        self.udp_factories.get(name).cloned()
    }

    /// Finds the first outbound connector with kind "direct" as a fallback.
    ///
    /// This is used when no specific outbound is found and a safe default is needed.
    pub fn find_direct_fallback(&self) -> Option<Arc<dyn OutboundConnector>> {
        self.outbounds
            .iter()
            .find_map(|(_n, k, ob)| (k == "direct").then(|| Arc::clone(ob)))
    }

    /// Returns a snapshot of all outbound (name, kind) pairs.
    ///
    /// Useful for health checks and visualization.
    pub fn outbounds_snapshot(&self) -> Vec<(String, String)> {
        self.outbounds
            .iter()
            .map(|(n, k, _)| (n.clone(), k.clone()))
            .collect()
    }

    /// Gets inbound kind for index, or "unknown" if missing
    pub fn inbound_kind_at(&self, idx: usize) -> &str {
        self.inbound_kinds
            .get(idx)
            .map(|s| s.as_str())
            .unwrap_or("unknown")
    }

    /// Alias for `find_outbound` - finds an outbound connector by name.
    pub fn get_member(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.find_outbound(name)
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("inbounds", &format!("{} services", self.inbounds.len()))
            .field("inbound_kinds", &self.inbound_kinds)
            .field("outbounds", &format!("{} connectors", self.outbounds.len()))
            .field(
                "udp_factories",
                &format!("{} factories", self.udp_factories.len()),
            )
            .field("endpoints", &format!("{} endpoints", self.endpoints.len()))
            .field("services", &format!("{} services", self.services.len()))
            .finish()
    }
}
