//! Adapter traits and factory interfaces.
//!
//! This module defines the core abstraction layer between configuration and runtime:
//! - [`InboundService`]: Trait for inbound protocol handlers (socks5, http, tun, etc.)
//! - [`OutboundConnector`]: Trait for outbound connection providers
//! - [`Bridge`]: Runtime container managing all inbound/outbound instances
//!
//! sb-adapters provides concrete implementations; sb-core defines interfaces and bridging logic.

use sb_config::ir::Credentials;
use std::sync::Arc;

pub use crate::outbound::selector::Member as SelectorMember;
pub mod bridge;

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
}

/// Outbound connector trait for establishing TCP connections to targets.
///
/// Implementers handle protocol-specific handshakes (e.g., SOCKS5 upstream, HTTP CONNECT).
#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync + std::fmt::Debug + 'static {
    /// Establish a TCP connection to the specified host and port.
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream>;
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
#[derive(Clone, Debug)]
pub struct Bridge {
    pub inbounds: Vec<Arc<dyn InboundService>>,
    /// (name, kind, connector) tuples
    pub outbounds: Vec<(String, String, Arc<dyn OutboundConnector>)>,
}

impl Bridge {
    /// Creates a new empty bridge.
    pub fn new() -> Self {
        Self {
            inbounds: vec![],
            outbounds: vec![],
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
                };

                // Stage 1: acknowledge sniff flag without changing behavior
                if inbound.sniff {
                    tracing::info!(
                        kind = ?inbound.ty,
                        listen = %format!("{}:{}", inbound.listen, inbound.port),
                        "inbound sniff requested (stage1 noop)"
                    );
                }

                bridge.add_inbound(inbound_service);
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
                sb_config::ir::OutboundType::Direct => {
                    direct_connector_fallback()
                }
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
                    // HTTP proxy connector would be implemented here
                    // For now, fall back to direct
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::Socks => {
                    // SOCKS5 proxy connector would be implemented here
                    // For now, fall back to direct
                    direct_connector_fallback()
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
                sb_config::ir::OutboundType::Shadowsocks => {
                    direct_connector_fallback()
                }
                sb_config::ir::OutboundType::UrlTest => {
                    direct_connector_fallback()
                }
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
                                            alpn: outbound
                                                .alpn
                                                .clone()
                                                .or_else(|| outbound.tls_alpn.clone()),
                                            skip_cert_verify: outbound
                                                .skip_cert_verify
                                                .unwrap_or(false),
                                            udp_relay_mode: relay_mode,
                                            udp_over_stream: outbound
                                                .udp_over_stream
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
            };

            bridge.add_outbound(name, kind, connector);
        }

        Ok(bridge)
    }
    /// Registers an inbound service.
    pub fn add_inbound(&mut self, ib: Arc<dyn InboundService>) {
        self.inbounds.push(ib);
    }

    /// Registers an outbound connector with name and kind.
    pub fn add_outbound(&mut self, name: String, kind: String, ob: Arc<dyn OutboundConnector>) {
        self.outbounds.push((name, kind, ob));
    }

    /// Finds an outbound connector by name.
    ///
    /// Returns `None` if no outbound with the given name exists.
    pub fn find_outbound(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.outbounds
            .iter()
            .find_map(|(n, _k, ob)| (n == name).then(|| Arc::clone(ob)))
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
