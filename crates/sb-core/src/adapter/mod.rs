//! Adapter traits and factory interfaces.
//! 适配器 trait 和工厂接口。
//!
//! This module defines the core abstraction layer between configuration and runtime:
//! 本模块定义了配置和运行时之间的核心抽象层：
//! - [`InboundTaskDriver`]: Trait for inbound protocol handlers (socks5, http, tun, etc.)
//!   入站协议处理程序的 Trait（socks5, http, tun 等）
//! - [`Outbound`]: Trait for outbound connection providers
//!   出站连接提供者的 Trait
//! - [`Bridge`]: Runtime container managing all inbound/outbound instances
//!   管理所有入站/出站实例的运行时容器
//!
//! sb-adapters provides concrete implementations; sb-core defines interfaces and bridging logic.
//! sb-adapters 提供具体实现；sb-core 定义接口和桥接逻辑。

use crate::context::Context;
use crate::endpoint::{endpoint_registry, Endpoint, EndpointContext};
#[cfg(feature = "router")]
use crate::router::RouterHandle;
use crate::service::{service_registry, Service, ServiceContext};
use sb_config::ir::{Credentials, MultiplexOptionsIR};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

pub use crate::outbound::selector::Member as SelectorMember;
pub mod bridge;
pub mod canonical_bridge;
pub mod clash;
pub mod handler;
mod inbound_transition;
pub mod registry;
pub mod surface;

#[doc(hidden)]
pub use inbound_transition::{manage_inbound, InboundTaskDriver};

pub type InboundReadySender = tokio::sync::oneshot::Sender<io::Result<()>>;

/// Helper to parse socket address from listen and port
#[allow(dead_code)]
fn parse_socket_addr(listen: &str, port: u16) -> anyhow::Result<std::net::SocketAddr> {
    format!("{listen}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid inbound address: {e}"))
}

#[derive(Debug, Clone)]
struct UnsupportedOutboundConnector {
    reason: Arc<str>,
}

impl UnsupportedOutboundConnector {
    fn new(reason: impl Into<Arc<str>>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl sb_types::Outbound for UnsupportedOutboundConnector {
    fn r#type(&self) -> &str {
        "unsupported"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new("core-fallback")
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }

    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                self.reason.to_string(),
            ))
        })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                self.reason.to_string(),
            ))
        })
    }
}

fn unsupported_outbound_connector(reason: impl Into<Arc<str>>) -> Arc<dyn sb_types::Outbound> {
    Arc::new(UnsupportedOutboundConnector::new(reason))
}

/// Inbound construction parameters (derived from IR).
#[derive(Clone, Debug)]
pub struct InboundParam {
    /// Protocol kind: "socks", "http", "tun", etc.
    pub kind: String,
    /// Inbound tag for tracking/routing metadata.
    pub tag: Option<String>,
    pub listen: String,
    pub port: u16,
    pub basic_auth: Option<Credentials>,
    pub sniff: bool,
    /// Override destination with sniffed hostname (Go parity: sniff_override_destination).
    pub sniff_override_destination: bool,
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

    // Generic fields requiring specific mapping
    pub uuid: Option<String>,
    pub method: Option<String>,
    pub security: Option<String>,
    pub flow: Option<String>,

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
    /// Hysteria2 Masquerade configuration (JSON-encoded)
    pub masquerade: Option<String>,

    // Tun-specific fields
    /// Tun interface options (JSON-encoded)
    pub tun_options: Option<String>,

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
    /// Hysteria v1 QUIC receive window for stream
    pub hysteria_recv_window: Option<u64>,
    /// Multiplex options
    pub multiplex: Option<MultiplexOptionsIR>,
    /// Trojan multi-user authentication (JSON-encoded for now)
    pub users_trojan: Option<String>,
    /// ShadowTLS protocol version.
    pub shadowtls_version: Option<u8>,
    /// ShadowTLS multi-user authentication (JSON-encoded for now).
    pub users_shadowtls: Option<String>,
    /// ShadowTLS handshake target (JSON-encoded for now).
    pub shadowtls_handshake: Option<String>,
    /// ShadowTLS handshake overrides by server name (JSON-encoded for now).
    pub shadowtls_handshake_for_server_name: Option<String>,
    /// ShadowTLS strict mode.
    pub shadowtls_strict_mode: Option<bool>,
    /// ShadowTLS wildcard SNI mode.
    pub shadowtls_wildcard_sni: Option<String>,
    /// VLESS multi-user authentication (JSON-encoded for now)
    pub users_vless: Option<String>,
    /// VMess multi-user authentication (JSON-encoded for now)
    pub users_vmess: Option<String>,
    /// Shadowsocks multi-user authentication (JSON-encoded for now)
    pub users_shadowsocks: Option<String>,
    /// UDP Timeout
    pub udp_timeout: Option<std::time::Duration>,
    /// Detour to another inbound tag.
    pub detour: Option<String>,
    /// Domain resolution strategy
    pub domain_strategy: Option<String>,
    pub set_system_proxy: bool,
    pub allow_private_network: bool,
    /// Explicit conntrack dependency for inbound adapters.
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,

    // SSH-specific fields
    /// SSH server host key file path (PEM format)
    pub ssh_host_key_path: Option<String>,
}

impl Default for InboundParam {
    fn default() -> Self {
        Self {
            kind: String::new(),
            tag: None,
            listen: "127.0.0.1".to_string(),
            port: 0,
            basic_auth: None,
            sniff: false,
            sniff_override_destination: false,
            udp: false,
            override_host: None,
            override_port: None,
            network: None,
            users_anytls: None,
            password: None,
            anytls_padding: None,
            uuid: None,
            method: None,
            security: None,
            flow: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            users_hysteria2: None,
            congestion_control: None,
            salamander: None,
            obfs: None,
            brutal_up_mbps: None,
            brutal_down_mbps: None,
            masquerade: None,
            tun_options: None,
            users_tuic: None,
            users_hysteria: None,
            hysteria_protocol: None,
            hysteria_obfs: None,
            hysteria_up_mbps: None,
            hysteria_down_mbps: None,
            hysteria_recv_window_conn: None,
            hysteria_recv_window: None,
            multiplex: None,
            users_trojan: None,
            shadowtls_version: None,
            users_shadowtls: None,
            shadowtls_handshake: None,
            shadowtls_handshake_for_server_name: None,
            shadowtls_strict_mode: None,
            shadowtls_wildcard_sni: None,
            users_vless: None,
            users_vmess: None,
            users_shadowsocks: None,
            udp_timeout: None,
            detour: None,
            domain_strategy: None,
            set_system_proxy: false,
            allow_private_network: true,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
            ssh_host_key_path: None,
        }
    }
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
    // Dialer options
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
    pub routing_mark: Option<u32>,
    pub reuse_addr: Option<bool>,
    pub connect_timeout: Option<std::time::Duration>,
    pub tcp_fast_open: Option<bool>,
    pub tcp_multi_path: Option<bool>,
    pub udp_fragment: Option<bool>,
    pub domain_strategy: Option<String>,
    /// Multiplex options
    pub multiplex: Option<MultiplexOptionsIR>,
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
            bind_interface: None,
            inet4_bind_address: None,
            inet6_bind_address: None,
            routing_mark: None,
            reuse_addr: None,
            connect_timeout: None,
            tcp_fast_open: None,
            tcp_multi_path: None,
            udp_fragment: None,
            domain_strategy: None,
            multiplex: None,
        }
    }
}

/// Runtime bridge: manages inbound services and outbound connectors.
/// 运行时桥接：管理入站服务和出站连接器。
///
/// The bridge is assembled from IR configuration and serves as the central registry
/// for all protocol handlers. It supports adapter-first fallback to scaffold implementations.
/// 桥接器由 IR 配置组装而成，作为所有协议处理程序的中央注册表。它支持适配器优先回退到脚手架实现。
#[derive(Clone)]
pub struct Bridge {
    pub inbounds: Vec<Arc<dyn sb_types::Inbound>>,
    /// Inbound protocol kinds aligned with `inbounds` indices
    pub inbound_kinds: Vec<String>,
    /// Optional inbound tags aligned with `inbounds` indices
    pub inbound_tags: Vec<Option<String>>,
    /// (name, kind, connector) tuples
    pub outbounds: Vec<(String, String, Arc<dyn sb_types::Outbound>)>,
    /// Outbound dependency graph: tag → depends-on tags (group members)
    pub outbound_deps: HashMap<String, Vec<String>>,
    /// Endpoints (WireGuard, Tailscale, etc.)
    pub endpoints: Vec<Arc<dyn Endpoint>>,

    /// Background services (Resolved, DERP, SSM API, etc.)
    pub services: Vec<Arc<dyn Service>>,
    /// Fatal adapter startup/build errors that must block runtime readiness.
    pub startup_errors: Vec<String>,
    /// Global runtime context
    pub context: Context,
    /// Router handle (if available)
    #[cfg(feature = "router")]
    pub router: Option<Arc<RouterHandle>>,
    pub experimental: Option<sb_config::ir::ExperimentalIR>,
}

impl Bridge {
    /// Creates a new empty bridge.
    pub fn new(context: Context) -> Self {
        Self {
            inbounds: vec![],
            inbound_kinds: vec![],
            inbound_tags: vec![],
            outbounds: vec![],
            outbound_deps: HashMap::new(),
            endpoints: vec![],
            services: vec![],
            startup_errors: vec![],
            context,
            #[cfg(feature = "router")]
            router: None,
            experimental: None,
        }
    }

    /// Create bridge from IR configuration
    pub fn new_from_config(ir: &sb_config::ir::ConfigIR, context: Context) -> anyhow::Result<Self> {
        let mut bridge = Self::new(context);

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
                            as Arc<dyn InboundTaskDriver>
                    }
                    sb_config::ir::InboundType::Http => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "http",
                            "core bridge HTTP inbound is disabled",
                            Some(
                                "Use adapter::bridge::build_bridge (sb-adapters HTTP inbound) instead"
                                    .to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundTaskDriver>
                    }
                    sb_config::ir::InboundType::Mixed => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "mixed",
                            "core bridge mixed inbound is disabled",
                            Some(
                                "Use adapter::bridge::build_bridge (sb-adapters mixed inbound) instead"
                                    .to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundTaskDriver>
                    }
                    sb_config::ir::InboundType::Tun => {
                        // TUN inbound service
                        use crate::inbound::tun::TunInboundService;

                        let stats = bridge.context.v2ray_server.as_ref().and_then(|s| s.stats());
                        Arc::new(
                            TunInboundService::new()
                                .with_tag(inbound.tag.clone())
                                .with_stats(stats),
                        ) as Arc<dyn InboundTaskDriver>
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
                        let stats = bridge.context.v2ray_server.as_ref().and_then(|s| s.stats());
                        Arc::new(
                            DirectForward::new(addr, host, dst_port, inbound.udp)
                                .with_tag(inbound.tag.clone())
                                .with_stats(stats)
                                .with_conn_tracker(bridge.context.conn_tracker.clone()),
                        ) as Arc<dyn InboundTaskDriver>
                    }
                    sb_config::ir::InboundType::Redirect => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "redirect",
                            "requires Linux iptables REDIRECT and adapter integration",
                            Some(
                                "Use 'tun' inbound or SOCKS/HTTP inbound as a fallback".to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundTaskDriver>
                    }
                    sb_config::ir::InboundType::Tproxy => {
                        let msg = crate::inbound::unsupported::UnsupportedInbound::new(
                            "tproxy",
                            "requires Linux IP_TRANSPARENT and adapter integration",
                            Some(
                                "Use 'tun' inbound or SOCKS/HTTP inbound as a fallback".to_string(),
                            ),
                        );
                        Arc::new(msg) as Arc<dyn InboundTaskDriver>
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
                        Arc::new(msg) as Arc<dyn InboundTaskDriver>
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
                sb_config::ir::OutboundType::Direct => unsupported_outbound_connector(
                    "core bridge Direct outbound is disabled; use adapter::bridge::build_bridge",
                ),
                sb_config::ir::OutboundType::Block => {
                    Arc::new(canonical_bridge::BlockOutbound::new(name.clone()))
                        as Arc<dyn sb_types::Outbound>
                }
                sb_config::ir::OutboundType::Http => {
                    unsupported_outbound_connector(
                        "core bridge HTTP outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Socks => {
                    unsupported_outbound_connector(
                        "core bridge SOCKS outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Vless => {
                    unsupported_outbound_connector(
                        "core bridge VLESS outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Selector => {
                    unsupported_outbound_connector(
                        "core bridge Selector outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Shadowsocks => unsupported_outbound_connector(
                    "core bridge Shadowsocks outbound is disabled; use adapter::bridge::build_bridge",
                ),
                sb_config::ir::OutboundType::UrlTest => unsupported_outbound_connector(
                    "core bridge URLTest outbound is disabled; use adapter::bridge::build_bridge",
                ),
                sb_config::ir::OutboundType::Shadowtls => {
                    unsupported_outbound_connector(
                        "core bridge ShadowTLS outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Hysteria2 => {
                    unsupported_outbound_connector(
                        "core bridge Hysteria2 outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Tuic => {
                    unsupported_outbound_connector(
                        "core bridge TUIC outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Vmess => {
                    unsupported_outbound_connector(
                        "core bridge VMess outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Trojan => {
                    unsupported_outbound_connector(
                        "core bridge Trojan outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                sb_config::ir::OutboundType::Ssh => {
                    unsupported_outbound_connector(
                        "core bridge SSH outbound is disabled; use adapter::bridge::build_bridge",
                    )
                }
                _ => unsupported_outbound_connector(
                    "core bridge outbound type is disabled; use adapter::bridge::build_bridge",
                ),
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

        // Build a minimal outbounds registry handle for service detour support.
        // This mirrors adapter/bridge.rs's helper and is intentionally best-effort.
        let outbounds_handle: Arc<crate::outbound::OutboundRegistryHandle> = {
            use crate::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
            let mut reg = OutboundRegistry::default();
            for (name, _kind, conn) in &bridge.outbounds {
                reg.insert(name.clone(), OutboundImpl::Connector(conn.clone()));
            }
            Arc::new(OutboundRegistryHandle::new(reg))
        };

        let endpoints_map: Arc<
            std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>,
        > = Arc::new(
            bridge
                .endpoints
                .iter()
                .map(|ep| (ep.tag().to_string(), ep.clone()))
                .collect(),
        );

        // Best-effort DNSRouter for services (e.g., DERP /bootstrap-dns).
        #[cfg(feature = "router")]
        let dns_router = crate::dns::config_builder::build_dns_components(ir, None)
            .ok()
            .and_then(|(_resolver, router)| router);
        #[cfg(not(feature = "router"))]
        let dns_router: Option<std::sync::Arc<dyn crate::dns::DnsRouter>> = None;

        // Build services from IR
        for service_ir in &ir.services {
            let mut ctx = ServiceContext::default()
                .with_outbounds(outbounds_handle.clone())
                .with_endpoints(endpoints_map.clone());
            ctx.dns_router = dns_router.clone();
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
    pub fn add_inbound(&mut self, ib: Arc<dyn InboundTaskDriver>) {
        self.inbounds.push(manage_inbound(ib, "unknown", "unknown"));
        self.inbound_kinds.push("unknown".to_string());
        self.inbound_tags.push(None);
    }

    /// Registers an inbound service with explicit kind label
    pub fn add_inbound_with_kind(&mut self, kind: &str, ib: Arc<dyn InboundTaskDriver>) {
        self.inbounds
            .push(manage_inbound(ib, kind, format!("{kind}-inbound")));
        self.inbound_kinds.push(kind.to_string());
        self.inbound_tags.push(None);
    }

    /// Registers an inbound service with explicit kind label and optional tag.
    pub fn add_inbound_with_meta(
        &mut self,
        kind: &str,
        tag: Option<String>,
        ib: Arc<dyn InboundTaskDriver>,
    ) {
        self.inbounds.push(manage_inbound(
            ib,
            kind,
            tag.clone().unwrap_or_else(|| format!("{kind}-inbound")),
        ));
        self.inbound_kinds.push(kind.to_string());
        self.inbound_tags.push(tag);
    }

    /// Register an already-canonical inbound built by the adapter registry.
    pub fn add_canonical_inbound_with_meta(
        &mut self,
        kind: &str,
        tag: Option<String>,
        inbound: Arc<dyn sb_types::Inbound>,
    ) {
        self.inbounds.push(inbound);
        self.inbound_kinds.push(kind.to_string());
        self.inbound_tags.push(tag);
    }

    /// Registers an outbound connector with name and kind.
    pub fn add_outbound(&mut self, name: String, kind: String, ob: Arc<dyn sb_types::Outbound>) {
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

    /// Finds an outbound connector by name.
    ///
    /// Returns `None` if no outbound with the given name exists.
    pub fn find_outbound(&self, name: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        self.outbounds
            .iter()
            .find_map(|(n, _k, ob)| (n == name).then(|| Arc::clone(ob)))
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
    pub fn get_member(&self, name: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        self.find_outbound(name)
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new(Context::new())
    }
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("inbounds", &format!("{} services", self.inbounds.len()))
            .field("inbound_kinds", &self.inbound_kinds)
            .field("outbounds", &format!("{} connectors", self.outbounds.len()))
            .field(
                "outbound_deps",
                &format!("{} deps", self.outbound_deps.len()),
            )
            .field("endpoints", &format!("{} endpoints", self.endpoints.len()))
            .field("services", &format!("{} services", self.services.len()))
            .finish()
    }
}
