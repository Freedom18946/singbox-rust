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
use crate::endpoint::Endpoint;

use crate::router::RouterHandle;
use crate::service::Service;
use sb_config::ir::{Credentials, InboundRealityIR, MultiplexOptionsIR};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

pub mod bridge;
pub mod clash;
pub mod handler;
mod inbound_transition;
pub mod registry;
pub mod surface;

#[doc(hidden)]
pub use inbound_transition::{manage_inbound, InboundTaskDriver};

pub type InboundReadySender = tokio::sync::oneshot::Sender<io::Result<()>>;

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
    /// Multiple inbound credentials (Go `users` field).
    pub users: Option<Vec<Credentials>>,
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
    /// Typed Go-shaped inbound TLS options.
    pub tls: Option<sb_config::ir::InboundTlsOptionsIR>,
    /// VLESS inbound REALITY server configuration.
    pub reality: Option<InboundRealityIR>,

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
            users: None,
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
            tls: None,
            reality: None,
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
/// for all protocol handlers. Protocol implementations come from adapter registries.
/// 桥接器由 IR 配置组装而成，作为所有协议处理程序的中央注册表。协议实现由 adapter registry 提供。
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

            router: None,
            experimental: None,
        }
    }

    /// Create bridge from IR configuration through the installed adapter registry.
    pub fn new_from_config(ir: &sb_config::ir::ConfigIR, context: Context) -> anyhow::Result<Self> {
        let bridge = bridge::build_bridge(
            ir,
            crate::router::Engine::new(Arc::new(ir.clone())),
            context,
        );

        if bridge.startup_errors.is_empty() {
            Ok(bridge)
        } else {
            Err(anyhow::anyhow!(
                "adapter registry failed to build configured protocols: {}",
                bridge.startup_errors.join("; ")
            ))
        }
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
