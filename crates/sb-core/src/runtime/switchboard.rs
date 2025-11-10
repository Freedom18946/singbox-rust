//! Outbound switchboard: registry and selection of outbound connectors
//!
//! This module provides the central registry for outbound adapters/connectors,
//! mapping routing decisions to actual connector implementations.

use crate::error::SbResult;
use anyhow::Context;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Transport type for connection requests
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    Udp,
}

/// Connection target specification
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub kind: TransportKind,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16, kind: TransportKind) -> Self {
        Self {
            host: host.into(),
            port,
            kind,
        }
    }

    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Tcp)
    }

    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Udp)
    }
}

/// Dial options for connection requests
#[derive(Debug, Clone)]
pub struct DialOpts {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for DialOpts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
        }
    }
}

impl DialOpts {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }
}

/// Boxed async stream for connections (temporary abstraction)
pub type BoxedStream = Box<dyn AsyncStream>;

/// Combined trait for async read + write + unpin + send
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Blanket implementation for any type that implements the required traits
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Adapter error types
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type AdapterResult<T> = Result<T, AdapterError>;

/// Unified outbound connector trait for all adapters
#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync + std::fmt::Debug {
    /// Initialize the connector (load certificates, resolve DNS, etc.)
    async fn start(&self) -> AdapterResult<()> {
        Ok(())
    }

    /// Establish connection to target
    async fn dial(&self, target: Target, opts: DialOpts) -> AdapterResult<BoxedStream>;

    /// Get connector type/name for logging
    fn name(&self) -> &'static str {
        "unknown"
    }
}

/// Outbound switchboard for managing and selecting connectors
#[derive(Debug)]
pub struct OutboundSwitchboard {
    /// Registry mapping outbound names to connector instances
    registry: HashMap<String, Arc<dyn OutboundConnector>>,
    /// Default connector when no routing match is found
    default_connector: Option<Arc<dyn OutboundConnector>>,
    /// UDP factories by outbound name (for QUIC-based protocols, etc.)
    udp_registry: HashMap<String, Arc<dyn crate::adapter::UdpOutboundFactory>>,
}

impl OutboundSwitchboard {
    /// Create a new empty switchboard
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            default_connector: None,
            udp_registry: HashMap::new(),
        }
    }

    /// Register an outbound connector with a given name
    pub fn register<C>(&mut self, name: String, connector: C) -> SbResult<()>
    where
        C: OutboundConnector + 'static,
    {
        let connector = Arc::new(connector);

        // Initialize the connector
        let connector_clone = connector.clone();
        let connector_name = connector.name();
        let fut = async move {
            if let Err(e) = connector_clone.start().await {
                error!(
                    "Failed to initialize outbound connector '{}': {}",
                    connector_name, e
                );
            } else {
                info!(
                    "Outbound connector '{}' initialized successfully",
                    connector_name
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(fut);
            }
            Err(_) => {
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Runtime::new() {
                        rt.block_on(fut);
                    }
                });
            }
        }

        self.registry.insert(name.clone(), connector);
        info!("Registered outbound connector: '{}'", name);
        Ok(())
    }

    /// Set the default connector to use when no routing match is found
    pub fn set_default<C>(&mut self, connector: C) -> SbResult<()>
    where
        C: OutboundConnector + 'static,
    {
        let connector = Arc::new(connector);

        // Initialize the connector
        let connector_clone = connector.clone();
        let connector_name = connector.name();
        let fut = async move {
            if let Err(e) = connector_clone.start().await {
                error!(
                    "Failed to initialize default outbound connector '{}': {}",
                    connector_name, e
                );
            } else {
                info!(
                    "Default outbound connector '{}' initialized successfully",
                    connector_name
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(fut);
            }
            Err(_) => {
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Runtime::new() {
                        rt.block_on(fut);
                    }
                });
            }
        }

        self.default_connector = Some(connector);
        info!("Set default outbound connector");
        Ok(())
    }

    /// Get a connector by name, falling back to default if not found
    pub fn get_connector(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        if let Some(connector) = self.registry.get(name) {
            return Some(connector.clone());
        }

        if name == "direct" || name == "default" {
            return self.default_connector.clone();
        }

        // Log warning for unknown connector
        warn!("Unknown outbound connector '{}', attempting fallback", name);
        self.default_connector.clone()
    }

    /// Register a UDP factory for an outbound by name
    pub fn register_udp_factory(
        &mut self,
        name: String,
        f: Arc<dyn crate::adapter::UdpOutboundFactory>,
    ) -> SbResult<()> {
        self.udp_registry.insert(name, f);
        Ok(())
    }

    /// Get a UDP factory by name
    pub fn get_udp_factory(&self, name: &str) -> Option<Arc<dyn crate::adapter::UdpOutboundFactory>> {
        self.udp_registry.get(name).cloned()
    }

    /// List all registered UDP factory names
    pub fn list_udp_factories(&self) -> Vec<String> {
        let mut names: Vec<_> = self.udp_registry.keys().cloned().collect();
        names.sort();
        names
    }

    /// List all registered connector names
    pub fn list_connectors(&self) -> Vec<String> {
        let mut names: Vec<_> = self.registry.keys().cloned().collect();
        names.sort();
        names
    }

    /// Get the number of registered connectors
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Check if the switchboard is empty
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.default_connector.is_none()
    }
}

impl Default for OutboundSwitchboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing outbound switchboard from configuration
pub struct SwitchboardBuilder {
    switchboard: OutboundSwitchboard,
}

impl SwitchboardBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            switchboard: OutboundSwitchboard::new(),
        }
    }

    /// Build outbound connectors from configuration IR
    pub fn from_config_ir(ir: &sb_config::ir::ConfigIR) -> SbResult<OutboundSwitchboard> {
        let mut builder = Self::new();

        // Add direct connector as default
        {
            let direct = DirectConnector;
            builder
                .switchboard
                .set_default(direct)
                .context("Failed to set direct connector as default")?;
        }

        // Register outbound connectors from IR
        for outbound_ir in &ir.outbounds {
            let name = outbound_ir.name.as_deref().unwrap_or("unnamed");
            let result = builder.try_register_from_ir(outbound_ir);
            match result {
                Ok(()) => {
                    info!("Successfully registered outbound: {}", name);
                }
                Err(e) => {
                    warn!(
                        "Failed to register outbound '{}': {}. Using 501 degraded mode.",
                        name, e
                    );

                    // Register a 501 degraded connector for this outbound
                    let degraded = DegradedConnector::new(name, e.to_string());
                    builder
                        .switchboard
                        .register(name.to_string(), degraded)
                        .context("Failed to register degraded connector")?;
                }
            }
        }

        Ok(builder.switchboard)
    }

    /// Try to register a connector from outbound IR
    fn try_register_from_ir(&mut self, ir: &sb_config::ir::OutboundIR) -> AdapterResult<()> {
        use sb_config::ir::OutboundType;

        let name = ir.name.as_deref().unwrap_or("unnamed");

        match ir.ty {
            OutboundType::Ssh => {
                #[cfg(feature = "out_ssh")]
                {
                    use crate::outbound::ssh_stub::{SshConfig, SshOutbound};
                    use crate::outbound::crypto_types::{HostPort as Hp, OutboundTcp};

                    // Map IR → SSH config
                    let server = ir
                        .server
                        .clone()
                        .ok_or(AdapterError::InvalidConfig("ssh.server is required"))?;
                    let port = ir
                        .port
                        .ok_or(AdapterError::InvalidConfig("ssh.port is required"))?;

                    let (username, password) = ir
                        .credentials
                        .as_ref()
                        .map(|c| (c.username.clone().unwrap_or_default(), c.password.clone()))
                        .unwrap_or((String::new(), None));
                    if username.is_empty() {
                        return Err(AdapterError::InvalidConfig("ssh.credentials.username is required"));
                    }

                    // Inline private key: prefer `ssh_private_key`, else try to read from `ssh_private_key_path`.
                    let mut private_key = ir.ssh_private_key.clone();
                    if private_key.is_none() {
                        if let Some(path) = ir.ssh_private_key_path.as_ref() {
                            match std::fs::read_to_string(path) {
                                Ok(s) => private_key = Some(s),
                                Err(e) => {
                                    tracing::warn!(target="sb_core::ssh", path=%path, error=%e, "failed to read ssh_private_key_path; continuing without key");
                                }
                            }
                        }
                    }

                    let cfg = SshConfig {
                        server,
                        port,
                        username,
                        password,
                        private_key,
                        private_key_passphrase: ir.ssh_private_key_passphrase.clone(),
                        host_key_verification: ir.ssh_host_key_verification.unwrap_or(true),
                        compression: ir.ssh_compression.unwrap_or(false),
                        keepalive_interval: ir.ssh_keepalive_interval,
                        connect_timeout: ir.connect_timeout_sec.map(|v| v as u64),
                        connection_pool_size: ir.ssh_connection_pool_size,
                        known_hosts_path: ir.ssh_known_hosts_path.clone(),
                    };

                    let outbound = SshOutbound::new(cfg)
                        .map_err(|e| AdapterError::Other(anyhow::anyhow!(e).into()))?;
                    #[derive(Debug, Clone)]
                    struct SshConn { inner: std::sync::Arc<SshOutbound> }
                    #[async_trait::async_trait]
                    impl OutboundConnector for SshConn {
                        async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
                            if target.kind != TransportKind::Tcp {
                                return Err(AdapterError::UnsupportedProtocol("SSH only supports TCP".into()));
                            }
                            let hp = Hp::new(target.host, target.port);
                            let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                            Ok(Box::new(s))
                        }
                        fn name(&self) -> &'static str { "ssh" }
                    }
                    let conn = SshConn { inner: std::sync::Arc::new(outbound) };
                    self.switchboard
                        .register(ir.name.clone().unwrap_or_else(|| "ssh".into()), conn)
                        .map_err(|e| AdapterError::Other(e.into()))?;
                }
                #[cfg(not(feature = "out_ssh"))]
                {
                    return Err(AdapterError::UnsupportedProtocol("SSH feature not enabled".into()));
                }
            }
            OutboundType::Http => {
                // Minimal HTTP upstream connector using scaffold implementation
                use crate::adapter::OutboundConnector as AdapterConnector;

                #[derive(Debug, Clone)]
                struct HttpConnector {
                    inner: std::sync::Arc<crate::outbound::http_upstream::HttpUp>,
                }

                #[async_trait::async_trait]
                impl OutboundConnector for HttpConnector {
                    async fn dial(
                        &self,
                        target: Target,
                        _opts: DialOpts,
                    ) -> AdapterResult<BoxedStream> {
                        if target.kind != TransportKind::Tcp {
                            return Err(AdapterError::UnsupportedProtocol(
                                "HTTP upstream does not support UDP".into(),
                            ));
                        }
                        let s = self
                            .inner
                            .connect(&target.host, target.port)
                            .await
                            .map_err(AdapterError::Io)?;
                        Ok(Box::new(s))
                    }
                    fn name(&self) -> &'static str { "http" }
                }

                let (user, pass) = ir
                    .credentials
                    .as_ref()
                    .map(|c| (c.username.clone(), c.password.clone()))
                    .unwrap_or((None, None));
                let server = ir.server.clone().ok_or(AdapterError::InvalidConfig(
                    "http.server is required",
                ))?;
                let port = ir.port.ok_or(AdapterError::InvalidConfig(
                    "http.port is required",
                ))?;
                let up = crate::outbound::http_upstream::HttpUp::new(server, port, user, pass);
                let conn = HttpConnector { inner: std::sync::Arc::new(up) };
                self.switchboard
                    .register(name.to_string(), conn)
                    .map_err(|e| AdapterError::Other(e.into()))?;
            }

            OutboundType::Vmess => {
                #[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
                {
                    if let Some(conn) = VmessConnector::from_ir(ir) {
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "vmess".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "Vmess outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Socks => {
                // Minimal SOCKS5 upstream connector using scaffold implementation
                use crate::adapter::OutboundConnector as AdapterConnector;

                #[derive(Debug, Clone)]
                struct SocksConnector {
                    inner: std::sync::Arc<crate::outbound::socks_upstream::SocksUp>,
                }

                #[async_trait::async_trait]
                impl OutboundConnector for SocksConnector {
                    async fn dial(
                        &self,
                        target: Target,
                        _opts: DialOpts,
                    ) -> AdapterResult<BoxedStream> {
                        if target.kind != TransportKind::Tcp {
                            return Err(AdapterError::UnsupportedProtocol(
                                "SOCKS upstream does not support UDP (use UDP associate path)".into(),
                            ));
                        }
                        let s = self
                            .inner
                            .connect(&target.host, target.port)
                            .await
                            .map_err(AdapterError::Io)?;
                        Ok(Box::new(s))
                    }
                    fn name(&self) -> &'static str { "socks" }
                }

                let (user, pass) = ir
                    .credentials
                    .as_ref()
                    .map(|c| (c.username.clone(), c.password.clone()))
                    .unwrap_or((None, None));
                let server = ir.server.clone().ok_or(AdapterError::InvalidConfig(
                    "socks.server is required",
                ))?;
                let port = ir.port.ok_or(AdapterError::InvalidConfig(
                    "socks.port is required",
                ))?;
                let up = crate::outbound::socks_upstream::SocksUp::new(server, port, user, pass);
                let conn = SocksConnector { inner: std::sync::Arc::new(up) };
                self.switchboard
                    .register(name.to_string(), conn)
                    .map_err(|e| AdapterError::Other(e.into()))?;
            }

            OutboundType::Vless => {
                #[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
                {
                    if let Some(conn) = VlessConnector::from_ir(ir) {
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "vless".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "Vless outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Trojan => {
                #[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
                {
                    if let Some(conn) = TrojanConnector::from_ir(ir) {
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "trojan".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "Trojan outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Tuic => {
                #[cfg(feature = "out_tuic")]
                {
                    if let Some(cfg) = tuic_from_ir(ir)? {
                        use crate::outbound::crypto_types::OutboundTcp;

                        #[derive(Debug, Clone)]
                        struct TuicConnector {
                            inner: std::sync::Arc<crate::outbound::tuic::TuicOutbound>,
                        }
                        #[async_trait::async_trait]
                        impl OutboundConnector for TuicConnector {
                            async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
                                if target.kind != TransportKind::Tcp {
                                    return Err(AdapterError::UnsupportedProtocol("TUIC UDP not implemented in switchboard".into()));
                                }
                                let hp = crate::outbound::types::HostPort::new(target.host, target.port);
                                let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                                Ok(Box::new(s))
                            }
                            fn name(&self) -> &'static str { "tuic" }
                        }
                        let inner = crate::outbound::tuic::TuicOutbound::new(cfg)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        let inner = std::sync::Arc::new(inner);
                        let conn = TuicConnector { inner: inner.clone() };
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "tuic".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        // Register UDP factory for TUIC
                        if let Some(ref name) = ir.name {
                            let _ = self
                                .switchboard
                                .register_udp_factory(name.clone(), inner.clone());
                        }
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "TUIC outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Hysteria2 => {
                #[cfg(feature = "out_hysteria2")]
                {
                    if let Some(cfg) = hysteria2_from_ir(ir)? {
                        use crate::outbound::crypto_types::OutboundTcp;

                        #[derive(Debug, Clone)]
                        struct Hy2Connector {
                            inner: std::sync::Arc<crate::outbound::hysteria2::Hysteria2Outbound>,
                        }
                        #[async_trait::async_trait]
                        impl OutboundConnector for Hy2Connector {
                            async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
                                if target.kind != TransportKind::Tcp {
                                    return Err(AdapterError::UnsupportedProtocol("Hysteria2 UDP not implemented in switchboard".into()));
                                }
                                let hp = crate::outbound::types::HostPort::new(target.host, target.port);
                                let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                                Ok(Box::new(s))
                            }
                            fn name(&self) -> &'static str { "hysteria2" }
                        }
                        let inner = crate::outbound::hysteria2::Hysteria2Outbound::new(cfg)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        let inner = std::sync::Arc::new(inner);
                        let conn = Hy2Connector { inner: inner.clone() };
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "hysteria2".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        if let Some(ref name) = ir.name {
                            let _ = self
                                .switchboard
                                .register_udp_factory(name.clone(), inner.clone());
                        }
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "Hysteria2 outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Shadowtls => {
                #[cfg(feature = "out_shadowtls")]
                {
                    if let Some(cfg) = shadowtls_from_ir(ir)? {
                        use crate::outbound::crypto_types::OutboundTcp;

                        #[derive(Clone)]
                        struct StlConnector {
                            inner: std::sync::Arc<crate::outbound::shadowtls::ShadowTlsOutbound>,
                        }

                        impl std::fmt::Debug for StlConnector {
                            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                                f.debug_struct("StlConnector").finish_non_exhaustive()
                            }
                        }

                        #[async_trait::async_trait]
                        impl OutboundConnector for StlConnector {
                            async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
                                if target.kind != TransportKind::Tcp {
                                    return Err(AdapterError::UnsupportedProtocol("ShadowTLS only supports TCP".into()));
                                }
                                let hp = crate::outbound::types::HostPort::new(target.host, target.port);
                                let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                                Ok(Box::new(s))
                            }
                            fn name(&self) -> &'static str { "shadowtls" }
                        }
                        let inner = crate::outbound::shadowtls::ShadowTlsOutbound::new(cfg)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        let conn = StlConnector { inner: std::sync::Arc::new(inner) };
                        self.switchboard
                            .register(ir.name.clone().unwrap_or_else(|| "shadowtls".into()), conn)
                            .map_err(|e| AdapterError::Other(e.into()))?;
                        return Ok(());
                    }
                }
                return Err(AdapterError::UnsupportedProtocol(
                    "ShadowTLS outbound not enabled or invalid config".to_string(),
                ));
            }

            OutboundType::Selector | OutboundType::UrlTest => {
                return Err(AdapterError::UnsupportedProtocol(
                    "Selector/urltest outbounds are handled via bridge/registry"
                        .to_string(),
                ));
            }

            OutboundType::Shadowsocks => {
                #[cfg(feature = "out_ss")]
                {
                    #[derive(Clone)]
                    struct SsConnector {
                        inner: std::sync::Arc<crate::outbound::shadowsocks::ShadowsocksOutbound>,
                    }

                    impl std::fmt::Debug for SsConnector {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            f.debug_struct("SsConnector").finish_non_exhaustive()
                        }
                    }

                    #[async_trait::async_trait]
                    impl OutboundConnector for SsConnector {
                        async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
                            if target.kind != TransportKind::Tcp {
                                return Err(AdapterError::UnsupportedProtocol("Shadowsocks UDP via switchboard not implemented".into()));
                            }
                            let hp = crate::outbound::crypto_types::HostPort::new(target.host, target.port);
                            let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                            Ok(Box::new(s))
                        }
                        fn name(&self) -> &'static str { "shadowsocks" }
                    }

                    use crate::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksCipher, ShadowsocksOutbound};
                    use crate::outbound::crypto_types::OutboundTcp;
                    let server = ir.server.clone().ok_or(AdapterError::InvalidConfig("shadowsocks.server is required"))?;
                    let port = ir.port.ok_or(AdapterError::InvalidConfig("shadowsocks.port is required"))?;
                    let password = ir.password.clone().ok_or(AdapterError::InvalidConfig("shadowsocks.password is required"))?;
                    let cipher = match ir.method.as_deref().unwrap_or("aes-256-gcm").to_ascii_lowercase().as_str() {
                        "chacha20-poly1305" => ShadowsocksCipher::Chacha20Poly1305,
                        _ => ShadowsocksCipher::Aes256Gcm,
                    };
                    let cfg = ShadowsocksConfig::new(server, port, password, cipher);
                    let inner = ShadowsocksOutbound::new(cfg);
                    let conn = SsConnector { inner: std::sync::Arc::new(inner) };
                    self.switchboard
                        .register(ir.name.clone().unwrap_or_else(|| "shadowsocks".into()), conn)
                        .map_err(|e| AdapterError::Other(e.into()))?;
                }
                #[cfg(not(feature = "out_ss"))]
                {
                    return Err(AdapterError::UnsupportedProtocol("Shadowsocks feature not enabled".into()));
                }
            }

            _ => {
                return Err(AdapterError::UnsupportedProtocol(format!(
                    "Outbound type {:?} not supported or feature not enabled",
                    ir.ty
                )));
            }
        }

        Ok(())
    }

    /// Consume the builder and return the switchboard
    pub fn build(self) -> OutboundSwitchboard {
        self.switchboard
    }
}

impl Default for SwitchboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// IR → Config mapping helpers (for reuse and contract tests)
// -----------------------------------------------------------------------------

#[cfg(feature = "out_tuic")]
fn tuic_from_ir(ir: &sb_config::ir::OutboundIR) -> AdapterResult<Option<crate::outbound::tuic::TuicConfig>> {
    use crate::outbound::tuic::{TuicConfig, UdpRelayMode};
    let server = match &ir.server { Some(s) if !s.is_empty() => s.clone(), _ => return Ok(None) };
    let port = ir.port.ok_or(AdapterError::InvalidConfig("tuic.port is required"))?;
    let uuid = ir
        .uuid
        .as_ref()
        .ok_or(AdapterError::InvalidConfig("tuic.uuid is required"))
        .and_then(|u| uuid::Uuid::parse_str(u).map_err(|_| AdapterError::InvalidConfig("tuic.uuid invalid")))?;
    let token = ir
        .token
        .as_ref()
        .ok_or(AdapterError::InvalidConfig("tuic.token is required"))?
        .clone();
    let relay_mode = match ir.udp_relay_mode.as_deref() {
        Some(m) if m.eq_ignore_ascii_case("quic") => UdpRelayMode::Quic,
        _ => UdpRelayMode::Native,
    };
    Ok(Some(TuicConfig {
        server,
        port,
        uuid,
        token,
        password: ir.password.clone(),
        congestion_control: ir.congestion_control.clone(),
        alpn: ir.alpn.clone().or_else(|| ir.tls_alpn.clone()),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        udp_relay_mode: relay_mode,
        udp_over_stream: ir.udp_over_stream.unwrap_or(false),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    }))
}

#[cfg(feature = "out_hysteria2")]
fn hysteria2_from_ir(ir: &sb_config::ir::OutboundIR) -> AdapterResult<Option<crate::outbound::hysteria2::Hysteria2Config>> {
    use crate::outbound::hysteria2::{BrutalConfig, Hysteria2Config};
    let server = match &ir.server { Some(s) if !s.is_empty() => s.clone(), _ => return Ok(None) };
    let port = ir.port.ok_or(AdapterError::InvalidConfig("hysteria2.port is required"))?;
    let password = ir.password.clone().ok_or(AdapterError::InvalidConfig("hysteria2.password is required"))?;
    let brutal = match (ir.brutal_up_mbps, ir.brutal_down_mbps) {
        (Some(up), Some(down)) => Some(BrutalConfig { up_mbps: up, down_mbps: down }),
        _ => None,
    };
    let alpn_list = ir
        .tls_alpn
        .as_ref()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect());
    Ok(Some(Hysteria2Config {
        server,
        port,
        password,
        congestion_control: ir.congestion_control.clone(),
        up_mbps: ir.up_mbps,
        down_mbps: ir.down_mbps,
        obfs: ir.obfs.clone(),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        alpn: alpn_list,
        salamander: ir.salamander.clone(),
        brutal,
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    }))
}

#[cfg(feature = "out_shadowtls")]
fn shadowtls_from_ir(ir: &sb_config::ir::OutboundIR) -> AdapterResult<Option<crate::outbound::shadowtls::ShadowTlsConfig>> {
    use crate::outbound::shadowtls::ShadowTlsConfig;
    let server = match &ir.server { Some(s) if !s.is_empty() => s.clone(), _ => return Ok(None) };
    let port = ir.port.ok_or(AdapterError::InvalidConfig("shadowtls.port is required"))?;
    let sni = ir.tls_sni.clone().unwrap_or(server.clone());
    Ok(Some(ShadowTlsConfig {
        server,
        port,
        sni,
        alpn: ir.alpn.clone().or_else(|| ir.tls_alpn.clone()),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_http_and_socks_connectors() {
        let ir = sb_config::ir::ConfigIR {
            outbounds: vec![
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Http,
                    name: Some("h1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(8080),
                    ..Default::default()
                },
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Socks,
                    name: Some("s1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(1080),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let sw = SwitchboardBuilder::from_config_ir(&ir).expect("switchboard");
        let names = sw.list_connectors();
        assert!(names.iter().any(|n| n == "h1"));
        assert!(names.iter().any(|n| n == "s1"));
    }

    #[cfg(feature = "out_ss")]
    #[test]
    fn registers_shadowsocks_connector() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Shadowsocks,
            name: Some("ss1".into()),
            server: Some("127.0.0.1".into()),
            port: Some(8388),
            password: Some("p@ss".into()),
            // method omitted to exercise default injection path
            ..Default::default()
        });
        let sw = SwitchboardBuilder::from_config_ir(&ir).expect("switchboard");
        let names = sw.list_connectors();
        assert!(names.iter().any(|n| n == "ss1"));
    }

    #[cfg(all(feature = "out_tuic", feature = "out_hysteria2"))]
    #[test]
    fn registers_udp_factories_for_quic_protocols() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Tuic,
            name: Some("tu1".into()),
            server: Some("1.1.1.1".into()),
            port: Some(443),
            uuid: Some(uuid::Uuid::new_v4().to_string()),
            token: Some("tok".into()),
            ..Default::default()
        });
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Hysteria2,
            name: Some("hy1".into()),
            server: Some("hy.example".into()),
            port: Some(8443),
            password: Some("pw".into()),
            ..Default::default()
        });
        let sw = SwitchboardBuilder::from_config_ir(&ir).expect("switchboard");
        let udp = sw.list_udp_factories();
        assert!(udp.iter().any(|n| n == "tu1"));
        assert!(udp.iter().any(|n| n == "hy1"));
    }

    #[cfg(feature = "out_tuic")]
    #[test]
    fn tuic_mapping_defaults() {
        let mut ob = sb_config::ir::OutboundIR::default();
        ob.ty = sb_config::ir::OutboundType::Tuic;
        ob.name = Some("tu1".into());
        ob.server = Some("example.com".into());
        ob.port = Some(443);
        ob.uuid = Some(uuid::Uuid::new_v4().to_string());
        ob.token = Some("tok".into());
        // leave optional fields None to exercise defaults

        let cfg = tuic_from_ir(&ob).expect("ok").expect("some");
        assert_eq!(cfg.server, "example.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.skip_cert_verify, false);
        assert_eq!(cfg.udp_over_stream, false);
        assert_eq!(cfg.zero_rtt_handshake, false);
        assert!(cfg.alpn.is_none());
        assert!(cfg.sni.is_none());
    }

    #[cfg(feature = "out_hysteria2")]
    #[test]
    fn hysteria2_mapping_defaults_and_alpn_split() {
        let mut ob = sb_config::ir::OutboundIR::default();
        ob.ty = sb_config::ir::OutboundType::Hysteria2;
        ob.name = Some("hy1".into());
        ob.server = Some("hy.example".into());
        ob.port = Some(8443);
        ob.password = Some("pw".into());
        ob.tls_alpn = Some("h3, hysteria2".into());

        let cfg = hysteria2_from_ir(&ob).expect("ok").expect("some");
        assert_eq!(cfg.server, "hy.example");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.skip_cert_verify, false);
        assert_eq!(cfg.zero_rtt_handshake, false);
        let alpn = cfg.alpn.unwrap();
        assert_eq!(alpn, vec!["h3".to_string(), "hysteria2".to_string()]);
    }

    #[cfg(feature = "out_shadowtls")]
    #[test]
    fn shadowtls_mapping_defaults() {
        let mut ob = sb_config::ir::OutboundIR::default();
        ob.ty = sb_config::ir::OutboundType::Shadowtls;
        ob.name = Some("st1".into());
        ob.server = Some("st.example".into());
        ob.port = Some(443);
        // no sni provided -> default to server

        let cfg = shadowtls_from_ir(&ob).expect("ok").expect("some");
        assert_eq!(cfg.sni, "st.example");
        assert_eq!(cfg.skip_cert_verify, false);
    }
}

/// A degraded connector that returns 501 Not Implemented for failed construction
#[derive(Debug)]
struct DegradedConnector {
    name: String,
    error_reason: String,
}

impl DegradedConnector {
    fn new(name: &str, error_reason: String) -> Self {
        Self {
            name: name.to_string(),
            error_reason,
        }
    }
}

#[async_trait::async_trait]
impl OutboundConnector for DegradedConnector {
    async fn dial(&self, _target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
        Err(AdapterError::NotImplemented(format!(
            "Outbound '{}' is in degraded mode: {}",
            self.name, self.error_reason
        )))
    }

    fn name(&self) -> &'static str {
        "degraded"
    }
}

/// A simple direct connector that establishes direct connections to targets
#[derive(Debug, Clone, Default)]
struct DirectConnector;

#[async_trait::async_trait]
impl OutboundConnector for DirectConnector {
    async fn dial(&self, target: Target, opts: DialOpts) -> AdapterResult<BoxedStream> {
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let addr = format!("{}:{}", target.host, target.port);

        let stream = match target.kind {
            TransportKind::Tcp => timeout(opts.connect_timeout, TcpStream::connect(&addr))
                .await
                .map_err(|_| AdapterError::Timeout(opts.connect_timeout))?
                .map_err(AdapterError::Io)?,
            TransportKind::Udp => {
                return Err(AdapterError::UnsupportedProtocol(
                    "DirectConnector does not support UDP".to_string(),
                ));
            }
        };

        Ok(Box::new(stream))
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

// ----- VMess connector (feature-gated) -----

#[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
#[derive(Debug, Clone)]
struct VmessConnector {
    server: String,
    port: u16,
    uuid: String,
    transport: Option<Vec<String>>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    h2_path: Option<String>,
    h2_host: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    // Extras
    http_upgrade_path: Option<String>,
    http_upgrade_headers: Vec<(String, String)>,
    grpc_service: Option<String>,
    grpc_method: Option<String>,
    grpc_authority: Option<String>,
    grpc_metadata: Vec<(String, String)>,
}

#[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
impl VmessConnector {
    fn from_ir(ob: &sb_config::ir::OutboundIR) -> Option<Self> {
        Some(Self {
            server: ob.server.clone()?,
            port: ob.port?,
            uuid: ob.uuid.clone().unwrap_or_default(),
            transport: ob.transport.clone(),
            ws_path: ob.ws_path.clone(),
            ws_host: ob.ws_host.clone(),
            h2_path: ob.h2_path.clone(),
            h2_host: ob.h2_host.clone(),
            tls_sni: ob.tls_sni.clone(),
            tls_alpn: ob.tls_alpn.clone(),
            http_upgrade_path: ob.http_upgrade_path.clone(),
            http_upgrade_headers: ob
                .http_upgrade_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            grpc_service: ob.grpc_service.clone(),
            grpc_method: ob.grpc_method.clone(),
            grpc_authority: ob.grpc_authority.clone(),
            grpc_metadata: ob
                .grpc_metadata
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        })
    }
}

#[cfg(feature = "v2ray_transport")]
#[allow(dead_code)]
struct IoWrapper(sb_transport::IoStream);

#[cfg(feature = "v2ray_transport")]
impl tokio::io::AsyncRead for IoWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

#[cfg(feature = "v2ray_transport")]
impl tokio::io::AsyncWrite for IoWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

// ----- Trojan connector (feature-gated) -----
#[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
#[derive(Debug, Clone)]
struct TrojanConnector {
    server: String,
    port: u16,
    password: String,
    transport: Option<Vec<String>>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    h2_path: Option<String>,
    h2_host: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    http_upgrade_path: Option<String>,
    http_upgrade_headers: Vec<(String, String)>,
    grpc_service: Option<String>,
    grpc_method: Option<String>,
    grpc_authority: Option<String>,
    grpc_metadata: Vec<(String, String)>,
}

#[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
impl TrojanConnector {
    fn from_ir(ob: &sb_config::ir::OutboundIR) -> Option<Self> {
        Some(Self {
            server: ob.server.clone()?,
            port: ob.port?,
            password: ob.password.clone()?,
            transport: ob.transport.clone(),
            ws_path: ob.ws_path.clone(),
            ws_host: ob.ws_host.clone(),
            h2_path: ob.h2_path.clone(),
            h2_host: ob.h2_host.clone(),
            tls_sni: ob.tls_sni.clone(),
            tls_alpn: ob.tls_alpn.clone(),
            http_upgrade_path: ob.http_upgrade_path.clone(),
            http_upgrade_headers: ob
                .http_upgrade_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            grpc_service: ob.grpc_service.clone(),
            grpc_method: ob.grpc_method.clone(),
            grpc_authority: ob.grpc_authority.clone(),
            grpc_metadata: ob
                .grpc_metadata
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        })
    }
}

#[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
#[async_trait::async_trait]
impl OutboundConnector for TrojanConnector {
    async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
        use crate::outbound::crypto_types::HostPort as Hp;
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        // Helper: single attempt for a given chain
        async fn attempt(
            this: &TrojanConnector,
            target: &Target,
            chain: Option<&[String]>,
        ) -> AdapterResult<BoxedStream> {
            let b = crate::runtime::transport::map::apply_layers(
                TransportBuilder::tcp(),
                chain,
                this.tls_sni.as_deref(),
                this.tls_alpn.as_deref(),
                this.ws_path.as_deref(),
                this.ws_host.as_deref(),
                this.h2_path.as_deref(),
                this.h2_host.as_deref(),
                this.http_upgrade_path.as_deref(),
                &this.http_upgrade_headers,
                this.grpc_service.as_deref(),
                this.grpc_method.as_deref(),
                this.grpc_authority.as_deref(),
                &this.grpc_metadata,
                None,
            );
            let mut s = b
                .build()
                .connect(this.server.as_str(), this.port)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(format!("transport dial failed: {}", e))))?;
            let hp = Hp::new(target.host.clone(), target.port);
            crate::outbound::trojan::TrojanOutbound::handshake_on(&this.password, &hp, &mut *s)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(e.to_string())))?;
            Ok(Box::new(IoWrapper(s)))
        }

        // Primary attempt
        match attempt(self, &target, self.transport.as_deref()).await {
            Ok(s) => Ok(s),
            Err(e) => {
                let enabled = std::env::var("SB_TRANSPORT_FALLBACK")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);
                if !enabled {
                    return Err(e);
                }
                // Build plan from IR hints
                let mut ob = sb_config::ir::OutboundIR::default();
                ob.transport = self.transport.clone();
                ob.ws_path = self.ws_path.clone();
                ob.ws_host = self.ws_host.clone();
                ob.h2_path = self.h2_path.clone();
                ob.h2_host = self.h2_host.clone();
                ob.tls_sni = self.tls_sni.clone();
                ob.tls_alpn = self.tls_alpn.clone();
                ob.http_upgrade_path = self.http_upgrade_path.clone();
                ob.http_upgrade_headers = self
                    .http_upgrade_headers
                    .iter()
                    .map(|(k, v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();
                ob.grpc_service = self.grpc_service.clone();
                ob.grpc_method = self.grpc_method.clone();
                ob.grpc_authority = self.grpc_authority.clone();
                ob.grpc_metadata = self
                    .grpc_metadata
                    .iter()
                    .map(|(k, v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();

                let plans = crate::runtime::transport::map::fallback_chains_from_ir(&ob);
                for alt in plans.into_iter().skip(1) {
                    let mode = alt.join("->");
                    tracing::warn!(
                        target: "sb_core::transport",
                        server = %self.server,
                        port = self.port,
                        alt = %mode,
                        "transport primary failed; trying fallback"
                    );
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>mode.clone(),
                        "result"=>"attempt"
                    ).increment(1);
                    if let Ok(s) = attempt(self, &target, Some(&alt)).await {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "transport_fallback_total",
                            "reason"=>"primary_failed",
                            "mode"=>mode,
                            "result"=>"ok"
                        ).increment(1);
                        return Ok(s);
                    }
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>mode,
                        "result"=>"fail"
                    ).increment(1);
                }
                Err(e)
            }
        }
    }
    fn name(&self) -> &'static str {
        "trojan"
    }
}
// ----- VLESS connector (feature-gated) -----
#[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
#[derive(Debug, Clone)]
struct VlessConnector {
    server: String,
    port: u16,
    uuid: String,
    transport: Option<Vec<String>>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    h2_path: Option<String>,
    h2_host: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    http_upgrade_path: Option<String>,
    http_upgrade_headers: Vec<(String, String)>,
    grpc_service: Option<String>,
    grpc_method: Option<String>,
    grpc_authority: Option<String>,
    grpc_metadata: Vec<(String, String)>,
}

#[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
impl VlessConnector {
    fn from_ir(ob: &sb_config::ir::OutboundIR) -> Option<Self> {
        Some(Self {
            server: ob.server.clone()?,
            port: ob.port?,
            uuid: ob.uuid.clone()?,
            transport: ob.transport.clone(),
            ws_path: ob.ws_path.clone(),
            ws_host: ob.ws_host.clone(),
            h2_path: ob.h2_path.clone(),
            h2_host: ob.h2_host.clone(),
            tls_sni: ob.tls_sni.clone(),
            tls_alpn: ob.tls_alpn.clone(),
            http_upgrade_path: ob.http_upgrade_path.clone(),
            http_upgrade_headers: ob
                .http_upgrade_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            grpc_service: ob.grpc_service.clone(),
            grpc_method: ob.grpc_method.clone(),
            grpc_authority: ob.grpc_authority.clone(),
            grpc_metadata: ob
                .grpc_metadata
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        })
    }
}

#[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
#[async_trait::async_trait]
impl OutboundConnector for VlessConnector {
    async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
        use crate::outbound::types::HostPort as Hp;
        use crate::outbound::vless::{VlessConfig, VlessOutbound};
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        // Attempt helper builds a fresh outbound per attempt
        async fn attempt(
            this: &VlessConnector,
            target: &Target,
            chain: Option<&[String]>,
        ) -> AdapterResult<BoxedStream> {
            let b = crate::runtime::transport::map::apply_layers(
                TransportBuilder::tcp(),
                chain,
                this.tls_sni.as_deref(),
                this.tls_alpn.as_deref(),
                this.ws_path.as_deref(),
                this.ws_host.as_deref(),
                this.h2_path.as_deref(),
                this.h2_host.as_deref(),
                this.http_upgrade_path.as_deref(),
                &this.http_upgrade_headers,
                this.grpc_service.as_deref(),
                this.grpc_method.as_deref(),
                this.grpc_authority.as_deref(),
                &this.grpc_metadata,
                None,
            );
            let mut s = b
                .build()
                .connect(this.server.as_str(), this.port)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(format!("transport dial failed: {}", e))))?;
            let id = uuid::Uuid::parse_str(&this.uuid)
                .map_err(|_| AdapterError::InvalidConfig("vless uuid parse"))?;
            let cfg = VlessConfig {
                server: this.server.clone(),
                port: this.port,
                uuid: id,
                flow: None,
                encryption: Some("none".into()),
                ..Default::default()
            };
            let outbound = VlessOutbound::new(cfg)
                .map_err(|_| AdapterError::InvalidConfig("vless config"))?;
            let hp = Hp::new(target.host.clone(), target.port);
            outbound
                .do_handshake_on(&hp, &mut *s)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(e.to_string())))?;
            Ok(Box::new(IoWrapper(s)) as BoxedStream)
        }

        match attempt(self, &target, self.transport.as_deref()).await {
            Ok(s) => Ok(s),
            Err(e) => {
                let enabled = std::env::var("SB_TRANSPORT_FALLBACK")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);
                if !enabled { return Err(e); }
                let mut ob = sb_config::ir::OutboundIR::default();
                ob.transport = self.transport.clone();
                ob.ws_path = self.ws_path.clone();
                ob.ws_host = self.ws_host.clone();
                ob.h2_path = self.h2_path.clone();
                ob.h2_host = self.h2_host.clone();
                ob.tls_sni = self.tls_sni.clone();
                ob.tls_alpn = self.tls_alpn.clone();
                ob.http_upgrade_path = self.http_upgrade_path.clone();
                ob.http_upgrade_headers = self
                    .http_upgrade_headers
                    .iter()
                    .map(|(k,v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();
                ob.grpc_service = self.grpc_service.clone();
                ob.grpc_method = self.grpc_method.clone();
                ob.grpc_authority = self.grpc_authority.clone();
                ob.grpc_metadata = self
                    .grpc_metadata
                    .iter()
                    .map(|(k,v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();
                let plans = crate::runtime::transport::map::fallback_chains_from_ir(&ob);
                for alt in plans.into_iter().skip(1) {
                    tracing::warn!(target:"sb_core::transport", server=%self.server, port=self.port, alt=%alt.join("->"), "transport primary failed; trying fallback");
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>alt.join("->"),
                        "result"=>"attempt"
                    ).increment(1);
                    if let Ok(s) = attempt(self, &target, Some(&alt)).await {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "transport_fallback_total",
                            "reason"=>"primary_failed",
                            "mode"=>alt.join("->"),
                            "result"=>"ok"
                        ).increment(1);
                        return Ok(s);
                    }
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>alt.join("->"),
                        "result"=>"fail"
                    ).increment(1);
                }
                Err(e)
            }
        }
    }
    fn name(&self) -> &'static str {
        "vless"
    }
}
#[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
#[async_trait::async_trait]
impl OutboundConnector for VmessConnector {
    async fn dial(&self, target: Target, _opts: DialOpts) -> AdapterResult<BoxedStream> {
        use crate::outbound::crypto_types::HostPort as Hp;
        use crate::outbound::vmess::{VmessConfig, VmessOutbound};
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        // Build + handshake per attempt (no captured moves)
        async fn attempt(
            this: &VmessConnector,
            target: &Target,
            chain: Option<&[String]>,
        ) -> AdapterResult<BoxedStream> {
            let b = crate::runtime::transport::map::apply_layers(
                TransportBuilder::tcp(),
                chain,
                this.tls_sni.as_deref(),
                this.tls_alpn.as_deref(),
                this.ws_path.as_deref(),
                this.ws_host.as_deref(),
                this.h2_path.as_deref(),
                this.h2_host.as_deref(),
                this.http_upgrade_path.as_deref(),
                &this.http_upgrade_headers,
                this.grpc_service.as_deref(),
                this.grpc_method.as_deref(),
                this.grpc_authority.as_deref(),
                &this.grpc_metadata,
                None,
            );
            let mut s = b
                .build()
                .connect(this.server.as_str(), this.port)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(format!("transport dial failed: {}", e))))?;
            // Build outbound and perform handshake for each attempt
            let id = uuid::Uuid::parse_str(&this.uuid)
                .map_err(|_| AdapterError::InvalidConfig("vmess uuid parse"))?;
            let vm_cfg = VmessConfig {
                server: this.server.clone(),
                port: this.port,
                id,
                security: "aes-128-gcm".to_string(),
                alter_id: 0,
                ..Default::default()
            };
            let outbound = VmessOutbound::new(vm_cfg)
                .map_err(|_| AdapterError::InvalidConfig("vmess config"))?;
            let hp = Hp::new(target.host.clone(), target.port);
            outbound
                .do_handshake_on(&hp, &mut *s)
                .await
                .map_err(|e| AdapterError::Other(anyhow::anyhow!(e.to_string())))?;
            Ok(Box::new(IoWrapper(s)) as BoxedStream)
        }

        match attempt(self, &target, self.transport.as_deref()).await {
            Ok(s) => Ok(s),
            Err(e) => {
                let enabled = std::env::var("SB_TRANSPORT_FALLBACK")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);
                if !enabled { return Err(e); }
                let mut ob = sb_config::ir::OutboundIR::default();
                ob.transport = self.transport.clone();
                ob.ws_path = self.ws_path.clone();
                ob.ws_host = self.ws_host.clone();
                ob.h2_path = self.h2_path.clone();
                ob.h2_host = self.h2_host.clone();
                ob.tls_sni = self.tls_sni.clone();
                ob.tls_alpn = self.tls_alpn.clone();
                ob.http_upgrade_path = self.http_upgrade_path.clone();
                ob.http_upgrade_headers = self
                    .http_upgrade_headers
                    .iter()
                    .map(|(k,v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();
                ob.grpc_service = self.grpc_service.clone();
                ob.grpc_method = self.grpc_method.clone();
                ob.grpc_authority = self.grpc_authority.clone();
                ob.grpc_metadata = self
                    .grpc_metadata
                    .iter()
                    .map(|(k,v)| sb_config::ir::HeaderEntry { name: k.clone(), value: v.clone() })
                    .collect();
                let plans = crate::runtime::transport::map::fallback_chains_from_ir(&ob);
                for alt in plans.into_iter().skip(1) {
                    let mode = alt.join("->");
                    tracing::warn!(target:"sb_core::transport", server=%self.server, port=self.port, alt=%mode, "transport primary failed; trying fallback");
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>mode.clone(),
                        "result"=>"attempt"
                    ).increment(1);
                    if let Ok(s) = attempt(self, &target, Some(&alt)).await {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "transport_fallback_total",
                            "reason"=>"primary_failed",
                            "mode"=>mode,
                            "result"=>"ok"
                        ).increment(1);
                        return Ok(s);
                    }
                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "transport_fallback_total",
                        "reason"=>"primary_failed",
                        "mode"=>mode,
                        "result"=>"fail"
                    ).increment(1);
                }
                Err(e)
            }
        }
    }
    fn name(&self) -> &'static str {
        "vmess"
    }
}
