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
    pub fn get_udp_factory(
        &self,
        name: &str,
    ) -> Option<Arc<dyn crate::adapter::UdpOutboundFactory>> {
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
    #[allow(unreachable_code)]
    fn try_register_from_ir(&mut self, ir: &sb_config::ir::OutboundIR) -> AdapterResult<()> {
        use sb_config::ir::OutboundType;

        #[allow(unused_variables)]
        let name = ir.name.as_deref().unwrap_or("unnamed");

        match ir.ty {
            OutboundType::Http => {
                #[cfg(feature = "scaffold")]
                {
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
                        fn name(&self) -> &'static str {
                            "http"
                        }
                    }

                    let (user, pass) = ir
                        .credentials
                        .as_ref()
                        .map(|c| (c.username.clone(), c.password.clone()))
                        .unwrap_or((None, None));
                    let server = ir
                        .server
                        .clone()
                        .ok_or(AdapterError::InvalidConfig("http.server is required"))?;
                    let port = ir
                        .port
                        .ok_or(AdapterError::InvalidConfig("http.port is required"))?;
                    let up = crate::outbound::http_upstream::HttpUp::new(server, port, user, pass);
                    let conn = HttpConnector {
                        inner: std::sync::Arc::new(up),
                    };
                    self.switchboard
                        .register(name.to_string(), conn)
                        .map_err(|e| AdapterError::Other(e.into()))?;
                }
                #[cfg(not(feature = "scaffold"))]
                {
                    return Err(AdapterError::UnsupportedProtocol(
                        "HTTP outbound requires scaffold feature".into(),
                    ));
                }
            }

            OutboundType::Socks => {
                #[cfg(feature = "scaffold")]
                {
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
                                    "SOCKS upstream does not support UDP (use UDP associate path)"
                                        .into(),
                                ));
                            }
                            let s = self
                                .inner
                                .connect(&target.host, target.port)
                                .await
                                .map_err(AdapterError::Io)?;
                            Ok(Box::new(s))
                        }
                        fn name(&self) -> &'static str {
                            "socks"
                        }
                    }

                    let (user, pass) = ir
                        .credentials
                        .as_ref()
                        .map(|c| (c.username.clone(), c.password.clone()))
                        .unwrap_or((None, None));
                    let server = ir
                        .server
                        .clone()
                        .ok_or(AdapterError::InvalidConfig("socks.server is required"))?;
                    let port = ir
                        .port
                        .ok_or(AdapterError::InvalidConfig("socks.port is required"))?;
                    let up =
                        crate::outbound::socks_upstream::SocksUp::new(server, port, user, pass);
                    let conn = SocksConnector {
                        inner: std::sync::Arc::new(up),
                    };
                    self.switchboard
                        .register(name.to_string(), conn)
                        .map_err(|e| AdapterError::Other(e.into()))?;
                }
                #[cfg(not(feature = "scaffold"))]
                {
                    return Err(AdapterError::UnsupportedProtocol(
                        "SOCKS outbound requires scaffold feature".into(),
                    ));
                }
            }

            OutboundType::Hysteria2 => {
                #[cfg(feature = "out_hysteria2")]
                {
                    use crate::outbound::types::OutboundTcp as _; // Trait import for .connect()
                    if let Some(cfg) = hysteria2_from_ir(ir)? {
                        #[derive(Debug, Clone)]
                        struct Hy2Connector {
                            inner: std::sync::Arc<crate::outbound::hysteria2::Hysteria2Outbound>,
                        }
                        #[async_trait::async_trait]
                        impl OutboundConnector for Hy2Connector {
                            async fn dial(
                                &self,
                                target: Target,
                                _opts: DialOpts,
                            ) -> AdapterResult<BoxedStream> {
                                if target.kind != TransportKind::Tcp {
                                    return Err(AdapterError::UnsupportedProtocol(
                                        "Hysteria2 UDP not implemented in switchboard".into(),
                                    ));
                                }
                                let hp =
                                    crate::outbound::types::HostPort::new(target.host, target.port);
                                let s = self.inner.connect(&hp).await.map_err(AdapterError::Io)?;
                                Ok(Box::new(s))
                            }
                            fn name(&self) -> &'static str {
                                "hysteria2"
                            }
                        }
                        let inner = crate::outbound::hysteria2::Hysteria2Outbound::new(cfg)
                            .map_err(AdapterError::Other)?;
                        let inner = std::sync::Arc::new(inner);
                        let conn = Hy2Connector {
                            inner: inner.clone(),
                        };
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

            OutboundType::Selector | OutboundType::UrlTest => {
                return Err(AdapterError::UnsupportedProtocol(
                    "Selector/urltest outbounds are handled via bridge/registry".to_string(),
                ));
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
// IR -> Config mapping helpers (for reuse and contract tests)
// -----------------------------------------------------------------------------

#[cfg(feature = "out_hysteria2")]
fn hysteria2_from_ir(
    ir: &sb_config::ir::OutboundIR,
) -> AdapterResult<Option<crate::outbound::hysteria2::Hysteria2Config>> {
    use crate::outbound::hysteria2::{BrutalConfig, Hysteria2Config};
    let server = match &ir.server {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return Ok(None),
    };
    let port = ir
        .port
        .ok_or(AdapterError::InvalidConfig("hysteria2.port is required"))?;
    let password = ir.password.clone().ok_or(AdapterError::InvalidConfig(
        "hysteria2.password is required",
    ))?;
    let brutal = match (ir.brutal_up_mbps, ir.brutal_down_mbps) {
        (Some(up), Some(down)) => Some(BrutalConfig {
            up_mbps: up,
            down_mbps: down,
        }),
        _ => None,
    };
    let alpn_list = ir.tls_alpn.clone();
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

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "scaffold")]
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

    #[cfg(feature = "out_hysteria2")]
    #[test]
    fn hysteria2_mapping_defaults_and_alpn_split() {
        let ob = sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Hysteria2,
            name: Some("hy1".into()),
            server: Some("hy.example".into()),
            port: Some(8443),
            password: Some("pw".into()),
            tls_alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            ..Default::default()
        };

        let cfg = hysteria2_from_ir(&ob).expect("ok").expect("some");
        assert_eq!(cfg.server, "hy.example");
        assert_eq!(cfg.port, 8443);
        assert!(!cfg.skip_cert_verify);
        assert!(!cfg.zero_rtt_handshake);
        let alpn = cfg.alpn.unwrap();
        assert_eq!(alpn, vec!["h3".to_string(), "hysteria2".to_string()]);
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
