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

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
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
}

impl OutboundSwitchboard {
    /// Create a new empty switchboard
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            default_connector: None,
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
        tokio::spawn(async move {
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
        });

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
        tokio::spawn(async move {
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
        });

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
                Ok(_) => {
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
            OutboundType::Http => {
                // For now, register as degraded - actual implementation will be added later
                let degraded =
                    DegradedConnector::new(name, "HTTP connector not implemented yet".to_string());
                self.switchboard
                    .register(name.to_string(), degraded)
                    .map_err(|e| AdapterError::Other(e.into()))?;
            }

            OutboundType::Socks => {
                // For now, register as degraded - actual implementation will be added later
                let degraded =
                    DegradedConnector::new(name, "SOCKS connector not implemented yet".to_string());
                self.switchboard
                    .register(name.to_string(), degraded)
                    .map_err(|e| AdapterError::Other(e.into()))?;
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
