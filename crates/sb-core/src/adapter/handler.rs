//! Extended handler traits and upstream wrappers (Go parity)
//!
//! This module provides Go-style extended handler interfaces:
//! - ConnectionHandlerEx: Extended TCP connection handling with OOB data
//! - PacketHandlerEx: Extended UDP packet handling
//! - UpstreamHandler: Upstream connection wrapper

use async_trait::async_trait;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Out-of-band data for connection handling (Go parity: N.OutOfBand)
#[derive(Debug, Clone, Default)]
pub struct OutOfBandData {
    /// Source address override
    pub source: Option<SocketAddr>,
    /// Destination address override
    pub destination: Option<SocketAddr>,
    /// Original destination (e.g., from TProxy)
    pub original_destination: Option<SocketAddr>,
    /// User identifier (for authentication)
    pub user: Option<String>,
    /// Inbound tag (which inbound accepted this connection)
    pub inbound_tag: Option<String>,
    /// Process info if available
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    /// Network type (tcp/udp)
    pub network: Option<String>,
}

/// Extended connection handler with OOB support (Go parity: adapter.ConnectionHandlerEx)
#[async_trait]
pub trait ConnectionHandlerEx: Send + Sync {
    /// Handle a new TCP connection with out-of-band data.
    async fn handle_connection_ex(
        &self,
        stream: Box<dyn AsyncStream>,
        oob: &OutOfBandData,
    ) -> Result<()>;
}

/// Extended packet handler (Go parity: adapter.PacketHandlerEx)
#[async_trait]
pub trait PacketHandlerEx: Send + Sync {
    /// Handle a UDP packet with out-of-band data.
    async fn handle_packet_ex(
        &self,
        packet: &[u8],
        source: SocketAddr,
        destination: SocketAddr,
        oob: &OutOfBandData,
    ) -> Result<Vec<u8>>;
}

/// Upstream handler wrapper (Go parity: upstream handler pattern)
#[async_trait]
pub trait UpstreamHandler: Send + Sync {
    /// Get the upstream tag/name
    fn tag(&self) -> &str;
    
    /// Connect to the upstream destination
    async fn connect(&self, host: &str, port: u16) -> Result<Box<dyn AsyncStream>>;
    
    /// Check if this upstream supports UDP
    fn supports_udp(&self) -> bool {
        false
    }
}

/// Combined read+write stream trait
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// Handler with lifecycle support (Go parity: adapter lifecycle pattern)
#[async_trait]
pub trait HandlerLifecycle: Send + Sync {
    /// Initialize the handler
    async fn start(&self) -> Result<()> {
        Ok(())
    }
    
    /// Close the handler
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Combined handler implementing both connection and packet handling
pub trait CombinedHandler: ConnectionHandlerEx + PacketHandlerEx + HandlerLifecycle {}

/// Upstream wrapper that adapts an outbound connector to UpstreamHandler
pub struct UpstreamWrapper {
    tag: String,
    connector: Arc<dyn super::OutboundConnector>,
}

impl UpstreamWrapper {
    pub fn new(tag: String, connector: Arc<dyn super::OutboundConnector>) -> Self {
        Self { tag, connector }
    }
}

#[async_trait]
impl UpstreamHandler for UpstreamWrapper {
    fn tag(&self) -> &str {
        &self.tag
    }
    
    async fn connect(&self, host: &str, port: u16) -> Result<Box<dyn AsyncStream>> {
        let stream = self.connector.connect(host, port).await?;
        Ok(Box::new(stream))
    }
}

/// Handler registry for extended handlers
pub struct HandlerRegistry {
    connection_handlers: parking_lot::RwLock<std::collections::HashMap<String, Arc<dyn ConnectionHandlerEx>>>,
    packet_handlers: parking_lot::RwLock<std::collections::HashMap<String, Arc<dyn PacketHandlerEx>>>,
    upstream_handlers: parking_lot::RwLock<std::collections::HashMap<String, Arc<dyn UpstreamHandler>>>,
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            connection_handlers: parking_lot::RwLock::new(std::collections::HashMap::new()),
            packet_handlers: parking_lot::RwLock::new(std::collections::HashMap::new()),
            upstream_handlers: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    /// Register a connection handler
    pub fn register_connection_handler(&self, tag: String, handler: Arc<dyn ConnectionHandlerEx>) {
        self.connection_handlers.write().insert(tag, handler);
    }
    
    /// Register a packet handler
    pub fn register_packet_handler(&self, tag: String, handler: Arc<dyn PacketHandlerEx>) {
        self.packet_handlers.write().insert(tag, handler);
    }
    
    /// Register an upstream handler
    pub fn register_upstream(&self, tag: String, handler: Arc<dyn UpstreamHandler>) {
        self.upstream_handlers.write().insert(tag, handler);
    }
    
    /// Get a connection handler by tag
    pub fn get_connection_handler(&self, tag: &str) -> Option<Arc<dyn ConnectionHandlerEx>> {
        self.connection_handlers.read().get(tag).cloned()
    }
    
    /// Get a packet handler by tag
    pub fn get_packet_handler(&self, tag: &str) -> Option<Arc<dyn PacketHandlerEx>> {
        self.packet_handlers.read().get(tag).cloned()
    }
    
    /// Get an upstream handler by tag
    pub fn get_upstream(&self, tag: &str) -> Option<Arc<dyn UpstreamHandler>> {
        self.upstream_handlers.read().get(tag).cloned()
    }
    
    /// List all registered tags
    pub fn list_connection_tags(&self) -> Vec<String> {
        self.connection_handlers.read().keys().cloned().collect()
    }
    
    pub fn list_packet_tags(&self) -> Vec<String> {
        self.packet_handlers.read().keys().cloned().collect()
    }
    
    pub fn list_upstream_tags(&self) -> Vec<String> {
        self.upstream_handlers.read().keys().cloned().collect()
    }
}
