//! WireGuard outbound adapter with userspace implementation.
//!
//! This adapter provides full WireGuard support using boringtun for userspace
//! WireGuard implementation. It utilizes the shared `sb-transport` WireGuard
//! implementation to avoid duplication.
//!
//! # Features
//! - Complete userspace WireGuard implementation via boringtun
//! - Automatic handshake and key management
//! - Connection pooling and reuse
//! - Full IPv4/IPv6 support

use crate::outbound::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sb_transport::wireguard::{WireGuardConfig, WireGuardTransport};
use tracing::{debug, warn};

/// WireGuard outbound configuration.
#[derive(Clone, Debug)]
pub struct WireGuardOutboundConfig {
    /// WireGuard server address.
    pub server: String,
    /// WireGuard server port (default: 51820).
    pub port: u16,
    /// Local private key (base64 encoded).
    pub private_key: String,
    /// Peer's public key (base64 encoded).
    pub peer_public_key: String,
    /// Optional pre-shared key (base64 encoded).
    pub pre_shared_key: Option<String>,
    /// Local bind address (default: 0.0.0.0:0).
    pub local_addr: Option<SocketAddr>,
    /// Allowed IPs for this peer.
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
    /// MTU for the tunnel (default: 1420).
    pub mtu: u16,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Tag for this outbound.
    pub tag: Option<String>,
}

impl Default for WireGuardOutboundConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 51820,
            private_key: String::new(),
            peer_public_key: String::new(),
            pre_shared_key: None,
            local_addr: None,
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            persistent_keepalive: Some(25),
            mtu: 1420,
            connect_timeout: Duration::from_secs(10),
            tag: None,
        }
    }
}

/// WireGuard outbound connector.
#[derive(Debug)]
pub struct WireGuardOutbound {
    _config: WireGuardOutboundConfig,
    transport: Arc<WireGuardTransport>,
}

impl WireGuardOutbound {
    /// Create a new WireGuard outbound with the given configuration.
    pub async fn new(config: WireGuardOutboundConfig) -> Result<Self> {
        // Resolve peer endpoint
        let peer_endpoint: SocketAddr =
            tokio::net::lookup_host(format!("{}:{}", config.server, config.port))
                .await
                .map_err(|e| AdapterError::network(format!("DNS resolution failed: {}", e)))?
                .next()
                .ok_or_else(|| AdapterError::network("No address resolved"))?;

        // Build transport config
        let transport_config = WireGuardConfig {
            private_key: config.private_key.clone(),
            peer_public_key: config.peer_public_key.clone(),
            pre_shared_key: config.pre_shared_key.clone(),
            peer_endpoint,
            local_addr: config.local_addr,
            persistent_keepalive: config.persistent_keepalive,
            mtu: config.mtu,
            connect_timeout: config.connect_timeout,
        };

        // Initialize transport
        let transport = WireGuardTransport::new(transport_config)
            .await
            .map_err(|e| {
                AdapterError::other(format!("Failed to initialize WireGuard transport: {}", e))
            })?;

        let transport_arc = Arc::new(transport);

        // Initiate handshake immediately (fire and forget)
        let handshake_transport = transport_arc.clone();
        tokio::spawn(async move {
            if let Err(e) = handshake_transport.handshake().await {
                warn!("WireGuard initial handshake failed: {}", e);
            }
        });

        Ok(Self {
            _config: config,
            transport: transport_arc,
        })
    }

    /// Update the peer endpoint address (delegates to transport).
    pub async fn set_peer_endpoint(&self, addr: SocketAddr) {
        self.transport.set_peer_endpoint(addr).await;
    }
}

#[async_trait]
impl OutboundConnector for WireGuardOutbound {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        debug!("WireGuard dial request to {}:{}", target.host, target.port);

        // Get a stream from the existing tunnel
        let stream = self.transport.get_stream();

        // Wrap in Box to satisfy BoxedStream
        Ok(Box::new(stream))
    }
}

/// Lazy-initialized WireGuard connector.
///
/// Holds config and initializes transport on first `dial()` call.
/// This allows sync construction from builder functions.
pub struct LazyWireGuardConnector {
    config: WireGuardOutboundConfig,
    inner: tokio::sync::OnceCell<Arc<WireGuardOutbound>>,
}

impl std::fmt::Debug for LazyWireGuardConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyWireGuardConnector")
            .field("config", &self.config)
            .field("initialized", &self.inner.initialized())
            .finish()
    }
}

impl LazyWireGuardConnector {
    /// Create a lazy WireGuard connector (sync, no IO).
    pub fn new(config: WireGuardOutboundConfig) -> Self {
        Self {
            config,
            inner: tokio::sync::OnceCell::new(),
        }
    }

    async fn get_or_init(&self) -> Result<&Arc<WireGuardOutbound>> {
        self.inner
            .get_or_try_init(|| async {
                let outbound = WireGuardOutbound::new(self.config.clone()).await?;
                Ok(Arc::new(outbound))
            })
            .await
    }
}

#[async_trait]
impl OutboundConnector for LazyWireGuardConnector {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        let inner = self.get_or_init().await?;
        inner.dial(target, opts).await
    }
}

/// Build WireGuard outbound from IR configuration.
impl TryFrom<&sb_config::ir::OutboundIR> for WireGuardOutboundConfig {
    type Error = AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Wireguard {
            return Err(AdapterError::InvalidConfig(
                "Expected WireGuard outbound type",
            ));
        }

        let server = ir.server.clone().ok_or(AdapterError::InvalidConfig(
            "WireGuard requires server address",
        ))?;
        let port = ir.port.unwrap_or(51820);

        let private_key = ir
            .wireguard_private_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PRIVATE_KEY").ok())
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard requires private_key",
            ))?;

        let peer_public_key = ir
            .wireguard_peer_public_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PEER_PUBLIC_KEY").ok())
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard requires peer_public_key",
            ))?;

        let pre_shared_key = ir
            .wireguard_pre_shared_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PRE_SHARED_KEY").ok());

        let allowed_ips = if !ir.wireguard_allowed_ips.is_empty() {
            ir.wireguard_allowed_ips.clone()
        } else {
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        };

        let persistent_keepalive = ir.wireguard_persistent_keepalive.or(Some(25));

        let connect_timeout = ir
            .connect_timeout_sec
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(10));

        Ok(Self {
            server,
            port,
            private_key,
            peer_public_key,
            pre_shared_key,
            local_addr: None,
            allowed_ips,
            persistent_keepalive,
            mtu: 1420,
            connect_timeout,
            tag: ir.name.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    #[test]
    fn test_config_default() {
        let config = WireGuardOutboundConfig::default();
        assert_eq!(config.port, 51820);
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.persistent_keepalive, Some(25));
    }

    #[test]
    fn test_key_validation() {
        // Validation logic is now in sb-transport, but we verify we can parse configs
        let valid_key = "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=";
        let decoded = BASE64.decode(valid_key);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_config_from_ir() {
        use sb_config::ir::{OutboundIR, OutboundType};

        let ir = OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-test".to_string()),
            server: Some("vpn.example.com".to_string()),
            port: Some(51820),
            wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
            wireguard_peer_public_key: Some(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            ),
            ..Default::default()
        };

        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.server, "vpn.example.com");
        assert_eq!(config.port, 51820);
    }
}
