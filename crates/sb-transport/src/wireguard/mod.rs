//! WireGuard transport layer implementation.
//!
//! Provides WireGuard tunnel transport using boringtun for the Noise crypto and a
//! smoltcp userspace TCP/IP stack (see [`netstack`]) for turning tunnel IP packets
//! into real proxyable streams.
//!
//! # Example
//! ```ignore
//! use sb_transport::wireguard::{WireGuardTransport, WireGuardConfig};
//!
//! let config = WireGuardConfig {
//!     private_key: "base64_private_key".to_string(),
//!     peer_public_key: "base64_peer_public_key".to_string(),
//!     peer_endpoint: "192.168.1.1:51820".parse().unwrap(),
//!     local_addrs: vec!["10.7.0.2".parse().unwrap()],
//!     ..Default::default()
//! };
//!
//! let transport = WireGuardTransport::new(config).await?;
//! ```

// Userspace TCP/IP netstack (smoltcp over boringtun `Tunn`) — see netstack.rs.
mod netstack;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::{DialError, Dialer, IoStream};
use netstack::WgNetStack;

pub use netstack::WgUdpSocket;

/// WireGuard transport configuration.
#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    /// Local private key (base64 encoded).
    pub private_key: String,
    /// Peer's public key (base64 encoded).
    pub peer_public_key: String,
    /// Optional pre-shared key (base64 encoded).
    pub pre_shared_key: Option<String>,
    /// Peer endpoint address.
    pub peer_endpoint: SocketAddr,
    /// Local UDP bind address for the outer socket (default: 0.0.0.0:0).
    pub local_addr: Option<SocketAddr>,
    /// WireGuard interface addresses, used as the source for in-tunnel connections.
    /// At least one matching the target's IP family is required to dial.
    pub local_addrs: Vec<IpAddr>,
    /// Persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
    /// MTU for the tunnel (default: 1408, matching Go sing-box).
    pub mtu: u16,
    /// WireGuard `reserved` bytes (written into packet[1..4] on send, cleared on
    /// receive), per Go `transport/wireguard/client_bind.go`. Default `[0,0,0]`.
    pub reserved: [u8; 3],
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            pre_shared_key: None,
            peer_endpoint: SocketAddr::from(([0, 0, 0, 0], 51820)),
            local_addr: None,
            local_addrs: Vec::new(),
            persistent_keepalive: Some(25),
            mtu: 1408,
            reserved: [0, 0, 0],
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Decode a base64 WireGuard key into 32 raw bytes.
fn decode_key32(s: &str) -> Option<[u8; 32]> {
    BASE64.decode(s).ok()?.try_into().ok()
}

/// WireGuard transport: a boringtun tunnel fronted by a smoltcp userspace netstack.
pub struct WireGuardTransport {
    netstack: WgNetStack,
    connect_timeout: Duration,
}

impl std::fmt::Debug for WireGuardTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardTransport").finish_non_exhaustive()
    }
}

impl WireGuardTransport {
    /// Create a new WireGuard transport and spawn its netstack driver.
    pub async fn new(config: WireGuardConfig) -> Result<Self, WireGuardError> {
        let private_key =
            decode_key32(&config.private_key).ok_or(WireGuardError::InvalidPrivateKey)?;
        let peer_pk =
            decode_key32(&config.peer_public_key).ok_or(WireGuardError::InvalidPeerPublicKey)?;
        let psk: Option<[u8; 32]> = match &config.pre_shared_key {
            Some(s) => Some(decode_key32(s).ok_or(WireGuardError::InvalidPreSharedKey)?),
            None => None,
        };

        let local_bind = config
            .local_addr
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = UdpSocket::bind(local_bind)
            .await
            .map_err(WireGuardError::SocketBind)?;

        debug!(
            "WireGuard bound to {}, peer endpoint: {}",
            socket
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| local_bind.to_string()),
            config.peer_endpoint
        );

        #[cfg(target_os = "android")]
        if let Err(e) = sb_platform::android_protect::protect_udp_socket(&socket) {
            tracing::warn!("Failed to protect WireGuard socket: {}", e);
        }

        let socket = std::sync::Arc::new(socket);

        let tunn = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(peer_pk),
            psk,
            config.persistent_keepalive,
            0,    // index
            None, // rate limiter
        );

        let netstack = WgNetStack::new(
            tunn,
            socket,
            config.peer_endpoint,
            &config.local_addrs,
            config.mtu as usize,
            config.reserved,
        );

        Ok(Self {
            netstack,
            connect_timeout: config.connect_timeout,
        })
    }

    /// Proactively (re)initiate the Noise handshake (warm-up / roaming aid).
    pub async fn handshake(&self) -> io::Result<()> {
        self.netstack.handshake().await;
        Ok(())
    }

    /// Update the peer endpoint address (roaming).
    pub async fn set_peer_endpoint(&self, addr: SocketAddr) {
        self.netstack.set_peer_endpoint(addr).await;
    }

    /// Open a UDP datagram socket through the tunnel.
    pub async fn connect_udp(&self) -> Result<WgUdpSocket, DialError> {
        self.netstack.connect_udp().await
    }
}

#[async_trait]
impl Dialer for WireGuardTransport {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("WireGuard dialing {}:{}", host, port);
        let stream = self
            .netstack
            .connect_tcp(host, port, self.connect_timeout)
            .await?;
        Ok(Box::new(stream) as IoStream)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Errors that can occur in WireGuard transport.
#[derive(Debug, thiserror::Error)]
pub enum WireGuardError {
    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid peer public key")]
    InvalidPeerPublicKey,

    #[error("Invalid pre-shared key")]
    InvalidPreSharedKey,

    #[error("Socket bind error: {0}")]
    SocketBind(#[source] io::Error),

    #[error("Handshake failed")]
    HandshakeFailed,

    #[error("Tunnel error: {0}")]
    Tunnel(String),
}

impl From<WireGuardError> for DialError {
    fn from(e: WireGuardError) -> Self {
        DialError::Other(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WireGuardConfig::default();
        assert_eq!(config.mtu, 1408);
        assert_eq!(config.persistent_keepalive, Some(25));
        assert_eq!(config.reserved, [0, 0, 0]);
        assert!(config.local_addrs.is_empty());
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_key_parsing() {
        let valid_private_key = "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=";
        let valid_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
        assert!(decode_key32(valid_private_key).is_some());
        assert!(decode_key32(valid_public_key).is_some());
    }

    #[test]
    fn test_invalid_key_detection() {
        assert!(decode_key32("not-valid-base64!!!").is_none());
        let too_short = BASE64.encode([0u8; 16]);
        assert!(decode_key32(&too_short).is_none());
    }
}
