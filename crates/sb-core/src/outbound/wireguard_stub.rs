//! WireGuard outbound placeholder implementation
//!
//! This is a placeholder implementation for WireGuard protocol support.
//! Full implementation will use boringtun or similar WireGuard implementation.

#[cfg(feature = "out_wireguard")]
use async_trait::async_trait;
#[cfg(feature = "out_wireguard")]
use std::io;
#[cfg(feature = "out_wireguard")]
use tokio::net::TcpStream;

#[cfg(feature = "out_wireguard")]
use super::crypto_types::{HostPort, OutboundTcp};

#[cfg(feature = "out_wireguard")]
#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub peer_public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[cfg(feature = "out_wireguard")]
pub struct WireGuardOutbound {
    config: WireGuardConfig,
}

#[cfg(feature = "out_wireguard")]
impl WireGuardOutbound {
    pub fn new(config: WireGuardConfig) -> anyhow::Result<Self> {
        // Validate configuration
        if config.private_key.is_empty() {
            return Err(anyhow::anyhow!("WireGuard private key is required"));
        }
        if config.public_key.is_empty() {
            return Err(anyhow::anyhow!("WireGuard public key is required"));
        }
        if config.peer_public_key.is_empty() {
            return Err(anyhow::anyhow!("WireGuard peer public key is required"));
        }

        Ok(Self { config })
    }
}

#[cfg(feature = "out_wireguard")]
#[async_trait]
impl OutboundTcp for WireGuardOutbound {
    type IO = TcpStream;

    async fn connect(&self, _target: &HostPort) -> io::Result<Self::IO> {
        // WireGuard is not yet implemented
        // This is a placeholder that returns NotImplemented error

        #[cfg(feature = "metrics")]
        {
            use metrics::counter;
            counter!("wireguard_connect_total", "result" => "not_implemented").increment(1);
        }

        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WireGuard outbound is not yet implemented. Full implementation planned with boringtun library."
        ))
    }

    fn protocol_name(&self) -> &'static str {
        "wireguard"
    }
}

#[cfg(not(feature = "out_wireguard"))]
pub struct WireGuardConfig;

#[cfg(not(feature = "out_wireguard"))]
impl WireGuardConfig {
    pub fn new() -> Self {
        Self
    }
}
