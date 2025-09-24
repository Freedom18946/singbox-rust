//! SSH outbound placeholder implementation
//!
//! This is a placeholder implementation for SSH tunnel support.
//! Full implementation will use thrussh or similar SSH implementation.

#[cfg(feature = "out_ssh")]
use async_trait::async_trait;
#[cfg(feature = "out_ssh")]
use std::io;
#[cfg(feature = "out_ssh")]
use tokio::net::TcpStream;

#[cfg(feature = "out_ssh")]
use super::crypto_types::{HostPort, OutboundTcp};

#[cfg(feature = "out_ssh")]
#[derive(Clone, Debug)]
pub struct SshConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key_verification: bool,
    pub compression: bool,
    pub keepalive_interval: Option<u64>,
}

#[cfg(feature = "out_ssh")]
pub struct SshOutbound {
    config: SshConfig,
}

#[cfg(feature = "out_ssh")]
impl SshOutbound {
    pub fn new(config: SshConfig) -> anyhow::Result<Self> {
        // Validate configuration
        if config.server.is_empty() {
            return Err(anyhow::anyhow!("SSH server address is required"));
        }
        if config.username.is_empty() {
            return Err(anyhow::anyhow!("SSH username is required"));
        }
        if config.password.is_none() && config.private_key.is_none() {
            return Err(anyhow::anyhow!(
                "Either SSH password or private key is required"
            ));
        }

        Ok(Self { config })
    }
}

#[cfg(feature = "out_ssh")]
#[async_trait]
impl OutboundTcp for SshOutbound {
    type IO = TcpStream;

    async fn connect(&self, _target: &HostPort) -> io::Result<Self::IO> {
        // SSH tunneling is not yet implemented
        // This is a placeholder that returns NotImplemented error

        #[cfg(feature = "metrics")]
        {
            use metrics::counter;
            counter!("ssh_connect_total", "result" => "not_implemented").increment(1);
        }

        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SSH outbound tunneling is not yet implemented. Full implementation planned with thrussh/openssh library."
        ))
    }

    fn protocol_name(&self) -> &'static str {
        "ssh"
    }
}

#[cfg(not(feature = "out_ssh"))]
pub struct SshConfig;

#[cfg(not(feature = "out_ssh"))]
impl SshConfig {
    pub fn new() -> Self {
        Self
    }
}
