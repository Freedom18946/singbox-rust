//! Hysteria v1 inbound adapter implementation

use crate::error::{AdapterError, Result};
use crate::traits::BoxedStream;
use std::net::SocketAddr;

#[cfg(feature = "adapter-hysteria")]
use sb_core::outbound::hysteria::v1::{HysteriaV1Inbound as CoreInbound, HysteriaV1ServerConfig};

/// Hysteria v1 user configuration
#[derive(Debug, Clone)]
pub struct HysteriaUserConfig {
    pub name: String,
    pub auth: String,
}

/// Hysteria v1 inbound configuration
#[derive(Debug, Clone)]
pub struct HysteriaInboundConfig {
    pub listen: SocketAddr,
    pub users: Vec<HysteriaUserConfig>,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
}

impl Default for HysteriaInboundConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([0, 0, 0, 0], 443)),
            users: vec![],
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            recv_window_conn: None,
            recv_window: None,
        }
    }
}

/// Hysteria v1 inbound adapter
#[derive(Debug, Clone)]
pub struct HysteriaInbound {
    config: HysteriaInboundConfig,
    #[cfg(feature = "adapter-hysteria")]
    _core_marker: std::marker::PhantomData<CoreInbound>,
    #[cfg(not(feature = "adapter-hysteria"))]
    _phantom: std::marker::PhantomData<()>,
}

impl HysteriaInbound {
    pub fn new(config: HysteriaInboundConfig) -> Result<Self> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        {
            // Validate config
            if config.users.is_empty() {
                return Err(AdapterError::NotImplemented {
                    what: "Hysteria v1 requires at least one user",
                });
            }

            Ok(Self {
                config,
                _core_marker: std::marker::PhantomData,
            })
        }
    }

    #[cfg(feature = "adapter-hysteria")]
    pub async fn start_server(&self) -> Result<()> {
        use sb_core::outbound::hysteria::v1::HysteriaV1Inbound as CoreInbound;

        // Use first user's auth for single-user mode
        let auth = if !self.config.users.is_empty() {
            Some(self.config.users[0].auth.clone())
        } else {
            None
        };

        let core_config = HysteriaV1ServerConfig {
            listen: self.config.listen,
            up_mbps: self.config.up_mbps,
            down_mbps: self.config.down_mbps,
            obfs: self.config.obfs.clone(),
            auth,
            cert_path: self.config.cert_path.clone(),
            key_path: self.config.key_path.clone(),
            recv_window_conn: self.config.recv_window_conn,
            recv_window: self.config.recv_window,
        };

        let core = CoreInbound::new(core_config);
        match core.start().await {
            Ok(()) => {
                // Server started, now continuously accept connections
                loop {
                    match core.accept().await {
                        Ok((_stream, peer)) => {
                            tracing::debug!("Hysteria v1: accepted connection from {}", peer);
                        }
                        Err(e) => {
                            tracing::error!("Hysteria v1: accept error: {}", e);
                            return Err(AdapterError::Io(e));
                        }
                    }
                }
            }
            Err(e) => {
                sb_core::metrics::http::record_error_display(&e);
                sb_core::metrics::record_inbound_error_display("hysteria", &e);
                Err(AdapterError::Io(e))
            }
        }
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        self.start_server().await
    }

    pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        {
            // This method is not used in the new architecture - start_server handles accept loop
            Err(AdapterError::NotImplemented {
                what: "Direct accept() not supported - use start() instead",
            })
        }
    }
}

impl sb_core::adapter::InboundService for HysteriaInbound {
    fn serve(&self) -> std::io::Result<()> {
        #[cfg(not(feature = "adapter-hysteria"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "adapter-hysteria feature not enabled",
            ));
        }

        #[cfg(feature = "adapter-hysteria")]
        {
            // Use current tokio runtime or fail
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    let config = self.config.clone();
                    // Start the server
                    handle.spawn(async move {
                        let adapter = HysteriaInbound {
                            config,
                            _core_marker: std::marker::PhantomData,
                        };
                        if let Err(e) = adapter.start().await {
                            tracing::error!(error=?e, "Hysteria v1 inbound server failed");
                        }
                    });
                    Ok(())
                }
                Err(_) => Err(std::io::Error::other("No tokio runtime available")),
            }
        }
    }
}
