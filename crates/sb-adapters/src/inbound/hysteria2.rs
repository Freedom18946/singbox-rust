//! Hysteria v2 inbound adapter implementation

use crate::error::{AdapterError, Result};
use crate::traits::BoxedStream;
use std::net::SocketAddr;

#[cfg(feature = "adapter-hysteria2")]
use sb_core::outbound::hysteria2::inbound::{
    Hysteria2Inbound as CoreInbound, Hysteria2ServerConfig, Hysteria2User,
};

/// Hysteria v2 inbound configuration
#[derive(Debug, Clone)]
pub struct Hysteria2InboundConfig {
    pub listen: SocketAddr,
    pub users: Vec<Hysteria2UserConfig>,
    pub cert: String,
    pub key: String,
    pub congestion_control: Option<String>,
    pub salamander: Option<String>,
    pub obfs: Option<String>,
}

/// Hysteria v2 user configuration
#[derive(Debug, Clone)]
pub struct Hysteria2UserConfig {
    pub password: String,
}

impl Default for Hysteria2InboundConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([0, 0, 0, 0], 443)),
            users: vec![Hysteria2UserConfig {
                password: "password".to_string(),
            }],
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            congestion_control: Some("bbr".to_string()),
            salamander: None,
            obfs: None,
        }
    }
}

/// Hysteria v2 inbound adapter
#[derive(Debug, Clone)]
pub struct Hysteria2Inbound {
    config: Hysteria2InboundConfig,
    #[cfg(feature = "adapter-hysteria2")]
    _core_marker: std::marker::PhantomData<CoreInbound>,
    #[cfg(not(feature = "adapter-hysteria2"))]
    _phantom: std::marker::PhantomData<()>,
}

impl Hysteria2Inbound {
    pub fn new(config: Hysteria2InboundConfig) -> Result<Self> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            // Validate config
            if config.users.is_empty() {
                return Err(AdapterError::NotImplemented {
                    what: "Hysteria2 requires at least one user",
                });
            }

            Ok(Self {
                config,
                _core_marker: std::marker::PhantomData,
            })
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    pub async fn start_server(&self) -> Result<()> {
        use sb_core::outbound::hysteria2::inbound::Hysteria2Inbound as CoreInbound;

        let core_config = Hysteria2ServerConfig {
            listen: self.config.listen,
            users: self
                .config
                .users
                .iter()
                .map(|u| Hysteria2User {
                    password: u.password.clone(),
                })
                .collect(),
            cert: self.config.cert.clone(),
            key: self.config.key.clone(),
            congestion_control: self.config.congestion_control.clone(),
            salamander: self.config.salamander.clone(),
            obfs: self.config.obfs.clone(),
        };

        let core = CoreInbound::new(core_config);
        match core.start().await {
            Ok(()) => {
                // Server started, now continuously accept connections
                loop {
                    match core.accept().await {
                        Ok((_stream, peer)) => {
                            tracing::debug!("Hysteria2: accepted connection from {}", peer);
                            // TODO: Handle the stream properly - route through router
                        }
                        Err(e) => {
                            tracing::error!("Hysteria2: accept error: {}", e);
                            return Err(AdapterError::Io(e));
                        }
                    }
                }
            }
            Err(e) => {
                sb_core::metrics::http::record_error_display(&e);
                sb_core::metrics::record_inbound_error_display("hysteria2", &e);
                Err(AdapterError::Io(e))
            }
        }
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        self.start_server().await
    }

    pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            // This method is not used in the new architecture - start_server handles accept loop
            Err(AdapterError::NotImplemented {
                what: "Direct accept() not supported - use start() instead",
            })
        }
    }
}

impl sb_core::adapter::InboundService for Hysteria2Inbound {
    fn serve(&self) -> std::io::Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "adapter-hysteria2 feature not enabled",
            ));
        }

        #[cfg(feature = "adapter-hysteria2")]
        {
            // Use current tokio runtime or fail
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    let config = self.config.clone();
                    // Start the server
                    handle.spawn(async move {
                        let adapter = Hysteria2Inbound {
                            config,
                            _core_marker: std::marker::PhantomData,
                        };
                        if let Err(e) = adapter.start().await {
                            tracing::error!(error=?e, "Hysteria2 inbound server failed");
                        }
                    });
                    Ok(())
                }
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No tokio runtime available",
                )),
            }
        }
    }

    fn request_shutdown(&self) {
        // TODO: Implement graceful shutdown for Hysteria2
        tracing::debug!("Hysteria2 inbound shutdown requested");
    }

    fn active_connections(&self) -> Option<u64> {
        // TODO: Track active connections
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Hysteria2InboundConfig::default();
        assert_eq!(config.listen.port(), 443);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].password, "password");
    }
}
