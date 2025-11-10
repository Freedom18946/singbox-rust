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
pub struct Hysteria2Inbound {
    #[cfg(feature = "adapter-hysteria2")]
    core: CoreInbound,
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
            let core_config = Hysteria2ServerConfig {
                listen: config.listen,
                users: config
                    .users
                    .into_iter()
                    .map(|u| Hysteria2User {
                        password: u.password,
                    })
                    .collect(),
                cert: config.cert,
                key: config.key,
                congestion_control: config.congestion_control,
                salamander: config.salamander,
                obfs: config.obfs,
            };

            Ok(Self {
                core: CoreInbound::new(core_config),
            })
        }
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            match self.core.start().await {
                Ok(()) => Ok(()),
                Err(e) => {
                    sb_core::metrics::http::record_error_display(&e);
                    sb_core::metrics::record_inbound_error_display("hysteria2", &e);
                    Err(AdapterError::Io(e))
                }
            }
        }
    }

    pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            match self.core.accept().await {
                Ok((stream, addr)) => Ok((Box::new(stream) as BoxedStream, addr)),
                Err(e) => {
                    sb_core::metrics::http::record_error_display(&e);
                    sb_core::metrics::record_inbound_error_display("hysteria2", &e);
                    Err(AdapterError::Io(e))
                }
            }
        }
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
