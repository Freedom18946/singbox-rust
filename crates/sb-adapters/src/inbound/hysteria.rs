//! Hysteria v1 inbound adapter implementation

use crate::error::{AdapterError, Result};
use crate::traits::BoxedStream;
use std::net::SocketAddr;

#[cfg(feature = "adapter-hysteria")]
use sb_core::outbound::hysteria::HysteriaV1Inbound as CoreInbound;
#[cfg(feature = "adapter-hysteria")]
use sb_core::outbound::hysteria::v1::HysteriaV1ServerConfig;

/// Hysteria v1 inbound configuration
#[derive(Debug, Clone)]
pub struct HysteriaInboundConfig {
    pub listen: SocketAddr,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
}

impl Default for HysteriaInboundConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".parse().expect("valid address"),
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            auth: None,
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            recv_window_conn: None,
            recv_window: None,
        }
    }
}

/// Hysteria v1 inbound adapter
pub struct HysteriaInbound {
    #[cfg(feature = "adapter-hysteria")]
    core: CoreInbound,
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
            let core_config = HysteriaV1ServerConfig {
                listen: config.listen,
                up_mbps: config.up_mbps,
                down_mbps: config.down_mbps,
                obfs: config.obfs,
                auth: config.auth,
                cert_path: config.cert_path,
                key_path: config.key_path,
                recv_window_conn: config.recv_window_conn,
                recv_window: config.recv_window,
            };

            Ok(Self {
                core: CoreInbound::new(core_config),
            })
        }
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        {
            self.core
                .start()
                .await
                .map_err(AdapterError::Io)
        }
    }

    pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        {
            let (stream, addr) = self.core
                .accept()
                .await
                .map_err(AdapterError::Io)?;

            Ok((Box::new(stream) as BoxedStream, addr))
        }
    }
}
