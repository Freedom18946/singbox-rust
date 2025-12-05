use crate::outbound::OutboundConnector;
use anyhow::Result;
use async_trait::async_trait;

pub mod crypto;
pub mod obfs;
pub mod protocol;
pub mod stream;

#[derive(Debug, Clone)]
pub struct ShadowsocksROutboundConfig {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub obfs: String,
    pub obfs_param: Option<String>,
    pub protocol: String,
    pub protocol_param: Option<String>,
}

#[derive(Debug)]
pub struct ShadowsocksROutbound {
    config: ShadowsocksROutboundConfig,
}

impl ShadowsocksROutbound {
    pub fn new(config: ShadowsocksROutboundConfig) -> Result<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl OutboundConnector for ShadowsocksROutbound {
    async fn dial(&self, _target: crate::traits::Target, _opts: crate::traits::DialOpts) -> crate::error::Result<crate::traits::BoxedStream> {
        // Connect to the SSR server
        let stream = tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port))
            .await
            .map_err(crate::error::AdapterError::Io)?;
        
        let cipher = crypto::Cipher::new(&self.config.method, &self.config.password);
        let obfs = obfs::Obfs::new(&self.config.obfs, self.config.obfs_param.as_deref());
        let protocol = protocol::Protocol::new(&self.config.protocol, self.config.protocol_param.as_deref());

        let ssr_stream = stream::ShadowsocksRStream::new(stream, cipher, obfs, protocol);
        
        Ok(Box::new(ssr_stream))
    }
}
