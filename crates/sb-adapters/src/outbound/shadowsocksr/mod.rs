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
        if !protocol::Protocol::is_supported(&config.protocol) {
            anyhow::bail!(
                "unsupported ShadowsocksR protocol '{}'; only origin/plain is currently supported",
                config.protocol
            );
        }
        if !obfs::Obfs::is_supported(&config.obfs) {
            anyhow::bail!(
                "unsupported ShadowsocksR obfs '{}'; only plain/none and http_simple are currently supported",
                config.obfs
            );
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl OutboundConnector for ShadowsocksROutbound {
    async fn dial(
        &self,
        _target: crate::traits::Target,
        _opts: crate::traits::DialOpts,
    ) -> crate::error::Result<crate::traits::BoxedStream> {
        // Connect to the SSR server
        let stream =
            tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port))
                .await
                .map_err(crate::error::AdapterError::Io)?;

        let cipher = crypto::Cipher::create(&self.config.method, &self.config.password);
        let obfs = obfs::Obfs::create(&self.config.obfs, self.config.obfs_param.as_deref());
        let protocol = protocol::Protocol::create(
            &self.config.protocol,
            self.config.protocol_param.as_deref(),
        );

        let ssr_stream = stream::ShadowsocksRStream::new(stream, cipher, obfs, protocol);

        Ok(Box::new(ssr_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> ShadowsocksROutboundConfig {
        ShadowsocksROutboundConfig {
            server: "127.0.0.1".to_string(),
            port: 8388,
            method: "aes-256-cfb".to_string(),
            password: "secret".to_string(),
            obfs: "plain".to_string(),
            obfs_param: None,
            protocol: "origin".to_string(),
            protocol_param: None,
        }
    }

    #[test]
    fn rejects_unsupported_auth_protocols() {
        let mut config = base_config();
        config.protocol = "auth_sha1_v4".to_string();

        let err = ShadowsocksROutbound::new(config).expect_err("auth protocol must be rejected");
        assert!(err
            .to_string()
            .contains("unsupported ShadowsocksR protocol"));
    }

    #[test]
    fn rejects_unsupported_tls_ticket_obfs() {
        let mut config = base_config();
        config.obfs = "tls1.2_ticket_auth".to_string();

        let err = ShadowsocksROutbound::new(config).expect_err("TLS obfs must be rejected");
        assert!(err.to_string().contains("unsupported ShadowsocksR obfs"));
    }
}
