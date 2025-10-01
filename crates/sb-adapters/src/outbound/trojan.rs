//! Trojan outbound connector implementation
//!
//! This module provides Trojan protocol support for outbound connections.
//! Trojan is a proxy protocol that disguises traffic as TLS traffic.

use crate::outbound::prelude::*;

/// Trojan configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrojanConfig {
    /// Server address (host:port)
    pub server: String,
    /// Connection tag
    #[serde(default)]
    pub tag: Option<String>,
    /// Password for authentication
    pub password: String,
    /// Connection timeout in seconds
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// SNI for TLS handshake
    #[serde(default)]
    pub sni: Option<String>,
    /// Skip certificate verification
    #[serde(default)]
    pub skip_cert_verify: bool,
}

/// Trojan outbound connector
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct TrojanConnector {
    _config: Option<TrojanConfig>,
}

impl TrojanConnector {
    pub fn new(config: TrojanConfig) -> Self {
        Self {
            _config: Some(config),
        }
    }
}


#[async_trait]
impl OutboundConnector for TrojanConnector {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-trojan"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-trojan",
        });

        #[cfg(feature = "adapter-trojan")]
        Ok(())
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-trojan"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-trojan",
        });

        #[cfg(feature = "adapter-trojan")]
        {
            // For now, return not implemented - full implementation would go here
            Err(AdapterError::NotImplemented {
                what: "Trojan dial",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_connector_creation() {
        let config = TrojanConfig {
            server: "127.0.0.1:443".to_string(),
            tag: Some("test".to_string()),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(30),
            sni: Some("example.com".to_string()),
            skip_cert_verify: false,
        };

        let connector = TrojanConnector::new(config);
        assert_eq!(connector.name(), "trojan");
    }
}
