use super::connector::{OutboundConnector, ProtoError, Target};

#[derive(Debug, Clone)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
}

pub struct Trojan {
    pub cfg: TrojanConfig,
}

#[async_trait::async_trait]
impl OutboundConnector for Trojan {
    async fn connect(&self, _t: &Target) -> Result<Box<dyn super::connector::IoStream>, ProtoError> {
        Err(ProtoError::NotImplemented)
    }
}
