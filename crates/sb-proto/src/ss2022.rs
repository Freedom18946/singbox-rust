use super::connector::{OutboundConnector, ProtoError, Target};

#[derive(Debug, Clone)]
pub struct Ss2022Config {
    pub server: String,
    pub port: u16,
    pub key: String, // 占位
}

pub struct Shadowsocks2022 {
    pub cfg: Ss2022Config,
}

#[async_trait::async_trait]
impl OutboundConnector for Shadowsocks2022 {
    async fn connect(
        &self,
        _t: &Target,
    ) -> Result<Box<dyn super::connector::IoStream>, ProtoError> {
        Err(ProtoError::NotImplemented)
    }
}
