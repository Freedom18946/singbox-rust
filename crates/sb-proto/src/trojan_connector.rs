//! R73: Trojan 最小出站 Connector（可注入 Dialer；默认关闭，不联网测试用）
//! 行为：connect() → 仅拨号并写入 TrojanHello 首包；不做后续代理逻辑
use crate::connector::{ProtoError, Target};
use crate::trojan_min::TrojanHello;
use async_trait::async_trait;
use sb_transport::dialer::Dialer;

#[derive(Debug, Clone)]
pub struct TrojanConnector<D: Dialer + Send + Sync + 'static> {
    pub dialer: D,
    pub password: String,
}

impl<D: Dialer + Send + Sync + 'static> TrojanConnector<D> {
    pub fn new(dialer: D, password: impl Into<String>) -> Self {
        Self {
            dialer,
            password: password.into(),
        }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> crate::connector::OutboundConnector for TrojanConnector<D> {
    async fn connect(
        &self,
        target: &Target,
    ) -> Result<Box<dyn crate::connector::IoStream>, ProtoError> {
        let mut s = self
            .dialer
            .connect(&target.host, target.port)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let hello = TrojanHello {
            password: self.password.clone(),
            host: target.host.clone(),
            port: target.port,
        };
        let buf = hello.to_bytes();
        // 写首包
        tokio::io::AsyncWriteExt::write_all(&mut s, &buf).await?;
        // 刷新
        tokio::io::AsyncWriteExt::flush(&mut s).await?;
        Ok(Box::new(s))
    }
}
