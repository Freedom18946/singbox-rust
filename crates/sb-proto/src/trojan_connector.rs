//! R73: Trojan 最小出站 Connector（可注入 Dialer；默认关闭，不联网测试用）
//! 行为：connect() → 仅拨号并写入 TrojanHello 首包；不做后续代理逻辑
use crate::trojan_min::TrojanHello;
use sb_transport::dialer::{Dialer, DialError, IoStream};
use async_trait::async_trait;
use tokio::io::{AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct TrojanConnector<D: Dialer + Send + Sync + 'static> {
    pub dialer: D,
    pub password: String,
}

impl<D: Dialer + Send + Sync + 'static> TrojanConnector<D> {
    pub fn new(dialer: D, password: impl Into<String>) -> Self {
        Self { dialer, password: password.into() }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> crate::connector::OutboundConnector for TrojanConnector<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, String> {
        let mut s = self.dialer.connect(host, port).await.map_err(|e| format!("{:?}", e))?;
        let hello = TrojanHello{ password: self.password.clone(), host: host.into(), port };
        let buf = hello.to_bytes();
        // 写首包
        tokio::io::AsyncWriteExt::write_all(&mut s, &buf).await.map_err(|e| format!("{:?}", e))?;
        // 刷新
        tokio::io::AsyncWriteExt::flush(&mut s).await.map_err(|e| format!("{:?}", e))?;
        Ok(s)
    }
}