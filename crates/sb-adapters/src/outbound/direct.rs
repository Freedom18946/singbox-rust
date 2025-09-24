use std::{io, time::Duration};

use sb_core::{net::Address, pipeline::Outbound};
use tokio::{net::TcpStream, time::timeout};

/// 直连出站：直接向目标地址发起 TCP 连接。
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectOutbound;

impl DirectOutbound {
    #[inline]
    pub fn new() -> Self {
        Self
    }

    /// 每个候选地址上的单次连接超时。
    fn per_attempt_timeout() -> Duration {
        // 保守值：2s/地址，兼顾 IPv6 优先失败的场景
        Duration::from_secs(2)
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    async fn connect(&self, target: Address) -> io::Result<TcpStream> {
        match target {
            Address::Ip(sock) => timeout(Self::per_attempt_timeout(), TcpStream::connect(sock))
                .await
                .map_err(|_| io::Error::other("connect timeout"))?,
            Address::Domain(host, port) => {
                // 解析所有候选地址，依次尝试，直至成功。
                let mut last_err: Option<io::Error> = None;
                let iter = tokio::net::lookup_host((host.as_str(), port)).await?;
                for sock in iter {
                    match timeout(Self::per_attempt_timeout(), TcpStream::connect(sock)).await {
                        Ok(Ok(s)) => return Ok(s),
                        Ok(Err(e)) => last_err = Some(e),
                        Err(_elapsed) => last_err = Some(io::Error::other("connect timeout")),
                    }
                }
                Err(last_err.unwrap_or_else(|| io::Error::other("no address resolved")))
            }
        }
    }
}
