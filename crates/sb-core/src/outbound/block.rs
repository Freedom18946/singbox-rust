//! Block 出站：用于路由命中"阻断"时的占位实现
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use super::{Outbound, TcpConnectRequest, UdpBindRequest};
use crate::transport::TlsStream;

#[derive(Clone, Default)]
pub struct BlockOutbound;

#[async_trait]
impl Outbound for BlockOutbound {
    async fn tcp_connect(&self, _req: TcpConnectRequest) -> Result<TcpStream> {
        Err(anyhow!("blocked by rule"))
    }
    async fn tcp_connect_tls(&self, _req: TcpConnectRequest) -> Result<TlsStream<TcpStream>> {
        Err(anyhow!("blocked by rule"))
    }
    async fn udp_bind(&self, _req: UdpBindRequest) -> Result<UdpSocket> {
        Err(anyhow!("blocked by rule"))
    }
    fn name(&self) -> &'static str { "block" }
}