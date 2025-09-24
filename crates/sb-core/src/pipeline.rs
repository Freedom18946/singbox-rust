use crate::net::Address;
use crate::session::ConnectParams;
use async_trait::async_trait;
use std::io;
use std::sync::Arc;
use tokio::net::TcpStream;

#[async_trait]
pub trait Inbound: Send + Sync {
    async fn serve(&self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait Outbound: Send + Sync {
    /// 发起到目标地址的 TCP 连接（旧接口，保留兼容）
    async fn connect(&self, dst: Address) -> io::Result<TcpStream>;

    /// 2.3d：扩展连接接口（带入 inbound/user/transport/sniff_host/超时/截止等上下文）
    /// 默认回退到旧的 `connect(&Address)`
    async fn connect_ex(&self, params: &ConnectParams) -> io::Result<TcpStream> {
        self.connect(params.target.clone()).await
    }
}

pub type DynOutbound = Arc<dyn Outbound>;

pub struct Pipeline<I: Inbound> {
    inbound: I,
}

impl<I: Inbound> Pipeline<I> {
    pub fn new(inbound: I) -> Self {
        Self { inbound }
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.inbound.serve().await
    }
}
