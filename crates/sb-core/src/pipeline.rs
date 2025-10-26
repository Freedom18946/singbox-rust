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

    /// 2.3d：扩展连接接口（带入 `inbound/user/transport/sniff_host/超时/截止等上下文`）
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
    pub const fn new(inbound: I) -> Self {
        Self { inbound }
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.inbound.serve().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInbound {
        should_fail: bool,
    }

    #[async_trait]
    impl Inbound for MockInbound {
        async fn serve(&self) -> anyhow::Result<()> {
            if self.should_fail {
                anyhow::bail!("inbound serve failed: test error");
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_pipeline_success() {
        let inbound = MockInbound { should_fail: false };
        let pipeline = Pipeline::new(inbound);
        
        let result = pipeline.run().await;
        assert!(result.is_ok(), "pipeline should succeed with successful inbound");
    }

    #[tokio::test]
    async fn test_pipeline_failure_propagation() {
        let inbound = MockInbound { should_fail: true };
        let pipeline = Pipeline::new(inbound);
        
        let result = pipeline.run().await;
        assert!(result.is_err(), "pipeline should propagate inbound errors");
        
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("inbound serve failed"),
                "error should mention inbound failure: {}", msg
            );
        }
    }
}
