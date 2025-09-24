use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tracing::trace;

use crate::transport::{Dialer, SystemDialer, TlsStream};

use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};
use crate::telemetry::{dial as dialm, error_class};

#[derive(Clone)]
pub struct DirectOutbound<D = SystemDialer> {
    ctx: OutboundContext<D>,
}

impl Default for DirectOutbound<SystemDialer> {
    fn default() -> Self {
        Self { ctx: OutboundContext::default() }
    }
}

impl<D> DirectOutbound<D> {
    pub fn with_ctx(ctx: OutboundContext<D>) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl<D> Outbound for DirectOutbound<D>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    async fn tcp_connect(&self, req: TcpConnectRequest) -> Result<TcpStream> {
        let sa = match &req.target {
            TargetAddr::Ip(sa) => *sa,
            TargetAddr::Domain(host, port) => {
                // 解析并尝试首个
                let addrs = self.ctx.dialer.resolve_host(host, *port).await?;
                *addrs.get(0).ok_or_else(|| anyhow!("resolve empty"))?
            }
        };
        // Phase 1: TCP connect (direct only has this phase)
        let t0 = dialm::start();
        match self.ctx.dialer.tcp_connect(sa, &req.opts).await {
            Ok(s) => {
                dialm::record_ok("direct", dialm::Phase::TcpConnect, t0);
                trace!(dest=%req.target, "outbound.direct tcp connected");
                Ok(s)
            }
            Err(e) => {
                let class = error_class::classify_proto(&e);
                dialm::record_err("direct", dialm::Phase::TcpConnect, t0, class);
                Err(e.into())
            }
        }
    }

    async fn tcp_connect_tls(&self, req: TcpConnectRequest) -> Result<TlsStream<TcpStream>> {
        // 避免借用/移动冲突：拆出字段，构造无 TLS 的请求
        let params = req
            .tls
            .clone()
            .ok_or_else(|| anyhow!("tls params required"))?;
        let target = req.target.clone();
        let opts = req.opts.clone();
        let tcp = self
            .tcp_connect(TcpConnectRequest {
                target,
                tls: None,
                opts,
            })
            .await?;
        let tls = params.client.connect(&params.server_name, tcp).await?;
        Ok(tls)
    }

    async fn udp_bind(&self, req: UdpBindRequest) -> Result<UdpSocket> {
        let s = self.ctx.dialer.udp_bind(req.bind).await?;
        Ok(s)
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

// 兼容 engine 内部可能调用的 `DirectOutbound::new()`（等价于 default）
impl DirectOutbound<SystemDialer> {
    pub fn new() -> Self {
        Self::default()
    }
}