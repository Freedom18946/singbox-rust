use std::io;
use std::sync::Arc;
use std::time::Duration;

use sb_config::ir::OutboundIR;
use sb_core::adapter::{registry, OutboundConnector, OutboundParam, UdpOutboundFactory};
use sb_core::outbound::selector_group::{ProxyMember, SelectorGroup};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct UrlTestOutbound {
    inner: Arc<SelectorGroup>,
}

impl UrlTestOutbound {
    pub fn new(inner: Arc<SelectorGroup>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for UrlTestOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTestOutbound")
            .field("name", &self.inner.name)
            .finish()
    }
}

#[async_trait::async_trait]
impl OutboundConnector for UrlTestOutbound {
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        self.inner.connect(host, port).await
    }
}

impl UdpOutboundFactory for UrlTestOutbound {
    fn open_session(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::io::Result<Arc<dyn sb_core::adapter::UdpOutboundSession>>,
                > + Send,
        >,
    > {
        let group = self.inner.clone();
        Box::pin(async move {
            let member = group.select_best().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no available proxy in urltest {}", group.name),
                )
            })?;

            // Track active connection
            member
                .health
                .active_connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let factory = member.udp_factory.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("proxy {} does not support UDP", member.tag),
                )
            });

            match factory {
                Ok(f) => {
                    let result = f.open_session().await;
                    // Decrement connection counter immediately to avoid leak (MVP)
                    member
                        .health
                        .active_connections
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    result
                }
                Err(e) => {
                    member
                        .health
                        .active_connections
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    Err(e)
                }
            }
        })
    }
}

type OutboundBuilderResult = Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

pub fn build_urltest_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    let name = ir
        .name
        .clone()
        .or(param.name.clone())
        .unwrap_or_else(|| "urltest".to_string());
    let member_tags = ir.members.clone().unwrap_or_default();

    let mut members = Vec::new();
    for tag in member_tags {
        if let Some(connector) = ctx.bridge.get_member(&tag) {
            let udp_factory = ctx.bridge.find_udp_factory(&tag);
            members.push(ProxyMember::new(tag, connector, udp_factory));
        } else {
            tracing::warn!("UrlTest {} member {} not found", name, tag);
        }
    }

    let test_url = ir
        .test_url
        .clone()
        .unwrap_or_else(|| "http://cp.cloudflare.com".to_string());
    let interval = Duration::from_millis(ir.test_interval_ms.unwrap_or(600000)); // 10 min default
    let timeout = Duration::from_millis(ir.test_timeout_ms.unwrap_or(5000));
    let tolerance = ir.test_tolerance_ms.unwrap_or(50);

    let group = SelectorGroup::new_urltest(name, members, test_url, interval, timeout, tolerance);
    let outbound = Arc::new(UrlTestOutbound::new(Arc::new(group)));

    Some((outbound.clone(), Some(outbound)))
}
