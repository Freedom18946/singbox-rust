use std::net::SocketAddr;
use std::sync::Arc;

use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use sb_core::router::{Router, RouterHandle};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind: SocketAddr = "127.0.0.1:28080".parse()?;
    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let registry = OutboundRegistry::new(map);
    let outbounds = Arc::new(OutboundRegistryHandle::new(registry));
    let router = Arc::new(RouterHandle::new(Router::with_default("direct")));

    let (_stop_tx, stop_rx) = mpsc::channel(1);
    let cfg = HttpProxyConfig {
        tag: Some("http_inbound_demo".to_string()),
        listen: bind,
        router,
        outbounds,
        tls: None,
        users: None,
        set_system_proxy: false,
        allow_private_network: true,
        stats: None,
    };

    eprintln!("http inbound demo on {}", bind);
    serve_http(cfg, stop_rx, None).await?;
    Ok(())
}
