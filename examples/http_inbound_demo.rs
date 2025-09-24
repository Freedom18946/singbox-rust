use std::net::SocketAddr;
use singbox_rust::inbound::http::{HttpInbound, DirectConnector};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind: SocketAddr = "127.0.0.1:28080".parse()?;
    let inbound = HttpInbound::new(bind, DirectConnector);
    eprintln!("http inbound demo on {}", bind);
    inbound.serve().await?;
    Ok(())
}
