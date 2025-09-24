use std::env;
use sb_core::outbound::{DirectOutbound, OutboundContext, TargetAddr, TcpConnectRequest};
use sb_core::transport::{ConnectOpts, SystemDialer};
use tokio::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = env::args().nth(1).unwrap_or_else(|| "example.com".into());
    let port: u16 = env::args()
        .nth(2)
        .unwrap_or_else(|| "80".into())
        .parse()
        .unwrap_or(80);

    // Create direct outbound with system dialer
    let ctx = OutboundContext::<SystemDialer>::default();
    let outbound = DirectOutbound::with_ctx(ctx);

    // Configure connection options
    let opts = ConnectOpts::default()
        .timeout(Duration::from_secs(5))
        .nodelay(true);

    // Create connection request
    let req = TcpConnectRequest {
        target: TargetAddr::Domain(host.clone(), port),
        tls: None,
        opts,
    };

    // Attempt connection - this will record dial metrics
    let _stream = outbound.tcp_connect(req).await?;

    println!("Successfully connected to {}:{}", host, port);
    Ok(())
}