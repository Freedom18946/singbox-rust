use std::env;
use sb_transport::{Dialer as _, TcpDialer};
use tokio::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = env::args().nth(1).unwrap_or_else(|| "example.com".into());
    let port: u16 = env::args()
        .nth(2)
        .unwrap_or_else(|| "80".into())
        .parse()
        .unwrap_or(80);

    // Create a transport dialer with a 5s timeout
    let dialer = TcpDialer {
        connect_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };

    // Attempt connection
    let _stream = dialer.connect(&host, port).await?;

    println!("Successfully connected to {}:{}", host, port);
    Ok(())
}
