use sb_core::dns::client::DnsClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("Usage: dns_udp_probe <host>");
        std::process::exit(2);
    }
    let host = args.remove(0);
    // Enable client
    std::env::set_var("SB_DNS_ENABLE", "1");
    // Optional:
    // SB_DNS_MODE=udp SB_DNS_UPSTREAM=1.1.1.1:53 SB_DNS_PARALLEL=1
    let c = DnsClient::new(Duration::from_secs(60));
    let addrs = c.resolve(&host, 443).await?;
    for sa in addrs {
        println!("{sa}");
    }
    Ok(())
}
