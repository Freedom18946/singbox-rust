#![cfg(feature = "dns_cache")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".into());
    std::env::set_var("SB_DNS_CACHE_ENABLE", "1");
    let a1 = sb_core::dns::resolve::resolve_all(&host, 80).await?;
    let a2 = sb_core::dns::resolve::resolve_all(&host, 80).await?;
    println!("first:  {:?}\nsecond: {:?}", a1, a2);
    Ok(())
}
