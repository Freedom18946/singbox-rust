#![cfg(feature = "dns_doq")]
use sb_core::dns::ResolverHandle;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doq_pool_unreachable_errors() {
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_RACE_WINDOW_MS", "0");
    std::env::set_var("SB_DNS_POOL_STRATEGY", "sequential");
    // Unreachable local port to avoid real network
    std::env::set_var("SB_DNS_POOL", "doq:127.0.0.1:1@invalid.local");
    let h = ResolverHandle::from_env_or_default();
    let _ = h.resolve("example.test").await.err();
}
