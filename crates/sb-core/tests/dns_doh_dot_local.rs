#![cfg(any(feature = "dns_doh", feature = "dns_dot"))]
use sb_core::dns::ResolverHandle;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_dot_pool_fallback_errors() {
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_RACE_WINDOW_MS", "0");
    #[cfg(feature = "dns_doh")]
    {
        std::env::set_var("SB_DNS_POOL", "doh:https://127.0.0.1:1/dns-query");
        let h = ResolverHandle::from_env_or_default();
        let _ = h.resolve("example.test").await.err();
    }
    #[cfg(feature = "dns_dot")]
    {
        std::env::set_var("SB_DNS_POOL", "dot:127.0.0.1:1");
        let h = ResolverHandle::from_env_or_default();
        let _ = h.resolve("example.test").await.err();
    }
}
