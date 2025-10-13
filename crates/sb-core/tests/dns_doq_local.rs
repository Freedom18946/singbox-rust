#![cfg(feature = "dns_doq")]

use std::net::SocketAddr;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // network-dependent; requires outbound QUIC and public DoQ server
async fn doq_query_cloudflare_smoke() {
    // Cloudflare DoQ endpoint
    let addr: SocketAddr = "1.1.1.1:853".parse().unwrap();
    let sni = "cloudflare-dns.com";

    // Attempt a real DoQ query for example.com A record
    let res = sb_core::dns::doq::query_doq_once(addr, sni, "example.com", 1, 3000).await;
    // We don't enforce success here (CI may block network); the goal is plumbing
    // Ensure the function returns either Ok or a well-formed Err without panicking
    if let Err(e) = res {
        eprintln!("doq query error (expected in CI without network): {}", e);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doq_mode_graceful_error() {
    // Force DoQ backend with an unreachable local port; expect an error
    std::env::set_var("SB_DNS_MODE", "doq");
    std::env::set_var("SB_DNS_DOQ_ADDR", "127.0.0.1:1");
    std::env::set_var("SB_DNS_DOQ_SERVER_NAME", "invalid.local");

    let res = sb_core::dns::resolve::resolve_all("example.test", 80).await;
    assert!(res.is_err(), "DoQ backend should error on unreachable addr");
}
