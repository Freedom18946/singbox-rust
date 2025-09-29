#![cfg(feature = "dev-cli")]
use std::sync::Once;

static ONCE: Once = Once::new();

pub fn print_once_if_enabled() {
    let enabled = matches!(
        std::env::var("SB_PRINT_ENV").ok().as_deref(),
        Some("1" | "true" | "TRUE")
    );
    if !enabled {
        return;
    }
    ONCE.call_once(|| {
        let kv = [
            (
                "SB_SOCKS_UDP_ENABLE",
                std::env::var("SB_SOCKS_UDP_ENABLE").unwrap_or_default(),
            ),
            (
                "SB_SOCKS_UDP_LISTEN",
                std::env::var("SB_SOCKS_UDP_LISTEN").unwrap_or_default(),
            ),
            (
                "SB_ROUTER_UDP",
                std::env::var("SB_ROUTER_UDP").unwrap_or_default(),
            ),
            (
                "SB_ROUTER_UDP_RULES",
                std::env::var("SB_ROUTER_UDP_RULES").unwrap_or_default(),
            ),
            (
                "SB_UDP_PROXY_MODE",
                std::env::var("SB_UDP_PROXY_MODE").unwrap_or_else(|_| "direct".to_string()),
            ),
            // Code uses SB_UDP_PROXY_ADDR; include both for clarity
            (
                "SB_UDP_PROXY_ADDR",
                std::env::var("SB_UDP_PROXY_ADDR").unwrap_or_default(),
            ),
            (
                "SB_UDP_SOCKS5_ADDR",
                std::env::var("SB_UDP_SOCKS5_ADDR").unwrap_or_default(),
            ),
            (
                "SB_UDP_SOCKS5_POOL",
                std::env::var("SB_UDP_SOCKS5_POOL").unwrap_or_default(),
            ),
            (
                "SB_UDP_BALANCER_STRATEGY",
                std::env::var("SB_UDP_BALANCER_STRATEGY").unwrap_or_default(),
            ),
        ];
        // Emit as one-line JSON for easy grep/parse
        let mut first = true;
        print!("{{ ");
        for (k, v) in kv {
            if !first {
                print!(", ");
            }
            first = false;
            let vs = v.replace('"', "\\\"");
            print!("\"{}\":\"{}\"", k, vs);
        }
        println!(" }}");
    });
}
