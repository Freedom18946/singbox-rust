pub mod http;
pub mod http_util;
pub mod endpoints;
pub mod security;
pub mod security_async;
pub mod security_metrics;
pub mod cache;
pub mod breaker;
pub mod reloadable;
pub mod audit;
pub mod prefetch;

/// Initialize admin debug server if enabled
pub async fn init(addr: Option<&str>) {
    let bind_addr = match addr {
        Some(a) => a.to_string(),
        None => std::env::var("SB_DEBUG_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string()),
    };

    // Initialize SIGHUP signal handler for configuration reloading
    reloadable::init_signal_handler();

    if let Err(e) = http::serve_plain(&bind_addr).await {
        tracing::error!(error = %e, "failed to start admin debug server");
    }
}