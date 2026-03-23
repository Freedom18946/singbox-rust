use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Default to 127.0.0.1:9090 if not set
    if std::env::var("SB_METRICS_ADDR").is_err() {
        std::env::set_var("SB_METRICS_ADDR", "127.0.0.1:9090");
    }

    // Initialize a minimal tracing subscriber for visibility
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .compact()
        .try_init();

    let registry_owner = sb_metrics::install_default_registry_owner();

    // Start exporter
    if let Some(_jh) = sb_metrics::spawn_http_exporter_from_env(registry_owner.handle()) {
        tracing::info!(addr = %std::env::var("SB_METRICS_ADDR").unwrap(), "metrics exporter up");
    } else {
        tracing::warn!("metrics exporter failed to start (check SB_METRICS_ADDR)");
    }

    // Sleep briefly to allow bind; then print READY for CI step sync
    tokio::time::sleep(Duration::from_millis(150)).await;
    println!("READY");

    // Keep process alive until CI kills it
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
