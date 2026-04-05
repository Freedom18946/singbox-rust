use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Default to 127.0.0.1:9090 if not set
    if std::env::var("SB_METRICS_ADDR").is_err() {
        std::env::set_var("SB_METRICS_ADDR", "127.0.0.1:9090");
    }

    // Initialize logging via canonical tracing init contract
    let _ = app::tracing_init::init_tracing_once();

    let registry_owner = sb_metrics::install_default_registry_owner();

    // Start exporter via canonical MetricsExporterPlan contract
    match app::tracing_init::install_configured_metrics_exporter(registry_owner.handle())? {
        Some(handle) => {
            tracing::info!(addr = %std::env::var("SB_METRICS_ADDR").unwrap(), "metrics exporter up");
            // Detach the exporter task — it runs independently while main loops
            handle.detach();
        }
        None => {
            tracing::warn!("metrics exporter failed to start (check SB_METRICS_ADDR)");
        }
    }

    // Sleep briefly to allow bind; then print READY for CI step sync
    tokio::time::sleep(Duration::from_millis(150)).await;
    println!("READY");

    // Keep process alive until CI kills it
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
