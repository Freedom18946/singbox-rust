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

    // Start exporter via canonical MetricsExporterPlan contract.
    let handle =
        app::tracing_init::install_configured_metrics_exporter_checked(registry_owner.handle())
            .await?
            .ok_or_else(|| anyhow::anyhow!("SB_METRICS_ADDR is not configured"))?;
    let metrics_addr = std::env::var("SB_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".into());
    tracing::info!(addr = %metrics_addr, "metrics exporter up");
    // Detach the exporter task — it runs independently while main loops.
    handle.detach();

    // Checked startup binds before returning; print READY only after the socket is owned.
    println!("READY");

    // Keep process alive until CI kills it
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
