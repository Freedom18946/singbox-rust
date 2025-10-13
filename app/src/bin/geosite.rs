//! Geosite CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::geosite::GeositeArgs::parse();
    app::cli::geosite::run(args).await
}
