//! GeoIP CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::geoip::GeoipArgs::parse();
    app::cli::geoip::run(args).await
}
