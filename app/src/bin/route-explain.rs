#![cfg(feature = "explain")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]

use anyhow::{Context, Result};
use app::cli::{output, Format, GlobalArgs};
use app::config_loader;
use clap::Parser;
use sb_core::routing::ExplainEngine;
use serde_json::Value;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "route-explain", about = "Route explain helper")]
struct RouteExplainCli {
    #[command(flatten)]
    global: GlobalArgs,
    /// Destination host[:port] or ip
    #[arg(long = "destination", alias = "dest")]
    destination: String,
    /// Use UDP path
    #[arg(long = "udp", default_value_t = false)]
    udp: bool,
    /// Output format
    #[arg(long = "format", value_enum, default_value_t = Format::Json)]
    format: Format,
    /// Include detailed trace information
    #[arg(long = "with-trace", alias = "trace", default_value_t = false)]
    with_trace: bool,
}

fn main() -> Result<()> {
    let cli = RouteExplainCli::parse();
    app::cli::apply_global_options(&cli.global)?;

    let entries =
        config_loader::collect_config_entries(&cli.global.config, &cli.global.config_directory)?;
    let raw = config_loader::load_merged_value(&entries)?;
    validate_geo_resources(&raw)?;

    let cfg = config_loader::load_config(&entries).with_context(|| "load config for explain")?;
    let engine = ExplainEngine::from_config(&cfg).with_context(|| "create explain engine")?;
    let net = if cli.udp { "udp" } else { "tcp" };
    let result = engine.explain_with_network(&cli.destination, net, cli.with_trace);

    output::emit(
        cli.format,
        || {
            format!(
                "{} → {} (rule={})",
                result.dest, result.outbound, result.matched_rule
            )
        },
        &result,
    );
    Ok(())
}

#[cfg(feature = "router")]
fn validate_geo_resources(raw: &Value) -> Result<()> {
    use sb_core::router::geo::{GeoIpDb, GeoSiteDb};

    if let Some(path) = raw.pointer("/route/geoip/path").and_then(|v| v.as_str()) {
        GeoIpDb::load_from_file(Path::new(path))
            .map_err(|e| anyhow::anyhow!("geoip db load failed: {e}"))?;
    }
    if let Some(path) = raw.pointer("/route/geosite/path").and_then(|v| v.as_str()) {
        GeoSiteDb::load_from_file(Path::new(path))
            .map_err(|e| anyhow::anyhow!("geosite db load failed: {e}"))?;
    }
    Ok(())
}

#[cfg(not(feature = "router"))]
fn validate_geo_resources(_raw: &Value) -> Result<()> {
    Ok(())
}
