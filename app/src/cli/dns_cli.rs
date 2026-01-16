use crate::cli::{output, Format, GlobalArgs};
use crate::config_loader;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub command: DnsCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DnsCommands {
    /// Query DNS and show resolution path
    Query(QueryArgs),
    /// Show DNS cache statistics
    Cache(CacheArgs),
    /// Show DNS upstream status and health
    Upstream(UpstreamArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct QueryArgs {
    /// Domain name to query
    pub domain: String,
    /// Output format
    #[arg(long = "format", value_enum, default_value_t = Format::Human)]
    pub format: Format,
    /// Show detailed resolution path
    #[arg(long = "explain", default_value_t = false)]
    pub explain: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct CacheArgs {
    /// Output format
    #[arg(long = "format", value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Parser, Debug, Clone)]
pub struct UpstreamArgs {
    /// Output format
    #[arg(long = "format", value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

pub fn run(global: &GlobalArgs, args: DnsArgs) -> Result<()> {
    let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    let cfg = config_loader::load_config(&entries).with_context(|| "load config for DNS tools")?;
    match args.command {
        DnsCommands::Query(query_args) => run_query(&cfg, query_args),
        DnsCommands::Cache(cache_args) => run_cache(&cfg, cache_args),
        DnsCommands::Upstream(upstream_args) => run_upstream(&cfg, upstream_args),
    }
}

fn run_query(cfg: &sb_config::Config, args: QueryArgs) -> Result<()> {
    // Build DNS resolver from config IR
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;

    if cfg.ir().dns.is_none() {
        anyhow::bail!("No DNS configuration found in config");
    }

    let resolver = sb_core::dns::config_builder::resolver_from_ir(cfg.ir())
        .context("build DNS resolver from config")?;

    // Query DNS
    let result = rt.block_on(async {
        if args.explain {
            resolver.explain(&args.domain).await
        } else {
            // Regular query
            let answer = resolver.resolve(&args.domain).await?;
            Ok(serde_json::json!({
                "domain": args.domain,
                "ips": answer.ips,
                "ttl_secs": answer.ttl.as_secs(),
                "source": format!("{:?}", answer.source),
                "rcode": answer.rcode.as_str(),
            }))
        }
    })?;

    // Output result
    output::emit(
        args.format,
        || {
            if args.explain {
                format!("{} DNS query explain", args.domain)
            } else {
                format!("{} resolved", args.domain)
            }
        },
        &result,
    );

    Ok(())
}

fn run_cache(cfg: &sb_config::Config, args: CacheArgs) -> Result<()> {
    // Build DNS resolver and get cache statistics
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;

    let stats = if cfg.ir().dns.is_some() {
        match sb_core::dns::config_builder::resolver_from_ir(cfg.ir()) {
            Ok(resolver) => {
                let (cache_size, cache_cap) = resolver.cache_stats();
                serde_json::json!({
                    "cache_size": cache_size,
                    "cache_capacity": cache_cap,
                    "usage_percent": if cache_cap > 0 { (cache_size as f64 / cache_cap as f64 * 100.0).round() } else { 0.0 },
                    "resolver": resolver.name(),
                })
            }
            Err(e) => {
                serde_json::json!({
                    "error": format!("Failed to build resolver: {}", e),
                    "cache_size": 0,
                    "cache_capacity": 0,
                })
            }
        }
    } else {
        serde_json::json!({
            "note": "No DNS configuration found",
            "cache_size": 0,
            "cache_capacity": 0,
        })
    };

    // Silence unused warning for runtime (resolver is sync constructed)
    drop(rt);

    output::emit(args.format, || "DNS cache stats".to_string(), &stats);

    Ok(())
}

fn run_upstream(cfg: &sb_config::Config, args: UpstreamArgs) -> Result<()> {
    // Get upstream info from DNS config IR
    let upstream_names: Vec<String> = if let Some(dns) = &cfg.ir().dns {
        dns.servers
            .iter()
            .map(|s| format!("{} ({})", s.tag, s.address))
            .collect()
    } else {
        Vec::new()
    };

    let upstreams_info = serde_json::json!({
        "upstreams": upstream_names,
        "count": upstream_names.len(),
        "note": "Health checks not yet implemented"
    });

    output::emit(
        args.format,
        || "DNS upstream status".to_string(),
        &upstreams_info,
    );

    Ok(())
}
