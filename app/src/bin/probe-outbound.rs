use anyhow::{Context, Result};
use clap::Parser;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(name = "probe-outbound")]
#[command(about = "Probe a named outbound (VMess/VLESS/Trojan) with layered transports", long_about = None)]
struct Args {
    /// Path to config file (YAML/JSON)
    #[arg(long)]
    config: String,
    /// Outbound tag/name to use
    #[arg(long)]
    outbound: String,
    /// Target host:port to connect to through the outbound
    #[arg(long)]
    target: String,
    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
    /// Print derived transport chain for the outbound
    #[arg(long, default_value_t = false)]
    print_transport: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load config and convert to IR
    let cfg = sb_config::Config::load(&args.config)
        .with_context(|| format!("load config: {}", &args.config))?;
    let ir = sb_config::present::to_ir(&cfg).context("config -> IR")?;

    // Register adapters before bridge assembly.
    app::util::register_adapters_once();

    // Build adapter-aware bridge and find outbound.
    #[cfg(feature = "router")]
    let bridge = {
        let engine = sb_core::routing::engine::Engine::new(std::sync::Arc::new(ir.clone()));
        sb_core::adapter::bridge::build_bridge(&ir, engine, sb_core::context::Context::default())
    };
    #[cfg(not(feature = "router"))]
    let bridge =
        sb_core::adapter::bridge::build_bridge(&ir, (), sb_core::context::Context::default());

    if args.print_transport {
        #[cfg(feature = "v2ray_transport")]
        {
            if let Some(ob) = ir
                .outbounds
                .iter()
                .find(|o| o.name.as_deref() == Some(args.outbound.as_str()))
            {
                let chain = sb_core::runtime::transport::map::chain_from_ir(ob);
                eprintln!("transport_chain={}", chain.join(","));
            } else {
                eprintln!("outbound not found: {}", args.outbound);
            }
        }
        #[cfg(not(feature = "v2ray_transport"))]
        {
            eprintln!(
                "transport chain inspection requires the `v2ray_transport` feature. \
                 Re-run with `--features v2ray_transport`."
            );
        }
    }

    let connector = bridge
        .get_member(&args.outbound)
        .ok_or_else(|| anyhow::anyhow!("outbound not found: {}", args.outbound))?;

    // Parse target host:port
    let (host, port) = parse_hostport(&args.target)?;

    // Dial and send a basic HTTP GET to validate end-to-end
    let started = Instant::now();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(args.timeout),
        connector.connect(&host, port),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout after {}s", args.timeout))?
    .context("dial outbound")?;
    let connected_ms = started.elapsed().as_millis() as u64;

    // Write a GET request
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: singbox-rust/cli\r\nConnection: close\r\n\r\n",
        host
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context("write request")?;

    // Read some response bytes (up to 4 KB)
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.context("read response")?;

    println!(
        "OK connect_time_ms={} response_bytes={} first_line={}",
        connected_ms,
        n,
        extract_first_line(&buf[..n])
    );

    Ok(())
}

fn parse_hostport(s: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("parse port")?;
        Ok((h.to_string(), port))
    } else {
        Err(anyhow::anyhow!("invalid host:port: {}", s))
    }
}

fn extract_first_line(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.lines().next().unwrap_or("").to_string()
}
