//! Utility tooling subcommand (parity with sing-box `tools`)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(ValueEnum, Clone, Debug)]
pub enum Net {
    Tcp,
    Udp,
}

#[derive(Parser, Debug)]
#[command(name = "tools")]
#[command(about = "Utility tools", long_about = None)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub command: ToolsCmd,
}

#[derive(Subcommand, Debug)]
pub enum ToolsCmd {
    /// Connect to an address and pipe stdin/stdout
    Connect {
        /// host:port
        #[arg(value_name = "ADDR")]
        addr: String,
        /// Network type (tcp)
        #[arg(short = 'n', long = "network", value_enum, default_value_t = Net::Tcp)]
        network: Net,
        /// Config file path
        #[arg(short = 'c', long = "config")]
        config: PathBuf,
        /// Use named outbound (fallback to direct when absent)
        #[arg(long = "outbound")]
        outbound: Option<String>,
    },
    /// Download/update GeoIP/Geosite databases into a directory
    GeodataUpdate {
        /// Destination directory to write geoip.db and geosite.db
        #[arg(long, value_name = "DIR", default_value = "./data")]
        dest: PathBuf,
        /// GeoIP database URL
        #[arg(
            long,
            default_value = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
        )]
        geoip_url: String,
        /// Geosite database URL
        #[arg(
            long,
            default_value = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
        )]
        geosite_url: String,
        /// Optional SHA256 for geoip.db
        #[arg(long)]
        geoip_sha256: Option<String>,
        /// Optional SHA256 for geosite.db
        #[arg(long)]
        geosite_sha256: Option<String>,
    },
    /// Fetch a URL (HTTP/HTTPS) and print body to stdout
    Fetch {
        /// URL to fetch
        #[arg(value_name = "URL")]
        url: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Query NTP server and print time offset
    Synctime {
        /// NTP server (default: time.google.com:123)
        #[arg(long, default_value = "time.google.com:123")]
        server: String,
        /// Timeout seconds
        #[arg(long, default_value_t = 3u64)]
        timeout: u64,
    },
    /// Fetch a URL using HTTP/3 (feature-gated)
    FetchHttp3 {
        /// URL to fetch (https://...)
        #[arg(value_name = "URL")]
        url: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Lookup a domain using DNS
    DnsLookup {
        /// Domain to lookup
        #[arg(value_name = "DOMAIN")]
        domain: String,
        /// DNS server address (e.g. udp://1.1.1.1)
        #[arg(short = 's', long = "server")]
        server: Option<String>,
        /// Config file path (to use DNS config)
        #[arg(short = 'c', long = "config")]
        config: Option<PathBuf>,
        /// Explain the query (show rule match)
        #[arg(long)]
        explain: bool,
    },
}

pub async fn run(args: ToolsArgs) -> Result<()> {
    match args.command {
        ToolsCmd::Connect {
            addr,
            network,
            config,
            outbound,
        } => connect(addr, network, config, outbound).await,
        ToolsCmd::Fetch { url, output } => fetch(url, output).await,
        ToolsCmd::Synctime { server, timeout } => synctime(server, timeout).await,
        ToolsCmd::FetchHttp3 { url, output } => fetch_http3(url, output).await,
        ToolsCmd::GeodataUpdate {
            dest,
            geoip_url,
            geosite_url,
            geoip_sha256,
            geosite_sha256,
        } => {
            geodata_update(
                dest,
                &geoip_url,
                &geosite_url,
                geoip_sha256.as_deref(),
                geosite_sha256.as_deref(),
            )
            .await
        }
        ToolsCmd::DnsLookup {
            domain,
            server,
            config,
            explain,
        } => dns_lookup(domain, server, config, explain).await,
    }
}

async fn connect(
    addr: String,
    network: Net,
    config: PathBuf,
    outbound: Option<String>,
) -> Result<()> {
    match network {
        Net::Tcp => connect_tcp(addr.clone(), config.clone(), outbound.clone()).await,
        Net::Udp => connect_udp(addr, config, outbound).await,
    }
}

async fn connect_tcp(addr: String, config_path: PathBuf, outbound: Option<String>) -> Result<()> {
    // Load config JSON
    let raw =
        std::fs::read(&config_path).with_context(|| format!("read {}", config_path.display()))?;
    let val: serde_json::Value = serde_json::from_slice(&raw).context("parse JSON config")?;

    // Convert to IR
    let ir = sb_config::validator::v2::to_ir_v1(&val);

    // Register adapters (if feature enabled) before building bridge
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();

    // Build bridge using adapter-aware path (tries adapter registry first, falls back to scaffold)
    #[cfg(feature = "router")]
    let bridge = {
        let engine = sb_core::routing::engine::Engine::new(&ir);
        sb_core::adapter::bridge::build_bridge(&ir, engine, sb_core::context::Context::default())
    };
    #[cfg(not(feature = "router"))]
    let bridge = sb_core::adapter::bridge::build_bridge(&ir, (), sb_core::context::Context::default());

    // Parse host:port
    let (host, port) = parse_addr(&addr).context("invalid address, expected host:port")?;

    // Pick outbound
    let connector = if let Some(name) = outbound {
        bridge
            .get_member(&name)
            .or_else(|| bridge.find_direct_fallback())
            .context("outbound not found and no direct fallback")?
    } else {
        bridge
            .find_direct_fallback()
            .or_else(|| bridge.get_member("direct"))
            .context("no direct outbound found")?
    };

    // Dial
    let stream = connector
        .connect(&host, port)
        .await
        .context("connect failed")?;

    // Pipe stdin -> stream, stream -> stdout
    let (mut ro, mut wo) = tokio::io::split(stream);
    let a = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        tokio::io::copy(&mut stdin, &mut wo).await.ok();
        let _ = wo.shutdown().await;
    });
    let b = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut ro, &mut stdout).await.ok();
        let _ = stdout.flush().await;
    });
    let _ = tokio::join!(a, b);
    Ok(())
}

fn parse_addr(s: &str) -> Option<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    None
}

async fn connect_udp(addr: String, config_path: PathBuf, outbound: Option<String>) -> Result<()> {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    let (host, port) = parse_addr(&addr).context("invalid address, expected host:port")?;

    // Try to use an outbound UDP factory when available
    let factory = if let Some(name) = outbound.as_deref() {
        // Load config JSON and build bridge to access UDP factories
        let raw = std::fs::read(&config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        let val: serde_json::Value = serde_json::from_slice(&raw).context("parse JSON config")?;
        let ir = sb_config::validator::v2::to_ir_v1(&val);

        // Register adapters before building bridge
        #[cfg(feature = "adapters")]
        sb_adapters::register_all();

        // Build bridge using adapter-aware path
        #[cfg(feature = "router")]
        let bridge = {
            let engine = sb_core::routing::engine::Engine::new(&ir);
            sb_core::adapter::bridge::build_bridge(&ir, engine, sb_core::context::Context::default())
        };
        #[cfg(not(feature = "router"))]
        let bridge = sb_core::adapter::bridge::build_bridge(&ir, (), sb_core::context::Context::default());

        bridge.find_udp_factory(name)
    } else {
        None
    };

    if let Some(f) = factory {
        // Use adapter-provided UDP session
        let sess = f.open_session().await.context("open udp session")?;
        // stdin -> udp
        let host_c = host.clone();
        let sess_clone = sess.clone();
        let s1 = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sess_clone.send_to(&buf[..n], &host_c, port).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        // udp -> stdout
        let s2 = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            loop {
                match sess.recv_from().await {
                    Ok((data, _src)) => {
                        if tokio::io::AsyncWriteExt::write_all(&mut stdout, &data)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tokio::io::AsyncWriteExt::flush(&mut stdout).await;
        });
        let _ = tokio::join!(s1, s2);
        return Ok(());
    }

    // Fallback: direct UDP
    let target = format!("{}:{}", host, port);
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.context("bind udp")?);
    sock.connect(&target).await.context("connect udp")?;

    // stdin -> udp
    let s1 = sock.clone();
    let a = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if s1.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // udp -> stdout
    let s2 = sock.clone();
    let b = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = [0u8; 8192];
        loop {
            // add a small idle timeout to allow exit on no traffic
            match timeout(Duration::from_millis(500), s2.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if n == 0 {
                        break;
                    }
                    if tokio::io::AsyncWriteExt::write_all(&mut stdout, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    // idle, continue; allow CTRL-D on stdin task to finish
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::flush(&mut stdout).await;
    });

    let _ = tokio::join!(a, b);
    Ok(())
}

async fn fetch(url: String, output: Option<PathBuf>) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(format!("singbox-rust-tools/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let rsp = client.get(&url).send().await.context("http fetch")?;
    let status = rsp.status();
    let bytes = rsp.bytes().await.context("read body")?;
    if let Some(p) = output {
        std::fs::write(&p, &bytes).with_context(|| format!("write {}", p.display()))?;
        eprintln!(
            "{} {} -> {} bytes -> {}",
            status.as_u16(),
            url,
            bytes.len(),
            p.display()
        );
    } else {
        eprintln!("{} {} ({} bytes)", status.as_u16(), url, bytes.len());
        tokio::io::stdout().write_all(&bytes).await?;
    }
    Ok(())
}

async fn synctime(server: String, timeout: u64) -> Result<()> {
    use std::net::ToSocketAddrs;
    use tokio::net::UdpSocket;
    use tokio::time::{timeout as tk_timeout, Duration};

    let addr = server
        .to_socket_addrs()
        .context("resolve server")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for server"))?;

    let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind udp")?;
    sock.connect(addr).await.context("connect udp")?;

    let mut pkt = [0u8; 48];
    pkt[0] = 0b00_011_011; // LI=0 VN=3 Mode=3 (client)
                           // transmit timestamp is left zero; server will fill originate/receive/transmit

    sock.send(&pkt).await.context("send ntp")?;

    let mut buf = [0u8; 48];
    let n = tk_timeout(Duration::from_secs(timeout), sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timeout"))?
        .context("recv ntp")?;
    if n < 48 {
        anyhow::bail!("short NTP packet");
    }

    let t0 = ntp_now_seconds();
    let offset = compute_ntp_offset(t0, &buf);
    println!("ntp_server={server} offset_seconds={:.6}", offset);
    Ok(())
}

async fn geodata_update(
    dest: PathBuf,
    geoip_url: &str,
    geosite_url: &str,
    geoip_sha256: Option<&str>,
    geosite_sha256: Option<&str>,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::fs;

    fs::create_dir_all(&dest)
        .await
        .with_context(|| format!("create dir {}", dest.display()))?;

    let client = reqwest::Client::builder()
        .user_agent(format!("singbox-rust-tools/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Download helper
    async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
        if let Some(path) = file_url_to_path(url) {
            return fs::read(&path)
                .await
                .with_context(|| format!("read {}", path.display()));
        }

        let rsp = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        if !rsp.status().is_success() {
            anyhow::bail!("download failed: {} {}", rsp.status(), url);
        }
        let bytes = rsp
            .bytes()
            .await
            .with_context(|| format!("read body from {}", url))?;
        Ok(bytes.to_vec())
    }

    // Write helper with optional sha256
    async fn write_checked(
        path: &PathBuf,
        data: &[u8],
        sha256: Option<&str>,
        label: &str,
    ) -> Result<()> {
        if let Some(expect) = sha256 {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let got = format!("{:x}", hasher.finalize());
            if !got.eq_ignore_ascii_case(expect) {
                anyhow::bail!(
                    "{} sha256 mismatch: expected={}, got={}",
                    label,
                    expect,
                    got
                );
            }
        }
        tokio::fs::write(path, data)
            .await
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    let geoip = download(&client, geoip_url).await?;
    let geosite = download(&client, geosite_url).await?;

    let geoip_path = dest.join("geoip.db");
    let geosite_path = dest.join("geosite.db");
    write_checked(&geoip_path, &geoip, geoip_sha256, "geoip").await?;
    write_checked(&geosite_path, &geosite, geosite_sha256, "geosite").await?;

    // Produce a simple manifest for packaging/release integration
    // Includes filenames, sizes and SHA256 checksums for reproducibility
    let mut sha = Sha256::new();
    sha.update(&geoip);
    let geoip_sha = format!("{:x}", sha.finalize_reset());
    sha.update(&geosite);
    let geosite_sha = format!("{:x}", sha.finalize());

    let manifest = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "files": [
            {
                "name": "geoip.db",
                "path": geoip_path.to_string_lossy(),
                "size": geoip.len(),
                "sha256": geoip_sha,
                "source_url": geoip_url,
            },
            {
                "name": "geosite.db",
                "path": geosite_path.to_string_lossy(),
                "size": geosite.len(),
                "sha256": geosite_sha,
                "source_url": geosite_url,
            }
        ]
    });
    let manifest_path = dest.join("manifest.json");
    tokio::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .await
        .with_context(|| format!("write {}", manifest_path.display()))?;

    eprintln!(
        "updated: {} ({} bytes), {} ({} bytes)",
        geoip_path.display(),
        geoip.len(),
        geosite_path.display(),
        geosite.len()
    );
    eprintln!("manifest: {}", manifest_path.display());
    Ok(())
}

fn file_url_to_path(url: &str) -> Option<PathBuf> {
    let raw = url.strip_prefix("file://")?;
    #[cfg(windows)]
    let cleaned = if raw.starts_with('/') && raw.chars().nth(2) == Some(':') {
        &raw[1..]
    } else {
        raw
    };
    #[cfg(not(windows))]
    let cleaned = raw;
    Some(PathBuf::from(cleaned))
}

// Return current time in NTP seconds (seconds since 1900-01-01 with fractional part)
fn ntp_now_seconds() -> f64 {
    const NTP_UNIX_DELTA: u64 = 2_208_988_800; // seconds between 1900 and 1970
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (now.as_secs() + NTP_UNIX_DELTA) as f64 + (now.subsec_nanos() as f64) / 1e9
}

// Compute NTP offset using a simplified approach when originate timestamp is unavailable in request
// Uses server receive (t2) and transmit (t3) timestamps and local now (t0)
fn compute_ntp_offset(t0_ntp_seconds: f64, packet: &[u8]) -> f64 {
    // NTP timestamps are seconds since 1900-01-01 with 32.32 fixed point
    fn read_ts(b: &[u8]) -> f64 {
        if b.len() < 8 {
            return 0.0;
        }
        let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
        let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as u64;
        (secs as f64) + (frac as f64) / (u32::MAX as f64 + 1.0)
    }
    // In a fully correct exchange we would use t1 (originate), t2 (receive), t3 (transmit), t4 (arrival)
    // Here we approximate with t1≈0 because we didn't set transmit timestamp in the request.
    let t1 = 0.0f64;
    let t2 = read_ts(&packet[32..40]); // server receive time
    let t3 = read_ts(&packet[40..48]); // server transmit time
                                       // Normalize all timestamps to the integral seconds of t0 so large base seconds cancel out
    let base = t0_ntp_seconds.floor();
    let t0n = t0_ntp_seconds - base;
    let t2n = t2 - base;
    let t3n = t3 - base;
    // offset ≈ ((t2 - t1) + (t3 - t0)) / 2 with t1≈0, using normalized values
    ((t2n - t1) + (t3n - t0n)) / 2.0
}

#[cfg(test)]
mod ntp_tests {
    use super::*;

    // Helper to write a 32.32 fixed-point NTP timestamp
    fn write_ts(buf: &mut [u8], secs: u64, frac: u32) {
        let s = (secs as u32).to_be_bytes();
        let f = frac.to_be_bytes();
        buf[..4].copy_from_slice(&s);
        buf[4..8].copy_from_slice(&f);
    }

    #[test]
    fn compute_offset_basic() {
        // Construct minimal 48-byte NTP response
        let mut pkt = [0u8; 48];
        // Choose an arbitrary base time in NTP seconds (e.g., 3900000000)
        let base_secs = 3_900_000_000u64;
        // Server receive and transmit times are base+0.2s
        let frac_0p2 = ((0.2f64) * (u32::MAX as f64 + 1.0)) as u32;
        write_ts(&mut pkt[32..40], base_secs, frac_0p2); // t2
        write_ts(&mut pkt[40..48], base_secs, frac_0p2); // t3

        // Local now equals base time
        let t0 = base_secs as f64;
        let off = compute_ntp_offset(t0, &pkt);
        // With t1≈0, offset ≈ ((t2-0)+(t3-t0))/2 = (base+0.2 + (base+0.2 - base))/2 = ~0.2
        assert!(off > 0.19 && off < 0.21, "off={off}");
    }
}

#[cfg(feature = "tools_http3")]
async fn fetch_http3(url: String, output: Option<PathBuf>) -> Result<()> {
    // Use reqwest with http3 feature; if server supports H3, it will negotiate H3.
    // On non-H3 servers, it will fall back to H2/H1.
    let mut builder = reqwest::Client::builder().user_agent(format!(
        "singbox-rust-tools/{} (+http3)",
        env!("CARGO_PKG_VERSION")
    ));
    #[cfg(feature = "reqwest_unstable")]
    {
        use reqwest::ClientBuilder;
        builder = ClientBuilder::http3_prior_knowledge(builder);
    }
    let client = builder.build()?;
    let rsp = client.get(&url).send().await.context("http3 fetch")?;
    let status = rsp.status();
    let bytes = rsp.bytes().await.context("read body")?;
    if let Some(p) = output {
        std::fs::write(&p, &bytes).with_context(|| format!("write {}", p.display()))?;
        eprintln!(
            "{} {} -> {} bytes -> {}",
            status.as_u16(),
            url,
            bytes.len(),
            p.display()
        );
    } else {
        eprintln!("{} {} ({} bytes)", status.as_u16(), url, bytes.len());
        tokio::io::stdout().write_all(&bytes).await?;
    }
    Ok(())
}

#[cfg(not(feature = "tools_http3"))]
async fn fetch_http3(_url: String, _output: Option<PathBuf>) -> Result<()> {
    anyhow::bail!("http3 fetch not built: recompile with --features tools_http3")
}

async fn dns_lookup(
    domain: String,
    server: Option<String>,
    config: Option<PathBuf>,
    explain: bool,
) -> Result<()> {
    use sb_core::dns::Resolver;

    let resolver: Arc<dyn Resolver> = if let Some(s) = server {
        // Build single upstream resolver
        let up = sb_core::dns::config_builder::build_upstream(&s)?
            .ok_or_else(|| anyhow::anyhow!("invalid upstream address: {}", s))?;
        Arc::new(sb_core::dns::resolver::DnsResolver::new(vec![up]))
    } else if let Some(p) = config {
        // Load from config
        let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
        let val: serde_json::Value = serde_json::from_slice(&raw).context("parse JSON config")?;
        let ir = sb_config::validator::v2::to_ir_v1(&val);
        if let Some(dns_ir) = ir.dns {
            sb_core::dns::config_builder::resolver_from_ir(&dns_ir)?
        } else {
            // No DNS config, fallback to system
            Arc::new(sb_core::dns::resolver::DnsResolver::new(vec![Arc::new(
                sb_core::dns::upstream::SystemUpstream::new(),
            )]))
        }
    } else {
        // Default to system
        Arc::new(sb_core::dns::resolver::DnsResolver::new(vec![Arc::new(
            sb_core::dns::upstream::SystemUpstream::new(),
        )]))
    };

    if explain {
        let explanation = resolver.explain(&domain).await?;
        let answer = resolver.resolve(&domain).await?;
        let output = serde_json::json!({
            "domain": domain,
            "explain": explanation,
            "answer": {
                "ips": answer.ips,
                "ttl_secs": answer.ttl.as_secs(),
                "source": match answer.source {
                    sb_core::dns::cache::Source::Static => "static",
                    sb_core::dns::cache::Source::System => "system",
                    sb_core::dns::cache::Source::Upstream => "upstream",
                },
                "rcode": answer.rcode.as_str(),
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let answer = resolver.resolve(&domain).await?;
    for ip in answer.ips {
        println!("{}", ip);
    }

    Ok(())
}
