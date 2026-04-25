use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_adapters::traits::{DialOpts, OutboundConnector as _, Target, TransportKind};
#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_tls::TlsConnector as _;

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
    /// Emit structured probe diagnostics as JSON on stdout
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct ProbeJsonOutput {
    tool: &'static str,
    config: String,
    outbound: String,
    outbound_type: Option<String>,
    target: String,
    timeout_secs: u64,
    pre_bridge: Option<VlessDirectPhaseReport>,
    post_bridge: Option<VlessDirectPhaseReport>,
    bridge_probe: Option<BridgeProbeReport>,
}

#[derive(Debug, Serialize)]
struct VlessDirectPhaseReport {
    direct_reality: ProbePhaseResult,
    direct_vless_dial: ProbePhaseResult,
}

#[derive(Debug, Serialize)]
struct BridgeProbeReport {
    ok: bool,
    stream_mode: Option<&'static str>,
    stage: Option<&'static str>,
    class: Option<String>,
    connect_time_ms: u64,
    response_bytes: Option<usize>,
    first_line: Option<String>,
    raw_connect_error: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProbePhaseResult {
    ok: bool,
    status: &'static str,
    elapsed_micros: u64,
    class: Option<String>,
    error: Option<String>,
    reason: Option<String>,
}

#[allow(dead_code)] // Some constructors are only used when adapter-vless/tls_reality probes compile in.
impl ProbePhaseResult {
    fn ok(elapsed_micros: u64) -> Self {
        Self {
            ok: true,
            status: "ok",
            elapsed_micros,
            class: None,
            error: None,
            reason: None,
        }
    }

    fn error(elapsed_micros: u64, error: impl ToString) -> Self {
        let raw_error = error.to_string();
        let class = classify_probe_error_text(&raw_error).to_string();
        let error = sanitize_probe_detail(&raw_error);
        Self {
            ok: false,
            status: "err",
            elapsed_micros,
            class: Some(class),
            error: Some(error),
            reason: None,
        }
    }

    fn timeout(elapsed_micros: u64, timeout_secs: u64) -> Self {
        Self {
            ok: false,
            status: "timeout",
            elapsed_micros,
            class: Some("timeout".to_string()),
            error: Some(format!("timeout after {}s", timeout_secs)),
            reason: None,
        }
    }

    fn skip(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            status: "skip",
            elapsed_micros: 0,
            class: None,
            error: None,
            reason: Some(reason.into()),
        }
    }
}

enum ProbeStream {
    Raw(TcpStream),
    Layered(sb_transport::IoStream),
}

impl ProbeStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Raw(stream) => stream.write_all(buf).await,
            Self::Layered(stream) => stream.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Raw(stream) => stream.read(buf).await,
            Self::Layered(stream) => stream.read(buf).await,
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            Self::Raw(_) => "connect",
            Self::Layered(_) => "connect_io",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    #[cfg(feature = "tls_reality")]
    sb_tls::ensure_crypto_provider();

    // Load config and convert to IR
    let cfg = sb_config::Config::load(&args.config)
        .with_context(|| format!("load config: {}", &args.config))?;
    let ir = sb_config::present::to_ir(&cfg).context("config -> IR")?;
    let (host, port) = parse_hostport(&args.target)?;

    let selected_outbound = ir
        .outbounds
        .iter()
        .find(|o| o.name.as_deref() == Some(args.outbound.as_str()));

    let mut probe_output = ProbeJsonOutput {
        tool: "probe-outbound",
        config: args.config.clone(),
        outbound: args.outbound.clone(),
        outbound_type: selected_outbound.map(|outbound| outbound.ty.ty_str().to_string()),
        target: args.target.clone(),
        timeout_secs: args.timeout,
        pre_bridge: None,
        post_bridge: None,
        bridge_probe: None,
    };

    #[cfg(any(feature = "adapters", feature = "adapter-vless"))]
    if let Some(outbound) = selected_outbound {
        probe_output.pre_bridge =
            maybe_probe_vless_direct("pre_bridge", outbound, &host, port, args.timeout).await;
    }

    // Register adapters before bridge assembly.
    register_adapters_once();

    // Build adapter-aware bridge and find outbound.
    let bridge = {
        let engine = sb_core::routing::engine::Engine::new(std::sync::Arc::new(ir.clone()));
        sb_core::adapter::bridge::build_bridge(&ir, engine, sb_core::context::Context::default())
    };

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

    #[cfg(any(feature = "adapters", feature = "adapter-vless"))]
    if let Some(outbound) = selected_outbound {
        probe_output.post_bridge =
            maybe_probe_vless_direct("post_bridge", outbound, &host, port, args.timeout).await;
    }

    // Dial and send a basic HTTP GET to validate end-to-end
    let started = Instant::now();
    let mut raw_connect_error = None;
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(args.timeout),
        connector.connect(&host, port),
    )
    .await
    {
        Ok(Ok(stream)) => ProbeStream::Raw(stream),
        Err(_) => {
            let connected_ms = started.elapsed().as_millis() as u64;
            probe_output.bridge_probe = Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some("connect"),
                stage: Some("connect"),
                class: Some("timeout".to_string()),
                connect_time_ms: connected_ms,
                response_bytes: None,
                first_line: None,
                raw_connect_error: None,
                error: Some(format!("timeout after {}s", args.timeout)),
            });
            print_probe_error(
                args.json,
                "connect",
                "connect",
                "timeout",
                connected_ms,
                &format!("timeout after {}s", args.timeout),
            );
            maybe_print_probe_json(args.json, &probe_output);
            anyhow::bail!("connect timeout after {}s", args.timeout);
        }
        Ok(Err(connect_err)) => {
            let raw_error = sanitize_probe_detail(&connect_err.to_string());
            raw_connect_error = Some(raw_error.clone());
            match tokio::time::timeout(
                Duration::from_secs(args.timeout),
                connector.connect_io(&host, port),
            )
            .await
            {
                Ok(Ok(stream)) => ProbeStream::Layered(stream),
                Ok(Err(error)) => {
                    let connected_ms = started.elapsed().as_millis() as u64;
                    let detail = format!(
                        "dial outbound via connect_io after connect error: {connect_err}: {error}"
                    );
                    probe_output.bridge_probe = Some(BridgeProbeReport {
                        ok: false,
                        stream_mode: Some("connect_io"),
                        stage: Some("connect"),
                        class: Some(classify_probe_error_text(&error.to_string()).to_string()),
                        connect_time_ms: connected_ms,
                        response_bytes: None,
                        first_line: None,
                        raw_connect_error,
                        error: Some(sanitize_probe_detail(&detail)),
                    });
                    print_probe_error(
                        args.json,
                        "connect_io",
                        "connect",
                        classify_probe_error_text(&error.to_string()),
                        connected_ms,
                        &detail,
                    );
                    maybe_print_probe_json(args.json, &probe_output);
                    return Err(error).with_context(|| {
                        format!("dial outbound via connect_io after connect error: {connect_err}")
                    });
                }
                Err(_) => {
                    let connected_ms = started.elapsed().as_millis() as u64;
                    probe_output.bridge_probe = Some(BridgeProbeReport {
                        ok: false,
                        stream_mode: Some("connect_io"),
                        stage: Some("connect"),
                        class: Some("timeout".to_string()),
                        connect_time_ms: connected_ms,
                        response_bytes: None,
                        first_line: None,
                        raw_connect_error,
                        error: Some(format!("timeout after {}s", args.timeout)),
                    });
                    print_probe_error(
                        args.json,
                        "connect_io",
                        "connect",
                        "timeout",
                        connected_ms,
                        &format!("timeout after {}s", args.timeout),
                    );
                    maybe_print_probe_json(args.json, &probe_output);
                    anyhow::bail!("connect_io timeout after {}s", args.timeout);
                }
            }
        }
    };
    let connected_ms = started.elapsed().as_millis() as u64;

    // Write a GET request
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: singbox-rust/cli\r\nConnection: close\r\n\r\n",
        host
    );
    match tokio::time::timeout(
        Duration::from_secs(args.timeout),
        stream.write_all(req.as_bytes()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            probe_output.bridge_probe = Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some(stream.mode()),
                stage: Some("write"),
                class: Some(classify_probe_error_text(&error.to_string()).to_string()),
                connect_time_ms: connected_ms,
                response_bytes: None,
                first_line: None,
                raw_connect_error,
                error: Some(sanitize_probe_detail(&error.to_string())),
            });
            print_probe_error(
                args.json,
                stream.mode(),
                "write",
                classify_probe_error_text(&error.to_string()),
                connected_ms,
                &error,
            );
            maybe_print_probe_json(args.json, &probe_output);
            return Err(error).context("write request");
        }
        Err(_) => {
            probe_output.bridge_probe = Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some(stream.mode()),
                stage: Some("write"),
                class: Some("timeout".to_string()),
                connect_time_ms: connected_ms,
                response_bytes: None,
                first_line: None,
                raw_connect_error,
                error: Some(format!("timeout after {}s", args.timeout)),
            });
            print_probe_error(
                args.json,
                stream.mode(),
                "write",
                "timeout",
                connected_ms,
                &format!("timeout after {}s", args.timeout),
            );
            maybe_print_probe_json(args.json, &probe_output);
            anyhow::bail!("write request timeout after {}s", args.timeout);
        }
    }

    // Read some response bytes (up to 4 KB)
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_secs(args.timeout), stream.read(&mut buf))
        .await
    {
        Ok(Ok(read)) => read,
        Ok(Err(error)) => {
            probe_output.bridge_probe = Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some(stream.mode()),
                stage: Some("read"),
                class: Some(classify_probe_error_text(&error.to_string()).to_string()),
                connect_time_ms: connected_ms,
                response_bytes: None,
                first_line: None,
                raw_connect_error,
                error: Some(sanitize_probe_detail(&error.to_string())),
            });
            print_probe_error(
                args.json,
                stream.mode(),
                "read",
                classify_probe_error_text(&error.to_string()),
                connected_ms,
                &error,
            );
            maybe_print_probe_json(args.json, &probe_output);
            return Err(error).context("read response");
        }
        Err(_) => {
            probe_output.bridge_probe = Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some(stream.mode()),
                stage: Some("read"),
                class: Some("timeout".to_string()),
                connect_time_ms: connected_ms,
                response_bytes: None,
                first_line: None,
                raw_connect_error,
                error: Some(format!("timeout after {}s", args.timeout)),
            });
            print_probe_error(
                args.json,
                stream.mode(),
                "read",
                "timeout",
                connected_ms,
                &format!("timeout after {}s", args.timeout),
            );
            maybe_print_probe_json(args.json, &probe_output);
            anyhow::bail!("read response timeout after {}s", args.timeout);
        }
    };
    if n == 0 {
        probe_output.bridge_probe = Some(BridgeProbeReport {
            ok: false,
            stream_mode: Some(stream.mode()),
            stage: Some("read"),
            class: Some("post_dial_eof".to_string()),
            connect_time_ms: connected_ms,
            response_bytes: Some(0),
            first_line: None,
            raw_connect_error,
            error: Some("upstream returned eof before response bytes".to_string()),
        });
        print_probe_error(
            args.json,
            stream.mode(),
            "read",
            "post_dial_eof",
            connected_ms,
            "upstream returned eof before response bytes",
        );
        maybe_print_probe_json(args.json, &probe_output);
        anyhow::bail!("early eof while reading response");
    }

    let first_line = extract_first_line(&buf[..n]);
    probe_output.bridge_probe = Some(BridgeProbeReport {
        ok: true,
        stream_mode: Some(stream.mode()),
        stage: None,
        class: None,
        connect_time_ms: connected_ms,
        response_bytes: Some(n),
        first_line: Some(first_line.clone()),
        raw_connect_error,
        error: None,
    });
    print_probe_ok(args.json, stream.mode(), connected_ms, n, &first_line);
    maybe_print_probe_json(args.json, &probe_output);

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

fn print_probe_error(
    json_mode: bool,
    stream_mode: &str,
    stage: &str,
    class: &str,
    connected_ms: u64,
    detail: impl std::fmt::Display,
) {
    let line = format!(
        "ERR stream_mode={} stage={} class={} connect_time_ms={} detail={}",
        stream_mode,
        stage,
        class,
        connected_ms,
        sanitize_probe_detail(&detail.to_string())
    );
    if json_mode {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

fn print_probe_ok(
    json_mode: bool,
    stream_mode: &str,
    connected_ms: u64,
    response_bytes: usize,
    first_line: &str,
) {
    let line = format!(
        "OK stream_mode={} connect_time_ms={} response_bytes={} first_line={}",
        stream_mode, connected_ms, response_bytes, first_line
    );
    if json_mode {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

fn classify_probe_error_text(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("http2 framing") || lower.contains("http/2 framing") {
        "http2_framing"
    } else if lower.contains("tls handshake eof") || lower.contains("handshake eof") {
        "reality_dial_eof"
    } else if lower.contains("early eof") || lower.contains("unexpected eof") || lower == "eof" {
        "post_dial_eof"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("can't complete socks5") || lower.contains("socks5") {
        "socks_connect"
    } else if lower.contains("connection reset") {
        "connection_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("operation not permitted") || lower.contains("permission denied") {
        "permission_denied"
    } else if lower.contains("connection refused") {
        "connection_refused"
    } else {
        "other"
    }
}

fn sanitize_probe_detail(detail: &str) -> String {
    let collapsed = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX_DETAIL_LEN: usize = 240;
    if collapsed.len() <= MAX_DETAIL_LEN {
        collapsed
    } else {
        format!(
            "{}...",
            collapsed.chars().take(MAX_DETAIL_LEN).collect::<String>()
        )
    }
}

fn maybe_print_probe_json(enabled: bool, output: &ProbeJsonOutput) {
    if enabled {
        println!(
            "{}",
            serde_json::to_string_pretty(output).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

#[inline]
fn register_adapters_once() {
    #[cfg(feature = "sb-adapters")]
    sb_adapters::register_all();
}

#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
async fn maybe_probe_vless_direct(
    phase: &'static str,
    outbound: &sb_config::ir::OutboundIR,
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Option<VlessDirectPhaseReport> {
    if outbound.ty != sb_config::ir::OutboundType::Vless {
        return None;
    }

    let Some(server) = outbound.server.clone() else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_server");
        return Some(VlessDirectPhaseReport::skipped("missing_server"));
    };
    let Some(server_port) = outbound.port else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_port");
        return Some(VlessDirectPhaseReport::skipped("missing_port"));
    };
    let Some(uuid_raw) = outbound.uuid.as_deref() else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_uuid");
        return Some(VlessDirectPhaseReport::skipped("missing_uuid"));
    };
    let uuid = match uuid::Uuid::parse_str(uuid_raw) {
        Ok(uuid) => uuid,
        Err(error) => {
            eprintln!("direct_vless_dial phase={phase} result=skip reason=bad_uuid error={error}");
            return Some(VlessDirectPhaseReport::skipped(format!(
                "bad_uuid: {error}"
            )));
        }
    };
    if outbound
        .transport
        .as_ref()
        .is_some_and(|entries| !entries.is_empty())
    {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=non_tcp_transport");
        return Some(VlessDirectPhaseReport::skipped("non_tcp_transport"));
    }

    let flow = match outbound.flow.as_deref() {
        Some("xtls-rprx-vision") => FlowControl::XtlsRprxVision,
        Some("xtls-rprx-direct") => FlowControl::XtlsRprxDirect,
        _ => FlowControl::None,
    };
    let encryption = match outbound.encryption.as_deref() {
        Some("aes-128-gcm") => Encryption::Aes128Gcm,
        Some("chacha20-poly1305") | Some("chacha20-ietf-poly1305") => Encryption::ChaCha20Poly1305,
        _ => Encryption::None,
    };
    let reality = if outbound.reality_enabled.unwrap_or(false) {
        outbound
            .reality_public_key
            .as_ref()
            .map(|public_key| sb_tls::RealityClientConfig {
                target: outbound
                    .reality_server_name
                    .clone()
                    .or_else(|| outbound.tls_sni.clone())
                    .unwrap_or_else(|| server.clone()),
                server_name: outbound
                    .reality_server_name
                    .clone()
                    .or_else(|| outbound.tls_sni.clone())
                    .unwrap_or_else(|| server.clone()),
                public_key: public_key.clone(),
                short_id: outbound.reality_short_id.clone(),
                fingerprint: outbound
                    .utls_fingerprint
                    .clone()
                    .unwrap_or_else(|| "chrome".to_string()),
                alpn: outbound.tls_alpn.clone().unwrap_or_default(),
            })
    } else {
        None
    };
    let direct_reality = if let Some(reality_config) = reality.as_ref() {
        eprintln!(
            "direct_vless_config phase={phase} server={server} port={server_port} sni={} fp={} short_id_len={} alpn_len={}",
            reality_config.server_name,
            reality_config.fingerprint,
            reality_config.short_id.as_deref().unwrap_or_default().len(),
            reality_config.alpn.len()
        );
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
            let stream = TcpStream::connect((server.as_str(), server_port)).await?;
            let connector = sb_tls::RealityConnector::new(reality_config.clone())?;
            let _tls = connector
                .connect(stream, &reality_config.server_name)
                .await?;
            Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                let elapsed_micros = started.elapsed().as_micros() as u64;
                eprintln!(
                    "direct_reality phase={phase} result=ok elapsed_ms={}",
                    elapsed_micros / 1000
                );
                ProbePhaseResult::ok(elapsed_micros)
            }
            Ok(Err(error)) => {
                let elapsed_micros = started.elapsed().as_micros() as u64;
                eprintln!(
                    "direct_reality phase={phase} result=err class={} elapsed_ms={} error={}",
                    classify_probe_error_text(&error.to_string()),
                    elapsed_micros / 1000,
                    error
                );
                ProbePhaseResult::error(elapsed_micros, error)
            }
            Err(_) => {
                let elapsed_micros = started.elapsed().as_micros() as u64;
                eprintln!(
                    "direct_reality phase={phase} result=timeout class=timeout elapsed_ms={}",
                    elapsed_micros / 1000
                );
                ProbePhaseResult::timeout(elapsed_micros, timeout_secs)
            }
        }
    } else {
        eprintln!("direct_reality phase={phase} result=skip reason=no_reality_config");
        ProbePhaseResult::skip("no_reality_config")
    };

    let mut vless_config = VlessConfig {
        server,
        port: server_port,
        uuid,
        flow,
        encryption,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: sb_adapters::transport_config::TransportConfig::Tcp,
        ..VlessConfig::default()
    };
    #[cfg(feature = "tls_reality")]
    {
        vless_config.reality = reality;
    }
    let connector = VlessConnector::new(vless_config);
    let target = Target {
        host: host.to_string(),
        port,
        kind: TransportKind::Tcp,
    };

    let started = Instant::now();
    let direct_vless_dial = match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.dial(target, DialOpts::new()),
    )
    .await
    {
        Ok(Ok(_)) => {
            let elapsed_micros = started.elapsed().as_micros() as u64;
            eprintln!(
                "direct_vless_dial phase={phase} result=ok elapsed_ms={}",
                elapsed_micros / 1000
            );
            ProbePhaseResult::ok(elapsed_micros)
        }
        Ok(Err(error)) => {
            let elapsed_micros = started.elapsed().as_micros() as u64;
            eprintln!(
                "direct_vless_dial phase={phase} result=err class={} elapsed_ms={} error={}",
                classify_probe_error_text(&error.to_string()),
                elapsed_micros / 1000,
                error
            );
            ProbePhaseResult::error(elapsed_micros, error)
        }
        Err(_) => {
            let elapsed_micros = started.elapsed().as_micros() as u64;
            eprintln!(
                "direct_vless_dial phase={phase} result=timeout class=timeout elapsed_ms={}",
                elapsed_micros / 1000
            );
            ProbePhaseResult::timeout(elapsed_micros, timeout_secs)
        }
    };

    Some(VlessDirectPhaseReport {
        direct_reality,
        direct_vless_dial,
    })
}

#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
impl VlessDirectPhaseReport {
    fn skipped(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            direct_reality: ProbePhaseResult::skip(reason.clone()),
            direct_vless_dial: ProbePhaseResult::skip(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_probe_error_text_covers_reality_live_failures() {
        assert_eq!(
            classify_probe_error_text("REALITY handshake failed: tls handshake eof"),
            "reality_dial_eof"
        );
        assert_eq!(
            classify_probe_error_text("curl: (16) Error in the HTTP2 framing layer"),
            "http2_framing"
        );
        assert_eq!(
            classify_probe_error_text("timed out waiting for first upstream byte"),
            "timeout"
        );
        assert_eq!(classify_probe_error_text("early eof"), "post_dial_eof");
        assert_eq!(
            classify_probe_error_text("Can't complete SOCKS5 connection"),
            "socks_connect"
        );
        assert_eq!(
            classify_probe_error_text("connection reset by peer"),
            "connection_reset"
        );
        assert_eq!(classify_probe_error_text("broken pipe"), "broken_pipe");
        assert_eq!(
            classify_probe_error_text("Operation not permitted (os error 1)"),
            "permission_denied"
        );
    }

    #[test]
    fn sanitize_probe_detail_collapses_and_truncates() {
        assert_eq!(sanitize_probe_detail("a\n  b\tc"), "a b c");
        let long = "x".repeat(300);
        let sanitized = sanitize_probe_detail(&long);
        assert_eq!(sanitized.len(), 243);
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn probe_phase_result_classifies_before_truncating_details() {
        let result = ProbePhaseResult::error(9, format!("{} tls handshake eof", "x".repeat(260)));
        assert!(!result.ok);
        assert_eq!(result.status, "err");
        assert_eq!(result.class.as_deref(), Some("reality_dial_eof"));
        assert_eq!(result.error.as_ref().unwrap().len(), 243);
    }

    #[test]
    fn probe_phase_result_skip_keeps_failure_class_empty() {
        let result = ProbePhaseResult::skip("non_tcp_transport");
        assert!(!result.ok);
        assert_eq!(result.status, "skip");
        assert!(result.class.is_none());
        assert_eq!(result.reason.as_deref(), Some("non_tcp_transport"));

        let timeout = ProbePhaseResult::timeout(42, 10);
        assert!(!timeout.ok);
        assert_eq!(timeout.status, "timeout");
        assert_eq!(timeout.class.as_deref(), Some("timeout"));
        assert_eq!(timeout.error.as_deref(), Some("timeout after 10s"));
    }

    #[test]
    fn probe_json_output_serializes_phase_classes() {
        let output = ProbeJsonOutput {
            tool: "probe-outbound",
            config: "/tmp/config.json".to_string(),
            outbound: "node".to_string(),
            outbound_type: Some("vless".to_string()),
            target: "example.com:80".to_string(),
            timeout_secs: 10,
            pre_bridge: Some(VlessDirectPhaseReport {
                direct_reality: ProbePhaseResult::ok(1000),
                direct_vless_dial: ProbePhaseResult::error(
                    2000,
                    "REALITY handshake failed: tls handshake eof",
                ),
            }),
            post_bridge: None,
            bridge_probe: Some(BridgeProbeReport {
                ok: false,
                stream_mode: Some("connect_io"),
                stage: Some("read"),
                class: Some("post_dial_eof".to_string()),
                connect_time_ms: 12,
                response_bytes: Some(0),
                first_line: None,
                raw_connect_error: Some("connect unsupported".to_string()),
                error: Some("upstream returned eof before response bytes".to_string()),
            }),
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["pre_bridge"]["direct_reality"]["status"], "ok");
        assert_eq!(
            json["pre_bridge"]["direct_vless_dial"]["class"],
            "reality_dial_eof"
        );
        assert_eq!(json["bridge_probe"]["class"], "post_dial_eof");
    }
}
