use clap::{Parser, Subcommand};
use sb_core::log;
use sb_transport::{webpki_roots_config, DialError, Dialer as _, TcpDialer, TlsDialer};
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "diag")]
#[command(about = "Network diagnostics for singbox-rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// redact secrets in logs (env LOG_REDACT=1 equivalent)
    #[arg(long = "redact", default_value_t = false)]
    redact: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// TCP dial test: diag tcp --addr 1.1.1.1:80 [--timeout-ms 500]
    Tcp {
        #[arg(long = "addr")]
        addr: String,
        #[arg(long = "timeout-ms", default_value_t = 800)]
        timeout_ms: u64,
    },
    /// TLS handshake test: diag tls --addr 1.1.1.1:443 --sni cloudflare-dns.com
    Tls {
        #[arg(long = "addr")]
        addr: String,
        #[arg(long = "sni")]
        sni: String,
        #[arg(long = "timeout-ms", default_value_t = 1500)]
        timeout_ms: u64,
    },
}

fn main() {
    log::init("diag");
    let cli = Cli::parse();
    if cli.redact {
        std::env::set_var("LOG_REDACT", "1");
    }
    match cli.cmd {
        Cmd::Tcp { addr, timeout_ms } => {
            let started = Instant::now();
            let result = match parse_host_port(&addr) {
                Some((host, port)) => {
                    let tcp = TcpDialer {
                        connect_timeout: Some(Duration::from_millis(timeout_ms)),
                        ..Default::default()
                    };
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DialError::Other(format!("runtime_build_failed:{e}")))
                        .and_then(|rt| rt.block_on(async { tcp.connect(&host, port).await }))
                }
                None => Err(DialError::Other("bad_addr".to_string())),
            };
            let elapsed_ms = started.elapsed().as_millis();
            let (ok, error, class) = match result {
                Ok(_) => (true, None, None),
                Err(err) => {
                    let (code, class) = classify_dial_error(&err);
                    (false, Some(code), Some(class))
                }
            };
            let obj = json!({
                "tool":"tcp",
                "addr": addr,
                "elapsed_ms": elapsed_ms,
                "ok": ok,
                "error": error,
                "class": class,
            });
            let out = serde_json::to_string_pretty(&obj).unwrap_or_else(|_| obj.to_string());
            println!("{}", out);
        }
        Cmd::Tls {
            addr,
            sni,
            timeout_ms,
        } => {
            let (host, port) = match parse_host_port(&addr) {
                Some(v) => v,
                None => {
                    let obj = json!({
                        "tool":"tls",
                        "addr": addr,
                        "sni": sni,
                        "ok": false,
                        "error": "bad_addr",
                        "class": "input",
                        "alpn": serde_json::Value::Null,
                    });
                    let out =
                        serde_json::to_string_pretty(&obj).unwrap_or_else(|_| obj.to_string());
                    println!("{}", out);
                    return;
                }
            };

            let tcp = sb_transport::TcpDialer {
                connect_timeout: Some(Duration::from_millis(timeout_ms)),
                ..Default::default()
            };
            let tls = TlsDialer {
                inner: tcp,
                config: webpki_roots_config(),
                sni_override: Some(sni.clone()),
                alpn: None,
            };
            let started = Instant::now();
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DialError::Other(format!("runtime_build_failed:{e}")))
                .and_then(|rt| rt.block_on(async { tls.connect(&host, port).await }));
            let elapsed_ms = started.elapsed().as_millis();

            let (ok, error, class) = match result {
                Ok(_) => (true, None, None),
                Err(err) => {
                    let (code, class) = classify_dial_error(&err);
                    (false, Some(code), Some(class))
                }
            };
            let obj = json!({
                "tool":"tls",
                "addr": addr,
                "sni": sni,
                "elapsed_ms": elapsed_ms,
                "ok": ok,
                "error": error,
                "class": class,
                "alpn": serde_json::Value::Null,
            });
            let out = serde_json::to_string_pretty(&obj).unwrap_or_else(|_| obj.to_string());
            println!("{}", out);
        }
    }
}

fn parse_host_port(addr: &str) -> Option<(String, u16)> {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return Some((sock.ip().to_string(), sock.port()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn classify_dial_error(err: &DialError) -> (&'static str, &'static str) {
    match err {
        DialError::Io(_) => ("io", "io"),
        DialError::Tls(_) => ("tls", "tls"),
        DialError::NotSupported => ("not_supported", "unsupported"),
        DialError::Other(msg) if msg == "bad_addr" => ("bad_addr", "input"),
        DialError::Other(_) => ("other", "other"),
    }
}
