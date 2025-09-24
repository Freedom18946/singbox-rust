use clap::{Parser, Subcommand};
use sb_core::log;
use sb_core::transport::tcp::TcpDialer;
use sb_core::transport::tls::TlsClient;
use serde_json::json;

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
            let dial = TcpDialer {
                connect_timeout: std::time::Duration::from_millis(timeout_ms),
                ..Default::default()
            };
            let r = dial.dial(&addr);
            let obj = json!({
                "tool":"tcp",
                "addr": addr,
                "elapsed_ms": r.elapsed_ms,
                "ok": r.error.is_none(),
                "error": r.error.as_ref().map(|e| e.code.as_str()),
                "class": r.error.as_ref().map(|e| e.class),
            });
            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Cmd::Tls {
            addr,
            sni,
            timeout_ms,
        } => {
            let c = TlsClient {
                dialer: TcpDialer {
                    connect_timeout: std::time::Duration::from_millis(timeout_ms),
                    ..Default::default()
                },
                ..Default::default()
            };
            let r = c.handshake(&sni, &addr);
            let obj = json!({
                "tool":"tls",
                "addr": addr,
                "sni": sni,
                "ok": r.error.is_none(),
                "error": r.error.as_ref().map(|e| e.code.as_str()),
                "class": r.error.as_ref().map(|e| e.class),
                "alpn": r.negotiated_alpn,
            });
            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
    }
}
