use anyhow::Result;
use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
struct Args {
    /// config path (can be specified multiple times)
    #[arg(short = 'c', long = "config", action = ArgAction::Append)]
    config: Vec<PathBuf>,
    /// config directory (can be specified multiple times)
    #[arg(short = 'C', long = "config-directory", action = ArgAction::Append)]
    config_directory: Vec<PathBuf>,
    /// subscription import path
    #[arg(short = 'i', long = "import")]
    import_path: Option<PathBuf>,
    /// optional prometheus exporter listen addr, e.g., 127.0.0.1:19090
    #[arg(long = "prom-listen")]
    prom_listen: Option<String>,
    /// output format text|json
    #[arg(long = "format", default_value = "text")]
    format: String,
    /// enable outbound health task (also can set HEALTH=1)
    #[arg(long = "health", default_value_t = false)]
    health: bool,
    /// enable DNS stub+cache via env (DNS_STUB=1)
    #[arg(long = "dns-from-env", default_value_t = false)]
    dns_from_env: bool,
    /// admin http listen (e.g. 127.0.0.1:19090). Also can be set via ADMIN_LISTEN env var.
    #[arg(long = "admin-listen")]
    admin_listen: Option<String>,
    /// admin http token (optional). Also can be set via ADMIN_TOKEN env var.
    #[arg(long = "admin-token")]
    admin_token: Option<String>,
    /// graceful shutdown timeout in milliseconds
    #[arg(long = "grace", default_value = "1500")]
    grace: u64,
    /// config path for SIGHUP reload (optional, overrides --config for reload only)
    #[arg(long = "reload-path")]
    reload_path: Option<String>,
    /// admin implementation: core|debug (default: core). Also can be set via `SB_ADMIN_IMPL` env var.
    #[arg(long = "admin-impl", default_value = "core")]
    admin_impl: String,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    help_json: bool,
    /// Print transport plan (derived chain) for outbounds at startup
    #[arg(long = "print-transport", default_value_t = false)]
    print_transport: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Ensure rustls has a crypto provider installed (reqwest may use no-provider feature)
    #[allow(unused_must_use)]
    {
        use rustls::crypto::{ring, CryptoProvider};
        let _ = CryptoProvider::install_default(ring::default_provider());
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Handle --help-json
    if std::env::args().skip(1).any(|arg| arg == "--help-json") {
        app::cli::help::print_help_json::<Args>();
    }
    let args = Args::parse();

    // Build ConfigInputs (entries collected dynamically in run_supervisor)
    let config_inputs = app::run_engine::ConfigInputs {
        config_paths: args.config.clone(),
        config_dirs: args.config_directory.clone(),
    };

    // Resolve admin listen (CLI arg with env fallback)
    let admin_listen = args
        .admin_listen
        .or_else(|| std::env::var("ADMIN_LISTEN").ok());
    let admin_token = args
        .admin_token
        .or_else(|| std::env::var("ADMIN_TOKEN").ok());

    // Resolve admin_impl (CLI arg with env fallback)
    let admin_impl_str = std::env::var("SB_ADMIN_IMPL").unwrap_or(args.admin_impl);
    let admin_impl = match admin_impl_str.as_str() {
        "debug" => app::run_engine::AdminImpl::Debug,
        _ => app::run_engine::AdminImpl::Core,
    };

    // Resolve prom_listen (CLI arg with env fallback)
    let prom_listen = args
        .prom_listen
        .or_else(|| std::env::var("PROM_LISTEN").ok());

    // Determine startup output mode based on --format
    let startup_output = if args.format == "json" {
        app::run_engine::StartupOutputMode::JsonStdout
    } else {
        app::run_engine::StartupOutputMode::TextStdout
    };

    // Health enable: --health flag or HEALTH=1 env
    let health_enable = args.health || std::env::var("HEALTH").ok().as_deref() == Some("1");

    let opts = app::run_engine::RunOptions {
        config_inputs,
        import_path: args.import_path,
        watch: false, // bin/run doesn't have watch mode
        reload_path: args.reload_path.map(PathBuf::from),
        admin_listen,
        admin_token,
        admin_impl,
        print_startup: true,
        startup_output,
        reload_output: app::run_engine::ReloadOutputMode::JsonStderr,
        grace_ms: args.grace,
        prom_listen,
        dns_from_env: args.dns_from_env,
        print_transport: args.print_transport,
        health_enable,
        dns_env_bridge: true,
    };

    app::run_engine::run_supervisor(opts).await
}
