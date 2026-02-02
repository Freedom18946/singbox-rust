#!/usr/bin/env zsh
set -euo pipefail

# --- basic layout -------------------------------------------------------------
mkdir -p crates/{sb-core,sb-adapters,sb-platform,sb-config,sb-metrics}
cargo new app --bin
mkdir -p .cargo
touch .gitignore
: > deny.toml
: > clippy.toml

# --- top-level Cargo.toml (workspace) ----------------------------------------
cat > Cargo.toml <<'TOML'
[workspace]
members = [
  "app",
  "crates/sb-core",
  "crates/sb-adapters",
  "crates/sb-platform",
  "crates/sb-config",
  "crates/sb-metrics",
]
resolver = "2"

[workspace.package]
edition = "2021"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
anyhow = "1"
thiserror = "1"
bytes = "1"
tokio = { version = "1", features = ["rt-multi-thread","macros","net","io-util","time","sync"] }
tracing = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
toml = "0.8"
async-trait = "0.1"
TOML

# --- app (CLI) ----------------------------------------------------------------
cat > app/Cargo.toml <<'TOML'
[package]
name = "singbox-rs2"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
clap = { version = "4", features = ["derive"] }
tracing-subscriber = { version = "0.3", features = ["env-filter","fmt"] }
sb-core = { path = "../crates/sb-core" }
sb-config = { path = "../crates/sb-config" }
sb-adapters = { path = "../crates/sb-adapters" }
sb-platform = { path = "../crates/sb-platform" }
sb-metrics = { path = "../crates/sb-metrics" }
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
tracing = { workspace = true }

[features]
full = ["sb-core/full","sb-adapters/full","sb-platform/full","sb-config/full","sb-metrics/full"]
default = ["full"]
TOML

cat > app/src/main.rs <<'RS'
use clap::Parser;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name="singbox-rs2", version, about="Rust rewrite with clean boundaries")]
struct Opt {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(long)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let opt = Opt::parse();
    if opt.dry_run {
        let path = opt
            .config
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--dry-run requires --config <path>"))?;
        let contents = fs::read_to_string(path)?;
        let normalized = match Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
        {
            Some(ext) if ext == "yaml" || ext == "yml" => {
                let value: serde_yaml::Value = serde_yaml::from_str(&contents)?;
                serde_json::to_string_pretty(&value)?
            }
            _ => {
                let value: serde_json::Value = serde_json::from_str(&contents)?;
                serde_json::to_string_pretty(&value)?
            }
        };
        println!("{normalized}");
        return Ok(());
    }
    Ok(())
}
RS

# --- sb-core ------------------------------------------------------------------
cat > crates/sb-core/Cargo.toml <<'TOML'
[package]
name = "sb-core"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
bytes = { workspace = true }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
async-trait = { workspace = true }

[features]
full = []
default = []
TOML

mkdir -p crates/sb-core/src
cat > crates/sb-core/src/lib.rs <<'RS'
pub mod net;
pub mod pipeline;
pub mod error;
RS

cat > crates/sb-core/src/error.rs <<'RS'
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("config error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("route error: {0}")]
    Route(String),
}
pub type Result<T> = std::result::Result<T, CoreError>;
RS

cat > crates/sb-core/src/net.rs <<'RS'
#[derive(Clone, Debug)]
pub enum Address {
    Ip(std::net::SocketAddr),
    Domain(String, u16),
}
RS

cat > crates/sb-core/src/pipeline.rs <<'RS'
use crate::net::Address;
use async_trait::async_trait;

#[async_trait]
pub trait Inbound: Send + Sync {
    async fn serve(&self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait Outbound: Send + Sync {
    async fn connect(&self, target: Address) -> anyhow::Result<()>;
}

pub struct Pipeline<I: Inbound> {
    inbound: I,
}

impl<I: Inbound> Pipeline<I> {
    pub fn new(inbound: I) -> Self { Self { inbound } }
    pub async fn run(self) -> anyhow::Result<()> { self.inbound.serve().await }
}
RS

# --- sb-platform --------------------------------------------------------------
cat > crates/sb-platform/Cargo.toml <<'TOML'
[package]
name = "sb-platform"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }

[features]
linux = []
macos = []
windows = []
full = ["linux","macos","windows"]
default = []
TOML

mkdir -p crates/sb-platform/src
cat > crates/sb-platform/src/lib.rs <<'RS'
#[cfg(target_os = "linux")]
pub mod os { pub const NAME: &str = "linux"; }
#[cfg(target_os = "macos")]
pub mod os { pub const NAME: &str = "macos"; }
#[cfg(target_os = "windows")]
pub mod os { pub const NAME: &str = "windows"; }
RS

# --- sb-config ----------------------------------------------------------------
cat > crates/sb-config/Cargo.toml <<'TOML'
[package]
name = "sb-config"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }

[features]
compat_1_12_4 = []
full = ["compat_1_12_4"]
default = []
TOML

mkdir -p crates/sb-config/src
cat > crates/sb-config/src/lib.rs <<'RS'
pub mod model;
pub mod compat;
RS

cat > crates/sb-config/src/model.rs <<'RS'
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub inbounds: Vec<serde_json::Value>,
}

impl Config {
    pub fn normalize(self) -> Self { self }
}
RS

cat > crates/sb-config/src/compat.rs <<'RS'
use super::model::Config;

pub fn compat_1_12_4(cfg: Config) -> Config { cfg }
RS

# --- sb-adapters --------------------------------------------------------------
cat > crates/sb-adapters/Cargo.toml <<'TOML'
[package]
name = "sb-adapters"
version = "0.1.0"
edition = "2021"

[dependencies]
sb-core = { path = "../sb-core" }
tokio = { workspace = true }
bytes = { workspace = true }
tracing = { workspace = true }
async-trait = { workspace = true }

[features]
socks = []
http = []
tun = []
full = ["socks","http","tun"]
default = []
TOML

mkdir -p crates/sb-adapters/src/{inbound,outbound}
cat > crates/sb-adapters/src/lib.rs <<'RS'
pub mod inbound;
pub mod outbound;
RS

cat > crates/sb-adapters/src/inbound/mod.rs <<'RS'
#[cfg(feature="socks")]
pub mod socks;
RS

cat > crates/sb-adapters/src/inbound/socks.rs <<'RS'
use async_trait::async_trait;
use sb-core::pipeline::Inbound;

pub struct SocksInbound;

#[async_trait]
impl Inbound for SocksInbound {
    async fn serve(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
RS

# --- sb-metrics ---------------------------------------------------------------
cat > crates/sb-metrics/Cargo.toml <<'TOML'
[package]
name = "sb-metrics"
version = "0.1.0"
edition = "2021"

[dependencies]
tracing = { workspace = true }

[features]
prometheus = []
opentelemetry = []
full = ["prometheus","opentelemetry"]
default = []
TOML

mkdir -p crates/sb-metrics/src
cat > crates/sb-metrics/src/lib.rs <<'RS'
pub fn init() {}
RS

# --- configs ------------------------------------------------------------------
cat > .gitignore <<'GI'
/target
/_audit
**/*.lcov
GI

cat > .cargo/config.toml <<'CFG'
[build]
rustflags = ["-C","target-cpu=native"]
CFG

cat > rust-toolchain.toml <<'RT'
[toolchain]
channel = "stable"
RT

cat > deny.toml <<'DENY'
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"

[licenses]
allow = ["MIT","Apache-2.0","BSD-3-Clause","BSD-2-Clause","ISC","Unicode-DFS-2016","Zlib","OpenSSL"]
copyleft = "warn"
unlicensed = "deny"
DENY

cat > clippy.toml <<'CLP'
msrv = "1.77.0"
CLP

echo "OK - workspace scaffolded."
