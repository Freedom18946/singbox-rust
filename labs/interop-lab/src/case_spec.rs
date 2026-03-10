use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KernelMode {
    #[default]
    Rust,
    Go,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSpec {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub priority: Priority,
    #[serde(default)]
    pub kernel_mode: KernelMode,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub env_class: EnvClass,
    pub bootstrap: BootstrapSpec,
    #[serde(default)]
    pub gui_sequence: Vec<GuiStep>,
    #[serde(default)]
    pub upstream_topology: Vec<UpstreamServiceSpec>,
    #[serde(default)]
    pub traffic_plan: Vec<TrafficAction>,
    #[serde(default)]
    pub subscription_input: Option<SubscriptionInputSpec>,
    #[serde(default)]
    pub faults: Vec<FaultSpec>,
    #[serde(default)]
    pub assertions: Vec<AssertionSpec>,
    #[serde(default)]
    pub oracle: OracleSpec,
    #[serde(default)]
    pub post_traffic_gui_sequence: Option<Vec<GuiStep>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    #[default]
    P0,
    P1,
    P2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnvClass {
    #[default]
    Strict,
    EnvLimited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapSpec {
    #[serde(default)]
    pub rust: Option<KernelLaunchSpec>,
    #[serde(default)]
    pub go: Option<KernelLaunchSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelLaunchSpec {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub workdir: Option<PathBuf>,
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
    #[serde(default = "default_ready_path")]
    pub ready_path: String,
    pub api: ApiAccess,
}

fn default_startup_timeout_ms() -> u64 {
    30_000
}

fn default_ready_path() -> String {
    "/version".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAccess {
    pub base_url: String,
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuiStep {
    Http {
        name: String,
        method: String,
        path: String,
        #[serde(default)]
        body: Option<Value>,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
    },
    WsCollect {
        name: String,
        path: String,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default = "default_ws_max_frames")]
        max_frames: usize,
        #[serde(default = "default_ws_duration_ms")]
        duration_ms: u64,
    },
    Sleep {
        ms: u64,
    },
    SubscriptionParse,
    WsParallel {
        name: String,
        streams: Vec<WsStreamSpec>,
        #[serde(default = "default_ws_parallel_duration_ms")]
        duration_ms: u64,
    },
}

fn default_ws_parallel_duration_ms() -> u64 {
    3_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsStreamSpec {
    pub path: String,
    #[serde(default = "default_ws_max_frames")]
    pub max_frames: usize,
    #[serde(default)]
    pub params: Option<String>,
}

fn default_ws_max_frames() -> usize {
    3
}

fn default_ws_duration_ms() -> u64 {
    2_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServiceSpec {
    pub name: String,
    pub kind: UpstreamKind,
    pub bind: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub handshake_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    HttpEcho,
    TcpEcho,
    UdpEcho,
    WsEcho,
    DnsStub,
    TlsEcho,
    TlsRelayTcp,
    TrojanInbound,
    ShadowsocksInbound,
    ShadowTlsInbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrafficAction {
    HttpGet {
        name: String,
        url: String,
        #[serde(default)]
        proxy: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
    },
    TcpRoundTrip {
        name: String,
        addr: String,
        payload: String,
        #[serde(default)]
        proxy: Option<String>,
        /// When set, generates a deterministic payload of this size (bytes)
        /// instead of using the `payload` string.
        #[serde(default)]
        payload_size: Option<usize>,
    },
    UdpRoundTrip {
        name: String,
        addr: String,
        payload: String,
        #[serde(default)]
        proxy: Option<String>,
        /// When set, generates a deterministic payload of this size (bytes)
        /// instead of using the `payload` string.
        #[serde(default)]
        payload_size: Option<usize>,
    },
    DnsQuery {
        name: String,
        addr: String,
        qname: String,
        #[serde(default)]
        proxy: Option<String>,
    },
    FaultDisconnect {
        name: String,
        target: String,
    },
    FaultReconnect {
        name: String,
        target: String,
    },
    Sleep {
        name: String,
        ms: u64,
    },
    Command {
        name: String,
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        workdir: Option<PathBuf>,
        #[serde(default = "default_command_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        expect_exit: Option<i32>,
    },
    KernelControl {
        name: String,
        action: KernelControlAction,
        target: KernelTarget,
        #[serde(default = "default_kernel_control_wait_ready_ms")]
        wait_ready_ms: u64,
    },
    FaultJitter {
        name: String,
        target: String,
        #[serde(default)]
        base_ms: u64,
        #[serde(default)]
        jitter_ms: u64,
        #[serde(default = "default_jitter_ratio")]
        ratio: f64,
    },
    WsRoundTrip {
        name: String,
        url: String,
        payload: String,
        #[serde(default)]
        proxy: Option<String>,
        #[serde(default = "default_ws_roundtrip_timeout_ms")]
        timeout_ms: u64,
    },
    TlsRoundTrip {
        name: String,
        addr: String,
        payload: String,
        #[serde(default)]
        proxy: Option<String>,
        #[serde(default)]
        skip_verify: bool,
        #[serde(default = "default_tls_roundtrip_timeout_ms")]
        timeout_ms: u64,
    },
}

fn default_ws_roundtrip_timeout_ms() -> u64 {
    5_000
}

fn default_tls_roundtrip_timeout_ms() -> u64 {
    5_000
}

fn default_command_timeout_ms() -> u64 {
    300_000
}

fn default_kernel_control_wait_ready_ms() -> u64 {
    15_000
}

fn default_jitter_ratio() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KernelControlAction {
    Restart,
    Reload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KernelTarget {
    Rust,
    Go,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SubscriptionInputSpec {
    Inline { content: String },
    File { path: PathBuf },
    Http { url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaultSpec {
    Delay { target: String, ms: u64 },
    Disconnect { target: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionSpec {
    pub key: String,
    pub op: String,
    pub expected: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OracleSpec {
    #[serde(default)]
    pub ignore_http_paths: Vec<String>,
    #[serde(default)]
    pub ignore_ws_paths: Vec<String>,
    #[serde(default)]
    pub tolerate_counter_jitter: bool,
    #[serde(default)]
    pub counter_jitter_abs: i64,
}

pub fn load_cases(cases_dir: &Path) -> Result<Vec<CaseSpec>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(cases_dir)
        .with_context(|| format!("reading cases dir {}", cases_dir.display()))?
    {
        let entry = entry.with_context(|| "reading case entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext == "yaml" || ext == "yml" {
            files.push(path);
        }
    }

    files.sort();
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading case file {}", path.display()))?;
        let case: CaseSpec = serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing yaml {}", path.display()))?;
        out.push(case);
    }
    Ok(out)
}

pub fn load_case_by_id(cases_dir: &Path, id: &str) -> Result<CaseSpec> {
    let cases = load_cases(cases_dir)?;
    cases
        .into_iter()
        .find(|case| case.id == id)
        .with_context(|| format!("case '{id}' not found in {}", cases_dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_case_spec() {
        let data = r#"
id: p0_api_smoke
priority: p0
kernel_mode: both
bootstrap:
  rust:
    api:
      base_url: http://127.0.0.1:19090
  go:
    api:
      base_url: http://127.0.0.1:29090
gui_sequence:
  - kind: http
    name: get_configs
    method: GET
    path: /configs
    expect_status: 200
"#;

        let case: CaseSpec = serde_yaml::from_str(data).unwrap_or_else(|err| {
            panic!("must parse: {err}");
        });

        assert_eq!(case.id, "p0_api_smoke");
        assert_eq!(case.kernel_mode, KernelMode::Both);
        assert_eq!(case.gui_sequence.len(), 1);
        assert_eq!(case.env_class, EnvClass::Strict);
        assert!(case.tags.is_empty());
        assert!(case.owner.is_none());
    }
}
