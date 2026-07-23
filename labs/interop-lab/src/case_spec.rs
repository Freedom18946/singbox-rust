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
    /// Exact failure stages accepted only as explicit environment/harness limits.
    /// Any additional failure keeps the case outcome at FAIL.
    #[serde(default)]
    pub expected_env_failures: Vec<ExpectedEnvFailure>,
    /// S4 divergence IDs whose kernel-specific expectations are asserted by this case.
    #[serde(default)]
    pub covered_divergences: Vec<String>,
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
pub struct ExpectedEnvFailure {
    #[serde(default)]
    pub kernel: Option<KernelTarget>,
    pub stage: String,
    pub reason: String,
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
    #[serde(default)]
    pub answer_ipv4: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<u32>,
    /// File served verbatim by `http_static`.
    #[serde(default)]
    pub content_path: Option<PathBuf>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    HttpEcho,
    HttpStatic,
    TcpEcho,
    UdpEcho,
    WsEcho,
    DnsStub,
    TlsEcho,
    TlsRelayTcp,
    TrojanInbound,
    ShadowsocksInbound,
    ShadowTlsInbound,
    VlessInbound,
    VmessInbound,
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
    HttpGetLatency {
        name: String,
        url: String,
        #[serde(default)]
        proxy: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
        #[serde(default = "default_http_get_latency_samples")]
        samples: usize,
        #[serde(default = "default_http_get_latency_warmup")]
        warmup: usize,
        #[serde(default = "default_http_get_latency_timeout_ms")]
        timeout_ms: u64,
        max_p95_ms: u64,
    },
    TcpRoundTrip {
        name: String,
        addr: String,
        #[serde(default)]
        payload: String,
        #[serde(default)]
        proxy: Option<String>,
        /// Bind client connection to this local source port before connecting.
        #[serde(default)]
        source_port: Option<u16>,
        /// When set, generates a deterministic payload of this size (bytes)
        /// instead of using the `payload` string.
        #[serde(default)]
        payload_size: Option<usize>,
        /// When set, generates a minimal TLS ClientHello payload and ignores
        /// the literal `payload` string.
        #[serde(default)]
        payload_tls_client_hello: bool,
    },
    /// Measures end-to-end TCP echo throughput through a SOCKS5 proxy. Each
    /// sample opens a new connection, so results include SOCKS5 negotiation.
    TcpThroughput {
        name: String,
        addr: String,
        proxy: String,
        #[serde(default = "default_tcp_throughput_payload_size")]
        payload_size: usize,
        #[serde(default = "default_tcp_throughput_samples")]
        samples: usize,
        #[serde(default = "default_tcp_throughput_warmup")]
        warmup: usize,
        #[serde(default = "default_tcp_throughput_timeout_ms")]
        timeout_ms: u64,
        min_mib_per_sec: f64,
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
    UpstreamQueryCount {
        name: String,
        target: String,
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
    CommandStart {
        name: String,
        handle: String,
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        workdir: Option<PathBuf>,
    },
    CommandWait {
        name: String,
        handle: String,
        #[serde(default = "default_command_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        expect_exit: Option<i32>,
    },
    ApiHttp {
        name: String,
        method: String,
        path: String,
        #[serde(default)]
        method_rust: Option<String>,
        #[serde(default)]
        method_go: Option<String>,
        #[serde(default)]
        path_rust: Option<String>,
        #[serde(default)]
        path_go: Option<String>,
        #[serde(default)]
        body: Option<Value>,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
        #[serde(default)]
        expect_status_rust: Option<u16>,
        #[serde(default)]
        expect_status_go: Option<u16>,
    },
    ApiHttpLatency {
        name: String,
        method: String,
        path: String,
        #[serde(default)]
        method_rust: Option<String>,
        #[serde(default)]
        method_go: Option<String>,
        #[serde(default)]
        path_rust: Option<String>,
        #[serde(default)]
        path_go: Option<String>,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
        #[serde(default)]
        expect_status_rust: Option<u16>,
        #[serde(default)]
        expect_status_go: Option<u16>,
        #[serde(default = "default_api_http_latency_samples")]
        samples: usize,
        #[serde(default = "default_api_http_latency_warmup")]
        warmup: usize,
        #[serde(default = "default_api_http_latency_timeout_ms")]
        timeout_ms: u64,
        max_p95_ms: u64,
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
    ApiWsSoak {
        name: String,
        path: String,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default = "default_api_ws_soak_clients_per_wave")]
        clients_per_wave: usize,
        #[serde(default = "default_api_ws_soak_waves")]
        waves: usize,
        #[serde(default = "default_api_ws_soak_wave_delay_ms")]
        wave_delay_ms: u64,
        #[serde(default = "default_api_ws_soak_success_percent")]
        wave_success_percent: usize,
        #[serde(default = "default_api_ws_soak_success_percent")]
        overall_success_percent: usize,
        #[serde(default = "default_api_ws_soak_frame_timeout_ms")]
        frame_timeout_ms: u64,
        #[serde(default = "default_api_ws_soak_frames")]
        frames: usize,
    },
    ApiWsExpectCloseOnKernelControl {
        name: String,
        path: String,
        action: KernelControlAction,
        target: KernelTarget,
        #[serde(default)]
        no_auth: bool,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default = "default_api_ws_soak_frame_timeout_ms")]
        frame_timeout_ms: u64,
        #[serde(default = "default_api_ws_close_timeout_ms")]
        close_timeout_ms: u64,
        #[serde(default = "default_kernel_control_wait_ready_ms")]
        wait_ready_ms: u64,
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
    /// Opens a TCP connection through a proxy, verifies echo, sends SIGTERM,
    /// then verifies the connection is still usable (graceful drain).
    TcpDrainDuringShutdown {
        name: String,
        addr: String,
        proxy: String,
        payload: String,
        action: KernelControlAction,
        target: KernelTarget,
        /// How long to hold the connection after SIGTERM before closing (ms)
        #[serde(default = "default_drain_hold_ms")]
        hold_ms: u64,
        #[serde(default = "default_kernel_control_wait_ready_ms")]
        wait_ready_ms: u64,
        #[serde(default = "default_tcp_drain_timeout_ms")]
        timeout_ms: u64,
    },
}

fn default_ws_roundtrip_timeout_ms() -> u64 {
    5_000
}

fn default_drain_hold_ms() -> u64 {
    1_500
}

fn default_tcp_drain_timeout_ms() -> u64 {
    15_000
}

fn default_http_get_latency_samples() -> usize {
    20
}

fn default_http_get_latency_warmup() -> usize {
    3
}

fn default_http_get_latency_timeout_ms() -> u64 {
    5_000
}

fn default_tcp_throughput_payload_size() -> usize {
    1_048_576
}

fn default_tcp_throughput_samples() -> usize {
    5
}

fn default_tcp_throughput_warmup() -> usize {
    1
}

fn default_tcp_throughput_timeout_ms() -> u64 {
    10_000
}

fn default_api_ws_soak_clients_per_wave() -> usize {
    24
}

fn default_api_ws_soak_waves() -> usize {
    20
}

fn default_api_ws_soak_wave_delay_ms() -> u64 {
    120
}

fn default_api_ws_soak_success_percent() -> usize {
    95
}

fn default_api_ws_soak_frame_timeout_ms() -> u64 {
    3_000
}

fn default_api_ws_soak_frames() -> usize {
    1
}

fn default_api_ws_close_timeout_ms() -> u64 {
    5_000
}

fn default_tls_roundtrip_timeout_ms() -> u64 {
    5_000
}

fn default_command_timeout_ms() -> u64 {
    300_000
}

fn default_api_http_latency_samples() -> usize {
    20
}

fn default_api_http_latency_warmup() -> usize {
    3
}

fn default_api_http_latency_timeout_ms() -> u64 {
    5_000
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
    Shutdown,
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
    /// Limit this assertion to one kernel. Used to lock an S4 divergence without
    /// weakening assertions for the other kernel.
    #[serde(default)]
    pub kernel: Option<KernelTarget>,
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
        validate_case_spec(&case, cases_dir)
            .with_context(|| format!("validating case {}", path.display()))?;
        out.push(case);
    }
    Ok(out)
}

pub fn load_case_by_id(cases_dir: &Path, id: &str) -> Result<CaseSpec> {
    // Fast path: try loading {id}.yaml / {id}.yml directly.
    for ext in &["yaml", "yml"] {
        let path = cases_dir.join(format!("{id}.{ext}"));
        if path.is_file() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("reading case file {}", path.display()))?;
            let case: CaseSpec = serde_yaml::from_str(&raw)
                .with_context(|| format!("parsing yaml {}", path.display()))?;
            if case.id == id {
                validate_case_spec(&case, cases_dir)
                    .with_context(|| format!("validating case {}", path.display()))?;
                return Ok(case);
            }
        }
    }

    // Fallback: scan all cases (file name may not match id).
    let cases = load_cases(cases_dir)?;
    cases
        .into_iter()
        .find(|case| case.id == id)
        .with_context(|| format!("case '{id}' not found in {}", cases_dir.display()))
}

fn validate_case_spec(case: &CaseSpec, cases_dir: &Path) -> Result<()> {
    if !case.expected_env_failures.is_empty() {
        anyhow::ensure!(
            case.env_class == EnvClass::EnvLimited,
            "expected_env_failures requires env_class: env_limited"
        );
        for expected in &case.expected_env_failures {
            anyhow::ensure!(
                !expected.stage.trim().is_empty(),
                "expected_env_failures stage must not be empty"
            );
            anyhow::ensure!(
                !expected.reason.trim().is_empty(),
                "expected_env_failures reason must not be empty"
            );
        }
    }

    for action in &case.traffic_plan {
        if let TrafficAction::TcpThroughput {
            payload_size,
            samples,
            timeout_ms,
            min_mib_per_sec,
            ..
        } = action
        {
            anyhow::ensure!(*payload_size > 0, "tcp_throughput payload_size must be > 0");
            anyhow::ensure!(*samples > 0, "tcp_throughput samples must be > 0");
            anyhow::ensure!(*timeout_ms > 0, "tcp_throughput timeout_ms must be > 0");
            anyhow::ensure!(
                min_mib_per_sec.is_finite() && *min_mib_per_sec > 0.0,
                "tcp_throughput min_mib_per_sec must be finite and > 0"
            );
        }
    }

    if case.covered_divergences.is_empty() {
        return Ok(());
    }

    anyhow::ensure!(
        case.kernel_mode == KernelMode::Both,
        "covered_divergences requires kernel_mode: both"
    );
    anyhow::ensure!(
        case.assertions
            .iter()
            .any(|assertion| assertion.kernel.is_some()),
        "covered_divergences requires at least one kernel-scoped assertion"
    );

    let registry_path = cases_dir
        .parent()
        .unwrap_or(cases_dir)
        .join("docs/dual_kernel_golden_spec.md");
    let registry = fs::read_to_string(&registry_path)
        .with_context(|| format!("reading S4 registry {}", registry_path.display()))?;
    for divergence_id in &case.covered_divergences {
        let row_prefix = format!("| {divergence_id} |");
        anyhow::ensure!(
            registry.lines().any(|line| line.starts_with(&row_prefix)),
            "covered divergence {divergence_id} is not registered in S4"
        );
    }

    Ok(())
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

    #[test]
    fn repository_cases_validate_against_s4_registry() {
        let cases_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cases");
        let cases = load_cases(&cases_dir).expect("repository cases must validate");
        assert_eq!(cases.len(), 126);
    }

    #[test]
    fn tcp_throughput_defaults_and_validation() {
        let case: CaseSpec = serde_yaml::from_str(
            r#"
id: throughput
bootstrap: {}
traffic_plan:
  - kind: tcp_throughput
    name: live
    addr: 127.0.0.1:8080
    proxy: socks5://127.0.0.1:1080
    min_mib_per_sec: 1.0
"#,
        )
        .unwrap();

        let TrafficAction::TcpThroughput {
            payload_size,
            samples,
            warmup,
            timeout_ms,
            ..
        } = &case.traffic_plan[0]
        else {
            panic!("expected tcp_throughput action");
        };
        assert_eq!(*payload_size, 1_048_576);
        assert_eq!(*samples, 5);
        assert_eq!(*warmup, 1);
        assert_eq!(*timeout_ms, 10_000);

        let temp = tempfile::tempdir().unwrap();
        validate_case_spec(&case, temp.path()).unwrap();

        let mut invalid = case;
        let TrafficAction::TcpThroughput { samples, .. } = &mut invalid.traffic_plan[0] else {
            unreachable!();
        };
        *samples = 0;
        let err = validate_case_spec(&invalid, temp.path()).unwrap_err();
        assert!(err.to_string().contains("samples must be > 0"));
    }

    #[test]
    fn expected_env_failures_require_env_limited_case() {
        let case: CaseSpec = serde_yaml::from_str(
            r#"
id: invalid-env-limit
expected_env_failures:
  - stage: launch_kernel
    reason: fixture unavailable
bootstrap: {}
"#,
        )
        .unwrap();
        let err = validate_case_spec(&case, Path::new("cases")).unwrap_err();
        assert!(err
            .to_string()
            .contains("expected_env_failures requires env_class: env_limited"));
    }

    #[test]
    fn covered_divergence_must_exist_in_s4_registry() {
        let temp = tempfile::tempdir().unwrap();
        let cases_dir = temp.path().join("cases");
        let docs_dir = temp.path().join("docs");
        fs::create_dir_all(&cases_dir).unwrap();
        fs::create_dir_all(&docs_dir).unwrap();
        fs::write(
            docs_dir.join("dual_kernel_golden_spec.md"),
            "| DIV-M-012 | COSMETIC | registered |\n",
        )
        .unwrap();
        let case: CaseSpec = serde_yaml::from_str(
            r#"
id: invalid-divergence
kernel_mode: both
covered_divergences:
  - DIV-M-999
bootstrap: {}
assertions:
  - key: errors.count
    op: eq
    expected: 0
    kernel: rust
"#,
        )
        .unwrap();
        let err = validate_case_spec(&case, &cases_dir).unwrap_err();
        assert!(err
            .to_string()
            .contains("covered divergence DIV-M-999 is not registered in S4"));
    }
}
