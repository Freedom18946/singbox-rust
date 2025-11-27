//! scenario.rs - Scenario-driven offline regression executor (handshake_alpha/io_local_alpha)
//! scenario.rs - 场景驱动的离线回归执行器（handshake_alpha/io_local_alpha）
//!
//! # Goal / 目标
//!
//! Solidify "individual commands" into declarable, reproducible, and assertable test flows.
//! 把"一个个命令"固化为可声明、可复现、可断言的测试流。
use anyhow::{anyhow, Context, Result};
use glob::glob;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::handshake::Handshake;
use crate::jsonl;
use crate::loopback::run_once as loopback_once;
#[cfg(feature = "io_local_alpha")]
use crate::tcp_local::{io_local_once, spawn_echo_once, ChaosSpec};

/// Lightweight Protocol Description (Independent of CLI Proto Enum) / 轻量协议描述（不依赖 CLI 的 Proto 枚举）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtoLite {
    Trojan,
    Vmess,
}

impl ProtoLite {
    pub fn make(&self, host: String, port: u16) -> Box<dyn Handshake> {
        match self {
            ProtoLite::Trojan => Box::new(crate::protocols::trojan::Trojan::new(host, port)),
            ProtoLite::Vmess => Box::new(crate::protocols::vmess::Vmess::new(host, port)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChaosFile {
    pub delay_tx_ms: Option<u64>,
    pub delay_rx_ms: Option<u64>,
    pub rx_drop: Option<u64>,
    pub rx_trim: Option<u64>,
    /// Hex string, e.g., "aa" / 十六进制字符串，如 "aa"
    pub rx_xor: Option<String>,
}

impl ChaosFile {
    #[cfg(feature = "io_local_alpha")]
    pub fn to_spec(&self) -> ChaosSpec {
        let rx_xor = self
            .rx_xor
            .as_ref()
            .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        ChaosSpec {
            delay_tx_ms: self.delay_tx_ms.unwrap_or(0),
            delay_rx_ms: self.delay_rx_ms.unwrap_or(0),
            rx_drop: self.rx_drop.unwrap_or(0) as usize,
            rx_trim: self.rx_trim.map(|n| n as usize),
            rx_xor,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Expect {
    pub min_frames: Option<usize>,
    pub min_tx: Option<usize>,
    pub min_rx: Option<usize>,
    pub max_disorder: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Defaults {
    /// Allow using when step seed=0 / 允许 step 中 seed=0 时使用
    pub seed: Option<u64>,
    /// Optional unified output directory prefix / 可选的统一输出目录前缀
    /// If set, `out`/`from` will be joined with this path / 如设定则 `out`/`from` 走 join
    pub out_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Step {
    /// Generate a loopback log (No Network) / 生成一份回环日志（无网络）
    Loopback {
        proto: ProtoLite,
        host: String,
        port: u16,
        seed: u64,
        out: PathBuf,
    },
    /// Localhost TCP (127.0.0.1/::1 only), with optional chaos/file combination
    /// 本机 TCP（仅 127.0.0.1/::1），可选 chaos/file 组合
    IoLocal {
        proto: ProtoLite,
        port: u16,
        seed: u64,
        out: PathBuf,
        #[serde(default)]
        spawn_echo: bool,
        chaos_profile: Option<String>,
        chaos_from: Option<PathBuf>,
        delay_tx_ms: Option<u64>,
        delay_rx_ms: Option<u64>,
        rx_drop: Option<usize>,
        rx_trim: Option<usize>,
        rx_xor: Option<String>,
    },
    /// Quality Check: Statistics/Timing/Histogram and write JSON
    /// 质量体检：统计帧/时序/直方图并写 JSON
    VerifyJsonl { from: PathBuf, out: PathBuf },
    /// Assert Thresholds (CI Friendly) / 断言阈值（CI 友好）
    AssertMetrics { from: PathBuf, expect: Expect },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScenarioFile {
    pub name: Option<String>,
    pub steps: Vec<Step>,
    /// 缺省期望（可被 AssertMetrics 自身 expect 覆盖）
    pub default_expect: Option<Expect>,
    /// 停在首个失败（默认 true）
    #[serde(default = "ScenarioFile::default_stop_on_fail")]
    pub stop_on_fail: bool,
    /// 递归包含其他场景文件（相对当前文件路径）
    #[serde(default)]
    pub include: Vec<PathBuf>,
    /// 新增：按 glob 引入子场景（只允许 examples/code-examples/testing/scenarios/ 前缀）
    #[serde(default)]
    pub include_glob: Vec<String>,
    /// 变量表（仅用于 String/Path 类字段展开）
    #[serde(default)]
    pub vars: HashMap<String, String>,
    /// 全局默认参数
    #[serde(default)]
    pub defaults: Defaults,
}

impl ScenarioFile {
    fn default_stop_on_fail() -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StepResult {
    pub ok: bool,
    pub action: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScenarioSummary {
    pub name: Option<String>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub steps: Vec<StepResult>,
}

fn chaos_from_profile(name: &str) -> Result<ChaosFile> {
    match name {
        "none" => Ok(ChaosFile::default()),
        "slowloss" => Ok(ChaosFile {
            delay_tx_ms: Some(20),
            delay_rx_ms: Some(30),
            rx_drop: Some(1),
            rx_trim: Some(24),
            rx_xor: None,
        }),
        "evil" => Ok(ChaosFile {
            delay_tx_ms: Some(50),
            delay_rx_ms: Some(50),
            rx_drop: Some(4),
            rx_trim: Some(16),
            rx_xor: Some("aa".into()),
        }),
        // 新增移动/边缘/WiFi 不佳预设（参数保守，教学用途）
        "mobile3g" => Ok(ChaosFile {
            delay_tx_ms: Some(120),
            delay_rx_ms: Some(180),
            rx_drop: Some(2),
            rx_trim: Some(32),
            rx_xor: None,
        }),
        "edge" => Ok(ChaosFile {
            delay_tx_ms: Some(250),
            delay_rx_ms: Some(350),
            rx_drop: Some(3),
            rx_trim: Some(24),
            rx_xor: Some("55".into()),
        }),
        "wifi_bad" => Ok(ChaosFile {
            delay_tx_ms: Some(40),
            delay_rx_ms: Some(60),
            rx_drop: Some(1),
            rx_trim: Some(8),
            rx_xor: None,
        }),
        other => Err(anyhow!("unknown chaos_profile: {other}")),
    }
}

/// 载入并解析场景文件，展开 include，应用 vars/out_dir
pub fn run_file<P: AsRef<Path>>(p: P) -> Result<ScenarioSummary> {
    let base = p
        .as_ref()
        .parent()
        .map(|x| x.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let sc = load_and_resolve(&p, &base, &mut Vec::new())?;
    run(sc)
}

fn load_and_resolve<P: AsRef<Path>>(
    path: P,
    base: &Path,
    stack: &mut Vec<PathBuf>,
) -> Result<ScenarioFile> {
    let abspath = if path.as_ref().is_absolute() {
        path.as_ref().to_path_buf()
    } else {
        base.join(path.as_ref())
    };
    if stack.contains(&abspath) {
        return Err(anyhow!("include cycle detected at {}", abspath.display()));
    }
    let txt = fs::read_to_string(&abspath)
        .with_context(|| format!("read scenario file {} failed", abspath.display()))?;
    let mut sc: ScenarioFile = serde_json::from_str(&txt)
        .with_context(|| format!("parse scenario json {} failed", abspath.display()))?;
    // resolve includes
    stack.push(abspath.clone());
    let mut merged_steps = Vec::new();
    for inc in sc.include.drain(..) {
        let sub = load_and_resolve(&inc, abspath.parent().unwrap_or(base), stack)?;
        merged_steps.extend(sub.steps);
    }
    // resolve include_glob (仅允许 examples/code-examples/testing/scenarios/ 开头，避免越界)
    for pat in sc.include_glob.drain(..) {
        if !(pat.starts_with("./examples/code-examples/testing/scenarios/")
            || pat.starts_with("examples/code-examples/testing/scenarios/"))
        {
            return Err(anyhow!(
                "include_glob must be under examples/code-examples/testing/scenarios/: {}",
                pat
            ));
        }
        for entry in glob(&pat).map_err(|e| anyhow!("bad glob pattern {}: {e}", pat))? {
            let p = entry.map_err(|e| anyhow!("glob entry error: {e}"))?;
            let sub = load_and_resolve(&p, abspath.parent().unwrap_or(base), stack)?;
            merged_steps.extend(sub.steps);
        }
    }
    merged_steps.append(&mut sc.steps);
    sc.steps = merged_steps;
    stack.pop();
    Ok(sc)
}

fn expand_vars_in_path(
    p: &Path,
    vars: &HashMap<String, String>,
    out_dir: &Option<PathBuf>,
) -> PathBuf {
    let s = p.to_string_lossy().to_string();
    let mut t = s.clone();
    for (k, v) in vars {
        let key = format!("${{{}}}", k);
        if t.contains(&key) {
            t = t.replace(&key, v);
        }
    }
    let pb = PathBuf::from(t);
    if let Some(dir) = out_dir {
        if pb.is_absolute() {
            pb
        } else {
            dir.join(pb)
        }
    } else {
        pb
    }
}

fn eff_seed(step_seed: u64, defaults: &Defaults) -> u64 {
    if step_seed == 0 {
        defaults.seed.unwrap_or(42)
    } else {
        step_seed
    }
}

pub fn run(sc: ScenarioFile) -> Result<ScenarioSummary> {
    let mut sum = ScenarioSummary {
        name: sc.name.clone(),
        total: sc.steps.len(),
        ..Default::default()
    };
    for st in sc.steps {
        let (ok, detail, name) = match st {
            Step::Loopback {
                proto,
                host,
                port,
                seed,
                out,
            } => {
                let hs = proto.make(host, port);
                let eff_out = expand_vars_in_path(&out, &sc.vars, &sc.defaults.out_dir);
                let m = loopback_once(hs.as_ref(), eff_seed(seed, &sc.defaults), Some(&eff_out))?;
                (
                    true,
                    Some(format!(
                        "bytes_tx={} bytes_rx={} out='{}'",
                        m.bytes_tx,
                        m.bytes_rx,
                        eff_out.display()
                    )),
                    "loopback".into(),
                )
            }
            Step::IoLocal {
                proto,
                port,
                seed,
                out,
                spawn_echo,
                chaos_profile,
                chaos_from,
                delay_tx_ms,
                delay_rx_ms,
                rx_drop,
                rx_trim,
                rx_xor,
            } => {
                #[cfg(not(feature = "io_local_alpha"))]
                {
                    return Err(anyhow!(
                        "io_local_alpha feature is required for IoLocal step"
                    ));
                }
                #[cfg(feature = "io_local_alpha")]
                {
                    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .map_err(|e| anyhow!("runtime build failed: {e}"))?;
                    let host = "localhost".to_string();
                    let hs = proto.make(host, port);
                    let mut target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                    if spawn_echo {
                        let bound = rt.block_on(spawn_echo_once(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                            None,
                        ))?;
                        target = bound;
                    }
                    // 合成 Chaos
                    let mut cf: ChaosFile = if let Some(p) = chaos_from {
                        let p2 = expand_vars_in_path(&p, &sc.vars, &None);
                        let t = fs::read_to_string(&p2)
                            .map_err(|e| anyhow!("read chaos_from failed: {e}"))?;
                        serde_json::from_str(&t)
                            .map_err(|e| anyhow!("parse chaos_from failed: {e}"))?
                    } else if let Some(name) = chaos_profile {
                        chaos_from_profile(&name)?
                    } else {
                        ChaosFile::default()
                    };
                    // flags 覆盖
                    if delay_tx_ms.is_some() {
                        cf.delay_tx_ms = delay_tx_ms;
                    }
                    if delay_rx_ms.is_some() {
                        cf.delay_rx_ms = delay_rx_ms;
                    }
                    if rx_drop.is_some() {
                        cf.rx_drop = rx_drop.map(|v| v as u64);
                    }
                    if rx_trim.is_some() {
                        cf.rx_trim = rx_trim.map(|v| v as u64);
                    }
                    if rx_xor.is_some() {
                        cf.rx_xor = rx_xor;
                    }
                    let spec = cf.to_spec();
                    let eff_out = expand_vars_in_path(&out, &sc.vars, &sc.defaults.out_dir);
                    let (tx, rx) = rt.block_on(io_local_once(
                        hs.as_ref(),
                        target,
                        eff_seed(seed, &sc.defaults),
                        &eff_out,
                        64,
                        3000,
                        Some(spec),
                    ))?;
                    (
                        true,
                        Some(format!(
                            "addr='{}' bytes_tx={} bytes_rx={} out='{}'",
                            target,
                            tx,
                            rx,
                            eff_out.display()
                        )),
                        "io_local".into(),
                    )
                }
            }
            Step::VerifyJsonl { from, out } => {
                let eff_from = expand_vars_in_path(&from, &sc.vars, &sc.defaults.out_dir);
                let eff_out = expand_vars_in_path(&out, &sc.vars, &sc.defaults.out_dir);
                let v = jsonl::basic_verify(&eff_from)?;
                fs::write(&eff_out, serde_json::to_string_pretty(&v)?)?;
                (
                    true,
                    Some(format!(
                        "frames={} out='{}'",
                        v.get("frames").and_then(|x| x.as_u64()).unwrap_or(0),
                        eff_out.display()
                    )),
                    "verify_jsonl".into(),
                )
            }
            Step::AssertMetrics { from, expect } => {
                let eff_from = expand_vars_in_path(&from, &sc.vars, &sc.defaults.out_dir);
                let v = jsonl::basic_verify(&eff_from)?;
                let g = |k| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                let frames = g("frames");
                let tx = g("tx");
                let rx = g("rx");
                let dis = g("ts_disorder");
                let e = expect;
                if let Some(min) = e.min_frames {
                    if frames < min {
                        return Err(anyhow!("frames {} < {}", frames, min));
                    }
                }
                if let Some(min) = e.min_tx {
                    if tx < min {
                        return Err(anyhow!("tx {} < {}", tx, min));
                    }
                }
                if let Some(min) = e.min_rx {
                    if rx < min {
                        return Err(anyhow!("rx {} < {}", rx, min));
                    }
                }
                if let Some(max) = e.max_disorder {
                    if dis > max {
                        return Err(anyhow!("ts_disorder {} > {}", dis, max));
                    }
                }
                (
                    true,
                    Some(format!(
                        "frames={} tx={} rx={} disorder={}",
                        frames, tx, rx, dis
                    )),
                    "assert_metrics".into(),
                )
            }
        };
        sum.steps.push(StepResult {
            ok,
            action: name,
            detail,
        });
        if ok {
            sum.passed += 1;
        } else {
            sum.failed += 1;
        }
        if sc.stop_on_fail && !ok {
            break;
        }
    }
    Ok(sum)
}
