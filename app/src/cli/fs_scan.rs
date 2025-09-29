#[cfg(feature = "dev-cli")]
use ignore::WalkBuilder;
#[cfg(feature = "dev-cli")]
use regex::Regex;
use serde::Serialize;
#[cfg(feature = "dev-cli")]
use std::fs;
#[cfg(feature = "dev-cli")]
use std::path::{Path, PathBuf};

#[derive(Serialize, Default)]
pub struct ScanSummary {
    pub files_scanned: u64,
    pub bytes_total: u64,
}

#[derive(Serialize, Default, Clone)]
pub struct Occur {
    pub path: String,
    pub count: u64,
}

#[derive(Serialize, Default)]
pub struct ErrorJsonCoverage {
    pub respond_json_error_calls: u64,
    pub text_plain_occurrences: u64,
    /// 明细：哪些文件仍有 text/plain
    pub text_plain_files: Vec<Occur>,
    /// 明细：哪些文件调用了 respond_json_error(
    pub json_error_call_files: Vec<Occur>,
}

#[derive(Serialize, Default)]
pub struct AnalyzeDispatch {
    pub build_single_patch_matches: u64,
    /// 粗略估算 match 语句数量（以 "match " 出现次数近似）
    pub match_arms_estimate: u64,
    /// 明细：哪些文件定义/调用了 build_single_patch(
    pub build_single_patch_files: Vec<Occur>,
}

#[derive(Serialize, Default)]
pub struct BinGates {
    pub minimal_bins: Vec<String>,
    pub router_gated_bins: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct SubsLimits {
    pub max_redirects: u64,
    pub timeout_ms: u64,
    pub max_bytes: u64,
}

#[derive(Serialize, Default)]
pub struct SecurityFlags {
    pub subs_fetch_guard_present: bool,
    pub limits: Option<SubsLimits>,
    pub private_allowlist: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct ReportMetrics {
    pub error_json: ErrorJsonCoverage,
    pub analyze_dispatch: AnalyzeDispatch,
    pub bin_gates: BinGates,
    pub has_admin_portfile_usage: bool,
    pub security_flags: SecurityFlags,
}

#[cfg(feature = "dev-cli")]
#[derive(Serialize)]
pub struct FsReport {
    pub root: String,
    pub summary: ScanSummary,
    pub metrics: ReportMetrics,
}

#[cfg(feature = "dev-cli")]
pub struct Scanner {
    root: PathBuf,
}

#[cfg(feature = "dev-cli")]
impl Scanner {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn run(&self) -> anyhow::Result<FsReport> {
        let mut summary = ScanSummary::default();
        let mut respond_json_error_calls = 0u64;
        let mut text_plain_occurrences = 0u64;
        let mut build_single_patch_matches = 0u64;
        let mut match_arms_estimate = 0u64;
        let mut has_admin_portfile_usage = false;
        let mut subs_guard = false;

        // Parse environment variables for security limits
        let max_redirects = std::env::var("SB_SUBS_MAX_REDIRECTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let timeout_ms = std::env::var("SB_SUBS_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4000);
        let max_bytes = std::env::var("SB_SUBS_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512 * 1024);
        let subs_limits = SubsLimits {
            max_redirects,
            timeout_ms,
            max_bytes: max_bytes as u64,
        };

        let private_allowlist = if let Ok(s) = std::env::var("SB_SUBS_PRIVATE_ALLOWLIST") {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        } else {
            vec![]
        };

        let _ = Regex::new(r"\brespond_json_error\s*\(");
        // 仅统计可能设置响应头为 text/plain 的代码片段：
        // - header("content-type", "text/plain")
        // - .content_type("text/plain")
        // - ContentType::from("text/plain")
        // 严格限制，避免把注释/字符串/样例误计入
        let re_text_plain = Regex::new(r#"(?i)(content[-_ ]?type).{0,40}text/plain"#).unwrap();
        let re_build_single = Regex::new(r"\bbuild_single_patch\s*\(").unwrap();
        // 注意：Rust 是 `match <expr>`，不是 `match(`
        let re_match_kw = Regex::new(r"\bmatch\s+").unwrap();
        let re_admin_portfile = Regex::new(r#"SB_ADMIN_PORTFILE"#).unwrap();

        let mut text_plain_files: Vec<Occur> = vec![];
        let mut json_error_call_files: Vec<Occur> = vec![];
        let mut build_single_patch_files: Vec<Occur> = vec![];

        // 仅扫描常见源文件
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .add_custom_ignore_filename(".gitignore")
            .add_custom_ignore_filename(".ignore")
            .standard_filters(true);
        let walker = builder.build();

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if !is_source_file(path) {
                continue;
            }
            // 允许清单：排除 Prometheus 导出器与当前扫描器自身文件，避免"自污染"与合法用例
            if let Some(p) = path.to_str() {
                if p.ends_with("crates/sb-core/src/metrics/http_exporter.rs")
                    || p.ends_with("app/src/cli/fs_scan.rs")
                {
                    continue;
                }
            }
            if let Ok(meta) = entry.metadata() {
                summary.files_scanned += 1;
                summary.bytes_total += meta.len();
            }
            let Ok(s) = fs::read_to_string(path) else {
                continue;
            };
            // respond_json_error 计数 + 文件清单
            let json_err_cnt = s.matches("respond_json_error(").count() as u64;
            if json_err_cnt > 0 {
                respond_json_error_calls += json_err_cnt;
                json_error_call_files.push(Occur {
                    path: path
                        .strip_prefix(&self.root)
                        .unwrap_or(path)
                        .display()
                        .to_string(),
                    count: json_err_cnt,
                });
            }
            // text/plain 计数 + 文件清单
            let text_plain_cnt = re_text_plain.find_iter(&s).count() as u64;
            if text_plain_cnt > 0 {
                text_plain_occurrences += text_plain_cnt;
                text_plain_files.push(Occur {
                    path: path
                        .strip_prefix(&self.root)
                        .unwrap_or(path)
                        .display()
                        .to_string(),
                    count: text_plain_cnt,
                });
            }
            // 仅统计函数调用形态（避免字符串/注释）：\bbuild_single_patch\s*\(
            let bsp_cnt = re_build_single.find_iter(&s).count() as u64;
            if bsp_cnt > 0 {
                build_single_patch_matches += bsp_cnt;
                build_single_patch_files.push(Occur {
                    path: path
                        .strip_prefix(&self.root)
                        .unwrap_or(path)
                        .display()
                        .to_string(),
                    count: bsp_cnt,
                });
            }
            match_arms_estimate += re_match_kw.find_iter(&s).count() as u64;
            if re_admin_portfile.is_match(&s) {
                has_admin_portfile_usage = true;
            }
            // 简易探测：端点中出现 fetch_with_limits / forbid_private_host 即视为启用
            if s.contains("fetch_with_limits(") || s.contains("forbid_private_host(") {
                subs_guard = true;
            }
        }

        // 解析 app/Cargo.toml 的 [[bin]] 门控（用 TOML 解析更稳）
        let gates = parse_bin_gates_toml(self.root.join("app").join("Cargo.toml"));

        Ok(FsReport {
            root: self.root.display().to_string(),
            summary,
            metrics: ReportMetrics {
                error_json: ErrorJsonCoverage {
                    respond_json_error_calls,
                    text_plain_occurrences,
                    text_plain_files,
                    json_error_call_files,
                },
                analyze_dispatch: AnalyzeDispatch {
                    build_single_patch_matches,
                    match_arms_estimate,
                    build_single_patch_files,
                },
                bin_gates: gates,
                has_admin_portfile_usage,
                security_flags: SecurityFlags {
                    subs_fetch_guard_present: subs_guard,
                    limits: Some(subs_limits),
                    private_allowlist,
                },
            },
        })
    }
}

#[cfg(feature = "dev-cli")]
fn is_source_file(p: &Path) -> bool {
    match p.extension().and_then(|s| s.to_str()) {
        Some("rs" | "toml" | "sh" | "yml" | "yaml") => true,
        // 避免 .md 里的示例代码干扰调用统计
        Some("md") => false,
        _ => false,
    }
}

#[cfg(feature = "dev-cli")]
fn parse_bin_gates_toml(toml_path: PathBuf) -> BinGates {
    let mut g = BinGates {
        minimal_bins: vec![],
        router_gated_bins: vec![],
    };
    let Ok(s) = fs::read_to_string(&toml_path) else {
        return g;
    };
    let Ok(t) = s.parse::<toml::Value>() else {
        return g;
    };
    if let Some(bins) = t.get("bin").and_then(|x| x.as_array()) {
        for b in bins {
            let name = b
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let req = b
                .get("required-features")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if req.iter().any(|f| f == "router") {
                g.router_gated_bins.push(name);
            } else {
                g.minimal_bins.push(name);
            }
        }
    }
    g.minimal_bins.sort();
    g.router_gated_bins.sort();
    g
}
