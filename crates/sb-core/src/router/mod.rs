//! Router rules: 编译化索引 + 原子热重载 + 规则 Lint/越界计数 + 可观测
//! 设计原则：
//! 1) 读路径无锁：Arc<RouterIndex> 快照原子替换
//! 2) 数据结构简单可预期：HashMap + 按长度/前缀降序 Vec
//! 3) Never break userspace：任何加载失败均不切换现行索引

// 重要：确保 engine 子模块对外可见，供 sb-core/src/lib.rs 重导出使用
pub mod dns_bridge;
pub mod dns_integration;
pub mod engine;
pub mod geo;
pub mod hot_reload;
pub mod hot_reload_cli;
#[cfg(feature = "json")]
pub mod json_bridge;
pub mod process_router;
pub mod rules;
pub mod runtime;
// R13：导出 analyze（离线分析，不影响运行路径）
pub mod analyze;
// R15：可选试验模块
#[cfg(feature = "suffix_trie")]
pub mod suffix_trie;
// R13：CLI patch 构建工具，仅 feature=rules_tool 时导出
#[cfg(feature = "rules_tool")]
pub mod analyze_fix;
// R21：可选规则文本捕获，仅在启用 feature=rules_capture 时编译
#[cfg(feature = "rules_capture")]
pub mod rules_capture;
// R25：可选缓存统计注册点
#[cfg(feature = "cache_stats")]
pub mod cache_stats;
// R28：轻量 JSON 工具（内部使用）
pub mod minijson;
// R33：热点查询（可选）
#[cfg(feature = "cache_stats_hot")]
pub mod cache_hot;
#[cfg(feature = "router_cache_wire")]
pub mod cache_wire;
// R34：纯文本补丁应用器（只读）
pub mod patch_apply;
// R113：预览临时索引与 explain（纯离线）
#[cfg(feature = "dsl_derive")]
pub mod dsl_derive;
#[cfg(feature = "dsl_analyze")]
pub mod dsl_inspect;
#[cfg(feature = "dsl_plus")]
pub mod dsl_plus;
#[cfg(feature = "preview_route")]
pub mod preview;
// R37：组合补丁计划
pub mod patch_plan;
// R38：规则规范化
pub mod decision_intern;
#[cfg(feature = "router_keyword")]
pub mod keyword;
pub mod normalize;
// 路由解释链（旁路分析）
#[cfg(feature = "rule_coverage")]
pub mod coverage;
#[cfg(feature = "explain")]
pub mod explain;
#[cfg(feature = "explain")]
pub mod explain_bridge;
#[cfg(feature = "explain")]
pub mod explain_index;
#[cfg(feature = "explain")]
pub mod explain_util;
#[cfg(feature = "explain")]
pub mod rule_id;
#[cfg(feature = "explain")]
pub use self::explain::{ExplainDto, ExplainQuery, ExplainResult, ExplainStep, ExplainTrace};
#[cfg(feature = "explain")]
pub use explain_bridge::rebuild_index;
#[cfg(feature = "explain")]
pub use explain_index::get_index;
// 为了兼容历史导出路径：router::{RouterHandle,RouteCtx,Transport,Router,RouteDecision,RouteTarget,DnsResolve,DnsResult}
pub use self::dns_bridge::{DnsResolverBridge, EnhancedDnsResolver};
pub use self::dns_integration::{
    setup_dns_routing, setup_dns_routing_with_config, setup_dns_routing_with_resolver,
    validate_dns_integration, DnsIntegrationConfig,
};
pub use self::engine::{decide_http_explain, decide_udp_async_explain, DecisionExplain};
pub use self::engine::{DnsResolve, DnsResult, Router, RouterHandle, Transport};
pub use self::hot_reload::{HotReloadConfig, HotReloadError, HotReloadEvent, HotReloadManager};
pub use self::hot_reload_cli::{
    show_rule_stats, start_hot_reload_cli, validate_rule_files, HotReloadCliConfig,
};
pub use crate::outbound::RouteTarget;

/// Route decision result for hot reload compatibility
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub target: String,
    pub matched_rule: Option<String>,
}

impl RouteDecision {
    pub fn as_str(&self) -> &str {
        &self.target
    }
}

/// Route context for routing decisions
#[derive(Debug, Clone)]
pub struct RouteCtx<'a> {
    pub host: Option<&'a str>,
    pub ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub transport: Transport,
    pub network: &'a str,
}

use blake3::Hasher as Blake3;
use once_cell::sync::Lazy;
#[cfg(feature = "json")]
use serde::Serialize;
use std::fs as sfs;
#[allow(unused)]
use std::io;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};
#[cfg(feature = "metrics")]
use std::time::Instant;
use tokio::fs as tfs;
use tokio::time::sleep;

#[cfg(feature = "metrics")]
#[inline]
fn incr_counter(name: &'static str, kv: &[(&'static str, &'static str)]) {
    // metrics 0.23 expects IntoLabels; build Vec<Label> explicitly.
    let labels: Vec<metrics::Label> = kv
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, *v))
        .collect();
    let c = metrics::counter!(name, labels.iter());
    c.increment(1);
}

#[cfg(feature = "metrics")]
#[inline]
fn set_gauge(name: &'static str, v: f64) {
    metrics::gauge!(name).set(v);
}

#[derive(Clone, Debug)]
pub struct RouterIndex {
    pub exact: HashMap<String, &'static str>,
    /// suffix 使用不含前导点的域名片段，按长度降序匹配
    pub suffix: Vec<(String, &'static str)>,
    /// suffix 精确尾段直查索引：key=去前导点的后缀（如 "example.com"）
    /// 注意：这是一种"更严格"的后缀（基于标签边界），用于快速命中；非边界匹配仍由 `suffix` 线扫兜底保障旧语义。
    pub suffix_map: HashMap<String, &'static str>,
    /// 端口精确匹配：key=目的端口（0-65535），命中即用
    pub port_rules: HashMap<u16, &'static str>,
    /// 端口区间（first-wins，保持插入顺序）
    pub port_ranges: Vec<(u16, u16, &'static str)>,
    /// 传输层默认：tcp/udp 两个可选优先级（在未命中 host/IP/port 时尝试）
    pub transport_tcp: Option<&'static str>,
    pub transport_udp: Option<&'static str>,
    /// IPv4/IPv6 CIDR，按前缀长度降序匹配
    pub cidr4: Vec<(Ipv4Net, &'static str)>,
    pub cidr6: Vec<(Ipv6Net, &'static str)>,
    /// CIDR 桶化索引：按前缀长度分桶，加速最长前缀匹配（构建期生成，读路径只读）
    pub cidr4_buckets: Vec<Vec<(Ipv4Net, &'static str)>>, // 33 个桶，索引即掩码长度 0..=32
    pub cidr6_buckets: Vec<Vec<(Ipv6Net, &'static str)>>, // 129 个桶，索引即掩码长度 0..=128
    /// GeoIP CC → decision（例如 CN→direct / !CN→proxy），简单数组遍历
    pub geoip_rules: Vec<(String, &'static str)>,
    /// GeoSite category → decision（例如 google→proxy / ads→reject），简单数组遍历
    pub geosite_rules: Vec<(String, &'static str)>,
    #[cfg(feature = "router_keyword")]
    pub keyword_rules: Vec<(String, String)>, // 原始存储
    #[cfg(feature = "router_keyword")]
    pub keyword_idx: Option<crate::router::keyword::Index>,
    pub default: &'static str,
    /// 构建代号（热重载成功 +1），仅用于可观测
    pub gen: u64,
    /// 用于热重载"变更检测"的校验和（blake3 of 文本）
    pub checksum: [u8; 32],
}

/// 用于 JSON 摘要导出的只读视图（保持字段名稳定以便运维接入）
#[cfg_attr(feature = "json", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct RouterSnapshotSummary {
    pub generation: u64,
    pub checksum_hex: String,
    pub sizes: RuleSizes,
    pub footprint_bytes: usize,
}

#[cfg_attr(feature = "json", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct RuleSizes {
    pub exact: usize,
    pub suffix: usize,
    pub port: usize,
    pub portset: usize,
    pub portrange: usize,
    pub transport: usize,
    pub cidr4: usize,
    pub cidr6: usize,
    pub geoip: usize,
    pub geosite: usize,
}

// R14/R25: 决策缓存摘要（保底返回 disabled=true；若注册 Provider 则返回实化字段）
impl RouterIndex {
    /// 决策缓存摘要（如果运行时未启用缓存，则返回 disabled）
    pub fn decision_cache_summary_json(&self) -> String {
        #[cfg(feature = "cache_stats")]
        {
            if let Some(s) = crate::router::cache_stats::snapshot() {
                if !s.enabled {
                    return r#"{"disabled":true}"#.to_string();
                }
                let hr = if s.hits + s.misses > 0 {
                    (s.hits as f64) / ((s.hits + s.misses) as f64)
                } else {
                    0.0
                };
                return minijson::obj([
                    ("disabled", minijson::Val::Bool(false)),
                    ("size", minijson::Val::NumU(s.size)),
                    ("capacity", minijson::Val::NumU(s.capacity)),
                    ("hits", minijson::Val::NumU(s.hits)),
                    ("misses", minijson::Val::NumU(s.misses)),
                    ("hit_ratio", minijson::Val::NumF(hr)),
                ]);
            }
        }
        // 保底：统一返回 disabled=true
        r#"{"disabled":true}"#.to_string()
    }
}

// R15: 试验性后缀 Trie 支持（仅当启用 feature="suffix_trie" 时暴露）
#[cfg(feature = "suffix_trie")]
impl RouterIndex {
    /// 当环境变量 `SB_ROUTER_SUFFIX_TRIE=1` 时，使用 Trie 查询后缀命中
    pub fn trial_decide_by_suffix(&self, host: &str) -> Option<&'static str> {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Mutex, OnceLock,
        };
        static ONCE: OnceLock<(AtomicU64, Mutex<suffix_trie::RevTrie>)> = OnceLock::new();
        let (ver, trie) =
            ONCE.get_or_init(|| (AtomicU64::new(0), Mutex::new(suffix_trie::RevTrie::new())));
        let cur = self.checksum_version64();
        if ver.load(Ordering::Relaxed) != cur {
            let mut t = suffix_trie::RevTrie::new();
            for (dom, dec) in &self.suffix {
                t.insert_suffix(dom, *dec);
            }
            *trie.lock().unwrap_or_else(|e| e.into_inner()) = t;
            ver.store(cur, Ordering::Relaxed);
        }
        if std::env::var("SB_ROUTER_SUFFIX_TRIE").ok().as_deref() == Some("1") {
            {
                let guard = trie.lock().unwrap_or_else(|e| e.into_inner());
                guard.query(host)
            }
        } else {
            None
        }
    }
}

impl RouterIndex {
    #[allow(dead_code)]
    pub(crate) fn checksum_version64(&self) -> u64 {
        // Avoid unwrap: copy bytes explicitly; length is guaranteed by checksum invariant.
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.checksum[0..8]);
        u64::from_le_bytes(arr)
    }

    pub fn decide_http_explain(&self, host_norm: &str) -> crate::router::engine::DecisionExplain {
        // exact、suffix ...
        #[cfg(feature = "router_keyword")]
        if let Some(idx) = &self.keyword_idx {
            if let Some(i) = idx.find_idx(host_norm) {
                let dec = idx
                    .decs
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| "default".to_string());
                return crate::router::engine::DecisionExplain {
                    decision: dec.clone(),
                    reason: "keyword_match".to_string(),
                    reason_kind: "keyword".to_string(),
                    #[cfg(feature = "router_cache_explain")]
                    cache_status: None,
                };
            }
        }
        // default ... (host_norm checked but no matches found)
        let reason = if host_norm.is_empty() {
            "default_empty_host"
        } else {
            "default_no_match"
        };
        crate::router::engine::DecisionExplain {
            decision: self.default.to_string(),
            reason: reason.to_string(),
            reason_kind: "default".to_string(),
            #[cfg(feature = "router_cache_explain")]
            cache_status: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Overflow,
    DupExact,
    EmptyHost,     // 空 pattern
    EmptyDecision, // 空 decision
    BadGeoip,
    BadGeosite,
    InvalidCidr,
    Io,
    InvalidChar,          // pattern/decision 含非法字符（控制符、空白、',' 或 '='）
    UnknownKind,          // 未知 kind（仅计数，不报错）
    DupSuffix,            // 重复 suffix（first-wins）
    DupDefault,           // 多次 default（last-wins）
    DupPort,              // 重复端口（first-wins）
    BadPort,              // 非法端口
    BadTransport,         // 非法传输关键字
    BadPortRange,         // 区间语法/范围非法
    BadPortSet,           // 端口集合非法
    MissingDefault,       // 缺少 default（当守门开关启用时）
    BadVarName,           // 变量名非法
    IncludeGlobError,     // include_glob 解析/读取错误
    IncludeDepthExceeded, // include_glob 递归/层级超限
}

#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum BuildError {
    #[error("invalid rule: {0:?}")]
    Invalid(InvalidReason),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("glob error: {0}")]
    Glob(String),
}

/// IPv4/6 Net 简易封装（不引入额外 crate）
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Net {
    pub net: Ipv4Addr,
    pub mask: u8,
}
#[derive(Clone, Copy, Debug)]
pub struct Ipv6Net {
    pub net: Ipv6Addr,
    pub mask: u8,
}

fn ip_in_v4net(ip: Ipv4Addr, net: Ipv4Net) -> bool {
    let ip_u = u32::from(ip);
    let net_u = u32::from(net.net);
    let m = if net.mask == 0 {
        0
    } else {
        u32::MAX << (32 - net.mask)
    };
    (ip_u & m) == (net_u & m)
}
fn ip_in_v6net(ip: Ipv6Addr, net: Ipv6Net) -> bool {
    let ip = u128::from(ip);
    let net_u = u128::from(net.net);
    let m = if net.mask == 0 {
        0
    } else {
        u128::MAX << (128 - net.mask)
    };
    (ip & m) == (net_u & m)
}

#[inline]
fn strip_bom(s: &str) -> &str {
    s.trim_start_matches('\u{feff}')
}

#[inline]
fn has_illegal_chars(s: &str) -> bool {
    // 控制符或包含空白/逗号/等号皆视为非法（避免解析歧义）
    s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ',' || c == '=')
}

/// 规则构建器（字符串 DSL → RouterIndex）
pub fn router_build_index_from_str(
    rules: &str,
    max: usize,
) -> Result<Arc<RouterIndex>, BuildError> {
    #[cfg(feature = "metrics")]
    let build_start = Instant::now();
    // 现有索引容器
    let mut exact = HashMap::new();
    let mut suffix = Vec::new();
    let mut suffix_map = HashMap::new();
    let mut port_rules = HashMap::new();
    let mut port_ranges = Vec::new();
    let mut transport_tcp: Option<&'static str> = Default::default();
    let mut transport_udp: Option<&'static str> = Default::default();
    let mut cidr4 = Vec::new();
    let mut cidr6 = Vec::new();
    // Pre-create empty buckets to avoid index-out-of-bounds on lookups with no CIDR rules.
    let buckets4 = vec![Vec::new(); 33]; // 0..=32
    let buckets6 = vec![Vec::new(); 129]; // 0..=128
    let mut geoip = Vec::new();
    let mut geosite = Vec::new();
    #[cfg(feature = "router_keyword")]
    let mut keyword_rules: Vec<(String, String)> = Vec::new();
    let mut default: Option<&'static str> = None;
    // 解析期去重/标记
    let mut seen_exact: HashSet<String> = HashSet::new();
    let mut seen_suffix: HashSet<String> = HashSet::new();
    let mut seen_port: HashSet<u16> = HashSet::new();
    let mut default_seen = false;
    // R5: let 变量
    let mut vars: HashMap<String, String> = HashMap::new();

    let mut count = 0usize;

    // R5/R10: include_glob 支持（相对路径以 SB_ROUTER_RULES_BASEDIR 或当前目录为基准）
    // 策略：预扫描，将 include_glob 展开为内联文本后再进入主解析循环；带深度/循环守卫
    let basedir = std::env::var("SB_ROUTER_RULES_BASEDIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let max_depth = std::env::var("SB_ROUTER_RULES_MAX_DEPTH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(3);
    let expanded = expand_include_glob_and_vars_prepass(rules, &basedir, &mut vars, 0, max_depth)?;
    let mut lines = expanded.lines();

    for raw_line in lines.by_ref() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // R5: let 变量定义
        if let Some(rest) = line.strip_prefix("let:") {
            let (name, val) = match rest.split_once('=') {
                Some((n, v)) => (n.trim(), v.trim()),
                None => continue, // 忽略空定义
            };
            if !is_valid_var_name(name) {
                #[cfg(feature = "metrics")]
                incr_counter("router_rules_invalid_total", &[("reason", "bad_var_name")]);
                return Err(BuildError::Invalid(InvalidReason::BadVarName));
            }
            vars.insert(name.to_string(), v_unquote(val).to_string());
            continue;
        }

        // 在本行进行变量替换：
        // - $NAME
        // - ${NAME:-default}  （R10 新增；default 可含空格，直至右花括号）
        let line = expand_vars_on_line(line, &vars);

        // 先处理 default:... 这种不含 '=' 的形式（兼容 normalize 的写法）
        if let Some(rest) = line.strip_prefix("default:") {
            let v = rest.trim();
            if v.is_empty() {
                #[cfg(feature = "metrics")]
                metrics::counter!("router_rules_invalid_total", "reason"=>"empty_decision")
                    .increment(1);
                return Err(BuildError::Invalid(InvalidReason::EmptyDecision));
            }
            default_seen = true;
            default = Some(intern_dec(v));
            continue;
        }

        // 形如： kind:pattern=decision   或   default=decision
        let mut it = line.splitn(2, '=');
        let left = it.next().unwrap_or("").trim();
        let decision = it.next().unwrap_or("").trim();
        if decision.is_empty() {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_rules_invalid_total", "reason"=>"empty_decision")
                .increment(1);
            return Err(BuildError::Invalid(InvalidReason::EmptyDecision));
        }
        if has_illegal_chars(decision) {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_char").increment(1);
            return Err(BuildError::Invalid(InvalidReason::InvalidChar));
        }
        if count >= max {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_rules_invalid_total", "reason"=>"overflow").increment(1);
            return Err(BuildError::Invalid(InvalidReason::Overflow));
        }

        // 对 IPv6 友好：只在第一个 ':' 处分割 kind 与 pattern
        let mut it2 = left.splitn(2, ':');
        let kind = strip_bom(it2.next().unwrap_or("")).trim();
        let pat = strip_bom(it2.next().unwrap_or("")).trim();

        match kind {
            "exact" => {
                if pat.is_empty() {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"empty_host")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::EmptyHost));
                }
                if has_illegal_chars(pat) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_char")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::InvalidChar));
                }
                if !seen_exact.insert(pat.to_string()) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"dup_exact")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::DupExact));
                }
                let dec = decision_intern::intern_decision(decision.trim());
                exact.insert(pat.to_string(), dec);
                count += 1;
            }
            #[cfg(feature = "router_keyword")]
            "keyword" => {
                // keyword:foo=decision
                if pat.is_empty() {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"empty_host")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::EmptyHost));
                }
                let kw = keyword::normalize_keyword(pat);
                if has_illegal_chars(&kw) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_char")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::InvalidChar));
                }
                keyword_rules.push((kw, decision.to_string()));
                count += 1;
            }
            "suffix" => {
                if pat.is_empty() {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"empty_host")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::EmptyHost));
                }
                if has_illegal_chars(pat) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_char")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::InvalidChar));
                }
                let key = pat.trim_start_matches('.').to_string();
                if !seen_suffix.insert(key.clone()) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"dup_suffix")
                        .increment(1);
                    // first-wins：跳过重复
                } else {
                    suffix.push((key.clone(), intern_dec(decision)));
                    // 建立精确尾段直查索引（基于标签边界）
                    suffix_map.insert(key, intern_dec(decision));
                }
                count += 1;
            }
            "cidr4" => {
                let mut it = pat.split('/');
                let ip = it
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<Ipv4Addr>()
                    .map_err(|_| BuildError::Invalid(InvalidReason::InvalidCidr))?;
                let mask = it
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| BuildError::Invalid(InvalidReason::InvalidCidr))?;
                if mask > 32 {
                    return Err(BuildError::Invalid(InvalidReason::InvalidCidr));
                }
                cidr4.push((Ipv4Net { net: ip, mask }, intern_dec(decision)));
                count += 1;
            }
            "cidr6" => {
                let mut it = pat.split('/');
                let ip = it
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<Ipv6Addr>()
                    .map_err(|_| BuildError::Invalid(InvalidReason::InvalidCidr))?;
                let mask = it
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| BuildError::Invalid(InvalidReason::InvalidCidr))?;
                if mask > 128 {
                    return Err(BuildError::Invalid(InvalidReason::InvalidCidr));
                }
                cidr6.push((Ipv6Net { net: ip, mask }, intern_dec(decision)));
                count += 1;
            }
            "geoip" => {
                if pat.len() != 2 || !pat.chars().all(|c| c.is_ascii_alphabetic()) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_geoip")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::BadGeoip));
                }
                geoip.push((pat.to_uppercase(), intern_dec(decision)));
                count += 1;
            }
            "geosite" => {
                if pat.is_empty() || has_illegal_chars(pat) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_geosite")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::BadGeosite));
                }
                geosite.push((pat.to_lowercase(), intern_dec(decision)));
                count += 1;
            }
            "port" => {
                // port:443=proxy
                let p: u16 = pat.parse().map_err(|_| {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_port")
                        .increment(1);
                    BuildError::Invalid(InvalidReason::BadPort)
                })?;
                if !seen_port.insert(p) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"dup_port")
                        .increment(1);
                } else {
                    port_rules.insert(p, intern_dec(decision));
                }
                count += 1;
            }
            "transport" => {
                // transport:tcp=reject / transport:udp=proxy
                let t = pat.to_ascii_lowercase();
                match t.as_str() {
                    "tcp" => transport_tcp = Some(intern_dec(decision)),
                    "udp" => transport_udp = Some(intern_dec(decision)),
                    _ => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_rules_invalid_total", "reason"=>"bad_transport")
                            .increment(1);
                        return Err(BuildError::Invalid(InvalidReason::BadTransport));
                    }
                }
                count += 1;
            }
            "portrange" => {
                // portrange:1000-2000=proxy
                let mut it = pat.splitn(2, '-');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                if a.is_empty() || b.is_empty() {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portrange")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::BadPortRange));
                }
                let s: u16 = a.parse().map_err(|_| {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portrange")
                        .increment(1);
                    BuildError::Invalid(InvalidReason::BadPortRange)
                })?;
                let e: u16 = b.parse().map_err(|_| {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portrange")
                        .increment(1);
                    BuildError::Invalid(InvalidReason::BadPortRange)
                })?;
                if e < s {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portrange")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::BadPortRange));
                }
                port_ranges.push((s, e, intern_dec(decision)));
                count += 1;
            }
            "portset" => {
                // portset:80,443,8443=proxy
                let mut any = false;
                for tok in pat.split(',') {
                    let t = tok.trim();
                    if t.is_empty() {
                        continue;
                    }
                    match t.parse::<u16>() {
                        Ok(p) => {
                            if seen_port.insert(p) {
                                port_rules.insert(p, intern_dec(decision));
                                any = true;
                            } else {
                                #[cfg(feature="metrics")] metrics::counter!("router_rules_invalid_total", "reason"=>"dup_port").increment(1);
                            }
                        }
                        Err(_) => {
                            #[cfg(feature="metrics")] metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portset").increment(1);
                            return Err(BuildError::Invalid(InvalidReason::BadPortSet));
                        }
                    }
                }
                if any {
                    count += 1;
                } else {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"bad_portset")
                        .increment(1);
                    return Err(BuildError::Invalid(InvalidReason::BadPortSet));
                }
            }
            "default" => {
                // default=decision；若同行还有内容，现已在分片阶段切开，不会拼串
                if default_seen {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("router_rules_invalid_total", "reason"=>"dup_default")
                        .increment(1);
                    eprintln!("router rule: duplicate default (last-wins)");
                }
                default_seen = true;
                default = Some(intern_dec(decision)); // last-wins
            }
            _ => {
                // 容错：未知 kind 计数并忽略，不中断构建
                #[cfg(feature = "metrics")]
                metrics::counter!("router_rules_invalid_total", "reason"=>"unknown_kind")
                    .increment(1);
                eprintln!("router rule: unknown kind `{}` -> ignored", kind);
                continue;
            }
        }
        count += 1;
        if count > max {
            break;
        }
    }

    // R5 守门：在开关启用时强制要求显式 default
    let require_default = std::env::var("SB_ROUTER_RULES_REQUIRE_DEFAULT")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_default && default.is_none() {
        #[cfg(feature = "metrics")]
        incr_counter(
            "router_rules_invalid_total",
            &[("reason", "missing_default")],
        );
        return Err(BuildError::Invalid(InvalidReason::MissingDefault));
    }

    // R21: 可选捕获展开后的文本，供只读分析/管理端使用
    #[cfg(feature = "rules_capture")]
    {
        // 捕获的是“预展开文本”（含 include_glob 与 let 展开后），利于复现
        rules_capture::capture(&expanded);
    }
    let checksum = blake3_checksum(&expanded /* 使用展开后的文本 */);
    #[cfg(feature = "router_keyword")]
    let mut idx = RouterIndex {
        exact,
        suffix,
        suffix_map,
        port_rules,
        port_ranges,
        transport_tcp,
        transport_udp,
        cidr4,
        cidr6,
        cidr4_buckets: buckets4,
        cidr6_buckets: buckets6,
        geoip_rules: geoip,
        geosite_rules: geosite,
        #[cfg(feature = "router_keyword")]
        keyword_rules,
        #[cfg(feature = "router_keyword")]
        keyword_idx: None,
        default: default.unwrap_or("direct"),
        gen: 0,
        checksum,
    };
    #[cfg(not(feature = "router_keyword"))]
    let idx = RouterIndex {
        exact,
        suffix,
        suffix_map,
        port_rules,
        port_ranges,
        transport_tcp,
        transport_udp,
        cidr4,
        cidr6,
        cidr4_buckets: buckets4,
        cidr6_buckets: buckets6,
        geoip_rules: geoip,
        geosite_rules: geosite,
        #[cfg(feature = "router_keyword")]
        keyword_rules,
        #[cfg(feature = "router_keyword")]
        keyword_idx: None,
        default: default.unwrap_or("direct"),
        gen: 0,
        checksum,
    };
    // 可选：构建完成后的收尾操作
    #[cfg(feature = "router_keyword")]
    {
        use crate::router::keyword;
        idx.keyword_idx = keyword::build_index(
            idx.keyword_rules
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        );
        // finalize 时把原 rules 决策也做一次驻留，供旧 &'static 路径复用
        for (_k, v) in &idx.keyword_rules {
            let _ = decision_intern::intern_decision(v);
        }
    }

    // 观测：索引规模（成功构建才写）
    #[cfg(feature = "metrics")]
    {
        metrics::gauge!("router_rules_size", "kind"=>"exact").set(idx.exact.len() as f64);
        metrics::gauge!("router_rules_size", "kind"=>"suffix").set(idx.suffix.len() as f64);
        metrics::gauge!("router_rules_size", "kind"=>"port").set(idx.port_rules.len() as f64);
        // portset 是语法糖：为观测计一个等同 port 的规模（近似）
        let portset_est = 0usize; // 构建期已落到单端口，无法区分；保留 0 以避免误导
        metrics::gauge!("router_rules_size", "kind"=>"portset").set(portset_est as f64);
        metrics::gauge!("router_rules_size", "kind"=>"portrange").set(idx.port_ranges.len() as f64);
        let tcnt = (idx.transport_tcp.is_some() as i32 + idx.transport_udp.is_some() as i32) as f64;
        metrics::gauge!("router_rules_size", "kind"=>"transport").set(tcnt);
        metrics::gauge!("router_rules_size", "kind"=>"cidr4").set(idx.cidr4.len() as f64);
        metrics::gauge!("router_rules_size", "kind"=>"cidr6").set(idx.cidr6.len() as f64);
        metrics::gauge!("router_rules_size", "kind"=>"geoip").set(idx.geoip_rules.len() as f64);
        metrics::gauge!("router_rules_size", "kind"=>"geosite").set(idx.geosite_rules.len() as f64);
        metrics::gauge!("router_rules_footprint_bytes").set(estimate_footprint_bytes(&idx) as f64);
        let elapsed = build_start.elapsed().as_millis() as f64;
        metrics::histogram!("router_rules_build_ms_bucket").record(elapsed);
    }
    Ok(Arc::new(idx))
}

// ---------------- R5：变量与 include_glob 辅助函数 ----------------
fn is_valid_var_name(name: &str) -> bool {
    // 约束：首字母必须大写字母，其余为 A-Z0-9_，长度 1..=32
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let c0 = bytes[0];
    if !(c0.is_ascii_uppercase()) {
        return false;
    }
    for &c in &bytes[1..] {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_') {
            return false;
        }
    }
    true
}

fn v_unquote(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn expand_vars_on_line(line: &str, vars: &HashMap<String, String>) -> String {
    // 支持两种形式：
    // 1) $NAME                          —— 未知变量：原样保留并计数 unknown_var
    // 2) ${NAME:-default value here}    —— 未知或空值时使用 default；default 不做递归替换
    let mut out = String::with_capacity(line.len() + 8);
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                // ${...}
                let mut j = i + 2;
                // 读取 NAME
                let start_name = j;
                while j < bytes.len()
                    && (bytes[j].is_ascii_uppercase()
                        || bytes[j].is_ascii_digit()
                        || bytes[j] == b'_')
                {
                    j += 1;
                }
                let name = &line[start_name..j];
                let mut default_val: Option<&str> = None;
                if j + 2 < bytes.len() && &line[j..j + 2] == ":-" {
                    j += 2;
                    let start_def = j;
                    while j < bytes.len() && bytes[j] != b'}' {
                        j += 1;
                    }
                    if j <= bytes.len() {
                        default_val = Some(&line[start_def..j]);
                    }
                } else {
                    // 找右花括号
                    while j < bytes.len() && bytes[j] != b'}' {
                        j += 1;
                    }
                }
                if j < bytes.len() && bytes[j] == b'}' {
                    let v = vars
                        .get(name)
                        .map(String::as_str)
                        .or(default_val)
                        .unwrap_or({
                            #[cfg(feature = "metrics")]
                            incr_counter(
                                "router_rules_invalid_total",
                                &[("reason", "unknown_var")],
                            );
                            // 保留原样
                            ""
                        });
                    out.push_str(v);
                    i = j + 1;
                    continue;
                }
            } else {
                // $NAME
                let start = i + 1;
                let mut j = start;
                while j < bytes.len()
                    && (bytes[j].is_ascii_uppercase()
                        || bytes[j].is_ascii_digit()
                        || bytes[j] == b'_')
                {
                    j += 1;
                }
                if j > start {
                    let key = &line[start..j];
                    if let Some(val) = vars.get(key) {
                        out.push_str(val);
                    } else {
                        #[cfg(feature = "metrics")]
                        incr_counter("router_rules_invalid_total", &[("reason", "unknown_var")]);
                        out.push('$');
                        out.push_str(key);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn expand_include_glob_and_vars_prepass(
    text: &str,
    basedir: &Path,
    vars: &mut HashMap<String, String>,
    depth: usize,
    max_depth: usize,
) -> Result<String, BuildError> {
    if depth > max_depth {
        #[cfg(feature = "metrics")]
        incr_counter(
            "router_rules_invalid_total",
            &[("reason", "include_depth_exceeded")],
        );
        return Err(BuildError::Invalid(InvalidReason::IncludeDepthExceeded));
    }
    let mut out = String::with_capacity(text.len() + 256);
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Some(rest) = line.strip_prefix("let:") {
            // 变量预收集，允许后续 include_glob 使用
            if let Some((n, v)) = rest.split_once('=') {
                let n = n.trim();
                let v = v_unquote(v.trim());
                if !is_valid_var_name(n) {
                    #[cfg(feature = "metrics")]
                    incr_counter("router_rules_invalid_total", &[("reason", "bad_var_name")]);
                    return Err(BuildError::Invalid(InvalidReason::BadVarName));
                }
                vars.insert(n.to_string(), v.to_string());
            }
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Some(rest) = line.strip_prefix("include_glob:") {
            let pat0 = v_unquote(rest.trim());
            let pat = expand_vars_on_line(pat0, vars);
            let pattern_path = basedir.join(&pat);
            let pattern_str = pattern_path.to_string_lossy().to_string();
            let mut matched: Vec<PathBuf> = Vec::new();
            match ::glob::glob(&pattern_str) {
                Ok(paths) => {
                    for entry in paths {
                        match entry {
                            Ok(p) => {
                                if p.is_file() {
                                    matched.push(p);
                                }
                            }
                            Err(e) => {
                                #[cfg(feature = "metrics")]
                                incr_counter(
                                    "router_rules_include_total",
                                    &[("result", "glob_error")],
                                );
                                return Err(BuildError::Glob(e.to_string()));
                            }
                        }
                    }
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    incr_counter("router_rules_include_total", &[("result", "glob_error")]);
                    return Err(BuildError::Glob(e.to_string()));
                }
            }
            if matched.is_empty() {
                #[cfg(feature = "metrics")]
                incr_counter("router_rules_include_total", &[("result", "glob_empty")]);
                continue;
            }
            matched.sort();
            #[cfg(feature = "metrics")]
            incr_counter("router_rules_include_total", &[("result", "glob_success")]);
            for p in matched {
                let s = sfs::read_to_string(&p)?;
                // 递归预展开：允许下层 include_glob / let
                let sub = expand_include_glob_and_vars_prepass(
                    &s,
                    p.parent().unwrap_or(basedir),
                    vars,
                    depth + 1,
                    max_depth,
                )?;
                out.push_str(&sub);
                if !sub.ends_with('\n') {
                    out.push('\n');
                }
            }
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    Ok(out)
}

fn blake3_checksum(text: &str) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(text.as_bytes());
    *hasher.finalize().as_bytes()
}

/// 静态泄漏帮助（便于 rules 保存 &'static str，不做分配拷贝）
// R65: unify &'static decision via intern pool; avoid scattered leaks.
#[inline]
fn intern_dec(s: &str) -> &'static str {
    crate::router::decision_intern::intern_decision(s)
}

fn estimate_footprint_bytes(idx: &RouterIndex) -> usize {
    // 粗略估算：字符串 key 长度 + (指针/元组)开销；只求数量级，不追求精确
    let mut bytes = 0usize;
    bytes += idx.exact.keys().map(|k| k.len()).sum::<usize>();
    bytes += idx.suffix.iter().map(|(k, _)| k.len()).sum::<usize>();
    bytes += idx.suffix_map.keys().map(|k| k.len()).sum::<usize>();
    bytes += idx.port_rules.len() * std::mem::size_of::<(u16, *const u8)>();
    bytes += idx.port_ranges.len() * std::mem::size_of::<(u16, u16, *const u8)>();
    bytes += idx.cidr4.len() * std::mem::size_of::<(Ipv4Net, *const u8)>();
    bytes += idx.cidr6.len() * std::mem::size_of::<(Ipv6Net, *const u8)>();
    // 桶向量的结构体占位
    bytes += idx
        .cidr4_buckets
        .iter()
        .map(|b| b.len() * std::mem::size_of::<(Ipv4Net, *const u8)>())
        .sum::<usize>();
    bytes += idx
        .cidr6_buckets
        .iter()
        .map(|b| b.len() * std::mem::size_of::<(Ipv6Net, *const u8)>())
        .sum::<usize>();
    bytes
}

#[inline]
pub fn normalize_host_ascii<'a>(host: &'a str) -> std::borrow::Cow<'a, str> {
    // DNS 名字大小写不敏感；保持简单与可预测：ASCII 小写
    if host.bytes().any(|b: u8| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(host.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

#[cfg(feature = "idna")]
#[inline]
pub fn normalize_host(host: &str) -> String {
    // 先 ASCII 小写，再 IDNA（domain_to_ascii 期望小写无所谓，但先做不伤害）
    let ascii = normalize_host_ascii(host);
    match idna::domain_to_ascii(&ascii) {
        Ok(puny) => puny,
        Err(_) => ascii.into_owned(), // 容错：失败就用小写原文，Never break userspace
    }
}

#[cfg(not(feature = "idna"))]
#[inline]
pub fn normalize_host(host: &str) -> String {
    normalize_host_ascii(host).into_owned()
}

/// 基本决策：仅 exact/suffix/default（测试使用）
pub fn router_index_decide_exact_suffix(idx: &RouterIndex, host: &str) -> Option<&'static str> {
    // 1) exact 优先（host 已规范化）
    if let Some(&d) = idx.exact.get(host) {
        return Some(d);
    }
    // 2) 生成"基于标签边界"的尾段候选（example.com / com ...）并在 suffix_map 中快速直查
    //    注意：这与 ends_with(无边界)语义不同，但我们只用于候选直查；未命中再走旧语义兜底。
    // 找到 host 中的每个 '.' 位置，从右往左，形成 &str 切片进行直查。
    let bytes = host.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        // 寻找上一个 '.'
        if let Some(dot_pos) = host[..i].rfind('.') {
            let candidate = &host[dot_pos + 1..];
            if let Some(&d) = idx.suffix_map.get(candidate) {
                return Some(d);
            }
            i = dot_pos;
        } else {
            // 没有更多点，最后一段（整个 host）作为 candidate（例如 TLD-only）
            if let Some(&d) = idx.suffix_map.get(host) {
                return Some(d);
            }
            break;
        }
    }
    // 3) 旧语义兜底：无边界 ends_with 线扫，保障"不破坏用户空间"
    if !*SUFFIX_STRICT {
        for (s, d) in &idx.suffix {
            if host.ends_with(s) {
                return Some(*d);
            }
        }
    }
    None
}

/// 控制是否开启严格后缀模式（仅标签边界直查）
static SUFFIX_STRICT: Lazy<bool> = Lazy::new(|| {
    std::env::var("SB_ROUTER_SUFFIX_STRICT")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false)
});

/// 基于端口/传输的后置兜底（只在 host/IP 未命中时尝试）
pub fn router_index_decide_transport_port(
    idx: &RouterIndex,
    port: Option<u16>,
    transport: Option<&str>,
) -> Option<&'static str> {
    // 先端口，后传输；两者都未命中则返回 None
    if let Some(p) = port {
        if let Some(d) = idx.port_rules.get(&p) {
            return Some(*d);
        }
        // 再查区间（first-wins）
        for (s, e, d) in &idx.port_ranges {
            if p >= *s && p <= *e {
                return Some(*d);
            }
        }
    }
    if let Some(t) = transport {
        match t {
            "tcp" => {
                if let Some(d) = idx.transport_tcp {
                    return Some(d);
                }
            }
            "udp" => {
                if let Some(d) = idx.transport_udp {
                    return Some(d);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extended version that returns decision type for metrics
pub fn router_index_decide_transport_port_with_kind(
    idx: &RouterIndex,
    port: Option<u16>,
    transport: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    // 先端口，后传输；两者都未命中则返回 None
    if let Some(p) = port {
        if let Some(d) = idx.port_rules.get(&p) {
            return Some((*d, "port"));
        }
        // 再查区间（first-wins）
        for (s, e, d) in &idx.port_ranges {
            if p >= *s && p <= *e {
                return Some((*d, "portrange"));
            }
        }
    }
    if let Some(t) = transport {
        match t {
            "tcp" => {
                if let Some(d) = idx.transport_tcp {
                    return Some((d, "transport"));
                }
            }
            "udp" => {
                if let Some(d) = idx.transport_udp {
                    return Some((d, "transport"));
                }
            }
            _ => {}
        }
    }
    None
}

pub fn router_index_decide_ip(idx: &RouterIndex, ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            // 最长前缀优先：从 /32 下降到 /0，仅检查对应桶
            for m in (0..=32).rev() {
                for (n, d) in &idx.cidr4_buckets[m] {
                    if ip_in_v4net(v4, *n) {
                        return Some(*d);
                    }
                }
            }
        }
        IpAddr::V6(v6) => {
            for m in (0..=128).rev() {
                for (n, d) in &idx.cidr6_buckets[m] {
                    if ip_in_v6net(v6, *n) {
                        return Some(*d);
                    }
                }
            }
        }
    }
    None
}

/// GeoSite domain categorization decision
///
/// This function checks if a domain matches any GeoSite category rules.
/// It requires a GeoSite database to be available through the RouterHandle.
///
/// # Arguments
/// * `idx` - Router index containing GeoSite rules
/// * `domain` - Domain to check against GeoSite categories
/// * `geosite_db` - GeoSite database for domain categorization
///
/// # Returns
/// * `Option<&'static str>` - Routing decision if domain matches any GeoSite category
pub fn router_index_decide_geosite(
    idx: &RouterIndex,
    domain: &str,
    geosite_db: &crate::router::geo::GeoSiteDb,
) -> Option<&'static str> {
    // Check against GeoSite rules in the router index
    for (category, decision) in &idx.geosite_rules {
        if geosite_db.match_domain(domain, category) {
            return Some(*decision);
        }
    }
    None
}

/// 文件读取
async fn read_rules_file(path: &Path) -> Result<String, std::io::Error> {
    let bytes = tfs::read(path).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// 递归展开 include 指令，支持两种形式：
// - `include path/to/file.rules`
// - `@include path/to/file.rules`
/// 相对路径基于父文件目录；深度由 `SB_ROUTER_RULES_INCLUDE_DEPTH` 控制（默认 4）
fn read_rules_with_includes<'a>(
    root: &'a Path,
    depth: usize,
    visited: &'a mut HashSet<PathBuf>,
) -> Pin<Box<dyn Future<Output = Result<String, std::io::Error>> + Send + 'a>> {
    Box::pin(async move {
        let max_depth = std::env::var("SB_ROUTER_RULES_INCLUDE_DEPTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);
        if depth > max_depth {
            return Ok(String::new());
        }
        // 标准化路径并检测环路
        let canon = match tfs::canonicalize(root).await {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        if !visited.insert(canon.clone()) {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_rules_include_total", "result"=>"cycle").increment(1);
            return Ok(String::new());
        }
        let raw = read_rules_file(root).await?;
        let mut out = String::new();
        let base = root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("include ") || trimmed.starts_with("@include ") {
                let path_str = trimmed.split_whitespace().nth(1).unwrap_or("");
                if path_str.is_empty() {
                    continue;
                }
                let inc_path = PathBuf::from(path_str);
                let full = if inc_path.is_absolute() {
                    inc_path
                } else {
                    base.join(inc_path)
                };
                match Box::pin(read_rules_with_includes(&full, depth + 1, visited)).await {
                    Ok(s) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_rules_include_total", "result"=>"success")
                            .increment(1);
                        out.push_str(&s);
                        out.push('\n');
                    }
                    Err(_) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_rules_include_total", "result"=>"error")
                            .increment(1);
                        // 包含失败：跳过该 include，继续处理后续规则，Never break userspace
                    }
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        // 完成本层后移除，允许同文件在不同 include 分支末端再次出现（由深度限制兜底）
        visited.remove(&canon);
        Ok(out)
    })
}

#[allow(dead_code)] // Fields used in hot reload implementation (run/try_reload_once methods)
pub struct HotReloader {
    path: PathBuf,
    // ...
    last_ok_checksum: [u8; 32],
    // R5: 失败退避（毫秒），成功后复位；上限由 SB_ROUTER_RULES_BACKOFF_MAX_MS 控制
    backoff_ms: u64,
    // R9/R10: 周期抖动（毫秒上限）；默认 0=关闭
    jitter_ms: u64,
}

impl HotReloader {
    pub fn spawn(path: PathBuf, router_handle: RouterHandle) {
        // 实现热重载逻辑：启动热重载监控
        tracing::info!("Router hot reloader configured for path: {:?}", path);

        // 检查是否启用热重载
        if std::env::var("SB_ROUTER_HOT_RELOAD").is_ok() {
            tracing::info!("Hot reload enabled for router configuration");

            // 创建热重载实例并启动监控任务
            let reloader = Self {
                path: path.clone(),
                last_ok_checksum: [0; 32], // 初始为空checksum，首次reload会检测
                backoff_ms: 0,
                jitter_ms: 0,
            };

            // 在后台异步任务中运行热重载逻辑
            tokio::spawn(async move {
                // 集成RouterHandle到热重载逻辑中，用于应用新的路由索引
                reloader.run_with_router_handle(router_handle).await;
            });
        } else {
            tracing::debug!("Hot reload not enabled (set SB_ROUTER_HOT_RELOAD=1 to enable)");
            // RouterHandle在热重载未启用时不需要使用，但保留接口一致性
            // 未来如果有其他用途（如手动重载API）可以在这里处理
        }
    }

    #[allow(dead_code)] // Hot reload implementation, to be activated when hot reload is enabled
    /// Run hot reload loop with RouterHandle integration
    async fn run_with_router_handle(mut self, router_handle: RouterHandle) {
        let mut interval = tokio::time::interval(Duration::from_millis(1000));
        let jitter_cap = std::env::var("SB_ROUTER_RULES_JITTER_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        self.jitter_ms = jitter_cap;

        loop {
            interval.tick().await;
            #[cfg(feature = "rand")]
            {
                if self.jitter_ms > 0 {
                    let j = rand::random::<u64>() % (self.jitter_ms + 1);
                    tokio::time::sleep(Duration::from_millis(j)).await;
                }
            }

            match self.try_reload_once().await {
                Ok(Some(newidx)) => {
                    // 成功重载新索引：应用到RouterHandle并复位退避
                    tracing::info!("Hot reload: applying new router index (gen {})", newidx.gen);

                    // Save checksum before moving newidx into Arc
                    let checksum = newidx.checksum;

                    if let Err(e) = router_handle.replace_index(newidx.clone()).await {
                        tracing::error!("Failed to apply new router index: {}", e);
                        // 即使应用失败，也更新checksum以避免重复尝试相同的配置
                    } else {
                        tracing::info!("Hot reload: successfully applied new router index");
                        #[cfg(feature = "metrics")]
                        incr_counter("router_rules_reload_success_total", &[]);
                    }

                    self.last_ok_checksum = checksum;
                    self.backoff_ms = 0;
                    #[cfg(feature = "metrics")]
                    set_gauge("router_rules_reload_backoff_ms", 0.0);
                }
                Ok(None) => { /* 无变化 */ }
                Err(e) => {
                    // 失败：记录并退避
                    tracing::error!("router reload failed: {}", e);
                    let cap = std::env::var("SB_ROUTER_RULES_BACKOFF_MAX_MS")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(30000);

                    self.backoff_ms = std::cmp::min(
                        if self.backoff_ms == 0 { 1000 } else { self.backoff_ms * 2 },
                        cap,
                    );
                    #[cfg(feature = "metrics")]
                    {
                        set_gauge("router_rules_reload_backoff_ms", self.backoff_ms as f64);
                        incr_counter("router_rules_reload_error_total", &[]);
                    }
                    tokio::time::sleep(Duration::from_millis(self.backoff_ms)).await;
                }
            }
        }
    }


    #[allow(dead_code)] // Hot reload implementation, to be activated when hot reload is enabled
    async fn try_reload_once(&mut self) -> Result<Option<Arc<RouterIndex>>, BuildError> {
        // 读取文件, mtime + checksum 判定是否变更；变更则构建
        let s = sfs::read_to_string(&self.path)?;
        let max_rules: usize = std::env::var("SB_ROUTER_RULES_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8192);
        let idx = router_build_index_from_str(&s, max_rules)?;
        if idx.checksum == self.last_ok_checksum {
            return Ok(None);
        }
        // 原子切换
        let shared = shared_index();
        *shared.write().unwrap_or_else(|e| e.into_inner()) = idx.clone();
        #[cfg(feature = "metrics")]
        incr_counter("router_rules_reload_total", &[("result", "success")]);
        Ok(Some(idx))
    }
}


// ---------------- R11: bench feature 下的最小导出（不影响运行路径） ----------------
#[cfg(feature = "bench")]
pub mod bench_api {
    use super::*;
    /// 构建索引供基准使用；避免基准测试复制内部细节
    #[allow(clippy::expect_used)]
    pub fn build_index(text: &str) -> Arc<RouterIndex> {
        super::router_build_index_from_str(text, 1 << 24).expect("bench build index")
    }
}

/// 原子热重载：成功才替换；失败仅计数不切换
pub async fn spawn_rules_hot_reload(
    shared: Arc<RwLock<Arc<RouterIndex>>>,
) -> Result<tokio::task::JoinHandle<()>, BuildError> {
    let file = std::env::var("SB_ROUTER_RULES_FILE").unwrap_or_default();
    let interval_ms: u64 = std::env::var("SB_ROUTER_RULES_HOT_RELOAD_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if file.is_empty() || interval_ms == 0 {
        // 热重载未启用，直接返回一个 no-op handle
        return Ok(tokio::spawn(async move {}));
    }
    let path = PathBuf::from(&file);
    let max_rules: usize = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8192);
    let mut last_mtime: Option<SystemTime> = None;
    let h = tokio::spawn(async move {
        loop {
            let mut should_check = true;
            // 观测 mtime
            match tokio::fs::metadata(&path).await {
                Ok(meta) => {
                    if let Ok(m) = meta.modified() {
                        if Some(m) == last_mtime {
                            should_check = false;
                        }
                        last_mtime = Some(m);
                    }
                }
                Err(_) => { /* 文件可能暂时不存在，继续轮询 */ }
            }
            if should_check {
                let mut visited = HashSet::new();
                match read_rules_with_includes(&path, 0, &mut visited).await {
                    Ok(text) => {
                        // 与当前 checksum 比较，避免无谓切换
                        let cur_sum =
                            { shared.read().unwrap_or_else(|e| e.into_inner()).checksum };
                        let mut hasher = Blake3::new();
                        hasher.update(text.as_bytes());
                        let new_sum = *hasher.finalize().as_bytes();
                        if new_sum == cur_sum {
                            #[cfg(feature = "metrics")]
                            metrics::counter!("router_rules_reload_total", "result"=>"noop")
                                .increment(1);
                            continue;
                        }
                        #[cfg(feature = "metrics")]
                        let build_start = Instant::now();
                        match router_build_index_from_str(&text, max_rules) {
                            Ok(new_idx) => {
                                #[cfg(feature = "metrics")]
                                let elapsed = build_start.elapsed().as_millis() as f64;
                                // 生成号 +1，并暴露 generation
                                let mut w = shared.write().unwrap_or_else(|e| e.into_inner());
                                let prev_gen = w.gen;
                                let mut idx_cloned = (*new_idx).clone();
                                idx_cloned.gen = prev_gen.saturating_add(1);
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::gauge!("router_rules_generation")
                                        .set(idx_cloned.gen as f64);
                                    metrics::histogram!("router_rules_reload_ms_bucket")
                                        .record(elapsed);
                                    // reload 后再次写规模（便于观察变化）
                                    metrics::gauge!("router_rules_size", "kind"=>"exact")
                                        .set(idx_cloned.exact.len() as f64);
                                    metrics::gauge!("router_rules_size", "kind"=>"suffix")
                                        .set(idx_cloned.suffix.len() as f64);
                                    metrics::gauge!("router_rules_size", "kind"=>"port")
                                        .set(idx_cloned.port_rules.len() as f64);
                                    let tcnt = (idx_cloned.transport_tcp.is_some() as i32
                                        + idx_cloned.transport_udp.is_some() as i32)
                                        as f64;
                                    metrics::gauge!("router_rules_size", "kind"=>"transport")
                                        .set(tcnt);
                                    metrics::gauge!("router_rules_size", "kind"=>"cidr4")
                                        .set(idx_cloned.cidr4.len() as f64);
                                    metrics::gauge!("router_rules_size", "kind"=>"cidr6")
                                        .set(idx_cloned.cidr6.len() as f64);
                                    metrics::gauge!("router_rules_size", "kind"=>"geoip")
                                        .set(idx_cloned.geoip_rules.len() as f64);
                                    metrics::gauge!("router_rules_size", "kind"=>"geosite")
                                        .set(idx_cloned.geosite_rules.len() as f64);
                                    metrics::gauge!("router_rules_footprint_bytes")
                                        .set(estimate_footprint_bytes(&idx_cloned) as f64);
                                    metrics::counter!("router_rules_reload_total", "result"=>"success").increment(1);
                                }
                                *w = Arc::new(idx_cloned);
                            }
                            Err(_e) => {
                                #[cfg(feature = "metrics")]
                                {
                                    match _e {
                                        BuildError::Invalid(InvalidReason::Overflow) => metrics::counter!("router_rules_invalid_total", "reason"=>"overflow").increment(1),
                                        BuildError::Invalid(InvalidReason::DupExact) => metrics::counter!("router_rules_invalid_total", "reason"=>"dup_exact").increment(1),
                                        BuildError::Invalid(InvalidReason::EmptyHost) => metrics::counter!("router_rules_invalid_total", "reason"=>"empty_host").increment(1),
                                        BuildError::Invalid(InvalidReason::EmptyDecision) => metrics::counter!("router_rules_invalid_total", "reason"=>"empty_decision").increment(1),
                                        BuildError::Invalid(InvalidReason::BadGeoip) => metrics::counter!("router_rules_invalid_total", "reason"=>"bad_geoip").increment(1),
                                        BuildError::Invalid(InvalidReason::InvalidCidr) => metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_cidr").increment(1),
                                        BuildError::Invalid(InvalidReason::InvalidChar) => metrics::counter!("router_rules_invalid_total", "reason"=>"invalid_char").increment(1),
                                        BuildError::Invalid(InvalidReason::DupSuffix) => metrics::counter!("router_rules_invalid_total", "reason"=>"dup_suffix").increment(1),
                                        BuildError::Invalid(InvalidReason::DupDefault) => metrics::counter!("router_rules_invalid_total", "reason"=>"dup_default").increment(1),
                                        BuildError::Io(_) | _ => metrics::counter!("router_rules_invalid_total", "reason"=>"io").increment(1),
                                    };
                                    metrics::counter!("router_rules_reload_total", "result"=>"error").increment(1);
                                }
                                // 不切换旧索引
                            }
                        }
                    }
                    Err(_) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_rules_invalid_total", "reason"=>"io")
                            .increment(1);
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_rules_reload_total", "result"=>"error")
                            .increment(1);
                        // 不切换
                    }
                }
            }
            sleep(Duration::from_millis(interval_ms)).await;
        }
    });
    Ok(h)
}

/// 便捷：从 ENV 初始化索引并（可选）热重载
pub async fn router_index_from_env_with_reload() -> Arc<RwLock<Arc<RouterIndex>>> {
    let max_rules: usize = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8192);
    let init_rules = if let Ok(p) = std::env::var("SB_ROUTER_RULES_FILE") {
        tokio::fs::read_to_string(&p).await.unwrap_or_default()
    } else {
        std::env::var("SB_ROUTER_RULES").unwrap_or_default()
    };
    let idx = router_build_index_from_str(&init_rules, max_rules).unwrap_or_else(|_| {
        Arc::new(RouterIndex {
            exact: HashMap::new(),
            suffix: vec![],
            suffix_map: HashMap::new(),
            port_rules: HashMap::new(),
            port_ranges: vec![],
            transport_tcp: None,
            transport_udp: None,
            cidr4: vec![],
            cidr6: vec![],
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: vec![],
            geosite_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 0,
            checksum: [0; 32],
        })
    });
    let shared = Arc::new(RwLock::new(idx));
    // 可选热重载
    let _ = spawn_rules_hot_reload(shared.clone()).await;
    shared
}

// ===== 共享快照（给 RouterHandle / decide_http 复用）=====
static SHARED_INDEX: Lazy<Arc<RwLock<Arc<RouterIndex>>>> = Lazy::new(|| {
    // 同步阶段：尽力按 ENV 构造一份索引；失败就用空配置 direct
    let max_rules: usize = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8192);
    let inline = std::env::var("SB_ROUTER_RULES").unwrap_or_default();
    let initial_text = if inline.is_empty() {
        if let Ok(p) = std::env::var("SB_ROUTER_RULES_FILE") {
            std::fs::read_to_string(p).unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        inline
    };
    let idx = router_build_index_from_str(&initial_text, max_rules).unwrap_or_else(|_| {
        Arc::new(RouterIndex {
            exact: Default::default(),
            suffix: vec![],
            suffix_map: HashMap::new(),
            port_rules: HashMap::new(),
            port_ranges: vec![],
            transport_tcp: None,
            transport_udp: None,
            cidr4: vec![],
            cidr6: vec![],
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: vec![],
            geosite_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 0,
            checksum: [0; 32],
        })
    });
    Arc::new(RwLock::new(idx))
});

/// 提供共享快照（在 Tokio runtime 内自动启动热重载）
pub fn shared_index() -> Arc<RwLock<Arc<RouterIndex>>> {
    // 若在 async 上下文，后台拉起热重载（只尝试一次）
    if tokio::runtime::Handle::try_current().is_ok() {
        static STARTED: Lazy<std::sync::Once> = Lazy::new(std::sync::Once::new);
        STARTED.call_once(|| {
            let s = SHARED_INDEX.clone();
            tokio::spawn(async move {
                let _ = spawn_rules_hot_reload(s).await;
            });
        });
    }
    SHARED_INDEX.clone()
}

/// —— 运行时覆盖（仅用于调试）———————————————————————————————————————————————
#[derive(Debug, Clone)]
struct RuntimeOverride {
    exact: HashMap<String, &'static str>,
    suffix: Vec<(String, &'static str)>,
    port: HashMap<u16, &'static str>,
    port_ranges: Vec<(u16, u16, &'static str)>,
    transport_tcp: Option<&'static str>,
    transport_udp: Option<&'static str>,
    default: Option<&'static str>,
}

static RUNTIME_OVERRIDE: Lazy<Option<RuntimeOverride>> = Lazy::new(|| {
    let raw = match std::env::var("SB_ROUTER_OVERRIDE") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return None,
    };
    let mut exact = HashMap::new();
    let mut suffix = Vec::new();
    let mut port = HashMap::new();
    let mut port_ranges = Vec::new();
    let mut transport_tcp = None;
    let mut transport_udp = None;
    let mut default = None;
    // 支持逗号或分号分隔
    let parts = raw.split([',', ';']);
    for seg in parts {
        let s = seg.trim();
        if s.is_empty() {
            continue;
        }
        let (k, v) = match s.split_once('=') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => continue,
        };
        // k 形如 kind:pattern 或 default
        if k.eq_ignore_ascii_case("default") {
            default = Some(intern_dec(v));
            continue;
        }
        if let Some((kind, pat)) = k.split_once(':') {
            match kind.to_ascii_lowercase().as_str() {
                "exact" => {
                    exact.insert(normalize_host(pat), intern_dec(v));
                }
                "suffix" => {
                    let patt = pat.trim_start_matches('.');
                    suffix.push((patt.to_ascii_lowercase().to_string(), intern_dec(v)));
                }
                "port" => {
                    if let Ok(p) = pat.parse::<u16>() {
                        port.insert(p, intern_dec(v));
                    }
                }
                "portrange" => {
                    let mut it = pat.splitn(2, '-');
                    if let (Some(a), Some(b)) = (it.next(), it.next()) {
                        if let (Ok(s), Ok(e)) = (a.parse::<u16>(), b.parse::<u16>()) {
                            if e >= s {
                                port_ranges.push((s, e, intern_dec(v)));
                            }
                        }
                    }
                }
                "portset" => {
                    for t in pat.split(',') {
                        if let Ok(p) = t.trim().parse::<u16>() {
                            port.insert(p, intern_dec(v));
                        }
                    }
                }
                "transport" => match pat.to_ascii_lowercase().as_str() {
                    "tcp" => transport_tcp = Some(intern_dec(v)),
                    "udp" => transport_udp = Some(intern_dec(v)),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    Some(RuntimeOverride {
        exact,
        suffix,
        port,
        port_ranges,
        transport_tcp,
        transport_udp,
        default,
    })
});

pub fn runtime_override_http(
    host_norm: &str,
    port: Option<u16>,
) -> Option<(&'static str, &'static str)> {
    let ov = RUNTIME_OVERRIDE.as_ref()?;
    if let Some(d) = ov.exact.get(host_norm) {
        return Some((*d, "override"));
    }
    // suffix 匹配：检查 host 是否以 suffix 结尾
    for (s, d) in &ov.suffix {
        if host_norm.ends_with(s) {
            return Some((*d, "override"));
        }
    }
    if let Some(p) = port {
        if let Some(d) = ov.port.get(&p) {
            return Some((*d, "override"));
        }
        for (s, e, d) in &ov.port_ranges {
            if p >= *s && p <= *e {
                return Some((*d, "override"));
            }
        }
    }
    if let Some(d) = ov.transport_tcp {
        return Some((d, "override"));
    }
    if let Some(d) = ov.default {
        return Some((d, "override_default"));
    }
    None
}

pub fn runtime_override_udp(host_norm: &str) -> Option<(&'static str, &'static str)> {
    let ov = RUNTIME_OVERRIDE.as_ref()?;
    if let Some(d) = ov.exact.get(host_norm) {
        return Some((*d, "override"));
    }
    // suffix 匹配：检查 host 是否以 suffix 结尾
    for (s, d) in &ov.suffix {
        if host_norm.ends_with(s) {
            return Some((*d, "override"));
        }
    }
    if let Some(d) = ov.transport_udp {
        return Some((d, "override"));
    }
    if let Some(d) = ov.default {
        return Some((d, "override_default"));
    }
    None
}

/// —— 快照摘要导出（JSON 字符串；feature=json 才返回 JSON，否则返回人类可读文本）———
pub fn router_snapshot_summary() -> String {
    let snap = shared_index();
    let idx = snap.read().unwrap_or_else(|e| e.into_inner());
    let sizes = RuleSizes {
        exact: idx.exact.len(),
        suffix: idx.suffix.len(),
        port: idx.port_rules.len(),
        portset: 0,
        portrange: idx.port_ranges.len(),
        transport: (idx.transport_tcp.is_some() as usize) + (idx.transport_udp.is_some() as usize),
        cidr4: idx.cidr4.len(),
        cidr6: idx.cidr6.len(),
        geoip: idx.geoip_rules.len(),
        geosite: idx.geosite_rules.len(),
    };
    let summary = RouterSnapshotSummary {
        generation: idx.gen,
        checksum_hex: hex_checksum(&idx.checksum),
        footprint_bytes: estimate_footprint_bytes(&idx),
        sizes,
    };
    #[cfg(feature = "json")]
    {
        return serde_json::to_string(&summary).unwrap_or_else(|_| "<json-error>".into());
    }
    #[cfg(not(feature = "json"))]
    {
        format!(
            "gen={}; checksum={}; sizes={{exact:{},suffix:{},port:{},portrange:{},transport:{},cidr4:{},cidr6:{},geoip:{}}}; footprint_bytes={}",
            summary.generation, summary.checksum_hex,
            summary.sizes.exact, summary.sizes.suffix, summary.sizes.port, summary.sizes.portrange,
            summary.sizes.transport, summary.sizes.cidr4, summary.sizes.cidr6, summary.sizes.geoip,
            summary.footprint_bytes
        )
    }
}

/// R14: 对外导出获取当前索引并生成 cache 摘要（只读）
pub fn router_cache_summary() -> String {
    let s = shared_index();
    let guard = s.read().unwrap_or_else(|e| e.into_inner());
    guard.decision_cache_summary_json()
}

/// R38：对外暴露一次性规范化（便于外层复用/测试）
pub fn rules_normalize(text: &str) -> String {
    normalize::normalize(text)
}

// 预览导出（仅在 feature 打开时可用）
#[cfg(feature = "preview_route")]
pub use preview::{build_index_from_rules, preview_decide_http, preview_decide_udp};

/// R21: 获取被捕获的规则文本（若启用了 rules_capture）
#[cfg(feature = "rules_capture")]
pub fn router_captured_rules() -> Option<String> {
    rules_capture::get()
}

fn hex_checksum(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// 旧接口：HTTP 决策（同步、零 DNS）。支持 "host" 或 "host:port" 或字面量 IP。
pub fn decide_http(target: &str) -> RouteDecision {
    // 改为共享快照：零分配、零 rebuild
    let idx = {
        shared_index()
            .read()
            .unwrap_or_else(|e| {
                eprintln!("RwLock poisoned; proceeding with inner guard");
                e.into_inner()
            })
            .clone()
    };

    // 解析目标
    let (host_raw, port_opt) = if let Some((h, p)) = target.rsplit_once(':') {
        let po = p.parse::<u16>().ok();
        (h, po)
    } else {
        (target, None)
    };
    let host = normalize_host(host_raw);
    // 运行时覆盖（仅调试）
    if let Some((d, tag)) = runtime_override_http(&host, port_opt) {
        #[cfg(feature = "metrics")]
        metrics::counter!("router_decide_reason_total", "kind"=>tag).increment(1);
        return RouteDecision {
            target: d.to_string(),
            matched_rule: Some(tag.to_string()),
        };
    }

    if let Some(d) = router_index_decide_exact_suffix(&idx, &host) {
        #[cfg(feature = "metrics")]
        {
            let kind = if idx.exact.contains_key(&host) {
                "exact"
            } else {
                "suffix"
            };
            metrics::counter!("router_decide_reason_total", "kind"=>kind).increment(1);
        }
        return RouteDecision {
            target: d.to_string(),
            matched_rule: Some("matched".to_string()),
        };
    }
    // keyword（可选）：在 suffix 之后尝试
    #[cfg(feature = "router_keyword")]
    {
        if let Some(d) = router_index_decide_keyword(&idx, &host) {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decide_reason_total", "kind"=>"keyword").increment(1);
            return RouteDecision {
                target: d.to_string(),
                matched_rule: Some("matched".to_string()),
            };
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(d) = router_index_decide_ip(&idx, ip) {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decide_reason_total", "kind"=>"ip").increment(1);
            return RouteDecision {
                target: d.to_string(),
                matched_rule: Some("matched".to_string()),
            };
        }
    }
    // 传输/端口兜底（HTTP 场景：transport=tcp）
    #[cfg(feature = "metrics")]
    if let Some((d, kind)) =
        router_index_decide_transport_port_with_kind(&idx, port_opt, Some("tcp"))
    {
        {
            metrics::counter!("router_decide_reason_total", "kind"=>kind).increment(1);
        }
        return RouteDecision {
            target: d.to_string(),
            matched_rule: Some("matched".to_string()),
        };
    }
    #[cfg(not(feature = "metrics"))]
    if let Some((d, _)) =
        router_index_decide_transport_port_with_kind(&idx, port_opt, Some("tcp"))
    {
        return RouteDecision {
            target: d.to_string(),
            matched_rule: Some("matched".to_string()),
        };
    }
    #[cfg(feature = "metrics")]
    metrics::counter!("router_decide_reason_total", "kind"=>"default").increment(1);
    RouteDecision {
        target: idx.default.to_string(),
        matched_rule: Some("default".to_string()),
    }
}

/// 可选：基于关键词的命中（顺扫；first-wins）
#[cfg(feature = "router_keyword")]
#[inline]
pub fn router_index_decide_keyword(idx: &RouterIndex, host: &str) -> Option<&'static str> {
    if let Some(index) = &idx.keyword_idx {
        if let Some(i) = index.find_idx(host) {
            if let Some(dec) = index.decs.get(i) {
                // Use intern pool to avoid scattered leaks when converting to &'static
                return Some(crate::router::decision_intern::intern_decision(dec));
            }
        }
    }
    None
}

/// 旧 API 场景若需要 &'static，统一从驻留池取，避免泄漏
#[cfg(feature = "router_keyword")]
pub fn router_index_decide_keyword_static<'a>(
    idx: &'a RouterIndex,
    host_norm: &str,
) -> Option<&'static str> {
    if let Some(k) = &idx.keyword_idx {
        if let Some(i) = k.find_idx(host_norm) {
            let dec = k.decs.get(i).map(|s| s.as_str()).unwrap_or("default");
            return Some(crate::router::decision_intern::intern_decision(dec));
        }
    }
    None
}

// ===== Test helper functions =====
pub fn decide_udp_with_rules(host_or_ip: &str, _use_geoip: bool, rules: &str) -> &'static str {
    let idx = router_build_index_from_str(rules, 8192).unwrap_or_else(|_| {
        Arc::new(RouterIndex {
            exact: Default::default(),
            suffix: vec![],
            suffix_map: Default::default(),
            port_rules: Default::default(),
            port_ranges: vec![],
            transport_tcp: None,
            transport_udp: None,
            cidr4: vec![],
            cidr6: vec![],
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: vec![],
            geosite_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 0,
            checksum: [0; 32],
        })
    });

    // Check exact/suffix first
    if let Some(d) = router_index_decide_exact_suffix(&idx, host_or_ip) {
        return d;
    }

    // Check IP rules
    if let Ok(ip) = host_or_ip.parse::<IpAddr>() {
        if let Some(d) = router_index_decide_ip(&idx, ip) {
            return d;
        }
        // GeoIP check if enabled
        if _use_geoip {
            if let Some(lookup_cc) = crate::geoip::lookup_with_metrics_decision(ip) {
                for (cc, decision) in &idx.geoip_rules {
                    if cc == lookup_cc {
                        return decision;
                    }
                }
            }
        }
    }

    idx.default
}

/// UDP 决策：基于 UdpTargetAddr 进行路由
pub fn decide_udp(target: &crate::net::datagram::UdpTargetAddr) -> &'static str {
    let host_str = match target {
        crate::net::datagram::UdpTargetAddr::Ip(addr) => addr.ip().to_string(),
        crate::net::datagram::UdpTargetAddr::Domain { host, .. } => host.clone(),
    };

    // 复用现有的 decide_http 逻辑（都基于共享索引）
    let decision = decide_http(&host_str);
    // Use intern to convert to &'static str
    crate::router::decision_intern::intern_decision(&decision.target)
}

pub fn decide_udp_with_rules_and_ips_v46(
    host: &str,
    rules: &str,
    _ipv4s: &[std::net::Ipv4Addr],
    ipv6s: &[std::net::Ipv6Addr],
) -> &'static str {
    let idx = router_build_index_from_str(rules, 8192).unwrap_or_else(|_| {
        Arc::new(RouterIndex {
            exact: Default::default(),
            suffix: vec![],
            suffix_map: Default::default(),
            port_rules: Default::default(),
            port_ranges: vec![],
            transport_tcp: None,
            transport_udp: None,
            cidr4: vec![],
            cidr6: vec![],
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: vec![],
            geosite_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 0,
            checksum: [0; 32],
        })
    });

    // Check exact/suffix first (host-based)
    if let Some(d) = router_index_decide_exact_suffix(&idx, host) {
        return d;
    }

    // Check IPv6 addresses
    for &ip in ipv6s {
        let ipaddr = IpAddr::V6(ip);
        if let Some(d) = router_index_decide_ip(&idx, ipaddr) {
            return d;
        }
    }

    // Check IPv4 addresses
    for &ip in _ipv4s {
        let ipaddr = IpAddr::V4(ip);
        if let Some(d) = router_index_decide_ip(&idx, ipaddr) {
            return d;
        }
    }

    idx.default
}

pub fn decide_udp_with_rules_and_ips(
    host: &str,
    rules: &str,
    ipv4s: &[std::net::Ipv4Addr],
) -> &'static str {
    let idx = router_build_index_from_str(rules, 8192).unwrap_or_else(|_| {
        Arc::new(RouterIndex {
            exact: Default::default(),
            suffix: vec![],
            suffix_map: Default::default(),
            port_rules: Default::default(),
            port_ranges: vec![],
            transport_tcp: None,
            transport_udp: None,
            cidr4: vec![],
            cidr6: vec![],
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: vec![],
            geosite_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_rules: vec![],
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 0,
            checksum: [0; 32],
        })
    });

    // Check exact/suffix first (host-based)
    if let Some(d) = router_index_decide_exact_suffix(&idx, host) {
        return d;
    }

    // Check IPv4 addresses
    for &ip in ipv4s {
        let ipaddr = IpAddr::V4(ip);
        if let Some(d) = router_index_decide_ip(&idx, ipaddr) {
            return d;
        }
    }

    idx.default
}

#[cfg(feature = "router_cache_wire")]
pub use cache_hot::{register_hot_provider, HotItem};
#[cfg(feature = "router_cache_wire")]
pub use cache_stats::{register_provider, CacheStats};
#[cfg(feature = "router_cache_wire")]
pub use cache_wire::{register_router_decision_cache_adapter, register_router_hot_adapter};
