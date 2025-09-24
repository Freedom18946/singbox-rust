use ipnet::IpNet;
use once_cell::sync::OnceCell;
use std::fs;
use std::sync::Arc;
use std::{net::IpAddr, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Direct,
    Proxy(Option<String>), // Support named proxy pools with "proxy:name" syntax
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Exact(String),       // exact:example.com
    Suffix(String),      // suffix:.example.com
    Keyword(String),     // keyword:tracker
    IpCidr(IpNet),       // ip_cidr:10.0.0.0/8
    TransportTcp,        // transport:tcp
    TransportUdp,        // transport:udp
    Port(u16),           // port:443
    PortRange(u16, u16), // portrange:1000-2000
    PortSet(Vec<u16>),   // portset:80,443,8443
    ProcessName(String), // process_name:firefox
    ProcessPath(String), // process_path:/usr/bin/firefox
    Default,             // default
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub decision: Decision,
}

#[derive(Debug, Clone)]
pub struct RouteCtx<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub transport_udp: bool,
    pub port: Option<u16>,
    pub process_name: Option<&'a str>,
    pub process_path: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct Engine {
    // 分桶存储，便于按优先级短路
    exact: Vec<Rule>,
    suffix: Vec<Rule>,
    keyword: Vec<Rule>,
    ipcidr: Vec<Rule>,
    transport: Vec<Rule>, // TransportTcp/TransportUdp
    port_like: Vec<Rule>, // Port/PortRange/PortSet
    process: Vec<Rule>,   // ProcessName/ProcessPath
    default: Option<Rule>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(rules: Vec<Rule>) -> Self {
        let mut e = Engine::new();
        for r in rules {
            match r.kind {
                RuleKind::Exact(_) => e.exact.push(r),
                RuleKind::Suffix(_) => e.suffix.push(r),
                RuleKind::Keyword(_) => e.keyword.push(r),
                RuleKind::IpCidr(_) => e.ipcidr.push(r),
                RuleKind::TransportTcp | RuleKind::TransportUdp => e.transport.push(r),
                RuleKind::Port(_) | RuleKind::PortRange(_, _) | RuleKind::PortSet(_) => {
                    e.port_like.push(r)
                }
                RuleKind::ProcessName(_) | RuleKind::ProcessPath(_) => e.process.push(r),
                RuleKind::Default => e.default = Some(r),
            }
        }
        e
    }

    #[inline]
    fn hit(rule: &Rule, ctx: &RouteCtx) -> bool {
        match &rule.kind {
            RuleKind::Exact(d) => {
                if let Some(s) = ctx.domain {
                    s.eq_ignore_ascii_case(d)
                } else {
                    false
                }
            }
            RuleKind::Suffix(sfx) => {
                if let Some(s) = ctx.domain {
                    let s = s.to_ascii_lowercase();
                    let sfx = sfx.to_ascii_lowercase();
                    s.ends_with(&sfx)
                } else {
                    false
                }
            }
            RuleKind::Keyword(k) => {
                if let Some(s) = ctx.domain {
                    s.to_ascii_lowercase().contains(&k.to_ascii_lowercase())
                } else {
                    false
                }
            }
            RuleKind::IpCidr(n) => {
                if let Some(ip) = ctx.ip {
                    n.contains(&ip)
                } else {
                    false
                }
            }
            RuleKind::TransportTcp => !ctx.transport_udp,
            RuleKind::TransportUdp => ctx.transport_udp,
            RuleKind::Port(p) => ctx.port.map(|x| x == *p).unwrap_or(false),
            RuleKind::PortRange(a, b) => ctx.port.map(|x| x >= *a && x <= *b).unwrap_or(false),
            RuleKind::PortSet(v) => {
                if let Some(p) = ctx.port {
                    v.contains(&p)
                } else {
                    false
                }
            }
            RuleKind::ProcessName(name) => {
                if let Some(process_name) = ctx.process_name {
                    process_name.eq_ignore_ascii_case(name)
                } else {
                    false
                }
            }
            RuleKind::ProcessPath(path) => {
                if let Some(process_path) = ctx.process_path {
                    process_path.eq_ignore_ascii_case(path)
                        || process_path.ends_with(path)
                        || process_path.contains(path)
                } else {
                    false
                }
            }
            RuleKind::Default => true,
        }
    }

    /// 决策：固定优先级 + 短路
    /// 1.exact 2.suffix 3.keyword 4.ip_cidr 5.transport 6.port/portrange/portset 7.process 8.default
    pub fn decide(&self, ctx: &RouteCtx) -> Decision {
        #[cfg(feature = "metrics")]
        use metrics::counter;
        let record = |krule: &'static str, d: &Decision| -> Decision {
            let _ = krule; // keep label for metrics-disabled builds
            #[cfg(feature = "metrics")]
            {
                counter!("router_match_total", "rule"=>krule, "decision"=>decision_label(d))
                    .increment(1);
                counter!("router_decide_total", "decision"=>decision_label(d)).increment(1);
            }
            d.clone()
        };
        for r in &self.exact {
            if Self::hit(r, ctx) {
                return record("exact", &r.decision);
            }
        }
        for r in &self.suffix {
            if Self::hit(r, ctx) {
                return record("suffix", &r.decision);
            }
        }
        for r in &self.keyword {
            if Self::hit(r, ctx) {
                return record("keyword", &r.decision);
            }
        }
        for r in &self.ipcidr {
            if Self::hit(r, ctx) {
                return record("ip_cidr", &r.decision);
            }
        }
        for r in &self.transport {
            if Self::hit(r, ctx) {
                return record("transport", &r.decision);
            }
        }
        for r in &self.port_like {
            if Self::hit(r, ctx) {
                return record("port", &r.decision);
            }
        }
        for r in &self.process {
            if Self::hit(r, ctx) {
                return record("process", &r.decision);
            }
        }
        if let Some(r) = &self.default {
            return record("default", &r.decision);
        }
        // 默认兜底：direct（不增加指标以免误导）
        Decision::Direct
    }
}

#[inline]
fn decision_label(d: &Decision) -> &'static str {
    match d {
        Decision::Direct => "direct",
        Decision::Proxy(_) => "proxy",
        Decision::Reject => "reject",
    }
}

// -------- 解析器（从简单 rule 行构建规则列表） ----------
pub fn parse_rules(lines: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for raw in lines.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (lhs, rhs) = match line.split_once('=') {
            Some((l, r)) => (l.trim(), r.trim()),
            None => continue,
        };
        let decision = if rhs.to_ascii_lowercase() == "direct" {
            Decision::Direct
        } else if rhs.to_ascii_lowercase() == "proxy" {
            Decision::Proxy(None)
        } else if rhs.to_ascii_lowercase() == "reject" {
            Decision::Reject
        } else if let Some(pool_name) = rhs.strip_prefix("proxy:") {
            Decision::Proxy(Some(pool_name.trim().to_string()))
        } else {
            continue;
        };
        // 支持逗号复合（仅 transport/port 组合场景。其余按单条 rule 解析）
        let mut kinds = Vec::<RuleKind>::new();
        for tok in lhs.split(',').map(|s| s.trim()) {
            if tok.is_empty() {
                continue;
            }
            if let Some(v) = tok.strip_prefix("exact:") {
                kinds.push(RuleKind::Exact(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("domain:") {
                kinds.push(RuleKind::Exact(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("suffix:") {
                kinds.push(RuleKind::Suffix(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("keyword:") {
                kinds.push(RuleKind::Keyword(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("ip_cidr:") {
                if let Ok(n) = IpNet::from_str(v) {
                    kinds.push(RuleKind::IpCidr(n));
                }
            } else if let Some(v) = tok.strip_prefix("transport:") {
                let v = v.to_ascii_lowercase();
                if v == "udp" {
                    kinds.push(RuleKind::TransportUdp);
                } else if v == "tcp" {
                    kinds.push(RuleKind::TransportTcp);
                }
            } else if let Some(v) = tok.strip_prefix("port:") {
                if let Ok(p) = v.parse::<u16>() {
                    kinds.push(RuleKind::Port(p));
                }
            } else if let Some(v) = tok.strip_prefix("portrange:") {
                if let Some((a, b)) = v.split_once('-') {
                    if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                        kinds.push(RuleKind::PortRange(a, b));
                    }
                }
            } else if let Some(v) = tok.strip_prefix("portset:") {
                let mut set = Vec::<u16>::new();
                for p in v.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                    if let Ok(u) = p.parse::<u16>() {
                        if !set.contains(&u) {
                            set.push(u);
                        }
                    }
                }
                kinds.push(RuleKind::PortSet(set));
            } else if let Some(v) = tok.strip_prefix("process_name:") {
                kinds.push(RuleKind::ProcessName(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("process_path:") {
                kinds.push(RuleKind::ProcessPath(v.to_string()));
            } else if tok == "default" {
                kinds.push(RuleKind::Default);
            }
        }
        // 组合：仅当存在单一 kind 时，直接生成；对于组合（transport+port），拆分为多条具名规则
        if kinds.is_empty() {
            continue;
        }
        if kinds.len() == 1 {
            out.push(Rule {
                kind: kinds.pop().unwrap(),
                decision,
            });
        } else {
            for k in kinds {
                out.push(Rule {
                    kind: k,
                    decision: decision.clone(),
                });
            }
        }
    }
    out
}

// --------- 辅助：便捷构建 & 示例 ----------
impl Decision {
    pub fn from_str(s: &str) -> Option<Self> {
        if s.to_ascii_lowercase() == "direct" {
            Some(Decision::Direct)
        } else if s.to_ascii_lowercase() == "proxy" {
            Some(Decision::Proxy(None))
        } else if s.to_ascii_lowercase() == "reject" {
            Some(Decision::Reject)
        } else if let Some(pool_name) = s.strip_prefix("proxy:") {
            Some(Decision::Proxy(Some(pool_name.trim().to_string())))
        } else {
            None
        }
    }
}

// ================== 全局安装（运行态接线：非侵入式） ==================
static GLOBAL_RULES: OnceCell<Arc<Engine>> = OnceCell::new();
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 在进程内安装一次规则引擎（若多次调用，仅首次生效）
pub fn install_global(engine: Engine) {
    let _ = GLOBAL_RULES.set(Arc::new(engine));
    ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// 获取全局引擎（未启用或未安装则 None）
pub fn global() -> Option<&'static Engine> {
    if !ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    GLOBAL_RULES.get().map(|x| x.as_ref())
}

/// 从 ENV 初始化（可选）：
/// - SB_ROUTER_RULES_ENABLE=1 开关
/// - SB_ROUTER_RULES_FILE=/path/to/rules  或  SB_ROUTER_RULES_TEXT=内联文本
pub fn init_from_env() {
    let enable = std::env::var("SB_ROUTER_RULES_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enable {
        return;
    }
    let txt = if let Ok(p) = std::env::var("SB_ROUTER_RULES_FILE") {
        match fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path=%p, error=%e, "router: read rules file failed");
                return;
            }
        }
    } else if let Ok(t) = std::env::var("SB_ROUTER_RULES_TEXT") {
        t
    } else {
        tracing::warn!("router: enabled but no rules provided (set SB_ROUTER_RULES_FILE or SB_ROUTER_RULES_TEXT)");
        return;
    };
    let rules = parse_rules(&txt);
    let n = rules.len();
    let eng = Engine::build(rules);
    install_global(eng);
    tracing::info!(enabled=%enable, rules=n, "router: global rules engine installed");
}
