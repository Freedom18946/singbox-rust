use ipnet::IpNet;
use once_cell::sync::OnceCell;
use regex::Regex;
use std::fs;
use std::sync::Arc;
use std::{net::IpAddr, str::FromStr};

// Re-export RecordType from DNS module for routing use
pub use crate::dns::RecordType as DnsRecordType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Direct,
    Proxy(Option<String>), // Support named proxy pools with "proxy:name" syntax
    Reject,
}

/// Wrapper for Regex that implements PartialEq/Eq based on the pattern string
#[derive(Debug, Clone)]
pub struct DomainRegexMatcher {
    pattern: String,
    regex: Regex,
}

impl DomainRegexMatcher {
    pub fn new(pattern: String) -> Result<Self, regex::Error> {
        let regex = Regex::new(&pattern)?;
        Ok(Self { pattern, regex })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl PartialEq for DomainRegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for DomainRegexMatcher {}

/// Regex matcher for process paths with structural equality on the pattern
#[derive(Debug, Clone)]
pub struct ProcessPathRegexMatcher {
    pattern: String,
    regex: Regex,
}

impl ProcessPathRegexMatcher {
    pub fn new(pattern: String) -> Result<Self, regex::Error> {
        let regex = Regex::new(&pattern)?;
        Ok(Self { pattern, regex })
    }

    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl PartialEq for ProcessPathRegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for ProcessPathRegexMatcher {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Exact(String),                             // exact:example.com
    Suffix(String),                            // suffix:.example.com
    Keyword(String),                           // keyword:tracker
    DomainRegex(DomainRegexMatcher),           // regex:^.*\.google\.com$
    IpCidr(IpNet),                             // ip_cidr:10.0.0.0/8
    TransportTcp,                              // transport:tcp
    TransportUdp,                              // transport:udp
    Port(u16),                                 // port:443
    PortRange(u16, u16),                       // portrange:1000-2000
    PortSet(Vec<u16>),                         // portset:80,443,8443
    ProcessName(String),                       // process_name:firefox
    ProcessPath(String),                       // process_path:/usr/bin/firefox
    ProcessPathRegex(ProcessPathRegexMatcher), // process_path_regex:^/usr/bin/.+$
    InboundTag(String),                        // inbound:http=proxy
    OutboundTag(String),                       // outbound:direct=block
    AuthUser(String),                          // auth_user:username=proxy
    QueryType(DnsRecordType),                  // query_type:A, query_type:AAAA
    IpVersionV4,                               // ipversion:ipv4
    IpVersionV6,                               // ipversion:ipv6
    IpIsPrivate,                               // ip_is_private
    Default,                                   // default
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
    pub inbound_tag: Option<&'a str>,
    pub outbound_tag: Option<&'a str>,
    pub auth_user: Option<&'a str>,
    pub query_type: Option<DnsRecordType>,
}

#[derive(Debug, Default)]
pub struct Engine {
    // 分桶存储，便于按优先级短路
    exact: Vec<Rule>,
    suffix: Vec<Rule>,
    keyword: Vec<Rule>,
    domain_regex: Vec<Rule>, // DomainRegex rules
    ipcidr: Vec<Rule>,
    transport: Vec<Rule>,   // TransportTcp/TransportUdp
    port_like: Vec<Rule>,   // Port/PortRange/PortSet
    process: Vec<Rule>,     // ProcessName/ProcessPath
    inbound: Vec<Rule>,     // InboundTag
    outbound: Vec<Rule>,    // OutboundTag
    auth_user: Vec<Rule>,   // AuthUser
    query_type: Vec<Rule>,  // QueryType (DNS record type)
    ipversion: Vec<Rule>,   // IpVersionV4/IpVersionV6
    ipisprivate: Vec<Rule>, // IpIsPrivate
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
                RuleKind::DomainRegex(_) => e.domain_regex.push(r),
                RuleKind::IpCidr(_) => e.ipcidr.push(r),
                RuleKind::TransportTcp | RuleKind::TransportUdp => e.transport.push(r),
                RuleKind::Port(_) | RuleKind::PortRange(_, _) | RuleKind::PortSet(_) => {
                    e.port_like.push(r)
                }
                RuleKind::ProcessName(_)
                | RuleKind::ProcessPath(_)
                | RuleKind::ProcessPathRegex(_) => e.process.push(r),
                RuleKind::InboundTag(_) => e.inbound.push(r),
                RuleKind::OutboundTag(_) => e.outbound.push(r),
                RuleKind::AuthUser(_) => e.auth_user.push(r),
                RuleKind::QueryType(_) => e.query_type.push(r),
                RuleKind::IpVersionV4 | RuleKind::IpVersionV6 => e.ipversion.push(r),
                RuleKind::IpIsPrivate => e.ipisprivate.push(r),
                RuleKind::Default => e.default = Some(r),
            }
        }
        e
    }

    /// Check if an IP address is private (RFC 1918, RFC 4193, loopback, link-local)
    #[inline]
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // RFC 1918 private ranges
                octets[0] == 10 // 10.0.0.0/8
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) // 172.16.0.0/12
                    || (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
                    // Loopback
                    || octets[0] == 127 // 127.0.0.0/8
                    // Link-local
                    || (octets[0] == 169 && octets[1] == 254) // 169.254.0.0/16
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // ULA (Unique Local Address): fc00::/7
                (segments[0] & 0xfe00) == 0xfc00
                    // Link-local: fe80::/10
                    || (segments[0] & 0xffc0) == 0xfe80
                    // Loopback: ::1
                    || ipv6.is_loopback()
            }
        }
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
            RuleKind::DomainRegex(matcher) => {
                if let Some(s) = ctx.domain {
                    matcher.is_match(s)
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
            RuleKind::ProcessPathRegex(matcher) => {
                if let Some(process_path) = ctx.process_path {
                    matcher.is_match(process_path)
                } else {
                    false
                }
            }
            RuleKind::InboundTag(tag) => {
                if let Some(inbound_tag) = ctx.inbound_tag {
                    inbound_tag.eq_ignore_ascii_case(tag)
                } else {
                    false
                }
            }
            RuleKind::OutboundTag(tag) => {
                if let Some(outbound_tag) = ctx.outbound_tag {
                    outbound_tag.eq_ignore_ascii_case(tag)
                } else {
                    false
                }
            }
            RuleKind::AuthUser(user) => {
                if let Some(auth_user) = ctx.auth_user {
                    auth_user.eq_ignore_ascii_case(user)
                } else {
                    false
                }
            }
            RuleKind::QueryType(qtype) => {
                if let Some(query_type) = ctx.query_type {
                    query_type == *qtype
                } else {
                    false
                }
            }
            RuleKind::IpVersionV4 => {
                if let Some(ip) = ctx.ip {
                    ip.is_ipv4()
                } else {
                    false
                }
            }
            RuleKind::IpVersionV6 => {
                if let Some(ip) = ctx.ip {
                    ip.is_ipv6()
                } else {
                    false
                }
            }
            RuleKind::IpIsPrivate => {
                if let Some(ip) = ctx.ip {
                    Self::is_private_ip(&ip)
                } else {
                    false
                }
            }
            RuleKind::Default => true,
        }
    }

    /// 决策：固定优先级 + 短路
    /// 1.exact 2.suffix 3.keyword 4.domain_regex 5.inbound 6.outbound 7.ip_cidr 8.transport 9.port/portrange/portset 10.process 11.auth_user 12.query_type 13.ipversion 14.ipisprivate 15.default
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
        for r in &self.domain_regex {
            if Self::hit(r, ctx) {
                return record("domain_regex", &r.decision);
            }
        }
        for r in &self.inbound {
            if Self::hit(r, ctx) {
                return record("inbound", &r.decision);
            }
        }
        for r in &self.outbound {
            if Self::hit(r, ctx) {
                return record("outbound", &r.decision);
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
        for r in &self.auth_user {
            if Self::hit(r, ctx) {
                return record("auth_user", &r.decision);
            }
        }
        for r in &self.query_type {
            if Self::hit(r, ctx) {
                return record("query_type", &r.decision);
            }
        }
        for r in &self.ipversion {
            if Self::hit(r, ctx) {
                return record("ipversion", &r.decision);
            }
        }
        for r in &self.ipisprivate {
            if Self::hit(r, ctx) {
                return record("ipisprivate", &r.decision);
            }
        }
        if let Some(r) = &self.default {
            return record("default", &r.decision);
        }
        // 默认兜底：direct（不增加指标以免误导）
        Decision::Direct
    }
}

#[allow(dead_code)] // Utility function for decision labeling, may be used in debugging/logging
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
        let decision = if rhs.eq_ignore_ascii_case("direct") {
            Decision::Direct
        } else if rhs.eq_ignore_ascii_case("proxy") {
            Decision::Proxy(None)
        } else if rhs.eq_ignore_ascii_case("reject") {
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
            } else if let Some(v) = tok.strip_prefix("regex:") {
                match DomainRegexMatcher::new(v.to_string()) {
                    Ok(matcher) => kinds.push(RuleKind::DomainRegex(matcher)),
                    Err(e) => {
                        tracing::warn!(pattern=%v, error=%e, "router: invalid regex pattern, skipping");
                        continue;
                    }
                }
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
            } else if let Some(v) = tok.strip_prefix("process_path_regex:") {
                match ProcessPathRegexMatcher::new(v.to_string()) {
                    Ok(matcher) => kinds.push(RuleKind::ProcessPathRegex(matcher)),
                    Err(e) => {
                        tracing::warn!(pattern=%v, error=%e, "router: invalid process_path_regex pattern, skipping");
                        continue;
                    }
                }
            } else if let Some(v) = tok.strip_prefix("inbound:") {
                kinds.push(RuleKind::InboundTag(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("outbound:") {
                kinds.push(RuleKind::OutboundTag(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("auth_user:") {
                kinds.push(RuleKind::AuthUser(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("query_type:") {
                // Parse DNS query type: A, AAAA, CNAME, MX, TXT
                let qtype = match v.trim().to_ascii_uppercase().as_str() {
                    "A" => Some(DnsRecordType::A),
                    "AAAA" => Some(DnsRecordType::AAAA),
                    "CNAME" => Some(DnsRecordType::CNAME),
                    "MX" => Some(DnsRecordType::MX),
                    "TXT" => Some(DnsRecordType::TXT),
                    _ => {
                        tracing::warn!(query_type=%v, "router: unknown DNS query type, skipping");
                        None
                    }
                };
                if let Some(qt) = qtype {
                    kinds.push(RuleKind::QueryType(qt));
                }
            } else if let Some(v) = tok.strip_prefix("ipversion:") {
                // Parse IP version: ipv4 or ipv6
                let v = v.trim().to_ascii_lowercase();
                if v == "ipv4" || v == "4" {
                    kinds.push(RuleKind::IpVersionV4);
                } else if v == "ipv6" || v == "6" {
                    kinds.push(RuleKind::IpVersionV6);
                } else {
                    tracing::warn!(ipversion=%v, "router: unknown IP version (expected ipv4/ipv6), skipping");
                }
            } else if tok == "ip_is_private" {
                kinds.push(RuleKind::IpIsPrivate);
            } else if tok == "default" {
                kinds.push(RuleKind::Default);
            }
        }
        // 组合：仅当存在单一 kind 时，直接生成；对于组合（transport+port），拆分为多条具名规则
        if kinds.is_empty() {
            continue;
        }
        if kinds.len() == 1 {
            if let Some(k) = kinds.pop() {
                out.push(Rule { kind: k, decision });
            } else {
                continue;
            }
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
    pub fn parse_decision(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("direct") {
            Some(Decision::Direct)
        } else if s.eq_ignore_ascii_case("proxy") {
            Some(Decision::Proxy(None))
        } else if s.eq_ignore_ascii_case("reject") {
            Some(Decision::Reject)
        } else {
            s.strip_prefix("proxy:")
                .map(|pool_name| Decision::Proxy(Some(pool_name.trim().to_string())))
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
// - SB_ROUTER_RULES_ENABLE=1 开关
// - SB_ROUTER_RULES_FILE=/path/to/rules  或  SB_ROUTER_RULES_TEXT=内联文本
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
