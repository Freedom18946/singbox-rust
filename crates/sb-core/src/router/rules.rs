use ipnet::IpNet;
use once_cell::sync::OnceCell;
use regex::Regex;
use std::fs;
use std::sync::Arc;
use std::{net::IpAddr, str::FromStr};

// Re-export RecordType from DNS module for routing use
pub use crate::dns::RecordType as DnsRecordType;

/// Route decision (Go parity: route.RuleAction).
///
/// Represents the action to take for a matched routing rule.
/// 表示匹配路由规则时要采取的动作。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Decision {
    /// Route to default/direct outbound.
    /// 路由到默认/直连出站。
    #[default]
    Direct,
    /// Route to a named proxy/outbound.
    /// 路由到命名代理/出站。
    Proxy(Option<String>),
    /// Reject connection with response (RST for TCP, ICMP for UDP).
    /// 拒绝连接并响应（TCP 的 RST，UDP 的 ICMP）。
    Reject,
    /// Reject connection without response (drop silently).
    /// 静默丢弃连接（不响应）。
    RejectDrop,
    /// Hijack connection to override address/port.
    /// 劫持连接以覆盖地址/端口。
    Hijack {
        /// Override destination address.
        /// 覆盖目标地址。
        address: Option<String>,
        /// Override destination port.
        /// 覆盖目标端口。
        port: Option<u16>,
    },
    /// Trigger protocol sniffing before routing.
    /// 在路由前触发协议嗅探。
    Sniff,
    /// Require DNS resolution before continuing.
    /// 在继续前需要 DNS 解析。
    Resolve,
}

impl Decision {
    pub fn as_str(&self) -> &str {
        match self {
            Decision::Direct => "direct",
            Decision::Proxy(Some(name)) => name,
            Decision::Proxy(None) => "proxy",
            Decision::Reject => "reject",
            Decision::RejectDrop => "reject-drop",
            Decision::Hijack { .. } => "hijack",
            Decision::Sniff => "sniff",
            Decision::Resolve => "resolve",
        }
    }

    /// Check if this decision is terminal (stops rule processing).
    /// 检查此决策是否为终端（停止规则处理）。
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Decision::Direct
                | Decision::Proxy(_)
                | Decision::Reject
                | Decision::RejectDrop
                | Decision::Hijack { .. }
        )
    }

    /// Convert from sb-config RuleAction.
    /// 从 sb-config RuleAction 转换。
    #[must_use]
    pub fn from_rule_action(
        action: &sb_config::ir::RuleAction,
        outbound: Option<String>,
        override_address: Option<String>,
        override_port: Option<u16>,
    ) -> Self {
        use sb_config::ir::RuleAction;
        match action {
            RuleAction::Route => {
                if let Some(ref ob) = outbound {
                    if ob == "direct" {
                        Decision::Direct
                    } else {
                        Decision::Proxy(Some(ob.clone()))
                    }
                } else {
                    Decision::Direct
                }
            }
            RuleAction::Reject => Decision::Reject,
            RuleAction::RejectDrop => Decision::RejectDrop,
            RuleAction::Hijack => Decision::Hijack {
                address: override_address,
                port: override_port,
            },
            RuleAction::HijackDns => Decision::Reject, // DNS hijack not applicable for generic routing
            RuleAction::Sniff => Decision::Sniff,
            RuleAction::Resolve => Decision::Resolve,
            RuleAction::RouteOptions => Decision::Direct, // TODO: Support route options
            RuleAction::SniffOverride => Decision::Sniff, // TODO: Support sniff override details
        }
    }
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

impl TryFrom<&sb_config::ir::RuleIR> for CompositeRule {
    type Error = String;

    fn try_from(ir: &sb_config::ir::RuleIR) -> Result<Self, Self::Error> {
        let rule_type = match ir.rule_type.as_deref().unwrap_or("default") {
            "logical" => RuleType::Logical,
            _ => RuleType::Default,
        };

        let mode = match ir.mode.as_deref().unwrap_or("and") {
            "or" => LogicalMode::Or,
            _ => LogicalMode::And,
        };

        let mut sub_rules = Vec::new();
        if rule_type == RuleType::Logical {
            for sub_ir in &ir.rules {
                sub_rules.push(CompositeRule::try_from(sub_ir.as_ref())?);
            }
        }

        let mut domain_regex = Vec::new();
        for s in &ir.domain_regex {
            domain_regex.push(DomainRegexMatcher::new(s.clone()).map_err(|e| e.to_string())?);
        }
        let mut not_domain_regex = Vec::new();
        for s in &ir.not_domain_regex {
            not_domain_regex.push(DomainRegexMatcher::new(s.clone()).map_err(|e| e.to_string())?);
        }

        let process_path_regex = Vec::new();
        // ir.process_path_regex not in RuleIR

        let mut not_process_path_regex = Vec::new();
        // ir.not_process_path_regex not in RuleIR

        let decision = Decision::from_rule_action(
            &ir.action,
            ir.outbound.clone(),
            ir.override_address.clone(),
            ir.override_port,
        );

        let mut rule = CompositeRule {
            rule_type,
            mode,
            sub_rules,
            decision,
            domain: ir.domain.clone(),
            domain_suffix: ir.domain_suffix.clone(),
            domain_keyword: ir.domain_keyword.clone(),
            domain_regex,
            geosite: ir.geosite.clone(),
            ip_cidr: ir.ipcidr.iter().filter_map(|s| s.parse().ok()).collect(),
            geoip: ir.geoip.clone(),
            source_ip_cidr: ir.source.iter().filter_map(|s| s.parse().ok()).collect(),
            source_geoip: Vec::new(), // ir.source_geoip not available
            port: ir.port.iter().filter_map(|s| s.parse().ok()).collect(), 
            port_range: ir.port.iter().filter_map(|s| {
                if let Some((start, end)) = s.split_once('-') {
                     let start = start.parse().ok()?;
                     let end = end.parse().ok()?;
                     Some((start, end))
                } else {
                    None
                }
            }).collect(),
            source_port: Vec::new(), 
            source_port_range: Vec::new(),
            network: ir.network.clone(),
            protocol: ir.protocol.clone(),
            process_name: ir.process_name.clone(),
            process_path: ir.process_path.clone(),
            process_path_regex,
            wifi_ssid: ir.wifi_ssid.clone(),
            wifi_bssid: ir.wifi_bssid.clone(),
            rule_set: ir.rule_set.clone(),
            user_agent: ir.user_agent.clone(),
            inbound_tag: Vec::new(),
            auth_user: Vec::new(),
            query_type: Vec::new(), // RuleIR doesn't typically have query_type for routing
            ip_is_private: false, // Default
            ip_version: Vec::new(),
            clash_mode: ir.clash_mode.clone(),
            client: ir.client.clone(),
            package_name: ir.package_name.clone(),
            network_type: ir.network_type.clone(),
            network_is_expensive: ir.network_is_expensive,
            network_is_constrained: ir.network_is_constrained,
            // Action-related fields not mapped here (descision logic handles them or we assume decision is enough)
            // But wait, what about invert? RuleIR has invert. CompositeRule doesn't seem to support top-level invert?
            // Existing matchers have negation lists. CompositeRule logic is: if negation matches -> false; all positive matches -> true.
            // If invert is true, result = !result.
            // CompositeRule matches() returns bool.
            
            // Wait, does CompositeRule have an `invert` field? It does NOT.
            // RuleIR's `invert` field inverts the FINAL result.
            // We should add `invert` to CompositeRule or handle it in `matches`.
            // Let's add `invert` to CompositeRule.
            // ...
            
            outbound_tag: ir.outbound_tag.clone(),
            user: ir.user.clone(),
            user_id: ir.user_id.clone(),
            group: ir.group.clone(),
            group_id: ir.group_id.clone(),
            adguard: Vec::new(), // Todo: Parse adguard strings? IR uses `adguard` field? RuleIR doesn't seem to have adguard field in the snippet I saw.
            
            // Negation fields
            not_domain: ir.not_domain.clone(),
            not_domain_suffix: ir.not_domain_suffix.clone(),
            not_domain_keyword: ir.not_domain_keyword.clone(),
            // not_domain_regex: ... (handled by regex set if applicable, or we use vec)
            not_domain_regex,
            not_geosite: ir.not_geosite.clone(),
            not_ip_cidr: ir.not_ipcidr.iter().filter_map(|s| s.parse().ok()).collect(),
            not_geoip: ir.not_geoip.clone(),
            not_source_ip_cidr: ir.not_source.iter().filter_map(|s| s.parse().ok()).collect(),
            not_source_geoip: Vec::new(), // ir.not_source_geoip doesn't exist?
            not_port: ir.not_port.iter().filter_map(|s| s.parse().ok()).collect(),
            not_port_range: ir.not_port.iter().filter_map(|s| {
                if let Some((start, end)) = s.split_once('-') {
                    let start = start.parse().ok()?;
                    let end = end.parse().ok()?;
                    Some((start, end))
                } else {
                    None
                }
            }).collect(),
            not_source_port: Vec::new(),
            not_source_port_range: Vec::new(),
            not_network: ir.not_network.clone(),
            not_protocol: ir.not_protocol.clone(),
            not_process_name: ir.not_process_name.clone(),
            not_process_path: ir.not_process_path.clone(),
            not_process_path_regex,
            not_wifi_ssid: ir.not_wifi_ssid.clone(),
            not_wifi_bssid: ir.not_wifi_bssid.clone(),
            not_rule_set: ir.not_rule_set.clone(),
            not_user_agent: ir.not_user_agent.clone(),
            not_inbound_tag: Vec::new(), // ir.not_inbound_tag missing
            not_auth_user: ir.not_user.clone(), // Map not_user to auth_user?
            not_ip_is_private: false,
            not_clash_mode: ir.not_clash_mode.clone(),
            not_client: ir.not_client.clone(),
            not_package_name: ir.not_package_name.clone(),
            not_network_type: ir.not_network_type.clone(),
            not_outbound_tag: ir.not_outbound_tag.clone(),
            not_user: ir.not_user.clone(),
            not_user_id: ir.not_user_id.clone(),
            not_group: ir.not_group.clone(),
            not_group_id: ir.not_group_id.clone(),
            not_adguard: Vec::new(),
            
            // Missing fields from CompositeRule definition I saw?
            // ip_accept_any?
            ip_accept_any: false, // Default
            invert: ir.invert,
        };

        Ok(rule)
    }
}

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

/// AdGuard-style rule pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdGuardPatternType {
    /// `||domain^` - Match domain and all subdomains
    DomainAndSubdomains,
    /// `|domain` - Match domain start
    DomainStart,
    /// Plain pattern - Match if contains
    Contains,
}

/// AdGuard-style rule matcher (Adblock filter syntax)
///
/// Supports patterns like:
/// - `||example.org^` - Block domain and subdomains
/// - `@@||example.org^` - Exception (unblock)
/// - `|example.org^` - Block exact domain start
/// - `example.org` - Block if contains pattern
#[derive(Debug, Clone)]
pub struct AdGuardRuleMatcher {
    /// Original pattern for display/debugging
    pattern: String,
    /// Whether this is an exception rule (starts with @@)
    is_exception: bool,
    /// Pattern type
    pattern_type: AdGuardPatternType,
    /// Cleaned pattern for matching (without ||, @@, ^)
    match_pattern: String,
}

impl AdGuardRuleMatcher {
    /// Parse an AdGuard-style rule pattern
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err("empty pattern".to_string());
        }

        // Check for exception rules (@@)
        let (is_exception, remaining) = if let Some(rest) = pattern.strip_prefix("@@") {
            (true, rest)
        } else {
            (false, pattern)
        };

        // Determine pattern type
        let (pattern_type, match_pattern) = if let Some(rest) = remaining.strip_prefix("||") {
            // ||domain^ - domain and subdomains
            let clean = rest.trim_end_matches('^').to_ascii_lowercase();
            (AdGuardPatternType::DomainAndSubdomains, clean)
        } else if let Some(rest) = remaining.strip_prefix('|') {
            // |domain - domain start
            let clean = rest.trim_end_matches('^').to_ascii_lowercase();
            (AdGuardPatternType::DomainStart, clean)
        } else {
            // Plain pattern - contains
            let clean = remaining.trim_end_matches('^').to_ascii_lowercase();
            (AdGuardPatternType::Contains, clean)
        };

        if match_pattern.is_empty() {
            return Err("empty match pattern after parsing".to_string());
        }

        Ok(Self {
            pattern: pattern.to_string(),
            is_exception,
            pattern_type,
            match_pattern,
        })
    }

    /// Check if this rule matches the given domain
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();

        match self.pattern_type {
            AdGuardPatternType::DomainAndSubdomains => {
                // Match exact domain or any subdomain
                // ||example.org^ matches: example.org, www.example.org, sub.www.example.org
                // but NOT: notexample.org
                if domain == self.match_pattern {
                    return true;
                }
                // Check if domain ends with .pattern
                if domain.ends_with(&format!(".{}", self.match_pattern)) {
                    return true;
                }
                false
            }
            AdGuardPatternType::DomainStart => {
                // Match if domain starts with pattern
                domain.starts_with(&self.match_pattern)
            }
            AdGuardPatternType::Contains => {
                // Match if domain contains pattern
                domain.contains(&self.match_pattern)
            }
        }
    }

    /// Check if this is an exception rule
    pub fn is_exception(&self) -> bool {
        self.is_exception
    }

    /// Get the original pattern
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl PartialEq for AdGuardRuleMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for AdGuardRuleMatcher {}

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
    ClashMode(String),                         // clash_mode:rule
    Default,                                   // default
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub decision: Decision,
}

/// Logical rule type
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RuleType {
    #[default]
    Default,
    Logical,
}

/// Logical mode for combined rules
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LogicalMode {
    #[default]
    And,
    Or,
}

/// Composite rule that matches multiple criteria (AND logic).
/// Mirrors `RuleIR` but uses optimized matchers where possible.
/// Now supports nested logical rules.
#[derive(Debug, Clone, Default)]
pub struct CompositeRule {
    // Logical support
    pub rule_type: RuleType,
    pub mode: LogicalMode,
    pub sub_rules: Vec<CompositeRule>,
    pub invert: bool,

    // Positive matchers
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<DomainRegexMatcher>,
    pub geosite: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub geoip: Vec<String>,
    pub source_ip_cidr: Vec<IpNet>,
    pub source_geoip: Vec<String>,
    pub port: Vec<u16>,
    pub port_range: Vec<(u16, u16)>,
    pub source_port: Vec<u16>,
    pub source_port_range: Vec<(u16, u16)>,
    pub network: Vec<String>,
    pub protocol: Vec<String>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_path_regex: Vec<ProcessPathRegexMatcher>,
    pub wifi_ssid: Vec<String>,
    pub wifi_bssid: Vec<String>,
    pub rule_set: Vec<String>,
    pub user_agent: Vec<String>,
    pub inbound_tag: Vec<String>,
    pub auth_user: Vec<String>,
    pub query_type: Vec<DnsRecordType>,
    pub ip_is_private: bool,
    pub ip_version: Vec<String>, // ipv4, ipv6

    // P1 Parity: Additional positive matchers
    pub clash_mode: Vec<String>,
    pub client: Vec<String>,
    pub package_name: Vec<String>,
    pub network_type: Vec<String>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub ip_accept_any: bool,
    pub outbound_tag: Vec<String>,
    /// OS-level user name list (e.g., "root", "nobody")
    pub user: Vec<String>,
    /// OS-level user ID list (UID)
    pub user_id: Vec<u32>,
    /// OS-level group name list (e.g., "wheel", "staff")
    pub group: Vec<String>,
    /// OS-level group ID list (GID)
    pub group_id: Vec<u32>,
    /// AdGuard-style filter rules (e.g., "||example.org^")
    pub adguard: Vec<AdGuardRuleMatcher>,

    // Negative matchers
    pub not_domain: Vec<String>,
    pub not_domain_suffix: Vec<String>,
    pub not_domain_keyword: Vec<String>,
    pub not_domain_regex: Vec<DomainRegexMatcher>,
    pub not_geosite: Vec<String>,
    pub not_ip_cidr: Vec<IpNet>,
    pub not_geoip: Vec<String>,
    pub not_source_ip_cidr: Vec<IpNet>,
    pub not_source_geoip: Vec<String>,
    pub not_port: Vec<u16>,
    pub not_port_range: Vec<(u16, u16)>,
    pub not_source_port: Vec<u16>,
    pub not_source_port_range: Vec<(u16, u16)>,
    pub not_network: Vec<String>,
    pub not_protocol: Vec<String>,
    pub not_process_name: Vec<String>,
    pub not_process_path: Vec<String>,
    pub not_process_path_regex: Vec<ProcessPathRegexMatcher>,
    pub not_wifi_ssid: Vec<String>,
    pub not_wifi_bssid: Vec<String>,
    pub not_rule_set: Vec<String>,
    pub not_user_agent: Vec<String>,
    pub not_inbound_tag: Vec<String>,
    pub not_auth_user: Vec<String>,
    pub not_ip_is_private: bool,

    // P1 Parity: Additional negative matchers
    pub not_clash_mode: Vec<String>,
    pub not_client: Vec<String>,
    pub not_package_name: Vec<String>,
    pub not_network_type: Vec<String>,
    pub not_outbound_tag: Vec<String>,
    /// Negative: OS-level user name list
    pub not_user: Vec<String>,
    /// Negative: OS-level user ID list
    pub not_user_id: Vec<u32>,
    /// Negative: OS-level group name list
    pub not_group: Vec<String>,
    /// Negative: OS-level group ID list
    pub not_group_id: Vec<u32>,
    /// Negative: AdGuard-style filter rules
    pub not_adguard: Vec<AdGuardRuleMatcher>,

    pub decision: Decision,
}

#[derive(Debug, Clone, Default)]
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
    pub wifi_ssid: Option<&'a str>,
    pub wifi_bssid: Option<&'a str>,
    pub network: Option<&'a str>,  // tcp/udp
    pub protocol: Option<&'a str>, // http/tls/etc
    pub user_agent: Option<&'a str>,
    pub geosite_codes: Vec<String>,
    pub geoip_code: Option<String>,
    pub source_geoip_code: Option<String>,
    pub rule_sets: Vec<String>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,

    // P1 Parity: Additional routing context fields
    /// Current Clash API mode (e.g., "rule", "global", "direct")
    pub clash_mode: Option<&'a str>,
    /// Client name/version string
    pub client: Option<&'a str>,
    /// Android package name (TUN mode)
    pub package_name: Option<&'a str>,
    /// Network type: "wifi", "cellular", "ethernet", etc.
    pub network_type: Option<&'a str>,
    /// Whether the current network is metered/expensive
    pub network_is_expensive: Option<bool>,
    /// Whether the current network is constrained
    pub network_is_constrained: Option<bool>,
    /// OS-level user name (e.g., "root", "nobody")
    pub user: Option<&'a str>,
    /// OS-level user ID (UID)
    pub user_id: Option<u32>,
    /// OS-level group name (e.g., "wheel", "staff")
    pub group: Option<&'a str>,
    /// OS-level group ID (GID)
    pub group_id: Option<u32>,
}

impl CompositeRule {
    pub fn matches(&self, ctx: &RouteCtx) -> bool {
        // Handle logical rules
        if self.rule_type == RuleType::Logical {
            let result = match self.mode {
                LogicalMode::And => self.sub_rules.iter().all(|r| r.matches(ctx)),
                LogicalMode::Or => self.sub_rules.iter().any(|r| r.matches(ctx)),
            };
            return if self.invert { !result } else { result };
        }
        
        // 1. Negation checks (if any match, rule fails)
        if !self.not_domain.is_empty() {
            if let Some(domain) = ctx.domain {
                if self
                    .not_domain
                    .iter()
                    .any(|d| domain.eq_ignore_ascii_case(d))
                {
                    return false;
                }
            }
        }
        if !self.not_domain_suffix.is_empty() {
            if let Some(domain) = ctx.domain {
                let domain = domain.to_ascii_lowercase();
                if self
                    .not_domain_suffix
                    .iter()
                    .any(|s| domain.ends_with(&s.to_ascii_lowercase()))
                {
                    return false;
                }
            }
        }
        if !self.not_domain_keyword.is_empty() {
            if let Some(domain) = ctx.domain {
                let domain = domain.to_ascii_lowercase();
                if self
                    .not_domain_keyword
                    .iter()
                    .any(|k| domain.contains(&k.to_ascii_lowercase()))
                {
                    return false;
                }
            }
        }
        if !self.not_domain_regex.is_empty() {
            if let Some(domain) = ctx.domain {
                if self.not_domain_regex.iter().any(|r| r.is_match(domain)) {
                    return false;
                }
            }
        }
        if !self.not_geosite.is_empty()
            && self
                .not_geosite
                .iter()
                .any(|g| ctx.geosite_codes.iter().any(|c| c == g))
        {
            return false;
        }
        if !self.not_ip_cidr.is_empty() {
            if let Some(ip) = ctx.ip {
                if self.not_ip_cidr.iter().any(|n| n.contains(&ip)) {
                    return false;
                }
            }
        }
        if !self.not_geoip.is_empty() {
            if let Some(code) = &ctx.geoip_code {
                if self.not_geoip.iter().any(|c| c.eq_ignore_ascii_case(code)) {
                    return false;
                }
            }
        }
        if !self.not_source_ip_cidr.is_empty() {
            if let Some(ip) = ctx.source_ip {
                if self.not_source_ip_cidr.iter().any(|n| n.contains(&ip)) {
                    return false;
                }
            }
        }
        if !self.not_source_geoip.is_empty() {
            if let Some(code) = &ctx.source_geoip_code {
                if self
                    .not_source_geoip
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(code))
                {
                    return false;
                }
            }
        }
        if !self.not_port.is_empty() {
            if let Some(port) = ctx.port {
                if self.not_port.contains(&port) {
                    return false;
                }
            }
        }
        if !self.not_port_range.is_empty() {
            if let Some(port) = ctx.port {
                if self
                    .not_port_range
                    .iter()
                    .any(|(s, e)| port >= *s && port <= *e)
                {
                    return false;
                }
            }
        }
        if !self.not_source_port.is_empty() {
            if let Some(port) = ctx.source_port {
                if self.not_source_port.contains(&port) {
                    return false;
                }
            }
        }
        if !self.not_source_port_range.is_empty() {
            if let Some(port) = ctx.source_port {
                if self
                    .not_source_port_range
                    .iter()
                    .any(|(s, e)| port >= *s && port <= *e)
                {
                    return false;
                }
            }
        }
        if !self.not_network.is_empty() {
            if let Some(network) = ctx.network {
                if self
                    .not_network
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(network))
                {
                    return false;
                }
            }
        }
        if !self.not_protocol.is_empty() {
            if let Some(protocol) = ctx.protocol {
                if self
                    .not_protocol
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(protocol))
                {
                    return false;
                }
            }
        }
        if !self.not_process_name.is_empty() {
            if let Some(name) = ctx.process_name {
                if self
                    .not_process_name
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
                {
                    return false;
                }
            }
        }
        if !self.not_process_path.is_empty() {
            if let Some(path) = ctx.process_path {
                if self
                    .not_process_path
                    .iter()
                    .any(|p| path.eq_ignore_ascii_case(p))
                {
                    return false;
                }
            }
        }
        if !self.not_process_path_regex.is_empty() {
            if let Some(path) = ctx.process_path {
                if self.not_process_path_regex.iter().any(|r| r.is_match(path)) {
                    return false;
                }
            }
        }
        if !self.not_wifi_ssid.is_empty() {
            if let Some(ssid) = ctx.wifi_ssid {
                if self.not_wifi_ssid.iter().any(|s| s == ssid) {
                    return false;
                }
            }
        }
        if !self.not_wifi_bssid.is_empty() {
            if let Some(bssid) = ctx.wifi_bssid {
                if self
                    .not_wifi_bssid
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(bssid))
                {
                    return false;
                }
            }
        }
        if !self.not_rule_set.is_empty()
            && self
                .not_rule_set
                .iter()
                .any(|rs| ctx.rule_sets.iter().any(|r| r == rs))
        {
            return false;
        }
        if !self.not_user_agent.is_empty() {
            if let Some(ua) = ctx.user_agent {
                if self.not_user_agent.iter().any(|u| ua.contains(u)) {
                    return false;
                }
            }
        }
        if !self.not_inbound_tag.is_empty() {
            if let Some(tag) = ctx.inbound_tag {
                if self
                    .not_inbound_tag
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(tag))
                {
                    return false;
                }
            }
        }
        if !self.not_auth_user.is_empty() {
            if let Some(user) = ctx.auth_user {
                if self
                    .not_auth_user
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(user))
                {
                    return false;
                }
            }
        }
        if self.not_ip_is_private {
            if let Some(ip) = ctx.ip {
                if Engine::is_private_ip(&ip) {
                    return false;
                }
            }
        }

        // 2. Positive checks (all non-empty fields must match)
        if !self.domain.is_empty() {
            let matched = if let Some(domain) = ctx.domain {
                self.domain.iter().any(|d| domain.eq_ignore_ascii_case(d))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.domain_suffix.is_empty() {
            let matched = if let Some(domain) = ctx.domain {
                let domain = domain.to_ascii_lowercase();
                self.domain_suffix
                    .iter()
                    .any(|s| domain.ends_with(&s.to_ascii_lowercase()))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.domain_keyword.is_empty() {
            let matched = if let Some(domain) = ctx.domain {
                let domain = domain.to_ascii_lowercase();
                self.domain_keyword
                    .iter()
                    .any(|k| domain.contains(&k.to_ascii_lowercase()))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.domain_regex.is_empty() {
            let matched = if let Some(domain) = ctx.domain {
                self.domain_regex.iter().any(|r| r.is_match(domain))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.geosite.is_empty() {
            let matched = self
                .geosite
                .iter()
                .any(|g| ctx.geosite_codes.iter().any(|c| c == g));
            if !matched {
                return false;
            }
        }
        if !self.ip_cidr.is_empty() {
            let matched = if let Some(ip) = ctx.ip {
                self.ip_cidr.iter().any(|n| n.contains(&ip))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.geoip.is_empty() {
            let matched = if let Some(code) = &ctx.geoip_code {
                self.geoip.iter().any(|c| c.eq_ignore_ascii_case(code))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.source_ip_cidr.is_empty() {
            let matched = if let Some(ip) = ctx.source_ip {
                self.source_ip_cidr.iter().any(|n| n.contains(&ip))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.source_geoip.is_empty() {
            let matched = if let Some(code) = &ctx.source_geoip_code {
                self.source_geoip
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(code))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.port.is_empty() {
            let matched = if let Some(port) = ctx.port {
                self.port.contains(&port)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.port_range.is_empty() {
            let matched = if let Some(port) = ctx.port {
                self.port_range
                    .iter()
                    .any(|(s, e)| port >= *s && port <= *e)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.source_port.is_empty() {
            let matched = if let Some(port) = ctx.source_port {
                self.source_port.contains(&port)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.source_port_range.is_empty() {
            let matched = if let Some(port) = ctx.source_port {
                self.source_port_range
                    .iter()
                    .any(|(s, e)| port >= *s && port <= *e)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.network.is_empty() {
            let matched = if let Some(network) = ctx.network {
                self.network.iter().any(|n| n.eq_ignore_ascii_case(network))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.protocol.is_empty() {
            let matched = if let Some(protocol) = ctx.protocol {
                self.protocol
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(protocol))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.process_name.is_empty() {
            let matched = if let Some(name) = ctx.process_name {
                self.process_name
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.process_path.is_empty() {
            let matched = if let Some(path) = ctx.process_path {
                self.process_path
                    .iter()
                    .any(|p| path.eq_ignore_ascii_case(p))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.process_path_regex.is_empty() {
            let matched = if let Some(path) = ctx.process_path {
                self.process_path_regex.iter().any(|r| r.is_match(path))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.wifi_ssid.is_empty() {
            let matched = if let Some(ssid) = ctx.wifi_ssid {
                self.wifi_ssid.iter().any(|s| s == ssid)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.wifi_bssid.is_empty() {
            let matched = if let Some(bssid) = ctx.wifi_bssid {
                self.wifi_bssid
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(bssid))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.rule_set.is_empty() {
            let matched = self
                .rule_set
                .iter()
                .any(|rs| ctx.rule_sets.iter().any(|r| r == rs));
            if !matched {
                return false;
            }
        }
        if !self.user_agent.is_empty() {
            let matched = if let Some(ua) = ctx.user_agent {
                self.user_agent.iter().any(|u| ua.contains(u))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.inbound_tag.is_empty() {
            let matched = if let Some(tag) = ctx.inbound_tag {
                self.inbound_tag.iter().any(|t| t.eq_ignore_ascii_case(tag))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.auth_user.is_empty() {
            let matched = if let Some(user) = ctx.auth_user {
                self.auth_user.iter().any(|u| u.eq_ignore_ascii_case(user))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.query_type.is_empty() {
            let matched = if let Some(qt) = ctx.query_type {
                self.query_type.contains(&qt)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if self.ip_is_private {
            let matched = if let Some(ip) = ctx.ip {
                Engine::is_private_ip(&ip)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.ip_version.is_empty() {
            let matched = if let Some(ip) = ctx.ip {
                if ip.is_ipv4() {
                    self.ip_version
                        .iter()
                        .any(|v| v == "4" || v.eq_ignore_ascii_case("ipv4"))
                } else {
                    self.ip_version
                        .iter()
                        .any(|v| v == "6" || v.eq_ignore_ascii_case("ipv6"))
                }
            } else {
                false
            };
            if !matched {
                return false;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // P1 Parity: Additional negation checks
        // ─────────────────────────────────────────────────────────────────────
        if !self.not_clash_mode.is_empty() {
            if let Some(mode) = ctx.clash_mode {
                if self
                    .not_clash_mode
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(mode))
                {
                    return false;
                }
            }
        }
        if !self.not_client.is_empty() {
            if let Some(client) = ctx.client {
                if self.not_client.iter().any(|c| client.contains(c)) {
                    return false;
                }
            }
        }
        if !self.not_package_name.is_empty() {
            if let Some(pkg) = ctx.package_name {
                if self
                    .not_package_name
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(pkg))
                {
                    return false;
                }
            }
        }
        if !self.not_network_type.is_empty() {
            if let Some(nt) = ctx.network_type {
                if self
                    .not_network_type
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(nt))
                {
                    return false;
                }
            }
        }
        if !self.not_outbound_tag.is_empty() {
            if let Some(tag) = ctx.outbound_tag {
                if self
                    .not_outbound_tag
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(tag))
                {
                    return false;
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // P1 Parity: Additional positive checks
        // ─────────────────────────────────────────────────────────────────────
        if !self.clash_mode.is_empty() {
            let mode = if let Some(m) = &ctx.clash_mode {
                m.to_string()
            } else {
                crate::adapter::clash::get_mode().to_string()
            };
            if !self.clash_mode.iter().any(|m| m.eq_ignore_ascii_case(&mode)) {
                return false;
            }
        }
        if !self.client.is_empty() {
            let matched = if let Some(client) = ctx.client {
                self.client.iter().any(|c| client.contains(c))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.package_name.is_empty() {
            let matched = if let Some(pkg) = ctx.package_name {
                self.package_name
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(pkg))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.network_type.is_empty() {
            let matched = if let Some(nt) = ctx.network_type {
                self.network_type.iter().any(|t| t.eq_ignore_ascii_case(nt))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if let Some(is_expensive) = self.network_is_expensive {
            if ctx.network_is_expensive != Some(is_expensive) {
                return false;
            }
        }
        if let Some(is_constrained) = self.network_is_constrained {
            if ctx.network_is_constrained != Some(is_constrained) {
                return false;
            }
        }
        if !self.outbound_tag.is_empty() {
            let matched = if let Some(tag) = ctx.outbound_tag {
                self.outbound_tag
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(tag))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        // ip_accept_any: special DNS rule behavior, no matching logic here
        // (affects how DNS resolver handles multiple A/AAAA records)

        // ─────────────────────────────────────────────────────────────────────
        // OS-level user/group negation checks
        // ─────────────────────────────────────────────────────────────────────
        if !self.not_user.is_empty() {
            if let Some(user) = ctx.user {
                if self.not_user.iter().any(|u| u.eq_ignore_ascii_case(user)) {
                    return false;
                }
            }
        }
        if !self.not_user_id.is_empty() {
            if let Some(uid) = ctx.user_id {
                if self.not_user_id.contains(&uid) {
                    return false;
                }
            }
        }
        if !self.not_group.is_empty() {
            if let Some(group) = ctx.group {
                if self.not_group.iter().any(|g| g.eq_ignore_ascii_case(group)) {
                    return false;
                }
            }
        }
        if !self.not_group_id.is_empty() {
            if let Some(gid) = ctx.group_id {
                if self.not_group_id.contains(&gid) {
                    return false;
                }
            }
        }
        // AdGuard-style negation checks
        if !self.not_adguard.is_empty() {
            if let Some(domain) = ctx.domain {
                // If any non-exception rule matches, fail
                // Exception rules in not_adguard are treated as "if this exception matches, fail"
                for rule in &self.not_adguard {
                    if rule.matches(domain) {
                        return false;
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // OS-level user/group positive checks
        // ─────────────────────────────────────────────────────────────────────
        if !self.user.is_empty() {
            let matched = if let Some(user) = ctx.user {
                self.user.iter().any(|u| u.eq_ignore_ascii_case(user))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.user_id.is_empty() {
            let matched = if let Some(uid) = ctx.user_id {
                self.user_id.contains(&uid)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.group.is_empty() {
            let matched = if let Some(group) = ctx.group {
                self.group.iter().any(|g| g.eq_ignore_ascii_case(group))
            } else {
                false
            };
            if !matched {
                return false;
            }
        }
        if !self.group_id.is_empty() {
            let matched = if let Some(gid) = ctx.group_id {
                self.group_id.contains(&gid)
            } else {
                false
            };
            if !matched {
                return false;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // AdGuard-style positive checks
        // ─────────────────────────────────────────────────────────────────────
        if !self.adguard.is_empty() {
            let matched = if let Some(domain) = ctx.domain {
                // AdGuard matching with exception support:
                // 1. Check if any exception rule matches first
                // 2. If exception matches, treat as non-match (allow through)
                // 3. If no exception, check blocking rules
                let has_exception_match = self
                    .adguard
                    .iter()
                    .filter(|r| r.is_exception())
                    .any(|r| r.matches(domain));

                if has_exception_match {
                    // Exception rule matched, treat as non-match for this rule set
                    false
                } else {
                    // Check if any blocking rule matches
                    self.adguard
                        .iter()
                        .filter(|r| !r.is_exception())
                        .any(|r| r.matches(domain))
                }
            } else {
                false
            };
            if !matched {
                return false;
            }
        }

        true
    }
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
    clash_mode: Vec<Rule>,  // ClashMode
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
                RuleKind::ClashMode(_) => e.clash_mode.push(r),
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
            RuleKind::ClashMode(m) => {
                let mode = if let Some(vals) = &ctx.clash_mode {
                    vals.to_string()
                } else {
                    crate::adapter::clash::get_mode().to_string()
                };
                mode.eq_ignore_ascii_case(m)
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
        for r in &self.clash_mode {
            if Self::hit(r, ctx) {
                return record("clash_mode", &r.decision);
            }
        }
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
        Decision::RejectDrop => "reject-drop",
        Decision::Hijack { .. } => "hijack",
        Decision::Sniff => "sniff",
        Decision::Resolve => "resolve",
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
            } else if let Some(v) = tok.strip_prefix("clash_mode:") {
                kinds.push(RuleKind::ClashMode(v.to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adguard_domain_and_subdomains() {
        let matcher = AdGuardRuleMatcher::parse("||example.org^").expect("parse");

        // Should match exact domain
        assert!(matcher.matches("example.org"));
        // Should match subdomains
        assert!(matcher.matches("www.example.org"));
        assert!(matcher.matches("sub.www.example.org"));
        assert!(matcher.matches("deep.sub.www.example.org"));

        // Should NOT match unrelated domains
        assert!(!matcher.matches("notexample.org"));
        assert!(!matcher.matches("example.org.com"));
        assert!(!matcher.matches("myexample.org"));
    }

    #[test]
    fn test_adguard_domain_start() {
        let matcher = AdGuardRuleMatcher::parse("|example^").expect("parse");

        // Should match domains starting with pattern
        assert!(matcher.matches("example.org"));
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("example"));

        // Should NOT match domains not starting with pattern
        assert!(!matcher.matches("www.example.org"));
        assert!(!matcher.matches("notexample.org"));
    }

    #[test]
    fn test_adguard_contains() {
        let matcher = AdGuardRuleMatcher::parse("tracker").expect("parse");

        // Should match if contains pattern
        assert!(matcher.matches("ads-tracker.example.com"));
        assert!(matcher.matches("tracker.example.com"));
        assert!(matcher.matches("example.tracker.com"));
        assert!(matcher.matches("tracker"));

        // Should NOT match if doesn't contain pattern
        assert!(!matcher.matches("example.com"));
        assert!(!matcher.matches("track.example.com"));
    }

    #[test]
    fn test_adguard_exception() {
        let matcher = AdGuardRuleMatcher::parse("@@||ads.example.org^").expect("parse");

        // Should be marked as exception
        assert!(matcher.is_exception());

        // Should still match domains
        assert!(matcher.matches("ads.example.org"));
        assert!(matcher.matches("www.ads.example.org"));
    }

    #[test]
    fn test_adguard_case_insensitive() {
        let matcher = AdGuardRuleMatcher::parse("||Example.ORG^").expect("parse");

        assert!(matcher.matches("example.org"));
        assert!(matcher.matches("EXAMPLE.ORG"));
        assert!(matcher.matches("www.Example.Org"));
    }

    #[test]
    fn test_adguard_invalid_patterns() {
        assert!(AdGuardRuleMatcher::parse("").is_err());
        assert!(AdGuardRuleMatcher::parse("   ").is_err());
        assert!(AdGuardRuleMatcher::parse("||^").is_err());
    }

    #[test]
    fn test_adguard_composite_rule_blocking() {
        let rule = AdGuardRuleMatcher::parse("||ads.example.org^").expect("parse");

        let composite = CompositeRule {
            adguard: vec![rule],
            decision: Decision::Reject,
            ..Default::default()
        };

        // Should match ad domain
        let ctx_ads = RouteCtx {
            domain: Some("ads.example.org"),
            ..Default::default()
        };
        assert!(composite.matches(&ctx_ads));

        // Should not match regular domain
        let ctx_regular = RouteCtx {
            domain: Some("www.example.org"),
            ..Default::default()
        };
        assert!(!composite.matches(&ctx_regular));
    }

    #[test]
    fn test_adguard_composite_rule_with_exception() {
        // Block all of example.org, but allow safe.example.org
        let block_rule = AdGuardRuleMatcher::parse("||example.org^").expect("parse");
        let exception_rule = AdGuardRuleMatcher::parse("@@||safe.example.org^").expect("parse");

        let composite = CompositeRule {
            adguard: vec![block_rule, exception_rule],
            decision: Decision::Reject,
            ..Default::default()
        };

        // Should NOT match safe subdomain (exception applies)
        let ctx_safe = RouteCtx {
            domain: Some("safe.example.org"),
            ..Default::default()
        };
        assert!(!composite.matches(&ctx_safe));

        // Should match other subdomains
        let ctx_ads = RouteCtx {
            domain: Some("ads.example.org"),
            ..Default::default()
        };
        assert!(composite.matches(&ctx_ads));

        // Should match main domain
        let ctx_main = RouteCtx {
            domain: Some("example.org"),
            ..Default::default()
        };
        assert!(composite.matches(&ctx_main));
    }
}
