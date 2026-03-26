//! Route/rule IR types (rule actions, routing rules, rule sets).

use serde::{Deserialize, Serialize};

/// Rule action type (Go parity: option/rule_action.go).
/// 规则动作类型（Go 对齐：option/rule_action.go）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Route traffic to specified outbound (default).
    /// 将流量路由到指定出站（默认）。
    #[default]
    Route,
    /// Reject connection (send RST/ICMP unreachable).
    /// 拒绝连接（发送 RST/ICMP 不可达）。
    Reject,
    /// Reject by dropping packets silently.
    /// 通过静默丢弃数据包拒绝。
    RejectDrop,
    /// DNS hijack action.
    /// DNS 劫持动作。
    Hijack,
    /// DNS hijack action (explicit).
    /// DNS 劫持动作（显式）。
    HijackDns,
    /// Sniff protocol to override destination.
    /// 嗅探协议以覆盖目标。
    Sniff,
    /// Resolve domain to IP address.
    /// 将域名解析为 IP 地址。
    Resolve,
    /// Apply route options (e.g. override Android VPN, mark).
    /// 应用路由选项（例如覆盖 Android VPN，标记）。
    RouteOptions,
    /// Sniff protocol and override destination (explicit).
    /// 嗅探协议并覆盖目标（显式）。
    SniffOverride,
}

impl RuleAction {
    /// Returns the string representation for config serialization.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Route => "route",
            RuleAction::Reject => "reject",
            RuleAction::RejectDrop => "reject-drop",
            RuleAction::Hijack => "hijack",
            RuleAction::HijackDns => "hijack-dns",
            RuleAction::Sniff => "sniff",
            RuleAction::Resolve => "resolve",
            RuleAction::RouteOptions => "route-options",
            RuleAction::SniffOverride => "sniff-override",
        }
    }

    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "route" => Some(RuleAction::Route),
            "reject" => Some(RuleAction::Reject),
            "reject-drop" | "reject_drop" => Some(RuleAction::RejectDrop),
            "hijack" => Some(RuleAction::Hijack),
            "hijack-dns" | "hijack_dns" => Some(RuleAction::HijackDns),
            "sniff" => Some(RuleAction::Sniff),
            "sniff-override" | "sniff_override" => Some(RuleAction::SniffOverride),
            "resolve" => Some(RuleAction::Resolve),
            "route-options" | "route_options" => Some(RuleAction::RouteOptions),
            _ => None,
        }
    }
}

/// Routing rule intermediate representation.
/// 路由规则中间表示。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleIR {
    // Positive match conditions
    /// Domain exact match list.
    /// 域名精确匹配列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain: Vec<String>,
    /// Domain suffix match list (e.g., ".google.com").
    /// 域名后缀匹配列表（例如 ".google.com"）。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_suffix: Vec<String>,
    /// Domain keyword match list.
    /// 域名关键字匹配列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_keyword: Vec<String>,
    /// Domain regex match list.
    /// 域名正则表达式匹配列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_regex: Vec<String>,
    /// Geosite category list.
    /// Geosite 分类列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub geosite: Vec<String>,
    /// GeoIP country code list.
    /// GeoIP 国家代码列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub geoip: Vec<String>,
    /// IP CIDR list.
    /// IP CIDR 列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub ipcidr: Vec<String>,
    /// Port or port range (e.g., `"80"`, `"80-90"`).
    /// 端口或端口范围（例如 `"80"`, `"80-90"`）。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub port: Vec<String>,
    /// Process name list.
    /// 进程名称列表。
    #[serde(
        default,
        alias = "process",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub process_name: Vec<String>,
    /// Process path list.
    /// 进程路径列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub process_path: Vec<String>,
    /// Network type: `"tcp"` or `"udp"`.
    /// 网络类型：`"tcp"` 或 `"udp"`。
    #[serde(default)]
    pub network: Vec<String>,
    /// Protocol list: `"http"`, `"socks"`, etc.
    /// 协议列表：`"http"`, `"socks"` 等。
    #[serde(default)]
    pub protocol: Vec<String>,
    /// Sniffed ALPN protocols (e.g., `"h2"`, `"http/1.1"`, `"h3"`).
    /// 嗅探到的 ALPN 协议（例如 `"h2"`, `"http/1.1"`, `"h3"`）。
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Source address list.
    /// 源地址列表。
    #[serde(default)]
    pub source: Vec<String>,
    /// Destination address list.
    /// 目标地址列表。
    #[serde(default)]
    pub dest: Vec<String>,
    /// User-Agent pattern list.
    /// User-Agent 模式列表。
    #[serde(default)]
    pub user_agent: Vec<String>,
    /// WiFi SSID list.
    /// WiFi SSID 列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub wifi_ssid: Vec<String>,
    /// WiFi BSSID list.
    /// WiFi BSSID 列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub wifi_bssid: Vec<String>,
    /// Rule set list.
    /// 规则集列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub rule_set: Vec<String>,
    /// IP-based rule set list.
    /// 基于 IP 的规则集列表。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub rule_set_ipcidr: Vec<String>,
    /// User ID list (UID-based matching, Linux/macOS).
    /// 用户 ID 列表（基于 UID 的匹配，Linux/macOS）。
    #[serde(default)]
    pub user_id: Vec<u32>,
    /// User name list (resolved to UID, Linux/macOS).
    /// 用户名列表（解析为 UID，Linux/macOS）。
    #[serde(
        default,
        alias = "uid",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub user: Vec<String>,
    /// Group ID list (GID-based matching, Linux/macOS).
    /// 组 ID 列表（基于 GID 的匹配，Linux/macOS）。
    #[serde(default)]
    pub group_id: Vec<u32>,
    /// Group name list (resolved to GID, Linux/macOS).
    /// 组名列表（解析为 GID，Linux/macOS）。
    #[serde(
        default,
        alias = "gid",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub group: Vec<String>,

    // P1 Parity: Additional routing rule fields (Go compatibility)
    /// Clash API mode (e.g., "rule", "global", "direct").
    /// Clash API 模式（例如 "rule", "global", "direct"）。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub clash_mode: Vec<String>,
    /// Client name or version patterns.
    /// 客户端名称或版本模式。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub client: Vec<String>,
    /// Android package names (for Android TUN mode).
    /// Android 包名（用于 Android TUN 模式）。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub package_name: Vec<String>,
    /// Network type (e.g., "wifi", "cellular", "ethernet").
    /// 网络类型（例如 "wifi", "cellular", "ethernet"）。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub network_type: Vec<String>,
    /// Metered/expensive network flag.
    /// 计费/昂贵网络标志。
    #[serde(default)]
    pub network_is_expensive: Option<bool>,
    /// Match constrained network status.
    /// 匹配受限网络状态。
    #[serde(default)]
    pub network_is_constrained: Option<bool>,
    /// Accept any resolved IP (used in DNS rules).
    /// 接受任何解析的 IP（用于 DNS 规则）。
    #[serde(default)]
    pub ip_accept_any: Option<bool>,
    /// Match specific outbound tag (as input).
    /// 匹配特定出站标签（作为输入）。
    #[serde(default)]
    pub outbound_tag: Vec<String>,

    // ==== AdGuard-style rules ====
    /// AdGuard-style filter rules (e.g., "||example.org^", "@@||safe.example.org^")
    /// AdGuard 风格过滤规则（例如 "||example.org^", "@@||safe.example.org^"）
    #[serde(default)]
    pub adguard: Vec<String>,
    /// AdGuard-style rules (negative match, exclusion)
    /// AdGuard 风格规则（否定匹配，排除）
    #[serde(default)]
    pub not_adguard: Vec<String>,

    // Negative match conditions (exclusions)
    /// Exclude domains.
    /// 排除域名。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain: Vec<String>,
    /// Exclude domain suffixes.
    /// 排除域名后缀。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_suffix: Vec<String>,
    /// Exclude domain keywords.
    /// 排除域名关键字。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_keyword: Vec<String>,
    /// Exclude domain regex.
    /// 排除域名正则表达式。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_regex: Vec<String>,
    /// Exclude geosite categories.
    /// 排除 Geosite 分类。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_geosite: Vec<String>,
    /// Exclude GeoIP countries.
    /// 排除 GeoIP 国家。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_geoip: Vec<String>,
    /// Exclude IP CIDRs.
    /// 排除 IP CIDR。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_ipcidr: Vec<String>,
    /// Exclude ports.
    /// 排除端口。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_port: Vec<String>,
    /// Exclude process names.
    /// 排除进程名称。
    #[serde(
        default,
        alias = "not_process",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub not_process_name: Vec<String>,
    /// Exclude process paths.
    /// 排除进程路径。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_process_path: Vec<String>,
    /// Exclude network types.
    /// 排除网络类型。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_network: Vec<String>,
    /// Exclude protocols.
    /// 排除协议。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_protocol: Vec<String>,
    /// Exclude ALPN.
    /// 排除 ALPN。
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_alpn: Vec<String>,
    /// Exclude source addresses.
    /// 排除源地址。
    #[serde(default)]
    pub not_source: Vec<String>,
    /// Exclude destination addresses.
    /// 排除目标地址。
    #[serde(default)]
    pub not_dest: Vec<String>,
    /// Exclude User-Agent patterns.
    /// 排除 User-Agent 模式。
    #[serde(default)]
    pub not_user_agent: Vec<String>,
    /// Exclude WiFi SSIDs.
    /// 排除 WiFi SSID。
    #[serde(default)]
    pub not_wifi_ssid: Vec<String>,
    /// Exclude WiFi BSSIDs.
    /// 排除 WiFi BSSID。
    #[serde(default)]
    pub not_wifi_bssid: Vec<String>,
    /// Exclude rule sets.
    /// 排除规则集。
    #[serde(default)]
    pub not_rule_set: Vec<String>,
    /// Exclude IP-based rule sets.
    /// 排除基于 IP 的规则集。
    #[serde(default)]
    pub not_rule_set_ipcidr: Vec<String>,
    /// Exclude user IDs.
    /// 排除用户 ID。
    #[serde(default)]
    pub not_user_id: Vec<u32>,
    /// Exclude user names.
    /// 排除用户名。
    #[serde(default)]
    pub not_user: Vec<String>,
    /// Exclude group IDs.
    /// 排除组 ID。
    #[serde(default)]
    pub not_group_id: Vec<u32>,
    /// Exclude group names.
    /// 排除组名。
    #[serde(default)]
    pub not_group: Vec<String>,
    /// Exclude Clash API modes.
    /// 排除 Clash API 模式。
    #[serde(default)]
    pub not_clash_mode: Vec<String>,
    /// Exclude client patterns.
    /// 排除客户端模式。
    #[serde(default)]
    pub not_client: Vec<String>,
    /// Exclude Android package names.
    /// 排除 Android 包名。
    #[serde(default)]
    pub not_package_name: Vec<String>,
    /// Exclude network types.
    /// 排除网络类型（如 wifi/cellular）。
    #[serde(default)]
    pub not_network_type: Vec<String>,
    /// Exclude outbound tags.
    /// 排除出站标签。
    #[serde(default)]
    pub not_outbound_tag: Vec<String>,

    // ==== Headless/Logical rule support ====
    /// Rule type: "default" (default) or "logical" for combined rules.
    /// 规则类型："default"（默认）或 "logical" 用于组合规则。
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    /// Logical mode for combined rules: "and" or "or".
    /// 组合规则的逻辑模式："and" 或 "or"。
    #[serde(default)]
    pub mode: Option<String>,
    /// Sub-rules for logical rule type.
    /// 逻辑规则类型的子规则。
    #[serde(default)]
    pub rules: Vec<Box<RuleIR>>,

    // Actions
    /// Rule action type (Go parity: route/reject/hijack/sniff/resolve).
    /// 规则动作类型（Go 对齐：route/reject/hijack/sniff/resolve）。
    #[serde(default)]
    pub action: RuleAction,
    /// Target outbound tag.
    /// 目标出站标签。
    #[serde(default)]
    pub outbound: Option<String>,
    /// Override destination address (for hijack action).
    /// 覆盖目标地址（用于 hijack 动作）。
    #[serde(default)]
    pub override_address: Option<String>,
    /// Override destination port (for hijack action).
    /// 覆盖目标端口（用于 hijack 动作）。
    #[serde(default)]
    pub override_port: Option<u16>,

    // DNS specific action fields
    /// DNS query type match (e.g. A, AAAA).
    #[serde(default)]
    pub query_type: Vec<String>,
    /// Rewrite DNS TTL.
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    /// Client subnet prefix (for ECS).
    #[serde(default)]
    pub client_subnet: Option<String>,

    /// Invert match result.
    /// 反转匹配结果。
    #[serde(default)]
    pub invert: bool,

    // Route Options Action Fields
    /// Override Android VPN (bypass VPN for this route).
    #[serde(default)]
    pub override_android_vpn: Option<bool>,
    /// Enable process name/path detection.
    #[serde(default)]
    pub find_process: Option<bool>,
    /// Automatically detect the default network interface.
    #[serde(default)]
    pub auto_detect_interface: Option<bool>,
    /// SO_MARK value for routing.
    #[serde(default)]
    pub mark: Option<u32>,
    /// Network selection strategy.
    #[serde(default)]
    pub network_strategy: Option<String>,
    /// Fallback network types.
    #[serde(default)]
    pub fallback_network_type: Option<Vec<String>>,
    /// Delay before using fallback network type.
    #[serde(default)]
    pub fallback_delay: Option<String>,

    // Sniff Action Fields
    /// Sniffer protocol (e.g. "http", "tls", "quic").
    #[serde(default)]
    pub sniffer: Option<String>,
    /// Sniffing timeout (e.g. "300ms").
    #[serde(default)]
    pub sniff_timeout: Option<String>,
}

/// Domain resolution options (Go parity: option/domain_resolve.go).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DomainResolveOptionsIR {
    /// DNS server address.
    pub server: String,
    /// Domain resolution strategy.
    #[serde(default)]
    pub strategy: Option<String>,
    /// Disable DNS cache.
    #[serde(default)]
    pub disable_cache: Option<bool>,
    /// Rewrite TTL.
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    /// Client subnet (ECS).
    #[serde(default)]
    pub client_subnet: Option<String>,
}

/// Routing table configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteIR {
    /// Routing rules (evaluated in order).
    #[serde(default)]
    pub rules: Vec<RuleIR>,
    /// Rule sets.
    #[serde(default)]
    pub rule_set: Vec<RuleSetIR>,
    /// Default outbound name (fallback).
    #[serde(default)]
    pub default: Option<String>,
    /// Final outbound for unmatched traffic (alias of `default` in some configs).
    #[serde(default, alias = "final")]
    pub final_outbound: Option<String>,

    // ──────────────────────────────────────────────────────────────────
    // GeoIP/Geosite Download Configuration
    // ──────────────────────────────────────────────────────────────────
    /// GeoIP database local path.
    #[serde(default)]
    pub geoip_path: Option<String>,
    /// GeoIP database download URL.
    /// GeoIP 数据库下载 URL。
    #[serde(default)]
    pub geoip_download_url: Option<String>,

    /// GeoIP download detour outbound tag.
    /// GeoIP 下载分流出站标签。
    #[serde(default)]
    pub geoip_download_detour: Option<String>,

    /// Geosite database local path.
    #[serde(default)]
    pub geosite_path: Option<String>,
    /// Geosite database download URL.
    /// Geosite 数据库下载 URL。
    #[serde(default)]
    pub geosite_download_url: Option<String>,

    /// Geosite download detour outbound tag.
    /// Geosite 下载分流出站标签。
    #[serde(default)]
    pub geosite_download_detour: Option<String>,

    /// Default rule set download detour outbound tag.
    /// 默认规则集下载分流出站标签。
    #[serde(default)]
    pub default_rule_set_download_detour: Option<String>,

    // ──────────────────────────────────────────────────────────────────
    // Process and Interface Options
    // ──────────────────────────────────────────────────────────────────
    /// Override Android VPN (bypass VPN for this route).
    /// 覆盖 Android VPN（此路由绕过 VPN）。
    #[serde(default)]
    pub override_android_vpn: Option<bool>,

    /// Enable process name/path detection for routing rules.
    /// 启用路由规则的进程名称/路径检测。
    #[serde(default)]
    pub find_process: Option<bool>,

    /// Automatically detect the default network interface.
    /// 自动检测默认网络接口。
    #[serde(default)]
    pub auto_detect_interface: Option<bool>,

    /// Default network interface name for outbound connections.
    /// 出站连接的默认网络接口名称。
    #[serde(default)]
    pub default_interface: Option<String>,

    // ──────────────────────────────────────────────────────────────────
    // Routing Mark
    // ──────────────────────────────────────────────────────────────────
    /// SO_MARK value for routing (Linux only).
    /// 路由的 SO_MARK 值（仅限 Linux）。
    #[serde(default)]
    pub mark: Option<u32>,

    // ──────────────────────────────────────────────────────────────────
    // DNS and Network Strategy
    // ──────────────────────────────────────────────────────────────────
    /// Default DNS resolver options.
    /// 默认 DNS 解析器选项。
    #[serde(default)]
    pub default_domain_resolver: Option<DomainResolveOptionsIR>,

    /// Network selection strategy: "ipv4_only" | "ipv6_only" | "prefer_ipv4" | "prefer_ipv6".
    /// 网络选择策略："ipv4_only" | "ipv6_only" | "prefer_ipv4" | "prefer_ipv6"。
    #[serde(default)]
    pub network_strategy: Option<String>,

    /// Default network type(s) for outbound connections.
    #[serde(default)]
    pub default_network_type: Option<Vec<String>>,
    /// Fallback network type(s) for outbound connections.
    #[serde(default)]
    pub default_fallback_network_type: Option<Vec<String>>,
    /// Delay before using fallback network type.
    #[serde(default)]
    pub default_fallback_delay: Option<String>,
}

/// Rule set configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleSetIR {
    /// Rule set tag.
    pub tag: String,
    /// Rule set type ("local" | "remote").
    #[serde(rename = "type")]
    pub ty: String,
    /// Rule set format ("binary" | "source").
    #[serde(default)]
    pub format: String,
    /// Path to local rule set file.
    #[serde(default)]
    pub path: Option<String>,
    /// URL to remote rule set.
    #[serde(default)]
    pub url: Option<String>,
    /// Download detour outbound tag.
    #[serde(default)]
    pub download_detour: Option<String>,
    /// Update interval (e.g., "24h").
    #[serde(default)]
    pub update_interval: Option<String>,
    /// Inline rules (for type "inline").
    #[serde(default)]
    pub rules: Option<Vec<RuleIR>>,
    /// Rule set version (for source format).
    #[serde(default)]
    pub version: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── RuleAction serde + as_str + from_str_opt ────────────────────

    #[test]
    fn rule_action_serde_kebab_case() {
        // All variants roundtrip via kebab-case
        let cases = [
            ("\"route\"", RuleAction::Route),
            ("\"reject\"", RuleAction::Reject),
            ("\"reject-drop\"", RuleAction::RejectDrop),
            ("\"hijack\"", RuleAction::Hijack),
            ("\"hijack-dns\"", RuleAction::HijackDns),
            ("\"sniff\"", RuleAction::Sniff),
            ("\"resolve\"", RuleAction::Resolve),
            ("\"route-options\"", RuleAction::RouteOptions),
            ("\"sniff-override\"", RuleAction::SniffOverride),
        ];
        for (json_str, expected) in &cases {
            let parsed: RuleAction = serde_json::from_str(json_str).unwrap();
            assert_eq!(&parsed, expected, "deserialize {json_str}");
            let rt_json = serde_json::to_string(&parsed).unwrap();
            let rt: RuleAction = serde_json::from_str(&rt_json).unwrap();
            assert_eq!(&rt, expected, "roundtrip {json_str}");
        }
    }

    #[test]
    fn rule_action_as_str() {
        assert_eq!(RuleAction::Route.as_str(), "route");
        assert_eq!(RuleAction::Reject.as_str(), "reject");
        assert_eq!(RuleAction::RejectDrop.as_str(), "reject-drop");
        assert_eq!(RuleAction::Hijack.as_str(), "hijack");
        assert_eq!(RuleAction::HijackDns.as_str(), "hijack-dns");
        assert_eq!(RuleAction::Sniff.as_str(), "sniff");
        assert_eq!(RuleAction::Resolve.as_str(), "resolve");
        assert_eq!(RuleAction::RouteOptions.as_str(), "route-options");
        assert_eq!(RuleAction::SniffOverride.as_str(), "sniff-override");
    }

    #[test]
    fn rule_action_from_str_opt_aliases() {
        // kebab-case
        assert_eq!(
            RuleAction::from_str_opt("hijack-dns"),
            Some(RuleAction::HijackDns)
        );
        // underscore alias
        assert_eq!(
            RuleAction::from_str_opt("hijack_dns"),
            Some(RuleAction::HijackDns)
        );
        assert_eq!(
            RuleAction::from_str_opt("reject-drop"),
            Some(RuleAction::RejectDrop)
        );
        assert_eq!(
            RuleAction::from_str_opt("reject_drop"),
            Some(RuleAction::RejectDrop)
        );
        assert_eq!(
            RuleAction::from_str_opt("sniff-override"),
            Some(RuleAction::SniffOverride)
        );
        assert_eq!(
            RuleAction::from_str_opt("sniff_override"),
            Some(RuleAction::SniffOverride)
        );
        assert_eq!(
            RuleAction::from_str_opt("route-options"),
            Some(RuleAction::RouteOptions)
        );
        assert_eq!(
            RuleAction::from_str_opt("route_options"),
            Some(RuleAction::RouteOptions)
        );
        // case insensitive
        assert_eq!(RuleAction::from_str_opt("ROUTE"), Some(RuleAction::Route));
        assert_eq!(RuleAction::from_str_opt("Reject"), Some(RuleAction::Reject));
        // unknown
        assert_eq!(RuleAction::from_str_opt("nonexistent"), None);
    }

    #[test]
    fn rule_action_default_is_route() {
        assert_eq!(RuleAction::default(), RuleAction::Route);
    }

    // ── RuleIR roundtrip ────────────────────────────────────────────

    #[test]
    fn rule_ir_positive_match_roundtrip() {
        let data = json!({
            "domain": ["example.com", "test.org"],
            "domain_suffix": [".cn"],
            "domain_keyword": ["google"],
            "domain_regex": ["^ads?\\."],
            "geosite": ["cn"],
            "geoip": ["CN"],
            "ipcidr": ["10.0.0.0/8"],
            "port": ["80", "443"],
            "process_name": ["chrome"],
            "process_path": ["/usr/bin/chrome"],
            "network": ["tcp"],
            "protocol": ["http"],
            "alpn": ["h2"],
            "wifi_ssid": ["home"],
            "wifi_bssid": ["aa:bb:cc:dd:ee:ff"],
            "rule_set": ["my-set"],
            "rule_set_ipcidr": ["ip-set"],
            "clash_mode": ["rule"],
            "package_name": ["com.example"],
            "outbound": "proxy",
            "action": "route"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, vec!["example.com", "test.org"]);
        assert_eq!(ir.domain_suffix, vec![".cn"]);
        assert_eq!(ir.geoip, vec!["CN"]);
        assert_eq!(ir.port, vec!["80", "443"]);
        assert_eq!(ir.process_name, vec!["chrome"]);
        assert_eq!(ir.wifi_ssid, vec!["home"]);
        assert_eq!(ir.clash_mode, vec!["rule"]);
        assert_eq!(ir.action, RuleAction::Route);
        assert_eq!(ir.outbound.as_deref(), Some("proxy"));

        // roundtrip
        let rt: RuleIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.domain, ir.domain);
        assert_eq!(rt.geoip, ir.geoip);
        assert_eq!(rt.action, ir.action);
    }

    #[test]
    fn rule_ir_negative_match_fields() {
        let data = json!({
            "not_domain": ["blocked.com"],
            "not_domain_suffix": [".bad"],
            "not_domain_keyword": ["spam"],
            "not_domain_regex": ["^evil"],
            "not_geosite": ["ads"],
            "not_geoip": ["US"],
            "not_ipcidr": ["192.168.0.0/16"],
            "not_port": ["8080"],
            "not_process_name": ["malware"],
            "not_process_path": ["/tmp/hack"],
            "not_network": ["udp"],
            "not_protocol": ["socks"],
            "not_alpn": ["h3"],
            "outbound": "direct"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.not_domain, vec!["blocked.com"]);
        assert_eq!(ir.not_domain_suffix, vec![".bad"]);
        assert_eq!(ir.not_geoip, vec!["US"]);
        assert_eq!(ir.not_ipcidr, vec!["192.168.0.0/16"]);
        assert_eq!(ir.not_process_name, vec!["malware"]);
        assert_eq!(ir.not_network, vec!["udp"]);
        assert_eq!(ir.not_alpn, vec!["h3"]);

        let rt: RuleIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.not_domain, ir.not_domain);
        assert_eq!(rt.not_geoip, ir.not_geoip);
    }

    #[test]
    fn rule_ir_deserialize_string_or_list_fields() {
        // Single string should deserialize into a one-element Vec
        let data = json!({
            "domain": "single.com",
            "domain_suffix": ".one",
            "port": "443",
            "process_name": "curl",
            "wifi_ssid": "mywifi",
            "rule_set": "my-ruleset",
            "outbound": "direct"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, vec!["single.com"]);
        assert_eq!(ir.domain_suffix, vec![".one"]);
        assert_eq!(ir.port, vec!["443"]);
        assert_eq!(ir.process_name, vec!["curl"]);
        assert_eq!(ir.wifi_ssid, vec!["mywifi"]);
        assert_eq!(ir.rule_set, vec!["my-ruleset"]);
    }

    #[test]
    fn rule_ir_logical_rule() {
        let data = json!({
            "type": "logical",
            "mode": "and",
            "rules": [
                {"domain_suffix": [".cn"], "outbound": "direct"},
                {"geoip": ["CN"], "outbound": "direct"}
            ],
            "outbound": "direct"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.rule_type.as_deref(), Some("logical"));
        assert_eq!(ir.mode.as_deref(), Some("and"));
        assert_eq!(ir.rules.len(), 2);
        assert_eq!(ir.rules[0].domain_suffix, vec![".cn"]);
        assert_eq!(ir.rules[1].geoip, vec!["CN"]);
    }

    #[test]
    fn rule_ir_action_hijack_dns() {
        let data = json!({
            "domain": ["dns.example.com"],
            "action": "hijack-dns",
            "override_address": "127.0.0.1",
            "override_port": 5353
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.action, RuleAction::HijackDns);
        assert_eq!(ir.override_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(ir.override_port, Some(5353));
    }

    #[test]
    fn rule_ir_action_route_options() {
        let data = json!({
            "action": "route-options",
            "override_android_vpn": true,
            "find_process": true,
            "auto_detect_interface": true,
            "mark": 255,
            "network_strategy": "prefer_ipv4",
            "fallback_network_type": ["wifi"],
            "fallback_delay": "300ms"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.action, RuleAction::RouteOptions);
        assert_eq!(ir.override_android_vpn, Some(true));
        assert_eq!(ir.find_process, Some(true));
        assert_eq!(ir.mark, Some(255));
        assert_eq!(ir.network_strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(
            ir.fallback_network_type.as_deref(),
            Some(&["wifi".to_string()][..])
        );
    }

    #[test]
    fn rule_ir_action_sniff_override() {
        let data = json!({
            "action": "sniff-override",
            "sniffer": "tls",
            "sniff_timeout": "500ms"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.action, RuleAction::SniffOverride);
        assert_eq!(ir.sniffer.as_deref(), Some("tls"));
        assert_eq!(ir.sniff_timeout.as_deref(), Some("500ms"));
    }

    #[test]
    fn rule_ir_invert_and_dns_fields() {
        let data = json!({
            "invert": true,
            "query_type": ["A", "AAAA"],
            "rewrite_ttl": 60,
            "client_subnet": "1.2.3.0/24",
            "outbound": "dns-out"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert!(ir.invert);
        assert_eq!(ir.query_type, vec!["A", "AAAA"]);
        assert_eq!(ir.rewrite_ttl, Some(60));
        assert_eq!(ir.client_subnet.as_deref(), Some("1.2.3.0/24"));
    }

    #[test]
    fn rule_ir_process_name_alias() {
        // "process" alias should map to process_name
        let data = json!({"process": ["firefox"], "outbound": "proxy"});
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.process_name, vec!["firefox"]);
    }

    #[test]
    fn rule_ir_user_uid_alias() {
        // "uid" alias should map to user
        let data = json!({"uid": ["bob"], "outbound": "proxy"});
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.user, vec!["bob"]);
    }

    #[test]
    fn rule_ir_parity_fields() {
        let data = json!({
            "network_is_expensive": true,
            "network_is_constrained": false,
            "ip_accept_any": true,
            "user_id": [1000, 1001],
            "group_id": [100],
            "outbound_tag": ["proxy-out"],
            "adguard": ["||ads.example.org^"],
            "not_adguard": ["@@||safe.example.org^"],
            "outbound": "direct"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.network_is_expensive, Some(true));
        assert_eq!(ir.network_is_constrained, Some(false));
        assert_eq!(ir.ip_accept_any, Some(true));
        assert_eq!(ir.user_id, vec![1000, 1001]);
        assert_eq!(ir.group_id, vec![100]);
        assert_eq!(ir.outbound_tag, vec!["proxy-out"]);
        assert_eq!(ir.adguard, vec!["||ads.example.org^"]);
        assert_eq!(ir.not_adguard, vec!["@@||safe.example.org^"]);
    }

    // ── DomainResolveOptionsIR ──────────────────────────────────────

    #[test]
    fn domain_resolve_options_roundtrip() {
        let data = json!({
            "server": "dns-local",
            "strategy": "prefer_ipv4",
            "disable_cache": true,
            "rewrite_ttl": 120,
            "client_subnet": "10.0.0.0/24"
        });
        let ir: DomainResolveOptionsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.server, "dns-local");
        assert_eq!(ir.strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(ir.disable_cache, Some(true));
        assert_eq!(ir.rewrite_ttl, Some(120));
        assert_eq!(ir.client_subnet.as_deref(), Some("10.0.0.0/24"));

        let rt: DomainResolveOptionsIR =
            serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.server, ir.server);
        assert_eq!(rt.strategy, ir.strategy);
    }

    #[test]
    fn domain_resolve_options_minimal() {
        let data = json!({"server": "local-dns"});
        let ir: DomainResolveOptionsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.server, "local-dns");
        assert!(ir.strategy.is_none());
        assert!(ir.disable_cache.is_none());
    }

    // ── RouteIR ─────────────────────────────────────────────────────

    #[test]
    fn route_ir_roundtrip() {
        let data = json!({
            "rules": [
                {"domain_suffix": [".cn"], "outbound": "direct"},
                {"geoip": ["US"], "outbound": "proxy"}
            ],
            "rule_set": [
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": "https://example.com/geosite-cn.srs", "update_interval": "24h"}
            ],
            "default": "proxy",
            "final": "direct",
            "geoip_path": "/data/geoip.db",
            "geoip_download_url": "https://example.com/geoip.db",
            "geosite_path": "/data/geosite.db",
            "default_rule_set_download_detour": "direct-out",
            "override_android_vpn": false,
            "find_process": true,
            "auto_detect_interface": true,
            "default_interface": "eth0",
            "mark": 100,
            "default_domain_resolver": {"server": "local-dns", "strategy": "ipv4_only"},
            "network_strategy": "prefer_ipv4",
            "default_network_type": ["wifi"],
            "default_fallback_network_type": ["cellular"],
            "default_fallback_delay": "300ms"
        });
        let ir: RouteIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.rules.len(), 2);
        assert_eq!(ir.rule_set.len(), 1);
        assert_eq!(ir.default.as_deref(), Some("proxy"));
        assert_eq!(ir.final_outbound.as_deref(), Some("direct"));
        assert_eq!(ir.geoip_path.as_deref(), Some("/data/geoip.db"));
        assert_eq!(ir.find_process, Some(true));
        assert_eq!(ir.mark, Some(100));
        assert_eq!(
            ir.default_domain_resolver
                .as_ref()
                .map(|d| d.server.as_str()),
            Some("local-dns")
        );
        assert_eq!(ir.network_strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(ir.default_fallback_delay.as_deref(), Some("300ms"));

        // roundtrip
        let rt: RouteIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.rules.len(), ir.rules.len());
        assert_eq!(rt.default, ir.default);
        assert_eq!(rt.mark, ir.mark);
    }

    #[test]
    fn route_ir_final_alias() {
        // "final" JSON key should map to final_outbound via alias
        let data = json!({"final": "fallback"});
        let ir: RouteIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.final_outbound.as_deref(), Some("fallback"));
    }

    #[test]
    fn route_ir_empty_default() {
        let ir = RouteIR::default();
        assert!(ir.rules.is_empty());
        assert!(ir.rule_set.is_empty());
        assert!(ir.default.is_none());
        assert!(ir.final_outbound.is_none());
        assert!(ir.default_domain_resolver.is_none());

        let rt: RouteIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert!(rt.rules.is_empty());
    }

    // ── RuleSetIR ───────────────────────────────────────────────────

    #[test]
    fn rule_set_ir_local() {
        let data = json!({
            "tag": "local-rules",
            "type": "local",
            "format": "source",
            "path": "/etc/sing-box/rules.json"
        });
        let ir: RuleSetIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.tag, "local-rules");
        assert_eq!(ir.ty, "local");
        assert_eq!(ir.format, "source");
        assert_eq!(ir.path.as_deref(), Some("/etc/sing-box/rules.json"));
        assert!(ir.url.is_none());
        assert!(ir.rules.is_none());

        let rt: RuleSetIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.tag, ir.tag);
        assert_eq!(rt.ty, ir.ty);
    }

    #[test]
    fn rule_set_ir_remote() {
        let data = json!({
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://example.com/geosite-cn.srs",
            "download_detour": "direct",
            "update_interval": "24h"
        });
        let ir: RuleSetIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.tag, "geosite-cn");
        assert_eq!(ir.ty, "remote");
        assert_eq!(ir.format, "binary");
        assert_eq!(
            ir.url.as_deref(),
            Some("https://example.com/geosite-cn.srs")
        );
        assert_eq!(ir.download_detour.as_deref(), Some("direct"));
        assert_eq!(ir.update_interval.as_deref(), Some("24h"));
    }

    #[test]
    fn rule_set_ir_inline() {
        let data = json!({
            "tag": "inline-rules",
            "type": "inline",
            "rules": [
                {"domain": ["example.com"], "outbound": "proxy"}
            ],
            "version": 2
        });
        let ir: RuleSetIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.tag, "inline-rules");
        assert_eq!(ir.ty, "inline");
        let rules = ir.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].domain, vec!["example.com"]);
        assert_eq!(ir.version, Some(2));
    }

    #[test]
    fn rule_set_ir_type_rename() {
        // Verify "type" JSON key maps to `ty` field
        let data = json!({"tag": "t", "type": "local"});
        let ir: RuleSetIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, "local");
        let rt = serde_json::to_value(&ir).unwrap();
        assert_eq!(rt["type"], "local");
        assert!(rt.get("ty").is_none());
    }
}
