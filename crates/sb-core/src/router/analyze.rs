//! R8: 规则离线分析（轻量，默认不影响运行路径）
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]
#[cfg(any(feature = "json", feature = "analyze_json"))]
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(any(feature = "json", feature = "analyze_json"))]
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Report {
    pub total_rules: usize,
    pub exact: usize,
    pub suffix: usize,
    pub ports: usize,
    pub portranges: usize,
    pub transports: usize,
    pub cidrs: usize,
    pub geoip: usize,
    pub defaults: usize,
    pub shadows: Vec<Shadow>,     // exact 被 suffix 等遮蔽
    pub conflicts: Vec<Conflict>, // 同一键值重复但决策不同
    pub suggestions: Vec<String>, // 合并相邻 portrange 等
}

#[derive(Debug, Clone)]
#[cfg_attr(
    any(feature = "analyze_json", feature = "rules_tool"),
    derive(serde::Serialize)
)]
pub struct Shadow {
    pub kind: &'static str, // "suffix_over_exact" | "cidr_over_ip" ...
    pub victim: String,
    pub by: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    any(feature = "analyze_json", feature = "rules_tool"),
    derive(serde::Serialize)
)]
pub struct Conflict {
    pub key: String,
    pub a: String,
    pub b: String,
}

impl Report {
    #[cfg(feature = "analyze_json")]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
    /// R35: 无 serde 时也能输出 JSON（内部使用）
    pub fn to_minijson(&self) -> String {
        use crate::router::minijson::{self, Val};
        minijson::obj([
            ("total_rules", Val::NumU(self.total_rules as u64)),
            ("exact", Val::NumU(self.exact as u64)),
            ("suffix", Val::NumU(self.suffix as u64)),
            ("ports", Val::NumU(self.ports as u64)),
            ("portranges", Val::NumU(self.portranges as u64)),
            ("transports", Val::NumU(self.transports as u64)),
            ("cidrs", Val::NumU(self.cidrs as u64)),
            ("geoip", Val::NumU(self.geoip as u64)),
            ("defaults", Val::NumU(self.defaults as u64)),
            ("shadows", Val::NumU(self.shadows.len() as u64)),
            ("conflicts", Val::NumU(self.conflicts.len() as u64)),
            ("suggestions", Val::NumU(self.suggestions.len() as u64)),
        ])
    }
}

#[cfg(any(feature = "analyze_json", feature = "rules_tool"))]
impl serde::Serialize for Report {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("Report", 12)?;
        st.serialize_field("total_rules", &self.total_rules)?;
        st.serialize_field("exact", &self.exact)?;
        st.serialize_field("suffix", &self.suffix)?;
        st.serialize_field("ports", &self.ports)?;
        st.serialize_field("portranges", &self.portranges)?;
        st.serialize_field("transports", &self.transports)?;
        st.serialize_field("cidrs", &self.cidrs)?;
        st.serialize_field("geoip", &self.geoip)?;
        st.serialize_field("defaults", &self.defaults)?;
        st.serialize_field("shadows", &self.shadows)?;
        st.serialize_field("conflicts", &self.conflicts)?;
        st.serialize_field("suggestions", &self.suggestions)?;
        st.end()
    }
}

pub fn analyze(text: &str) -> Report {
    // 朴素扫描，不依赖运行时索引结构，避免引入复杂依赖
    let mut r = Report {
        total_rules: 0,
        exact: 0,
        suffix: 0,
        ports: 0,
        portranges: 0,
        transports: 0,
        cidrs: 0,
        geoip: 0,
        defaults: 0,
        shadows: vec![],
        conflicts: vec![],
        suggestions: vec![],
    };
    let mut exact_map: BTreeMap<String, String> = BTreeMap::new();
    let mut suffix_vec: Vec<(String, String)> = Vec::new(); // (domain, decision)
    let mut cidr_vec_v4: Vec<(ipnet::Ipv4Net, String)> = Vec::new();
    let mut ip_lits_v4: Vec<(std::net::Ipv4Addr, String)> = Vec::new();
    let mut port_ranges: Vec<(u16, u16, String)> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        r.total_rules += 1;
        macro_rules! lhs_rhs {
            ($prefix:literal) => {{
                if let Some(rest) = line.strip_prefix($prefix) {
                    if let Some((lhs, rhs)) = rest.split_once('=') {
                        (lhs.trim().to_string(), rhs.trim().to_string())
                    } else {
                        (String::new(), String::new())
                    }
                } else {
                    (String::new(), String::new())
                }
            }};
        }
        if line.starts_with("exact:") {
            r.exact += 1;
            let (k, v) = lhs_rhs!("exact:");
            if let Some(prev) = exact_map.insert(k.clone(), v.clone()) {
                if prev != v {
                    r.conflicts.push(Conflict {
                        key: k,
                        a: prev,
                        b: v,
                    });
                }
            }
            continue;
        }
        if line.starts_with("suffix:") {
            r.suffix += 1;
            let (k, v) = lhs_rhs!("suffix:");
            suffix_vec.push((k, v));
            continue;
        }
        if line.starts_with("cidr4:") {
            r.cidrs += 1;
            if let Some((lhs, rhs)) = line.strip_prefix("cidr4:").and_then(|s| s.split_once('=')) {
                if let Ok(net) = lhs.trim().parse::<ipnet::Ipv4Net>() {
                    cidr_vec_v4.push((net, rhs.trim().to_string()));
                }
            }
            continue;
        }
        if line.starts_with("ip:") {
            // 扩展：字面量 IPv4
            if let Some((lhs, rhs)) = line.strip_prefix("ip:").and_then(|s| s.split_once('=')) {
                if let Ok(addr) = lhs.trim().parse::<std::net::Ipv4Addr>() {
                    ip_lits_v4.push((addr, rhs.trim().to_string()));
                }
            }
            continue;
        }
        if line.starts_with("port:") {
            r.ports += 1;
            continue;
        }
        if line.starts_with("portrange:") {
            r.portranges += 1;
            if let Some((lhs, _)) = line
                .strip_prefix("portrange:")
                .and_then(|s| s.split_once('='))
            {
                let mut it = lhs.split('-').filter_map(|x| x.trim().parse::<u16>().ok());
                if let (Some(a), Some(b)) = (it.next(), it.next()) {
                    let dec = line.split('=').nth(1).unwrap_or("").trim().to_string();
                    port_ranges.push((a.min(b), a.max(b), dec));
                }
            }
            continue;
        }
        if line.starts_with("transport:") {
            r.transports += 1;
            continue;
        }
        if line.starts_with("cidr") {
            r.cidrs += 1;
            continue;
        }
        if line.starts_with("geoip:") {
            r.geoip += 1;
            continue;
        }
        if line.starts_with("default:") {
            r.defaults += 1;
            continue;
        }
    }
    // 阴影 1：suffix 覆盖 exact
    for (dom, by_dec) in &suffix_vec {
        for (ex, ex_dec) in exact_map.iter() {
            if ex.ends_with(dom) && by_dec != ex_dec {
                r.shadows.push(Shadow {
                    kind: "suffix_over_exact",
                    victim: format!("exact:{}", ex),
                    by: format!("suffix:{}", dom),
                });
            }
        }
    }
    // 阴影 2：CIDR 覆盖 literal IP
    for (net, by_dec) in &cidr_vec_v4 {
        for (ip, dec) in &ip_lits_v4 {
            if net.contains(ip) && by_dec != dec {
                r.shadows.push(Shadow {
                    kind: "cidr_over_ip",
                    victim: format!("ip:{}", ip),
                    by: format!("cidr4:{}", net),
                });
            }
        }
    }
    // 建议：合并相邻/重叠 portrange（同决策）
    port_ranges.sort_by_key(|(a, b, _)| (*a, *b));
    let mut i = 0usize;
    while i + 1 < port_ranges.len() {
        let (a0, b0, d0) = &port_ranges[i];
        let (a1, b1, d1) = &port_ranges[i + 1];
        if d0 == d1 && (*b0 + 1 >= *a1) {
            r.suggestions.push(format!(
                "merge portrange:{}-{} & {}-{} -> {}-{} [{}]",
                a0, b0, a1, b1, a0, b1, d0
            ));
        }
        i += 1;
    }
    r
}

#[derive(Clone, Debug)]
pub struct AnalyzeIssue {
    pub code: &'static str, // "ConflictRule" | "UnreachableOutbound" | "ConflictRuleGroup" | "UnreachableOutboundGroup"
    pub ptr: String,        // RFC6901，尽可能指到 /route/rules/N
    pub msg: String,
    pub rule_id: Option<String>,
    pub key: Option<String>, // "exact:api.foo.com" / "suffix:example.com"
    pub members: Option<Vec<usize>>, // 组内规则索引
    pub tos: Option<Vec<String>>, // 组内 outbounds 去向集合
}

/// 从规范化规则视图分析潜在问题（只读，零副作用）
#[cfg(any(feature = "json", feature = "analyze_json"))]
pub fn analyze_rules(view: &Value) -> Vec<AnalyzeIssue> {
    let mut issues = Vec::new();
    let rules = view
        .get("route")
        .and_then(|r| r.get("rules"))
        .and_then(|x| x.as_array());
    if rules.is_none() {
        return issues;
    }
    let rules = rules.unwrap();

    // 不可达：收集 outbounds 列表
    let mut known_out = std::collections::HashSet::new();
    if let Some(outs) = view.get("outbounds").and_then(|x| x.as_array()) {
        for o in outs {
            if let Some(n) = o.get("name").and_then(|v| v.as_str()) {
                known_out.insert(n.to_string());
            }
        }
    }

    // 1) exact/suffix 冲突：同 key 多 to（组级 + 逐条）
    let mut exact_map: HashMap<String, BTreeMap<usize, String>> = HashMap::new();
    let mut suffix_map: HashMap<String, BTreeMap<usize, String>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        let to = r
            .get("to")
            .and_then(|v| v.as_str())
            .unwrap_or("direct")
            .to_string();
        if let Some(host) = r
            .get("when")
            .and_then(|w| w.get("host"))
            .and_then(|v| v.as_str())
        {
            exact_map
                .entry(host.to_string())
                .or_default()
                .insert(i, to.clone());
        }
        if let Some(suf) = r
            .get("when")
            .and_then(|w| w.get("suffix"))
            .and_then(|v| v.as_str())
        {
            suffix_map
                .entry(suf.to_string())
                .or_default()
                .insert(i, to.clone());
        }
        // 不可达出口
        if !known_out.is_empty() && !known_out.contains(to.as_str()) {
            issues.push(AnalyzeIssue {
                code: "UnreachableOutbound",
                ptr: format!("/route/rules/{}", i),
                msg: format!("rule references unknown outbound '{}'", to),
                rule_id: None,
                key: None,
                members: None,
                tos: None,
            });
        }
    }
    for (host, m) in exact_map {
        let mut tos = std::collections::HashSet::new();
        for (_, to) in m.iter() {
            tos.insert(to);
        }
        if tos.len() > 1 {
            // 组级
            let members: Vec<usize> = m.keys().cloned().collect();
            let to_sample = m.values().next().cloned().unwrap_or_default();
            let tos_vec: Vec<String> = tos.iter().map(|s| s.to_string()).collect();
            issues.push(AnalyzeIssue {
                code: "ConflictRuleGroup",
                ptr: "/route/rules".into(),
                msg: format!(
                    "exact '{}' conflicts; members={:?}; tos~{}",
                    host, members, to_sample
                ),
                rule_id: None,
                key: Some(format!("exact:{}", host)),
                members: Some(members),
                tos: Some(tos_vec),
            });
            // 逐条
            for (idx, to) in m {
                issues.push(AnalyzeIssue {
                    code: "ConflictRule",
                    ptr: format!("/route/rules/{}", idx),
                    msg: format!(
                        "exact host '{}' maps to multiple outbounds (e.g. '{}')",
                        host, to
                    ),
                    rule_id: None,
                    key: None,
                    members: None,
                    tos: None,
                });
            }
        }
    }
    for (suf, m) in suffix_map {
        let mut tos = std::collections::HashSet::new();
        for (_, to) in m.iter() {
            tos.insert(to);
        }
        if tos.len() > 1 {
            let members: Vec<usize> = m.keys().cloned().collect();
            let to_sample = m.values().next().cloned().unwrap_or_default();
            let tos_vec: Vec<String> = tos.iter().map(|s| s.to_string()).collect();
            issues.push(AnalyzeIssue {
                code: "ConflictRuleGroup",
                ptr: "/route/rules".into(),
                msg: format!(
                    "suffix '*.{}' conflicts; members={:?}; tos~{}",
                    suf, members, to_sample
                ),
                rule_id: None,
                key: Some(format!("suffix:{}", suf)),
                members: Some(members),
                tos: Some(tos_vec),
            });
            for (idx, to) in m {
                issues.push(AnalyzeIssue {
                    code: "ConflictRule",
                    ptr: format!("/route/rules/{}", idx),
                    msg: format!(
                        "suffix '*.{}' maps to multiple outbounds (e.g. '{}')",
                        suf, to
                    ),
                    rule_id: None,
                    key: None,
                    members: None,
                    tos: None,
                });
            }
        }
    }

    // 2) UnreachableOutbound 组级聚合
    if !known_out.is_empty() {
        let mut group: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, r) in rules.iter().enumerate() {
            if let Some(to) = r.get("to").and_then(|v| v.as_str()) {
                if !known_out.contains(to) {
                    group.entry(to.to_string()).or_default().push(i);
                }
            }
        }
        for (to, members) in group {
            issues.push(AnalyzeIssue {
                code: "UnreachableOutboundGroup",
                ptr: "/outbounds".into(),
                msg: format!("outbound '{}' unreachable; members={:?}", to, members),
                rule_id: None,
                key: None,
                members: Some(members),
                tos: Some(vec![to]),
            });
        }
    }
    issues
}
