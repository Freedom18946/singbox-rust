//! 路由匹配器集合（Domain 后缀/关键字/精确；IP CIDR）
//!
//! 对齐 WBS 15.4：规则载入与匹配执行的基础能力。
//! 该模块目前**不直接耦合** `engine.rs`，先提供稳定 API，后续在引擎中接入。
//!
//! 设计思路：
//! - Domain 采用三类集合：suffix/keyword/exact，匹配顺序 exact > suffix > keyword。
//! - IP 使用 `ipnet` 做 CIDR 解析与匹配。
//! - API 均为无状态匹配方法，可在上层封装读写锁或原子替换以实现热更新。

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// 域名规则集合
#[derive(Debug, Default, Clone)]
pub struct DomainRuleSet {
    /// 完整精确匹配：如 `example.com`
    exact: HashSet<String>,
    /// 后缀匹配：如 `.example.com`/`example.com`（内部统一为不带前导点）
    suffix: BTreeSet<String>,
    /// 关键字匹配：子串包含（不建议大量使用）
    keyword: HashSet<String>,
}

impl DomainRuleSet {
    /// 构建：传入 exact/suffix/keyword 三类列表
    pub fn new<I1, I2, I3>(exact: I1, suffix: I2, keyword: I3) -> Self
    where
        I1: IntoIterator<Item = String>,
        I2: IntoIterator<Item = String>,
        I3: IntoIterator<Item = String>,
    {
        let exact: HashSet<String> = exact
            .into_iter()
            .map(Self::normalize)
            .collect();
        let suffix: BTreeSet<String> = suffix
            .into_iter()
            .map(Self::normalize)
            .collect();
        let keyword: HashSet<String> = keyword
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();
        Self { exact, suffix, keyword }
    }

    /// 从统一的字符串列表加载，带前缀语义：
            // - `full:example.com` -> exact
            // - `suffix:example.com` -> suffix
            // - `keyword:foo` -> keyword
    pub fn from_tagged_rules<I>(rules: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut exact = HashSet::new();
        let mut suffix = BTreeSet::new();
        let mut keyword = HashSet::new();
        for r in rules {
            let r = r.trim().to_string();
            if r.is_empty() { continue; }
            if let Some(rest) = r.strip_prefix("full:") {
                exact.insert(Self::normalize(rest.to_string()));
            } else if let Some(rest) = r.strip_prefix("suffix:") {
                suffix.insert(Self::normalize(rest.to_string()));
            } else if let Some(rest) = r.strip_prefix("keyword:") {
                keyword.insert(rest.to_lowercase());
            } else {
                // 默认作为 suffix
                suffix.insert(Self::normalize(r));
            }
        }
        Self { exact, suffix, keyword }
    }

    /// 判断 host 是否匹配集合（匹配顺序：exact > suffix > keyword）
    pub fn matches_host(&self, host: &str) -> bool {
        let h = Self::normalize(host.to_string());
        if self.exact.contains(&h) {
            return true;
        }
        if self.suffix_match(&h) {
            return true;
        }
        self.keyword_match(&h)
    }

    /// 获取命中类型（用于上层打点/调试）
    pub fn match_kind(&self, host: &str) -> Option<&'static str> {
        let h = Self::normalize(host.to_string());
        if self.exact.contains(&h) {
            return Some("exact");
        }
        if self.suffix_match(&h) {
            return Some("suffix");
        }
        if self.keyword_match(&h) {
            return Some("keyword");
        }
        None
    }

    fn normalize(mut s: String) -> String {
        s.make_ascii_lowercase();
        // 统一去掉首位的点
        if let Some(stripped) = s.strip_prefix('.') {
            stripped.to_string()
        } else {
            s
        }
    }

    fn suffix_match(&self, host: &str) -> bool {
        // 直接后缀匹配：`a.b.example.com` 命中 `example.com`
        // 由于 BTreeSet 有序，从短到长扫描效率尚可（后续可做倒排索引/Trie）
        for suf in self.suffix.iter() {
            if host == suf || host.ends_with(&format!(".{suf}")) {
                return true;
            }
        }
        false
    }

    fn keyword_match(&self, host: &str) -> bool {
        // 关键字子串匹配
        for kw in self.keyword.iter() {
            if host.contains(kw) {
                return true;
            }
        }
        false
    }
}

/// IP CIDR 集合
#[derive(Debug, Default, Clone)]
pub struct IpCidrSet {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

impl IpCidrSet {
    pub fn new() -> Self {
        Self { v4: Vec::new(), v6: Vec::new() }
    }

    /// 从字符串列表加载，如：`"10.0.0.0/8"`, `"192.168.0.0/16"`, `"2001:db8::/32"`
    pub fn load<I>(&mut self, cidrs: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        for c in cidrs {
            let c = c.trim();
            if c.is_empty() { continue; }
            let net: IpNet = c.parse()
                .map_err(|e| anyhow::anyhow!("invalid cidr '{}': {e}", c))?;
            match net {
                IpNet::V4(n) => self.v4.push(n),
                IpNet::V6(n) => self.v6.push(n),
            }
        }
        Ok(())
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                self.v4.iter().any(|n| n.contains(&v4))
            }
            IpAddr::V6(v6) => {
                self.v6.iter().any(|n| n.contains(&v6))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_exact() {
        let r = DomainRuleSet::new(
            ["example.com".to_string()],
            [],
            []
        );
        assert!(r.matches_host("example.com"));
        assert!(!r.matches_host("a.example.com"));
    }

    #[test]
    fn test_domain_suffix() {
        let r = DomainRuleSet::new(
            [],
            ["example.com".to_string(), ".foo.bar".to_string()],
            []
        );
        assert!(r.matches_host("a.example.com"));
        assert!(r.matches_host("example.com"));
        assert!(r.matches_host("x.foo.bar"));
        assert!(!r.matches_host("evil-example.com"));
    }

    #[test]
    fn test_domain_keyword() {
        let r = DomainRuleSet::new(
            [],
            [],
            ["cdn".to_string(), "img".to_string()]
        );
        assert!(r.matches_host("fastly.cdn.net"));
        assert!(r.matches_host("static-img.example.com"));
        assert!(!r.matches_host("example.com"));
    }

    #[test]
    fn test_match_order() {
        let r = DomainRuleSet::new(
            ["foo.bar".to_string()],
            ["bar".to_string()],
            ["oo".to_string()],
        );
        assert_eq!(r.match_kind("foo.bar"), Some("exact"));
        assert_eq!(r.match_kind("x.bar"), Some("suffix"));
        assert_eq!(r.match_kind("zoo"), Some("keyword"));
        assert_eq!(r.match_kind("none"), None);
    }

    #[test]
    fn test_ip_cidr() {
        let mut s = IpCidrSet::new();
        s.load([
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
            "2001:db8::/32".to_string(),
        ]).unwrap();

        assert!(s.matches_ip(IpAddr::from([10, 1, 2, 3])));
        assert!(s.matches_ip(IpAddr::from([192, 168, 1, 1])));
        assert!(s.matches_ip("2001:db8::1".parse().unwrap()));
        assert!(!s.matches_ip(IpAddr::from([8, 8, 8, 8])));
    }
}