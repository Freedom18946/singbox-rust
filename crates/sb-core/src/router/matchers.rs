//! 兼容旧代码的匹配器函数（只暴露简单函数接口）
//! 说明：
//! - `engine.rs` 里仍然在用 `super::matchers::domain_has_suffix(...)` 之类的调用，
//!   这里提供同名函数以避免大改。
//! - 内部实现走 `crate::router::matcher` 的规范逻辑（统一大小写 / 去前导点）。

use crate::router::matcher::DomainRuleSet;

fn normalize_host(s: &str) -> String {
    let mut h = s.to_ascii_lowercase();
    if let Some(stripped) = h.strip_prefix('.') {
        h = stripped.to_string();
    }
    h
}

fn normalize_suffix(s: &str) -> String {
    let mut suf = s.to_ascii_lowercase();
    if let Some(stripped) = suf.strip_prefix('.') {
        suf = stripped.to_string();
    }
    suf
}

/// 旧接口：host 是否匹配指定后缀
pub fn domain_has_suffix(host: &str, suffix: &str) -> bool {
    let host_l = normalize_host(host);
    let suf = normalize_suffix(suffix);
    if host_l == suf { return true; }
    host_l.ends_with(&format!(".{suf}"))
}

/// 旧接口：host 是否包含关键字（子串）
pub fn domain_contains_keyword(host: &str, keyword: &str) -> bool {
    host.to_ascii_lowercase().contains(&keyword.to_ascii_lowercase())
}

/// 旧接口：host 是否精确匹配
pub fn domain_exact(host: &str, full: &str) -> bool {
    normalize_host(host) == normalize_host(full)
}

/// 高阶：基于规则集合检查（exact > suffix > keyword）
pub fn match_with_rules(host: &str, exact: &[String], suffix: &[String], keyword: &[String]) -> Option<&'static str> {
    let set = DomainRuleSet::new(
        exact.iter().cloned(),
        suffix.iter().cloned(),
        keyword.iter().cloned(),
    );
    set.match_kind(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_suffix() {
        assert!(domain_has_suffix("a.b.example.com", "example.com"));
        assert!(domain_has_suffix("example.com", ".example.com"));
        assert!(!domain_has_suffix("evil-example.com", "example.com"));
    }

    #[test]
    fn test_exact() {
        assert!(domain_exact("foo.bar", "foo.bar"));
        assert!(domain_exact(".Foo.Bar", "foo.bar"));
        assert!(!domain_exact("x.foo.bar", "foo.bar"));
    }
}