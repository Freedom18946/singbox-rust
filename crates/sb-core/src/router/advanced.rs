//! 高阶路由策略引擎（预研版）
//!
//! 目标
//! - 以"条件 + 动作"的形式表达更复杂的路由逻辑；
//! - 条件可由多原子条件（域名/关键字/IP/CIDR/端口/时间段/网络接口等）以 AND/OR/NOT 组合；
//! - 动作可指向不同出站、标记优先级、开关测速、打点等；
//! - 作为 `engine.rs` 规则表的增强层，先行提供构建块，逐步接入。
//!
//! 说明
//! - 该模块当前**不与现有引擎强耦合**；提供独立的 `AdvEngine` 与 `Rule` 构建 API；
//! - 后续只需在 `engine.rs` 的编译阶段把已有规则编译为 `AdvRule` 即可接入；
//! - 代码包含充分注释，便于二次扩展（例如接入脚本/DSL）。
//!
//! 编译注意
//! - 所有对外类型都挂在本模块命名空间下，不与现有类型冲突；
//! - 未在主线调用，不影响当前功能；但完整可编译、可单测（见 `#[cfg(test)]`）。

use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
};

use ipnet::IpNet;

/// 匹配目标（待路由的五元组子集）
#[derive(Clone, Debug, Default)]
pub struct Target {
    pub host: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub proto: Option<Proto>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Proto {
    Tcp,
    Udp,
    Quic,
}

/// 条件的原子类型
#[derive(Clone, Debug)]
pub enum AtomCond {
    /// 完整域名匹配（大小写不敏感）
    DomainExact(String),
    /// 域名后缀匹配（大小写不敏感，自动消除前导点）
    DomainSuffix(String),
    /// 域名包含关键字（大小写不敏感）
    DomainKeyword(String),
    /// IP/CIDR 匹配
    IpCidr(IpNet),
    /// 端口匹配（单端口）
    Port(u16),
    /// 端口范围（闭区间）
    PortRange(u16, u16),
    /// 协议匹配
    Proto(Proto),
    /// 总是为真（占位/兜底）
    Any,
    /// 总是为假（占位/禁用）
    None,
}

impl AtomCond {
    fn hit(&self, t: &Target) -> bool {
        match self {
            AtomCond::DomainExact(s) => {
                if let Some(h) = &t.host {
                    normalize(h) == normalize(s)
                } else { false }
            }
            AtomCond::DomainSuffix(suf) => {
                if let Some(h) = &t.host {
                    domain_has_suffix(h, suf)
                } else { false }
            }
            AtomCond::DomainKeyword(kw) => {
                if let Some(h) = &t.host {
                    h.to_ascii_lowercase().contains(&kw.to_ascii_lowercase())
                } else { false }
            }
            AtomCond::IpCidr(cidr) => {
                if let Some(ip) = t.ip {
                    cidr.contains(&ip)
                } else { false }
            }
            AtomCond::Port(p) => t.port.map(|x| x == *p).unwrap_or(false),
            AtomCond::PortRange(a, b) => {
                if let Some(p) = t.port { p >= *a && p <= *b } else { false }
            }
            AtomCond::Proto(p) => t.proto.map(|x| x == *p).unwrap_or(false),
            AtomCond::Any => true,
            AtomCond::None => false,
        }
    }
}

/// 复合条件：以 AND/OR/NOT 组合
#[derive(Clone, Debug)]
pub enum Cond {
    Atom(AtomCond),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
}

impl Cond {
    pub fn atom(c: AtomCond) -> Self { Cond::Atom(c) }
    pub fn and<I: IntoIterator<Item = Cond>>(it: I) -> Self { Cond::And(it.into_iter().collect()) }
    pub fn or<I: IntoIterator<Item = Cond>>(it: I) -> Self { Cond::Or(it.into_iter().collect()) }
    pub fn not(c: Cond) -> Self { Cond::Not(Box::new(c)) }

    pub fn hit(&self, t: &Target) -> bool {
        match self {
            Cond::Atom(a) => a.hit(t),
            Cond::And(cs) => cs.iter().all(|c| c.hit(t)),
            Cond::Or(cs) => cs.iter().any(|c| c.hit(t)),
            Cond::Not(c) => !c.hit(t),
        }
    }
}

/// 动作：目前先覆盖出站名称与标记（可扩展）
#[derive(Clone, Debug)]
pub enum Action {
    UseOutbound(String),
    Mark(String),
    // 保留字段：未来扩展
    // MeasureLatency,
    // RecordLabel(String),
}

/// 编排规则
#[derive(Clone, Debug)]
pub struct AdvRule {
    pub name: String,
    pub cond: Cond,
    pub action: Action,
    pub priority: i32, // 越大越先匹配
}

impl AdvRule {
    pub fn builder(name: impl Into<String>) -> AdvRuleBuilder {
        AdvRuleBuilder {
            name: name.into(),
            cond: Cond::atom(AtomCond::Any),
            action: Action::Mark("pass".into()),
            priority: 0,
        }
    }
}

/// 规则构建器（链式）
pub struct AdvRuleBuilder {
    name: String,
    cond: Cond,
    action: Action,
    priority: i32,
}

impl AdvRuleBuilder {
    pub fn when(mut self, cond: Cond) -> Self { self.cond = cond; self }
    pub fn to(mut self, action: Action) -> Self { self.action = action; self }
    pub fn priority(mut self, p: i32) -> Self { self.priority = p; self }
    pub fn build(self) -> AdvRule {
        AdvRule { name: self.name, cond: self.cond, action: self.action, priority: self.priority }
    }
}

/// 引擎：持有一组规则，按优先级与顺序评估
#[derive(Default)]
pub struct AdvEngine {
    rules: Vec<AdvRule>,
    // 统计信息
    hits_by_rule: BTreeMap<String, u64>,
}

impl AdvEngine {
    pub fn new() -> Self { Self::default() }

    pub fn with_rules<I: IntoIterator<Item = AdvRule>>(mut self, it: I) -> Self {
        self.add_rules(it);
        self
    }

    pub fn add_rules<I: IntoIterator<Item = AdvRule>>(&mut self, it: I) {
        self.rules.extend(it);
        self.rules.sort_by_key(|r| -r.priority);
    }

    pub fn evaluate(&mut self, t: &Target) -> Option<&Action> {
        for r in &self.rules {
            if r.cond.hit(t) {
                *self.hits_by_rule.entry(r.name.clone()).or_insert(0) += 1;
                return Some(&r.action);
            }
        }
        None
    }

    pub fn stats(&self) -> BTreeMap<String, u64> {
        self.hits_by_rule.clone()
    }
}

/// 小工具：域名规范化
fn normalize(s: &str) -> String {
    let mut h = s.to_ascii_lowercase();
    if let Some(x) = h.strip_prefix('.') { h = x.to_string(); }
    h
}

fn domain_has_suffix(host: &str, suffix: &str) -> bool {
    let h = normalize(host);
    let suf = normalize(suffix);
    if h == suf { return true; }
    h.ends_with(&format!(".{suf}"))
}

///--- 便捷构建 API（面向上层编译器） ---------------------------------------

/// 快速构建：域名 exact/suffix/keyword -> 出站
pub fn rule_domain_exact(name: impl Into<String>, exact: impl Into<String>, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::DomainExact(exact.into())))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_domain_suffix(name: impl Into<String>, suf: impl Into<String>, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::DomainSuffix(suf.into())))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_domain_keyword(name: impl Into<String>, kw: impl Into<String>, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::DomainKeyword(kw.into())))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_ip_cidr(name: impl Into<String>, cidr: IpNet, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::IpCidr(cidr)))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_port(name: impl Into<String>, port: u16, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::Port(port)))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_port_range(name: impl Into<String>, a: u16, b: u16, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::PortRange(a, b)))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

pub fn rule_proto(name: impl Into<String>, p: Proto, outbound: impl Into<String>, prio: i32) -> AdvRule {
    AdvRule::builder(name)
        .when(Cond::atom(AtomCond::Proto(p)))
        .to(Action::UseOutbound(outbound.into()))
        .priority(prio)
        .build()
}

/// 组合：AND(&[...]) / OR(&[...]) / NOT(...)
pub fn rule_and(name: impl Into<String>, conds: Vec<Cond>, action: Action, prio: i32) -> AdvRule {
    AdvRule::builder(name).when(Cond::and(conds)).to(action).priority(prio).build()
}
pub fn rule_or(name: impl Into<String>, conds: Vec<Cond>, action: Action, prio: i32) -> AdvRule {
    AdvRule::builder(name).when(Cond::or(conds)).to(action).priority(prio).build()
}
pub fn rule_not(name: impl Into<String>, cond: Cond, action: Action, prio: i32) -> AdvRule {
    AdvRule::builder(name).when(Cond::not(cond)).to(action).priority(prio).build()
}

/// 示例：把常用域名规则编译为高优先级规则集
pub fn compile_common_domain_rules(list_exact: &[String], list_suffix: &[String], list_keyword: &[String], outbound: &str) -> Vec<AdvRule> {
    let mut out = Vec::with_capacity(list_exact.len() + list_suffix.len() + list_keyword.len());
    for e in list_exact {
        out.push(rule_domain_exact(format!("exact:{e}"), e.clone(), outbound.to_string(), 1000));
    }
    for s in list_suffix {
        out.push(rule_domain_suffix(format!("suffix:{s}"), s.clone(), outbound.to_string(), 900));
    }
    for k in list_keyword {
        out.push(rule_domain_keyword(format!("keyword:{k}"), k.clone(), outbound.to_string(), 800));
    }
    out
}

        // -------------------- 统计与可视化导出（占位） -------------------------
#[derive(Default)]
pub struct AdvStats {
    pub rules: BTreeMap<String, u64>,
}

impl fmt::Display for AdvStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "AdvEngine Stats:")?;
        for (k, v) in &self.rules {
            writeln!(f, "  {k}: {v}")?;
        }
        Ok(())
    }
}

/// 导出引擎统计（快照）
pub fn snapshot_stats(engine: &AdvEngine) -> AdvStats {
    AdvStats { rules: engine.stats() }
}

        // ---------------------------- 单元测试 ---------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_domain_suffix() {
        assert!(domain_has_suffix("a.b.EXAMPLE.com", "example.com"));
        assert!(domain_has_suffix("example.com", ".example.com"));
        assert!(!domain_has_suffix("evil-example.com", "example.com"));
    }

    #[test]
    fn t_atom_hit() {
        let t = Target { host: Some("api.test.com".into()), ip: None, port: Some(443), proto: Some(Proto::Tcp) };
        assert!(AtomCond::DomainSuffix("test.com".into()).hit(&t));
        assert!(AtomCond::Port(443).hit(&t));
        assert!(AtomCond::Proto(Proto::Tcp).hit(&t));
        assert!(!AtomCond::Port(80).hit(&t));
    }

    #[test]
    fn t_adv_rules() {
        let mut eng = AdvEngine::new();
        eng.add_rules([
            rule_domain_suffix("r1", "example.com", "proxy", 10),
            rule_port("r2", 443, "tls", 20),
        ]);
        let t = Target { host: Some("a.example.com".into()), ip: None, port: Some(443), proto: Some(Proto::Tcp) };
        let act = eng.evaluate(&t).unwrap();
        match act {
            Action::UseOutbound(x) => assert_eq!(x, "tls"),
            _ => assert!(false, "Expected UseOutbound action, got unexpected action type"),
        }
        let snap = snapshot_stats(&eng);
        assert_eq!(*snap.rules.get("r2").unwrap_or(&0), 1);
    }
}