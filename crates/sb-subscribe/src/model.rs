use thiserror::Error;

#[derive(Debug, Error)]
pub enum SubsError {
    #[error("fetch error: {0}")]
    Fetch(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported")]
    Unsupported,
}

/// A single rule entry in the Intermediate Representation (IR).
/// [Chinese] 中间表示（IR）中的单条规则条目。
///
/// It wraps a raw DSL line directly reused from the Router DSL.
/// [Chinese] 它直接封装了复用于 Router DSL 的原始文本行。
#[derive(Debug, Clone, Default)]
pub struct RuleEntry {
    pub line: String, // 直接复用 Router DSL 的一行
}

#[cfg(feature = "subs_singbox")]
pub type JsonValue = serde_json::Value;
#[cfg(not(feature = "subs_singbox"))]
pub type JsonValue = ();

/// An outbound proxy definition in the IR.
/// [Chinese] IR 中的出站代理定义。
#[derive(Debug, Clone, Default)]
pub struct Outbound {
    /// The unique identifier/tag of the outbound.
    /// [Chinese] 出站的唯一标识符/标签。
    pub name: String,
    /// The type of the outbound (e.g., "shadowsocks", "trojan").
    /// [Chinese] 出站类型（如 "shadowsocks", "trojan"）。
    pub kind: String,
    #[cfg(feature = "subs_singbox")]
    pub params: serde_json::Value,
}

/// The Universal Intermediate Representation (IR) for a subscription.
/// [Chinese] 订阅的通用中间表示（IR）。
///
/// This structure normalizes data from various sources (Clash, Sing-box) into a unified format
/// that can be easily processed, converted, or diffed.
/// [Chinese] 该结构体将来自不同源（Clash, Sing-box）的数据标准化为统一格式，以便于处理、转换或对比。
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub rules: Vec<RuleEntry>,
    pub outbounds: Vec<Outbound>,
}

impl Profile {
    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }
    pub fn outbounds_kinds(&self) -> Vec<String> {
        let mut v = Vec::new();
        for o in &self.outbounds {
            v.push(format!("{}:{}", o.name, o.kind));
        }
        v
    }
}
