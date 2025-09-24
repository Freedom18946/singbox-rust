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

#[derive(Debug, Clone, Default)]
pub struct RuleEntry {
    pub line: String, // 直接复用 Router DSL 的一行
}

#[cfg(feature = "subs_singbox")]
pub type JsonValue = serde_json::Value;
#[cfg(not(feature = "subs_singbox"))]
pub type JsonValue = ();

#[derive(Debug, Clone, Default)]
pub struct Outbound {
    pub name: String,
    pub kind: String,
    #[cfg(feature = "subs_singbox")]
    pub params: serde_json::Value,
}

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
