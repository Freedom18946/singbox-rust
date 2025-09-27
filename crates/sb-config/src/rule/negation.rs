//! Negation detection utilities for routing rules.
//! 语义：当任何规则包含 not_* 维度时，视为启用否定维度。
//! 用途：在 CLI `check --minimize-rules` 下，遇到否定维度时仅做"规范化"，禁止"删除"。
use serde::Deserialize;

/// 路由规则（与 v1/v2 兼容的最小只读体）
#[derive(Debug, Clone, Deserialize)]
pub struct RuleLite {
    #[serde(default)]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub not_domain: Option<Vec<String>>,
    #[serde(default)]
    pub geoip: Option<Vec<String>>,
    #[serde(default)]
    pub not_geoip: Option<Vec<String>>,
    #[serde(default)]
    pub geosite: Option<Vec<String>>,
    #[serde(default)]
    pub not_geosite: Option<Vec<String>>,
    #[serde(default)]
    pub ipcidr: Option<Vec<String>>,
    #[serde(default)]
    pub not_ipcidr: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<Vec<String>>,
    #[serde(default)]
    pub not_port: Option<Vec<String>>,
    #[serde(default)]
    pub process: Option<Vec<String>>,
    #[serde(default)]
    pub not_process: Option<Vec<String>>,
    #[serde(default)]
    pub network: Option<Vec<String>>,
    #[serde(default)]
    pub not_network: Option<Vec<String>>,
    #[serde(default)]
    pub protocol: Option<Vec<String>>,
    #[serde(default)]
    pub not_protocol: Option<Vec<String>>,
    // ……可按需补充其他维度（source/dest/user-agent 等）
}

/// 配置根（只挑 route.rules 的只读体，用于快速检测）
#[derive(Debug, Clone, Deserialize)]
pub struct RouteLite {
    #[serde(default)]
    pub rules: Option<Vec<RuleLite>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigLite {
    #[serde(default)]
    pub route: Option<RouteLite>,
}

/// 判断配置是否包含任意 not_* 维度
pub fn has_any_negation(json_bytes: &[u8]) -> bool {
    let conf: ConfigLite = match serde_json::from_slice(json_bytes) {
        Ok(v) => v,
        Err(_) => return false, // 校验阶段失败时不阻断；由上游校验器报错
    };
    let Some(route) = conf.route else {
        return false;
    };
    let Some(rules) = route.rules else {
        return false;
    };
    rules.iter().any(|r| {
        r.not_domain.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_geoip.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_geosite.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_ipcidr.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_port.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_process.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_network.as_ref().is_some_and(|v| !v.is_empty())
            || r.not_protocol.as_ref().is_some_and(|v| !v.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_negation() {
        let j = br#"{
          "route": {
            "rules":[
              {"domain":["example.com"]},
              {"not_geoip":["CN"],"outbound":"proxy"}
            ]
          }
        }"#;
        assert!(has_any_negation(j));
    }
    #[test]
    fn detect_no_negation() {
        let j = br#"{"route":{"rules":[{"domain":["a.com"]}]}}"#;
        assert!(!has_any_negation(j));
    }
}
