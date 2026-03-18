//! Canonical explain output with sha256-8 rule id and CIDR→Geo chain.
use crate::routing::engine::{Engine, Input};
use crate::routing::trace::Trace;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ExplainResult {
    pub dest: String,
    pub matched_rule: String, // sha256-8
    pub chain: Vec<String>,   // ["cidr:1.2.3.0/24","geoip:US",...]
    pub outbound: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Trace>, // opt-in
}

/// External DTO for router explain responses
/// Schema locked for API stability
#[derive(Clone, Debug, Serialize)]
pub struct ExplainDto {
    pub dest: String,
    pub matched_rule: String,
    pub chain: Vec<String>,
    pub outbound: String,
    pub rule_id: String,
    pub reason: String,
}

impl ExplainDto {
    /// Create ExplainDto from ExplainResult with destination context
    pub fn from_result_with_dest(result: ExplainResult, dest: &str) -> Self {
        let chain = result.chain;
        let outbound = result.outbound.clone();
        let rule_id = calc_rule_id(&result.matched_rule); // sha256 前8位

        Self {
            dest: dest.into(),
            matched_rule: result.matched_rule.clone(),
            chain,
            outbound,
            rule_id,
            reason: format!("outbound:{}", result.outbound),
        }
    }
}

/// 稳定指纹（临时实现，后续可换成真实规则体指纹）
fn calc_rule_id(rule_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    format!("{:x}", hasher.finalize())[..8].to_string()
}

/// ExplainEngine holds IR and provides routing explanation
pub struct ExplainEngine {
    engine: Engine,
}

impl ExplainEngine {
    /// Create ExplainEngine from a Config using proper IR conversion
    pub fn from_config(cfg: &sb_config::Config) -> anyhow::Result<ExplainEngine> {
        // Convert Config to ConfigIR with proper rule translation
        let ir = std::sync::Arc::new(sb_config::present::to_ir(cfg)?);
        let engine = Engine::new(ir);

        Ok(ExplainEngine { engine })
    }

    /// Explain routing for a destination using TCP as the default network.
    /// This preserves existing behavior. For UDP decisions, prefer `explain_with_network`.
    pub fn explain(&self, dest: &str, with_trace: bool) -> ExplainResult {
        self.explain_with_network(dest, "tcp", with_trace)
    }

    /// Explain routing for a destination with an explicit network ("tcp"|"udp").
    /// Protocol defaults to "socks" for explain purposes.
    pub fn explain_with_network(
        &self,
        dest: &str,
        network: &str,
        with_trace: bool,
    ) -> ExplainResult {
        // 解析 host:port
        let (host, port) = if let Some((h, p)) = dest.rsplit_once(':') {
            let parsed_port = p.parse::<u16>().unwrap_or(0);
            (h.to_string(), parsed_port)
        } else {
            (dest.to_string(), 0)
        };
        let d = self.engine.decide(
            &Input {
                host: &host,
                port,
                network,
                protocol: "socks",
                ..Default::default()
            },
            with_trace,
        );
        let rid = d.matched_rule.clone();
        let chain = d.chain.clone();
        let outbound = d.outbound.clone();
        let trace = d.trace.clone();

        sb_metrics::inc_route_explain();
        ExplainResult {
            dest: dest.to_string(),
            matched_rule: rid,
            chain,
            outbound,
            trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::ConfigIR;

    #[test]
    fn sha_is_8_and_trace_optional() {
        // 构造空引擎（默认 direct）
        let ir = std::sync::Arc::new(ConfigIR::default());
        let engine = Engine::new(ir);
        let ee = ExplainEngine { engine };
        let r = ee.explain("example.com:443", false);
        assert_eq!(r.matched_rule.len(), 8);
        // chain is a Vec, so it's always valid
        assert!(r.trace.is_none());
        let r2 = ee.explain("example.com:443", true);
        assert!(r2.trace.is_none()); // Trace is None for default rule (direct) without steps
    }
}
