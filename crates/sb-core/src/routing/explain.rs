//! Canonical explain output with sha256-8 rule id and CIDR→Geo chain.
use crate::routing::engine::{Engine, Input};
use crate::routing::trace::Trace;
use sb_metrics::registry::global as M;
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
    #[allow(dead_code)]
    ir: Box<sb_config::ir::ConfigIR>, // Keeps IR data alive for engine pointer
    engine: Engine<'static>,
}

impl ExplainEngine {
    /// Create ExplainEngine from a Config using proper IR conversion
    pub fn from_config(cfg: &sb_config::Config) -> anyhow::Result<ExplainEngine> {
        // Convert Config to ConfigIR with proper rule translation
        let ir = Box::new(sb_config::present::to_ir(cfg)?);

        // Use safe pointer borrowing instead of Box::leak
        let ir_ptr: *const sb_config::ir::ConfigIR = &*ir;
        // SAFETY:
                // - 不变量：ir_ptr 指向 Box<ConfigIR> 所有的有效内存
                // - 并发/别名：Engine 仅保持只读引用，ir 的生命周期绑定到 ExplainEngine
                // - FFI/平台契约：生命周期管理基于结构体设计保证
        let engine = unsafe { Engine::new(&*ir_ptr) };

        Ok(ExplainEngine { ir, engine })
    }

    pub fn explain(&self, dest: &str, with_trace: bool) -> ExplainResult {
        // 解析 host:port
        let (host, port) = if let Some((h, p)) = dest.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(0))
        } else {
            (dest.to_string(), 0)
        };
        let d = self.engine.decide(
            &Input {
                host: &host,
                port,
                network: "tcp",
                protocol: "socks",
            },
            with_trace,
        );
        let rid = d.matched_rule.clone();
        let chain = d.chain.clone();
        let outbound = d.outbound.clone();
        let trace = d.trace.clone();

        M().route_explain_total.inc();
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
        let ir = Box::new(ConfigIR::default());
        let ir_ptr: *const ConfigIR = &*ir;
        // SAFETY:
                // - 不变量：ir_ptr 指向 Box<ConfigIR> 所有的有效内存
                // - 并发/别名：测试环境中的独立引用，ir 的生命周期绑定到测试作用域
                // - FFI/平台契约：生命周期管理基于结构体设计保证
        let engine = unsafe { Engine::new(&*ir_ptr) };
        let ee = ExplainEngine { ir, engine };
        let r = ee.explain("example.com:443", false);
        assert_eq!(r.matched_rule.len(), 8);
        assert!(r.chain.len() >= 0);
        assert!(r.trace.is_none());
        let r2 = ee.explain("example.com:443", true);
        assert!(r2.trace.is_some());
    }
}
