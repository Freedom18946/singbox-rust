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
        // SAFETY: ir's lifetime is tied to ExplainEngine, Engine only holds a read-only reference
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
