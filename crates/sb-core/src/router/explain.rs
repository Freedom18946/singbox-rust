#![cfg(feature = "explain")]
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct ExplainQuery {
    pub sni: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub proto: &'static str,
    pub transport: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct ExplainStep {
    pub phase: &'static str, // "override|cidr|geo|suffix|exact|default"
    pub rule_id: String,     // sha8 或稳定ID
    pub matched: bool,
    pub reason: String, // e.g., "cidr:10.0.0.0/8", "geo:CN"
}

#[derive(Clone, Debug, Default)]
pub struct ExplainTrace {
    pub steps: Vec<ExplainStep>,
}

#[derive(Clone, Debug)]
pub struct ExplainResult {
    pub phase: &'static str,
    pub rule_id: String,
    pub reason: String,
    pub steps: Vec<ExplainStep>,
}

impl ExplainTrace {
    pub fn push(
        &mut self,
        phase: &'static str,
        rule_id: impl Into<String>,
        matched: bool,
        reason: impl Into<String>,
    ) {
        self.steps.push(ExplainStep {
            phase,
            rule_id: rule_id.into(),
            matched,
            reason: reason.into(),
        });
    }

    pub fn into_steps(self) -> Vec<ExplainStep> {
        self.steps
    }
}

impl ExplainResult {
    pub fn new(
        phase: &'static str,
        rule_id: impl Into<String>,
        reason: impl Into<String>,
        trace: ExplainTrace,
    ) -> Self {
        Self {
            phase,
            rule_id: rule_id.into(),
            reason: reason.into(),
            steps: trace.into_steps(),
        }
    }
}

#[cfg(feature = "explain")]
pub fn envelope_from_parts(
    decision: serde_json::Map<String, serde_json::Value>,
    trace: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut root = serde_json::Map::with_capacity(2);
    root.insert("decision".into(), serde_json::Value::Object(decision));
    root.insert("trace".into(), serde_json::Value::Object(trace));
    serde_json::Value::Object(root)
}

#[cfg(feature = "explain")]
pub fn envelope_from_result(
    result: &ExplainResult,
    trace: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut decision = serde_json::Map::with_capacity(4);
    decision.insert(
        "phase".into(),
        serde_json::Value::String(result.phase.to_string()),
    );
    decision.insert(
        "rule_id".into(),
        serde_json::Value::String(result.rule_id.clone()),
    );
    decision.insert(
        "reason".into(),
        serde_json::Value::String(result.reason.clone()),
    );
    decision.insert(
        "steps".into(),
        serde_json::to_value(&result.steps)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
    );
    envelope_from_parts(decision, trace)
}

/// 注意：此函数不改变真实路由，仅做旁路分析（Never break userspace）
pub fn explain_decision(_router: &crate::router::RouterHandle, q: ExplainQuery) -> ExplainResult {
    crate::router::explain_bridge::run(_router, q)
}

#[cfg(feature = "explain")]
impl serde::Serialize for ExplainStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExplainStep", 4)?;
        state.serialize_field("phase", self.phase)?;
        state.serialize_field("rule_id", &self.rule_id)?;
        state.serialize_field("matched", &self.matched)?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
    }
}

#[cfg(feature = "explain")]
impl serde::Serialize for ExplainTrace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExplainTrace", 1)?;
        state.serialize_field("steps", &self.steps)?;
        state.end()
    }
}

#[cfg(feature = "explain")]
impl serde::Serialize for ExplainResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExplainResult", 4)?;
        state.serialize_field("phase", &self.phase)?;
        state.serialize_field("rule_id", &self.rule_id)?;
        state.serialize_field("reason", &self.reason)?;
        state.serialize_field("steps", &self.steps)?;
        state.end()
    }
}
