use serde_json::Value;
use std::process::Command;

#[test]
fn explain_json_shape() {
    // 启动/探测外部服务由 run-rc 负责；这里直接调用 sb-explaind 也可
    let out = Command::new("bash").args(["-lc",
        "curl -fsS 'http://127.0.0.1:18089/debug/explain?sni=www.example.com&port=443&proto=tcp&format=json'"]).output().expect("curl");
    assert!(out.status.success(), "explain http failed");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    let decision = v
        .get("decision")
        .and_then(|d| d.as_object())
        .expect("missing decision object");
    assert!(decision.get("phase").is_some(), "missing decision.phase");
    assert!(
        decision.get("rule_id").is_some(),
        "missing decision.rule_id"
    );
    assert!(decision.get("reason").is_some(), "missing decision.reason");
    assert!(
        decision.get("steps").and_then(|x| x.as_array()).is_some(),
        "missing decision.steps array"
    );
    let trace = v
        .get("trace")
        .and_then(|t| t.as_object())
        .expect("missing trace object");
    assert!(trace.is_empty() || trace.get("trace_id").is_some());
}
