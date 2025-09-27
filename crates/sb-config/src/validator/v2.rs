use crate::ir::{ConfigIR, Credentials};
use sb_types::IssueCode;
use serde_json::{json, Value};

fn resolve_cred(c: &mut Credentials) {
    if let Some(key) = &c.username_env {
        if let Ok(v) = std::env::var(key) {
            c.username = Some(v);
        }
    }
    if let Some(key) = &c.password_env {
        if let Ok(v) = std::env::var(key) {
            c.password = Some(v);
        }
    }
}

/// 解析并归一化认证字段（ENV > 明文），避免下游重复判断
fn normalize_credentials(ir: &mut ConfigIR) {
    for ob in &mut ir.outbounds {
        if let Some(c) = &mut ob.credentials {
            resolve_cred(c);
        }
    }
    for ib in &mut ir.inbounds {
        if let Some(c) = &mut ib.basic_auth {
            resolve_cred(c);
        }
    }
}

/// 将内部错误统一转换为固定结构
pub fn emit_issue(kind: &str, code: IssueCode, ptr: &str, msg: &str, hint: &str) -> Value {
    json!({"kind": kind, "code": code.as_str(), "ptr": ptr, "msg": msg, "hint": hint})
}

/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做 UnknownField/TypeMismatch/MissingRequired
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，保持输出结构不变。
pub fn validate_v2(doc: &serde_json::Value) -> Vec<Value> {
    let schema_text = include_str!("v2_schema.json");
    let schema: Value = match serde_json::from_str(schema_text) {
        Ok(v) => v,
        Err(_) => {
            return vec![emit_issue(
                "error",
                IssueCode::Conflict,
                "/",
                "schema load failed",
                "internal",
            )]
        }
    };
    let mut issues = Vec::<Value>::new();
    // 0) schema_version check (must be 2)
    match doc.get("schema_version") {
        Some(v) => {
            if v.as_u64() != Some(2) {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    "/schema_version",
                    "schema_version must be 2",
                    "set to 2",
                ));
            }
        }
        None => {
            // Optional: we accept missing but could warn to migrate
            issues.push(emit_issue(
                "warning",
                IssueCode::MissingRequired,
                "/schema_version",
                "missing schema_version (assuming v2)",
                "add: 2",
            ));
        }
    }
    // 1) 根 additionalProperties=false
    if let (Some(obj), Some(props)) = (doc.as_object(), schema.get("properties").and_then(|p| p.as_object())) {
        for k in obj.keys() {
            if !props.contains_key(k) {
                issues.push(emit_issue(
                    "error",
                    IssueCode::UnknownField,
                    &format!("/{}", k),
                    "unknown field",
                    "remove it",
                ));
            }
        }
    }
    // 2) inbounds required/type checks（节选）
    if let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for (i, ib) in arr.iter().enumerate() {
            // required: type, listen, port
            for rq in ["type", "listen", "port"] {
                if ib.get(rq).is_none() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::MissingRequired,
                        &format!("/inbounds/{}/{}", i, rq),
                        "missing required field",
                        "add it",
                    ));
                }
            }
            if let Some(port) = ib.get("port") {
                if !port.is_number() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/inbounds/{}/port", i),
                        "port must be integer",
                        "1..65535",
                    ));
                }
            }
            // additionalProperties=false
            if let Some(map) = ib.as_object() {
                for k in map.keys() {
                    match k.as_str() {
                        "type" | "listen" | "port" | "udp" | "sniff" | "auth" => {}
                        _ => issues.push(emit_issue(
                            "error",
                            IssueCode::UnknownField,
                            &format!("/inbounds/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        )),
                    }
                }
            }
        }
    }
    issues
}

/// 打包输出
pub fn pack_output(issues: Vec<Value>) -> Value {
    json!({ "issues": issues, "fingerprint": env!("CARGO_PKG_VERSION") })
}

/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    let mut ir = crate::ir::ConfigIR::default();
    if let Some(ins) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for i in ins {
            let ty = match i.get("type").and_then(|v| v.as_str()).unwrap_or("socks") {
                "socks" => crate::ir::InboundType::Socks,
                "http" => crate::ir::InboundType::Http,
                "tun" => crate::ir::InboundType::Tun,
                _ => crate::ir::InboundType::Socks,
            };
            ir.inbounds.push(crate::ir::InboundIR {
                ty,
                listen: i
                    .get("listen")
                    .and_then(|v| v.as_str())
                    .unwrap_or("127.0.0.1")
                    .to_string(),
                port: i.get("port").and_then(|v| v.as_u64()).unwrap_or(1080) as u16,
                sniff: i.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false),
                udp: i.get("udp").and_then(|v| v.as_bool()).unwrap_or(false),
                basic_auth: i.get("basicAuth").map(|a| Credentials {
                        username: a
                            .get("username")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        password: a
                            .get("password")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        username_env: a
                            .get("username_env")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        password_env: a
                            .get("password_env")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    }),
            });
        }
    }
    if let Some(outs) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for o in outs {
            let ty = match o.get("type").and_then(|v| v.as_str()).unwrap_or("direct") {
                "direct" => crate::ir::OutboundType::Direct,
                "http" => crate::ir::OutboundType::Http,
                "socks" => crate::ir::OutboundType::Socks,
                "block" => crate::ir::OutboundType::Block,
                _ => crate::ir::OutboundType::Direct,
            };
            ir.outbounds.push(crate::ir::OutboundIR {
                ty,
                server: o
                    .get("server")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                port: o.get("port").and_then(|v| v.as_u64()).map(|x| x as u16),
                udp: o.get("udp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                name: o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                members: o.get("members").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                }),
                credentials: o.get("credentials").map(|c| Credentials {
                        username: c
                            .get("username")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        password: c
                            .get("password")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        username_env: c
                            .get("username_env")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        password_env: c
                            .get("password_env")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    }),
            });
        }
    }
    if let Some(route) = doc.get("route") {
        if let Some(rules) = route.get("rules").and_then(|v| v.as_array()) {
            for rr in rules {
                let mut r = crate::ir::RuleIR::default();
                macro_rules! arrs {
                    ($k:literal, $dst:expr) => {
                        if let Some(a) = rr.get($k).and_then(|v| v.as_array()) {
                            for x in a {
                                if let Some(s) = x.as_str() {
                                    $dst.push(s.to_string());
                                }
                            }
                        }
                    };
                }
                arrs!("domain", r.domain);
                arrs!("geosite", r.geosite);
                arrs!("geoip", r.geoip);
                arrs!("ipcidr", r.ipcidr);
                arrs!("port", r.port);
                arrs!("process", r.process);
                arrs!("network", r.network);
                arrs!("protocol", r.protocol);
                arrs!("source", r.source);
                arrs!("dest", r.dest);
                arrs!("user-agent", r.user_agent);
                arrs!("not_domain", r.not_domain);
                arrs!("not_geosite", r.not_geosite);
                arrs!("not_geoip", r.not_geoip);
                arrs!("not_ipcidr", r.not_ipcidr);
                arrs!("not_port", r.not_port);
                arrs!("not_process", r.not_process);
                arrs!("not_network", r.not_network);
                arrs!("not_protocol", r.not_protocol);
                r.outbound = route
                    .get("outbound")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ir.route.rules.push(r);
            }
        }
        ir.route.default = route
            .get("default")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    normalize_credentials(&mut ir);
    ir
}
