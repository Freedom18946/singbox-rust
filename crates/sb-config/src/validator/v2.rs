use crate::ir::{ConfigIR, Credentials, DerpStunOptionsIR, HeaderEntry, InboundTlsOptionsIR};
use sb_types::IssueCode;
use serde_json::{json, Value};

const DEFAULT_URLTEST_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_URLTEST_INTERVAL_MS: u64 = 60_000;
const DEFAULT_URLTEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

fn extract_string_list(value: Option<&Value>) -> Option<Vec<String>> {
    match value? {
        Value::Array(arr) => {
            let collected: Vec<String> = arr
                .iter()
                .filter_map(|x| match x {
                    Value::String(s) => {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    }
                    Value::Number(n) => Some(n.to_string()),
                    Value::Object(obj) => obj
                        .get("value")
                        .or_else(|| obj.get("address"))
                        .or_else(|| obj.get("url"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    _ => None,
                })
                .collect();
            if collected.is_empty() {
                None
            } else {
                Some(collected)
            }
        }
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(vec![trimmed.to_string()])
            }
        }
        Value::Number(n) => Some(vec![n.to_string()]),
        Value::Object(obj) => obj
            .get("value")
            .or_else(|| obj.get("address"))
            .or_else(|| obj.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s]),
        _ => None,
    }
}

fn parse_seconds_field_to_millis(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64().map(|secs| secs.saturating_mul(1_000)),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

fn parse_millis_field(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64(),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

fn parse_u32_field(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut lowered = trimmed.to_ascii_lowercase();
            for suffix in ["mbps", "m", "bps"] {
                if lowered.ends_with(suffix) {
                    let len = lowered.len().saturating_sub(suffix.len());
                    lowered = lowered[..len].trim().to_string();
                    break;
                }
            }
            let digits: String = lowered.chars().filter(|c| c.is_ascii_digit()).collect();
            let target = if digits.is_empty() {
                lowered.replace('_', "")
            } else {
                digits
            };
            if target.is_empty() {
                None
            } else {
                target.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

fn parse_u16_field(value: Option<&Value>) -> Option<u16> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u16::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.parse::<u16>().ok()
            }
        }
        _ => None,
    }
}

fn parse_fwmark_field(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let hex = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"));
            if let Some(hex) = hex {
                u32::from_str_radix(hex.trim(), 16).ok()
            } else {
                trimmed.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

fn parse_inbound_tls_options(value: Option<&Value>) -> Option<InboundTlsOptionsIR> {
    let obj = value.and_then(|v| v.as_object())?;

    Some(InboundTlsOptionsIR {
        enabled: obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        server_name: obj
            .get("server_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        insecure: obj.get("insecure").and_then(|v| v.as_bool()),
        alpn: extract_string_list(obj.get("alpn")),
        min_version: obj
            .get("min_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        max_version: obj
            .get("max_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        cipher_suites: extract_string_list(obj.get("cipher_suites")),
        certificate: extract_string_list(obj.get("certificate")),
        certificate_path: obj
            .get("certificate_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        key: extract_string_list(obj.get("key")),
        key_path: obj
            .get("key_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn parse_derp_mesh_with(value: Option<&Value>) -> Option<Vec<String>> {
    let value = value?;
    let mut out: Vec<String> = Vec::new();
    match value {
        Value::String(s) => {
            let s = s.trim();
            if !s.is_empty() {
                out.push(s.to_string());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                match item {
                    Value::String(s) => {
                        let s = s.trim();
                        if !s.is_empty() {
                            out.push(s.to_string());
                        }
                    }
                    Value::Object(obj) => {
                        let server = obj.get("server").and_then(|v| v.as_str()).map(str::trim);
                        let port = parse_u16_field(obj.get("server_port"));
                        if let (Some(server), Some(port)) = (server, port) {
                            if !server.is_empty() {
                                out.push(format!("{server}:{port}"));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_derp_stun_options(value: Option<&Value>) -> Option<DerpStunOptionsIR> {
    let value = value?;
    match value {
        Value::Number(num) => {
            let port = num.as_u64().and_then(|v| u16::try_from(v).ok())?;
            Some(DerpStunOptionsIR {
                enabled: true,
                listen: None,
                listen_port: Some(port),
                ..Default::default()
            })
        }
        Value::Bool(enabled) => Some(DerpStunOptionsIR {
            enabled: *enabled,
            ..Default::default()
        }),
        Value::Object(obj) => Some(DerpStunOptionsIR {
            enabled: obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            listen: obj
                .get("listen")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            listen_port: parse_u16_field(obj.get("listen_port")),
            bind_interface: obj
                .get("bind_interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            routing_mark: parse_fwmark_field(obj.get("routing_mark")),
            reuse_addr: obj.get("reuse_addr").and_then(|v| v.as_bool()),
            netns: obj
                .get("netns")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
        _ => None,
    }
}

fn push_transport_token(tokens: &mut Vec<String>, token: &str) {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return;
    }
    let normalized = trimmed.to_ascii_lowercase();
    if !tokens
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&normalized))
    {
        tokens.push(normalized);
    }
}

fn push_header_entry(target: &mut Vec<HeaderEntry>, key: &str, value: &str) {
    if key.trim().is_empty() {
        return;
    }
    target.push(HeaderEntry {
        key: key.trim().to_string(),
        value: value.to_string(),
    });
}

fn parse_header_entries(value: &Value, target: &mut Vec<HeaderEntry>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(val) = v.as_str() {
                    push_header_entry(target, k, val);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                match item {
                    Value::Object(obj) => {
                        let name = obj
                            .get("name")
                            .or_else(|| obj.get("key"))
                            .and_then(|v| v.as_str());
                        let value = obj
                            .get("value")
                            .or_else(|| obj.get("val"))
                            .and_then(|v| v.as_str());
                        if let (Some(name), Some(value)) = (name, value) {
                            push_header_entry(target, name, value);
                        }
                    }
                    Value::Array(pair) => {
                        if pair.len() == 2 {
                            if let (Some(name), Some(value)) = (
                                pair.first().and_then(|v| v.as_str()),
                                pair.get(1).and_then(|v| v.as_str()),
                            ) {
                                push_header_entry(target, name, value);
                            }
                        }
                    }
                    Value::String(s) => {
                        if let Some((name, value)) = s.split_once('=') {
                            push_header_entry(target, name, value);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn parse_transport_object(
    obj: &serde_json::Map<String, Value>,
    ob: &mut crate::ir::OutboundIR,
    tokens: &mut Vec<String>,
) {
    if let Some(ty) = obj.get("type").and_then(|v| v.as_str()) {
        push_transport_token(tokens, ty);
        match ty.trim().to_ascii_lowercase().as_str() {
            "ws" => {
                if ob.ws_path.is_none() {
                    ob.ws_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.ws_host.is_none() {
                    if let Some(headers) = obj.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in headers {
                            if k.eq_ignore_ascii_case("host") {
                                if let Some(host) = v.as_str() {
                                    ob.ws_host = Some(host.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            "h2" => {
                if ob.h2_path.is_none() {
                    ob.h2_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.h2_host.is_none() {
                    ob.h2_host = obj
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            "grpc" => {
                if ob.grpc_service.is_none() {
                    ob.grpc_service = obj
                        .get("service_name")
                        .or_else(|| obj.get("service"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.grpc_method.is_none() {
                    ob.grpc_method = obj
                        .get("method_name")
                        .or_else(|| obj.get("method"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.grpc_authority.is_none() {
                    ob.grpc_authority = obj
                        .get("authority")
                        .or_else(|| obj.get("host"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if let Some(meta_val) = obj.get("metadata") {
                    parse_header_entries(meta_val, &mut ob.grpc_metadata);
                }
            }
            "httpupgrade" | "http_upgrade" => {
                if ob.http_upgrade_path.is_none() {
                    ob.http_upgrade_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if let Some(headers_val) = obj.get("headers") {
                    parse_header_entries(headers_val, &mut ob.http_upgrade_headers);
                }
            }
            _ => {}
        }
    }
}

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

/// Parse and normalize credentials (ENV > Plaintext), avoiding downstream duplicate checks.
/// 解析并归一化认证字段（ENV > 明文），避免下游重复判断。
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

/// Convert internal errors to a unified structure.
/// 将内部错误统一转换为固定结构。
pub fn emit_issue(kind: &str, code: IssueCode, ptr: &str, msg: &str, hint: &str) -> Value {
    json!({"kind": kind, "code": code.as_str(), "ptr": ptr, "msg": msg, "hint": hint})
}

/// Lightweight schema validation (placeholder implementation): parses built-in schema, checks against field set for UnknownField/TypeMismatch/MissingRequired.
/// Note: To avoid heavy dependencies, minimal necessary logic is implemented here; can be switched to jsonschema crate later while keeping output structure unchanged.
/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做 UnknownField/TypeMismatch/MissingRequired
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，保持输出结构不变。
///
/// # Arguments
/// * `doc` - The JSON document to validate / 待验证的 JSON 文档
/// * `allow_unknown` - Whether to treat unknown fields as warnings (true) instead of errors (false) / 是否将未知字段视为警告（true）而非错误（false）
pub fn validate_v2(doc: &serde_json::Value, allow_unknown: bool) -> Vec<Value> {
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
    if let (Some(obj), Some(props)) = (
        doc.as_object(),
        schema.get("properties").and_then(|p| p.as_object()),
    ) {
        for k in obj.keys() {
            // Allow $schema (Go optional field for JSON Schema tooling)
            if k == "$schema" {
                continue;
            }
            if !props.contains_key(k) {
                let kind = if allow_unknown { "warning" } else { "error" };
                issues.push(emit_issue(
                    kind,
                    IssueCode::UnknownField,
                    &format!("/{}", k),
                    "unknown field",
                    "remove it",
                ));
            }
        }
    }
    // 2) inbounds type and structure validation
    if let Some(inbounds_val) = doc.get("inbounds") {
        if !inbounds_val.is_array() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/inbounds",
                "inbounds must be an array",
                "use []",
            ));
        }
    }
    if let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for (i, ib) in arr.iter().enumerate() {
            // Each inbound must be an object
            if !ib.is_object() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}", i),
                    "inbound item must be an object",
                    "use {}",
                ));
                continue;
            }

            // required: type (always required)
            if ib.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/inbounds/{}/type", i),
                    "missing required field",
                    "add it",
                ));
            } else if !ib.get("type").unwrap().is_string() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/type", i),
                    "type must be a string",
                    "use string value",
                ));
            }

            // listen is only required for non-tun inbounds
            let is_tun = ib.get("type").and_then(|v| v.as_str()) == Some("tun");
            if !is_tun && ib.get("listen").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/inbounds/{}/listen", i),
                    "missing required field (except for tun type)",
                    "add it",
                ));
            }
            if let Some(listen_val) = ib.get("listen") {
                if !listen_val.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/inbounds/{}/listen", i),
                        "listen must be a string",
                        "use string value",
                    ));
                }
            }
            if let Some(port_val) = ib.get("port") {
                if !port_val.is_u64() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/inbounds/{}/port", i),
                        "port must be a number",
                        "use numeric value",
                    ));
                }
            }
            if let Some(port_val) = ib.get("listen_port") {
                if !port_val.is_u64() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/inbounds/{}/listen_port", i),
                        "listen_port must be a number",
                        "use numeric value",
                    ));
                }
            }

            // additionalProperties=false (V2 allowed fields)
            if let Some(map) = ib.as_object() {
                for k in map.keys() {
                    match k.as_str() {
                        // Go parity: include 'tag' for inbound identification
                        "tag" | "name" | "type" | "listen" | "port" | "udp" | "network" | "sniff"
                        | "override_address" | "override_host" | "override_port"
                        | "interface_name" | "inet4_address" | "inet6_address" | "auto_route"
                        | "auth" | "users" | "cert" | "key" | "congestion_control"
                        | "salamander" | "obfs" | "up_mbps" | "down_mbps" => {}
                        _ => {
                            let kind = if allow_unknown { "warning" } else { "error" };
                            issues.push(emit_issue(
                                kind,
                                IssueCode::UnknownField,
                                &format!("/inbounds/{}/{}", i, k),
                                "unknown field",
                                "remove it",
                            ));
                        }
                    }
                }
            }
        }
    }
    // 3) outbounds type and structure validation
    if let Some(outbounds_val) = doc.get("outbounds") {
        if !outbounds_val.is_array() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/outbounds",
                "outbounds must be an array",
                "use []",
            ));
        }
    }
    if let Some(arr) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for (i, ob) in arr.iter().enumerate() {
            // Each outbound must be an object
            if !ob.is_object() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/outbounds/{}", i),
                    "outbound item must be an object",
                    "use {}",
                ));
                continue;
            }

            // type is required
            if ob.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/outbounds/{}/type", i),
                    "missing required field",
                    "add it",
                ));
            } else if !ob.get("type").unwrap().is_string() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/outbounds/{}/type", i),
                    "type must be a string",
                    "use string value",
                ));
            }

            // tag/name should be string if present
            if let Some(tag_val) = ob.get("tag") {
                if !tag_val.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/outbounds/{}/tag", i),
                        "tag must be a string",
                        "use string value",
                    ));
                }
            }
        }
    }
    issues
}

/// Pack output.
/// 打包输出。
pub fn pack_output(issues: Vec<Value>) -> Value {
    json!({ "issues": issues, "fingerprint": env!("CARGO_PKG_VERSION") })
}

fn parse_rule_entry(val: &Value) -> crate::ir::RuleIR {
    let mut r = crate::ir::RuleIR::default();
    if let Some(obj) = val.as_object() {
        let condition_obj = obj
            .get("when")
            .and_then(|v| v.as_object())
            .unwrap_or(obj);
        // Parse type/mode/sub-rules for logical rules
        let rule_type = obj.get("type").and_then(|v| v.as_str());
        if rule_type == Some("logical") {
            r.mode = obj.get("mode").and_then(|v| v.as_str()).map(|s| s.to_string());
            if let Some(rules) = obj.get("rules").and_then(|v| v.as_array()) {
                r.rules = rules.iter().map(parse_rule_entry).map(Box::new).collect();
            }
        }

        r.domain = extract_string_list(condition_obj.get("domain")).unwrap_or_default();
        r.domain_suffix = extract_string_list(
            condition_obj
                .get("domain_suffix")
                .or_else(|| condition_obj.get("suffix")),
        )
        .unwrap_or_default();
        r.domain_keyword = extract_string_list(
            condition_obj
                .get("domain_keyword")
                .or_else(|| condition_obj.get("keyword")),
        )
        .unwrap_or_default();
        r.domain_regex = extract_string_list(
            condition_obj
                .get("domain_regex")
                .or_else(|| condition_obj.get("regex")),
        )
        .unwrap_or_default();
        r.geosite = extract_string_list(condition_obj.get("geosite")).unwrap_or_default();
        r.geoip = extract_string_list(condition_obj.get("geoip")).unwrap_or_default();
        r.ipcidr = extract_string_list(
            condition_obj
                .get("ipcidr")
                .or_else(|| condition_obj.get("ip_cidr")),
        )
        .unwrap_or_default();
        r.port = extract_string_list(condition_obj.get("port")).unwrap_or_default();
        r.process_name = extract_string_list(
            condition_obj
                .get("process_name")
                .or_else(|| condition_obj.get("process")),
        )
        .unwrap_or_default();
        r.process_path = extract_string_list(condition_obj.get("process_path")).unwrap_or_default();
        r.network = extract_string_list(condition_obj.get("network")).unwrap_or_default();
        r.protocol = extract_string_list(condition_obj.get("protocol")).unwrap_or_default();
        r.source = extract_string_list(condition_obj.get("source")).unwrap_or_default();
        r.dest = extract_string_list(condition_obj.get("dest")).unwrap_or_default();
        r.user_agent = extract_string_list(condition_obj.get("user_agent")).unwrap_or_default();
        r.wifi_ssid = extract_string_list(condition_obj.get("wifi_ssid")).unwrap_or_default();
        r.wifi_bssid = extract_string_list(condition_obj.get("wifi_bssid")).unwrap_or_default();
        r.rule_set = extract_string_list(condition_obj.get("rule_set")).unwrap_or_default();
        
        r.query_type = extract_string_list(condition_obj.get("query_type")).unwrap_or_default();

        r.not_domain = extract_string_list(obj.get("not_domain")).unwrap_or_default();
        r.not_geosite = extract_string_list(obj.get("not_geosite")).unwrap_or_default();
        r.not_geoip = extract_string_list(obj.get("not_geoip")).unwrap_or_default();
        r.not_ipcidr = extract_string_list(obj.get("not_ipcidr")).unwrap_or_default();
        r.not_port = extract_string_list(obj.get("not_port")).unwrap_or_default();
        r.not_process_name = extract_string_list(obj.get("not_process_name").or(obj.get("not_process"))).unwrap_or_default();
        r.not_process_path = extract_string_list(obj.get("not_process_path")).unwrap_or_default();
        r.not_network = extract_string_list(obj.get("not_network")).unwrap_or_default();
        r.not_protocol = extract_string_list(obj.get("not_protocol")).unwrap_or_default();
        r.not_wifi_ssid = extract_string_list(obj.get("not_wifi_ssid")).unwrap_or_default();
        r.not_wifi_bssid = extract_string_list(obj.get("not_wifi_bssid")).unwrap_or_default();
        r.not_rule_set = extract_string_list(obj.get("not_rule_set")).unwrap_or_default();

        // Parse action
        r.action = match obj.get("action").and_then(|v| v.as_str()) {
            Some(s) => crate::ir::RuleAction::from_str_opt(s).unwrap_or_default(),
            None => crate::ir::RuleAction::default(),
        };

        r.override_address = obj.get("override_address").and_then(|v| v.as_str()).map(|s| s.to_string());
        r.override_port = parse_u16_field(obj.get("override_port"));
        r.rewrite_ttl = parse_u32_field(obj.get("rewrite_ttl"));
        r.client_subnet = obj.get("client_subnet").and_then(|v| v.as_str()).map(|s| s.to_string());

        r.outbound = obj
            .get("outbound")
            .or_else(|| obj.get("to"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        r.invert = obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false);
    }
    r
}

/// Convert V1/V2 raw JSON to IR (excerpt; V1 unknown fields ignored but warning optional).
/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）。
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    let mut ir = crate::ir::ConfigIR::default();
    if let Some(ins) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for i in ins {
            let ty = match i.get("type").and_then(|v| v.as_str()).unwrap_or("socks") {
                "socks" => crate::ir::InboundType::Socks,
                "http" => crate::ir::InboundType::Http,
                "tun" => crate::ir::InboundType::Tun,
                "mixed" => crate::ir::InboundType::Mixed,
                "redirect" => crate::ir::InboundType::Redirect,
                "tproxy" => crate::ir::InboundType::Tproxy,
                "direct" => crate::ir::InboundType::Direct,
                "dns" => crate::ir::InboundType::Dns,
                "ssh" => crate::ir::InboundType::Ssh,
                _ => crate::ir::InboundType::Socks,
            };
            // Common fields
            let mut listen = i
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1")
                .to_string();
            let mut port = i
                .get("listen_port")
                .or_else(|| i.get("port"))
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok());
            if port.is_none() {
                if let Some((host, parsed_port)) = parse_listen_host_port(&listen) {
                    listen = host;
                    port = Some(parsed_port);
                }
            }
            let port = port.unwrap_or(1080);
            let sniff = i.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
            // Network selection: if network == "udp", set udp=true; if "tcp" or missing, false
            let udp = if let Some(net) = i.get("network").and_then(|v| v.as_str()) {
                net.eq_ignore_ascii_case("udp")
            } else {
                i.get("udp").and_then(|v| v.as_bool()).unwrap_or(false)
            };
            let basic_auth = i.get("basicAuth").map(|a| Credentials {
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
            });

            // Direct-only fields
            let (override_host, override_port) = if matches!(ty, crate::ir::InboundType::Direct) {
                let host = i
                    .get("override_address")
                    .or_else(|| i.get("override_host"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let port = i
                    .get("override_port")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u16);
                (host, port)
            } else {
                (None, None)
            };

            ir.inbounds.push(crate::ir::InboundIR {
                tag: i.get("tag").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ty,
                listen,
                port,
                sniff,
                udp,
                udp_timeout: i.get("udp_timeout").and_then(|v| v.as_str()).map(|s| s.to_string()),
                domain_strategy: i.get("domain_strategy").and_then(|v| v.as_str()).map(|s| s.to_string()),
                set_system_proxy: i.get("set_system_proxy").and_then(|v| v.as_bool()).unwrap_or(false),
                allow_private_network: i.get("allow_private_network").and_then(|v| v.as_bool()).unwrap_or(true),
                basic_auth,
                override_host,
                override_port,
                users: i.get("users").and_then(|v| {
                    v.as_array().and_then(|arr| {
                        let users: Vec<_> = arr
                            .iter()
                            .filter_map(|u| {
                                let name = u
                                    .get("username")
                                    .or_else(|| u.get("name"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                let pass = u
                                    .get("password")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                if name.is_some() || pass.is_some() {
                                    Some(crate::ir::Credentials {
                                        username: name,
                                        password: pass,
                                        username_env: None,
                                        password_env: None,
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if users.is_empty() {
                            None
                        } else {
                            Some(users)
                        }
                    })
                }),
                // Protocol-specific fields (all default to None)
                method: None,
                password: None,
                users_shadowsocks: None,
                network: None,
                uuid: None,
                alter_id: None,
                users_vmess: None,
                flow: i
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                users_vless: None,
                users_trojan: None,
                fallback: i
                    .get("fallback")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fallback_for_alpn: i.get("fallback_for_alpn").and_then(|v| {
                    v.as_object().map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                }),
                users_anytls: None,
                anytls_padding: None,
                transport: None,
                ws_path: None,
                ws_host: None,
                h2_path: None,
                h2_host: None,
                grpc_service: None,
                tls_enabled: None,
                tls_cert_path: None,
                tls_key_path: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                tls_server_name: None,
                tls_alpn: None,
                users_hysteria2: None,
                congestion_control: None,
                salamander: None,
                obfs: None,
                brutal_up_mbps: None,
                brutal_down_mbps: None,
                users_tuic: None,
                users_hysteria: None,
                hysteria_protocol: None,
                hysteria_obfs: None,
                hysteria_up_mbps: None,
                hysteria_down_mbps: None,
                hysteria_recv_window_conn: None,
                hysteria_recv_window: None,
                masquerade: None,
                multiplex: None,
                security: i
                    .get("security")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tun: None,
                ssh_host_key_path: i
                    .get("ssh_host_key_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
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
                "selector" => crate::ir::OutboundType::Selector,
                "urltest" => crate::ir::OutboundType::UrlTest,
                "shadowsocks" => crate::ir::OutboundType::Shadowsocks,
                "shadowtls" => crate::ir::OutboundType::Shadowtls,
                "hysteria2" => crate::ir::OutboundType::Hysteria2,
                "tuic" => crate::ir::OutboundType::Tuic,
                "vless" => crate::ir::OutboundType::Vless,
                "vmess" => crate::ir::OutboundType::Vmess,
                "trojan" => crate::ir::OutboundType::Trojan,
                "ssh" => crate::ir::OutboundType::Ssh,
                // Advanced/Go-only types
                "dns" => crate::ir::OutboundType::Dns,
                "tor" => crate::ir::OutboundType::Tor,
                "anytls" => crate::ir::OutboundType::Anytls,
                "hysteria" => crate::ir::OutboundType::Hysteria,
                "wireguard" => crate::ir::OutboundType::Wireguard,
                "tailscale" => crate::ir::OutboundType::Tailscale,
                _ => crate::ir::OutboundType::Direct,
            };
            let mut ob = crate::ir::OutboundIR {
                ty,
                server: o
                    .get("server")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                // Accept both Rust-native `port` and Go-style `server_port`.
                port: o
                    .get("port")
                    .or_else(|| o.get("server_port"))
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u16),
                udp: o.get("udp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                // Map Go-style `tag` to IR `name`, falling back to `name` if present.
                name: o
                    .get("tag")
                    .or_else(|| o.get("name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                members: None,
                default_member: None,
                domain_strategy: o
                    .get("domain_strategy")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                method: None,
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
                uuid: o
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                flow: o
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                security: o
                    .get("security")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                alter_id: o
                    .get("alter_id")
                    .and_then(|v| v.as_u64())
                    .and_then(|x| u8::try_from(x).ok()),
                encryption: o
                    .get("encryption")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                network: o
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                packet_encoding: o
                    .get("packet_encoding")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                transport: None,
                ws_path: o
                    .get("ws_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                ws_host: o
                    .get("ws_host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                h2_path: o
                    .get("h2_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                h2_host: o
                    .get("h2_host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                grpc_service: None,
                grpc_method: None,
                grpc_authority: None,
                grpc_metadata: Vec::new(),
                http_upgrade_path: None,
                http_upgrade_headers: Vec::new(),
                tls_sni: o
                    .get("tls_sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tls_alpn: match o.get("tls_alpn") {
                    Some(Value::String(s)) => {
                        let v = s
                            .split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect::<Vec<_>>();
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
                    }
                    Some(Value::Array(arr)) => {
                        let v = arr
                            .iter()
                            .filter_map(|it| it.as_str().map(|s| s.trim().to_string()))
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>();
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
                    }
                    _ => None,
                },
                tls_ca_paths: Vec::new(),
                tls_ca_pem: Vec::new(),
                tls_client_cert_path: None,
                tls_client_key_path: None,
                tls_client_cert_pem: None,
                tls_client_key_pem: None,
                reality_enabled: None,
                reality_public_key: None,
                reality_short_id: None,
                reality_server_name: None,
                password: o
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                plugin: o
                    .get("plugin")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                plugin_opts: o
                    .get("plugin_opts")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                token: o
                    .get("token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                congestion_control: o
                    .get("congestion_control")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                alpn: o
                    .get("alpn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                skip_cert_verify: o.get("skip_cert_verify").and_then(|v| v.as_bool()),
                udp_relay_mode: o
                    .get("udp_relay_mode")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                udp_over_stream: o.get("udp_over_stream").and_then(|v| v.as_bool()),
                zero_rtt_handshake: o.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
                up_mbps: parse_u32_field(o.get("up_mbps")),
                down_mbps: parse_u32_field(o.get("down_mbps")),
                obfs: o
                    .get("obfs")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                salamander: o
                    .get("salamander")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                brutal_up_mbps: o
                    .get("brutal")
                    .and_then(|v| v.as_object())
                    .and_then(|b| parse_u32_field(b.get("up_mbps"))),
                brutal_down_mbps: o
                    .get("brutal")
                    .and_then(|v| v.as_object())
                    .and_then(|b| parse_u32_field(b.get("down_mbps"))),
                ssh_private_key: None,
                ssh_private_key_path: None,
                ssh_private_key_passphrase: None,
                ssh_host_key_verification: None,
                ssh_known_hosts_path: None,
                ssh_connection_pool_size: None,
                ssh_compression: None,
                ssh_keepalive_interval: None,
                connect_timeout_sec: None,
                tor_proxy_addr: None,
                tor_executable_path: None,
                tor_extra_args: Vec::new(),
                tor_data_directory: None,
                tor_options: None,
                test_url: None,
                test_interval_ms: None,
                test_timeout_ms: None,
                test_tolerance_ms: None,
                interrupt_exist_connections: None,
                dns_transport: None,
                dns_timeout_ms: None,
                dns_query_timeout_ms: None,
                dns_tls_server_name: None,
                dns_enable_edns0: None,
                dns_edns0_buffer_size: None,
                dns_doh_url: None,
                hysteria_protocol: None,
                hysteria_auth: None,
                hysteria_recv_window_conn: None,
                hysteria_recv_window: None,
                wireguard_system_interface: None,
                wireguard_interface: None,
                wireguard_local_address: Vec::new(),
                wireguard_source_v4: None,
                wireguard_source_v6: None,
                wireguard_allowed_ips: Vec::new(),
                wireguard_private_key: None,
                wireguard_peer_public_key: None,
                wireguard_pre_shared_key: None,
                wireguard_persistent_keepalive: None,
                anytls_padding: extract_string_list(o.get("anytls_padding")),
                // Dialer options
                bind_interface: o
                    .get("bind_interface")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                inet4_bind_address: o
                    .get("inet4_bind_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                inet6_bind_address: o
                    .get("inet6_bind_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                routing_mark: o
                    .get("routing_mark")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u32),
                reuse_addr: o.get("reuse_addr").and_then(|v| v.as_bool()),
                connect_timeout: o
                    .get("connect_timeout")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tcp_fast_open: o.get("tcp_fast_open").and_then(|v| v.as_bool()),
                tcp_multi_path: o.get("tcp_multi_path").and_then(|v| v.as_bool()),
                udp_fragment: o.get("udp_fragment").and_then(|v| v.as_bool()),
                // Mux options
                mux_max_streams: o
                    .get("mux_max_streams")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as usize),
                mux_window_size: o
                    .get("mux_window_size")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u32),
                mux_padding: o.get("mux_padding").and_then(|v| v.as_bool()),
                mux_reuse_timeout: o.get("mux_reuse_timeout").and_then(|v| v.as_u64()),
                multiplex: None,
                obfs_param: o
                    .get("obfs_param")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                protocol: o
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                protocol_param: o
                    .get("protocol_param")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                // UDP over TCP config
                udp_over_tcp: o.get("udp_over_tcp").and_then(|v| v.as_bool()),
                udp_over_tcp_version: o
                    .get("udp_over_tcp_version")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u8),
                // uTLS fingerprint
                utls_fingerprint: o
                    .get("utls_fingerprint")
                    .or_else(|| o.get("fingerprint"))
                    .or_else(|| o.get("tls_fingerprint"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            };

            if let Some(transport_val) = o.get("transport") {
                let mut tokens: Vec<String> = Vec::new();
                match transport_val {
                    Value::Array(arr) => {
                        for item in arr {
                            match item {
                                Value::String(s) => {
                                    for part in s.split(',') {
                                        push_transport_token(&mut tokens, part);
                                    }
                                }
                                Value::Object(obj) => {
                                    parse_transport_object(obj, &mut ob, &mut tokens);
                                }
                                _ => {}
                            }
                        }
                    }
                    Value::String(s) => {
                        for part in s.split(',') {
                            push_transport_token(&mut tokens, part);
                        }
                    }
                    Value::Object(obj) => {
                        parse_transport_object(obj, &mut ob, &mut tokens);
                    }
                    _ => {}
                }
                if !tokens.is_empty() {
                    ob.transport = Some(tokens);
                }
            }

            ob.members = extract_string_list(o.get("members"));
            if ob.members.is_none() {
                ob.members = extract_string_list(o.get("outbounds"));
            }
            ob.default_member = o
                .get("default")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ob.interrupt_exist_connections = o
                .get("interrupt_exist_connections")
                .and_then(|v| v.as_bool());
            ob.method = o
                .get("method")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Defaults: Shadowsocks method defaults to aes-256-gcm when omitted
            if ob.ty == crate::ir::OutboundType::Shadowsocks && ob.method.is_none() {
                ob.method = Some("aes-256-gcm".to_string());
            }

            if matches!(ob.ty, crate::ir::OutboundType::UrlTest) {
                ob.test_url = Some(
                    o.get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or(DEFAULT_URLTEST_URL)
                        .to_string(),
                );
                ob.test_interval_ms = parse_seconds_field_to_millis(o.get("interval"))
                    .or_else(|| o.get("interval_ms").and_then(|v| v.as_u64()))
                    .or(Some(DEFAULT_URLTEST_INTERVAL_MS));
                ob.test_timeout_ms = parse_seconds_field_to_millis(o.get("timeout"))
                    .or_else(|| o.get("timeout_ms").and_then(|v| v.as_u64()))
                    .or(Some(DEFAULT_URLTEST_TIMEOUT_MS));
                ob.test_tolerance_ms = parse_millis_field(o.get("tolerance"))
                    .or_else(|| o.get("tolerance_ms").and_then(|v| v.as_u64()))
                    .or(Some(DEFAULT_URLTEST_TOLERANCE_MS));
            }

            if matches!(
                ob.ty,
                crate::ir::OutboundType::Selector | crate::ir::OutboundType::UrlTest
            ) && ob.members.is_none()
            {
                ob.members = Some(Vec::new());
            }

            // Fallback: allow top-level username/password for ssh/http/socks
            if ob.credentials.is_none() {
                let top_user = o
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let top_pass = o
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if top_user.is_some() || top_pass.is_some() {
                    ob.credentials = Some(Credentials {
                        username: top_user,
                        password: top_pass,
                        username_env: None,
                        password_env: None,
                    });
                }
            }

            // SSH specific optional fields
            if matches!(ob.ty, crate::ir::OutboundType::Ssh) {
                ob.ssh_private_key = o
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_private_key_path = o
                    .get("private_key_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_private_key_passphrase = o
                    .get("private_key_passphrase")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_host_key_verification =
                    o.get("host_key_verification").and_then(|v| v.as_bool());
                ob.ssh_known_hosts_path = o
                    .get("known_hosts_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_connection_pool_size = o
                    .get("connection_pool_size")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as usize);
                ob.ssh_compression = o.get("compression").and_then(|v| v.as_bool());
                ob.ssh_keepalive_interval = o.get("keepalive_interval").and_then(|v| v.as_u64());
            }

            if matches!(ob.ty, crate::ir::OutboundType::Wireguard) {
                if ob.wireguard_system_interface.is_none() {
                    ob.wireguard_system_interface =
                        o.get("system_interface").and_then(|v| v.as_bool());
                }
                if ob.wireguard_interface.is_none() {
                    ob.wireguard_interface = o
                        .get("wireguard_interface")
                        .or_else(|| o.get("interface_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_local_address.is_empty() {
                    if let Some(list) = extract_string_list(
                        o.get("wireguard_local_address")
                            .or_else(|| o.get("local_address")),
                    ) {
                        ob.wireguard_local_address = list;
                    }
                }
                if ob.wireguard_allowed_ips.is_empty() {
                    if let Some(list) = extract_string_list(o.get("allowed_ips")) {
                        ob.wireguard_allowed_ips = list;
                    }
                }
                if ob.wireguard_private_key.is_none() {
                    ob.wireguard_private_key = o
                        .get("private_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_peer_public_key.is_none() {
                    ob.wireguard_peer_public_key = o
                        .get("peer_public_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_pre_shared_key.is_none() {
                    ob.wireguard_pre_shared_key = o
                        .get("pre_shared_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_source_v4.is_none() {
                    ob.wireguard_source_v4 = o
                        .get("wireguard_source_v4")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_source_v6.is_none() {
                    ob.wireguard_source_v6 = o
                        .get("wireguard_source_v6")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.wireguard_persistent_keepalive.is_none() {
                    ob.wireguard_persistent_keepalive = o
                        .get("persistent_keepalive_interval")
                        .and_then(|v| v.as_u64())
                        .and_then(|x| u16::try_from(x).ok());
                }

                if ob.wireguard_allowed_ips.is_empty() || ob.wireguard_peer_public_key.is_none() {
                    if let Some(peers) = o.get("peers").and_then(|v| v.as_array()) {
                        if let Some(peer) = peers.first() {
                            if ob.wireguard_allowed_ips.is_empty() {
                                if let Some(list) = extract_string_list(peer.get("allowed_ips")) {
                                    ob.wireguard_allowed_ips = list;
                                }
                            }
                            if ob.wireguard_peer_public_key.is_none() {
                                ob.wireguard_peer_public_key = peer
                                    .get("public_key")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                            }
                            if ob.wireguard_pre_shared_key.is_none() {
                                ob.wireguard_pre_shared_key = peer
                                    .get("pre_shared_key")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                            }
                            if ob.wireguard_persistent_keepalive.is_none() {
                                ob.wireguard_persistent_keepalive = peer
                                    .get("persistent_keepalive_interval")
                                    .and_then(|v| v.as_u64())
                                    .and_then(|x| u16::try_from(x).ok());
                            }
                        }
                    }
                }
            }

            // Parse connect_timeout for all outbound types
            ob.connect_timeout_sec = o
                .get("connect_timeout")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);

            // Backward-compat: allow nested sections `ws`, `h2`, `tls` as objects
            if let Some(ws) = o.get("ws").and_then(|v| v.as_object()) {
                if ob.ws_path.is_none() {
                    ob.ws_path = ws
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.ws_host.is_none() {
                    ob.ws_host = ws
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            if let Some(h2) = o.get("h2").and_then(|v| v.as_object()) {
                if ob.h2_path.is_none() {
                    ob.h2_path = h2
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.h2_host.is_none() {
                    ob.h2_host = h2
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            if let Some(tls) = o.get("tls").and_then(|v| v.as_object()) {
                if ob.tls_sni.is_none() {
                    ob.tls_sni = tls
                        .get("sni")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.tls_alpn.is_none() {
                    if let Some(val) = tls.get("alpn") {
                        ob.tls_alpn = match val {
                            Value::String(s) => {
                                let v = s
                                    .split(',')
                                    .map(|x| x.trim().to_string())
                                    .filter(|x| !x.is_empty())
                                    .collect::<Vec<_>>();
                                if v.is_empty() {
                                    None
                                } else {
                                    Some(v)
                                }
                            }
                            Value::Array(arr) => {
                                let v = arr
                                    .iter()
                                    .filter_map(|it| it.as_str().map(|s| s.trim().to_string()))
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>();
                                if v.is_empty() {
                                    None
                                } else {
                                    Some(v)
                                }
                            }
                            _ => None,
                        };
                    }
                }
                if ob.alpn.is_none() {
                    ob.alpn = tls
                        .get("alpn")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.skip_cert_verify.is_none() {
                    ob.skip_cert_verify = tls
                        .get("skip_cert_verify")
                        .and_then(|v| v.as_bool())
                        .or_else(|| tls.get("allow_insecure").and_then(|v| v.as_bool()));
                }

                // Per-outbound additional CA and client auth
                if ob.tls_ca_paths.is_empty() {
                    if let Some(arr) = tls.get("ca_paths").and_then(|v| v.as_array()) {
                        for p in arr {
                            if let Some(s) = p.as_str() {
                                let s = s.trim();
                                if !s.is_empty() {
                                    ob.tls_ca_paths.push(s.to_string());
                                }
                            }
                        }
                    }
                }
                if ob.tls_ca_pem.is_empty() {
                    match tls.get("ca_pem") {
                        Some(v) if v.is_array() => {
                            for it in v.as_array().unwrap() {
                                if let Some(s) = it.as_str() {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        ob.tls_ca_pem.push(s.to_string());
                                    }
                                }
                            }
                        }
                        Some(v) if v.is_string() => {
                            if let Some(s) = v.as_str() {
                                let s = s.trim();
                                if !s.is_empty() {
                                    ob.tls_ca_pem.push(s.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if ob.tls_client_cert_path.is_none() {
                    ob.tls_client_cert_path = tls
                        .get("client_cert_path")
                        .or_else(|| tls.get("client_cert"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.tls_client_key_path.is_none() {
                    ob.tls_client_key_path = tls
                        .get("client_key_path")
                        .or_else(|| tls.get("client_key"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.tls_client_cert_pem.is_none() {
                    ob.tls_client_cert_pem = tls
                        .get("client_cert_pem")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.tls_client_key_pem.is_none() {
                    ob.tls_client_key_pem = tls
                        .get("client_key_pem")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }

                // Parse REALITY configuration
                if let Some(reality) = tls.get("reality").and_then(|v| v.as_object()) {
                    ob.reality_enabled = reality.get("enabled").and_then(|v| v.as_bool());
                    ob.reality_public_key = reality
                        .get("public_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    ob.reality_short_id = reality
                        .get("short_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    ob.reality_server_name = reality
                        .get("server_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }

            ir.outbounds.push(ob);
        }
    }

    if let Some(eps) = doc.get("endpoints").and_then(|v| v.as_array()) {
        for e in eps {
            let ty = match e
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("wireguard")
            {
                "wireguard" => crate::ir::EndpointType::Wireguard,
                "tailscale" => crate::ir::EndpointType::Tailscale,
                _ => crate::ir::EndpointType::Wireguard,
            };

            let peers = e.get("peers").and_then(|v| v.as_array()).map(|arr| {
                arr.iter()
                    .map(|p| crate::ir::WireGuardPeerIR {
                        address: p
                            .get("address")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        port: p.get("port").and_then(|v| v.as_u64()).map(|x| x as u16),
                        public_key: p
                            .get("public_key")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        pre_shared_key: p
                            .get("pre_shared_key")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        allowed_ips: extract_string_list(p.get("allowed_ips")),
                        persistent_keepalive_interval: p
                            .get("persistent_keepalive_interval")
                            .and_then(|v| v.as_u64())
                            .map(|x| x as u16),
                        reserved: p.get("reserved").and_then(|v| v.as_array()).map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_u64().map(|b| b as u8))
                                .collect()
                        }),
                    })
                    .collect()
            });

            ir.endpoints.push(crate::ir::EndpointIR {
                ty,
                tag: e.get("tag").and_then(|v| v.as_str()).map(|s| s.to_string()),
                network: extract_string_list(e.get("network")),
                wireguard_system: e.get("system_interface").and_then(|v| v.as_bool()),
                wireguard_name: e
                    .get("interface_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                wireguard_mtu: e.get("mtu").and_then(|v| v.as_u64()).map(|x| x as u32),
                wireguard_address: extract_string_list(e.get("address")),
                wireguard_private_key: e
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                wireguard_listen_port: e
                    .get("listen_port")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u16),
                wireguard_peers: peers,
                wireguard_udp_timeout: e
                    .get("udp_timeout")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                wireguard_workers: e.get("workers").and_then(|v| v.as_i64()).map(|x| x as i32),
                tailscale_state_directory: e
                    .get("state_directory")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tailscale_auth_key: e
                    .get("auth_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tailscale_control_url: e
                    .get("control_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tailscale_ephemeral: e.get("ephemeral").and_then(|v| v.as_bool()),
                tailscale_hostname: e
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tailscale_accept_routes: e.get("accept_routes").and_then(|v| v.as_bool()),
                tailscale_exit_node: e
                    .get("exit_node")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tailscale_exit_node_allow_lan_access: e
                    .get("exit_node_allow_lan_access")
                    .and_then(|v| v.as_bool()),
                tailscale_advertise_routes: extract_string_list(e.get("advertise_routes")),
                tailscale_advertise_exit_node: e
                    .get("advertise_exit_node")
                    .and_then(|v| v.as_bool()),
                tailscale_udp_timeout: e
                    .get("udp_timeout")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    if let Some(route) = doc.get("route") {
        // GeoIP/Geosite options
        if let Some(geoip) = route.get("geoip").and_then(|v| v.as_object()) {
            if let Some(p) = geoip.get("path").and_then(|v| v.as_str()) {
                ir.route.geoip_path = Some(p.to_string());
            }
            if let Some(u) = geoip.get("download_url").and_then(|v| v.as_str()) {
                ir.route.geoip_download_url = Some(u.to_string());
            }
            if let Some(d) = geoip.get("download_detour").and_then(|v| v.as_str()) {
                ir.route.geoip_download_detour = Some(d.to_string());
            }
        }
        if let Some(geosite) = route.get("geosite").and_then(|v| v.as_object()) {
            if let Some(p) = geosite.get("path").and_then(|v| v.as_str()) {
                ir.route.geosite_path = Some(p.to_string());
            }
            if let Some(u) = geosite.get("download_url").and_then(|v| v.as_str()) {
                ir.route.geosite_download_url = Some(u.to_string());
            }
            if let Some(d) = geosite.get("download_detour").and_then(|v| v.as_str()) {
                ir.route.geosite_download_detour = Some(d.to_string());
            }
        }

        if let Some(rules) = route.get("rules").and_then(|v| v.as_array()) {
            ir.route.rules = rules.iter().map(parse_rule_entry).collect();
        }
        if let Some(rule_sets) = route.get("rule_set").and_then(|v| v.as_array()) {
            for rs in rule_sets {
                if let Some(obj) = rs.as_object() {
                    let tag = obj
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ty = obj
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("local")
                        .to_string();
                    let path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let url = obj
                        .get("url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    
                    // Format inference
                    let format = obj
                        .get("format")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            // Infer from path extension (Go parity: .json=source, .srs=binary)
                            let infer_from_ext = |p: &str| -> Option<String> {
                                if p.ends_with(".json") {
                                    Some("source".to_string())
                                } else if p.ends_with(".srs") {
                                    Some("binary".to_string())
                                } else {
                                    None
                                }
                            };
                            
                            if let Some(p) = &path {
                                if let Some(fmt) = infer_from_ext(p) {
                                    return fmt;
                                }
                            }
                            if let Some(u) = &url {
                                // Simple extension check on URL (without url crate)
                                // Remove query params for extension check
                                let path_part = u.split('?').next().unwrap_or(u);
                                if let Some(fmt) = infer_from_ext(path_part) {
                                    return fmt;
                                }
                            }
                            // Default to binary for non-inline types
                            if ty != "inline" {
                                "binary".to_string()
                            } else {
                                String::new()
                            }
                        });

                    let download_detour = obj
                        .get("download_detour")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let update_interval = obj
                        .get("update_interval")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    
                    let rules = if ty == "inline" {
                         obj.get("rules").and_then(|v| v.as_array()).map(|arr| {
                             arr.iter().map(parse_rule_entry).collect()
                         })
                    } else {
                        None
                    };

                    if !tag.is_empty() {
                        ir.route.rule_set.push(crate::ir::RuleSetIR {
                            tag,
                            ty,
                            format,
                            path,
                            url,
                            download_detour,
                            update_interval,
                            rules,
                            version: obj.get("version")
                                .and_then(|v| v.as_u64())
                                .and_then(|v| u8::try_from(v).ok()),
                        });
                    }
                }
            }
        }
        ir.route.default = route
            .get("default")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        ir.route.final_outbound = route
            .get("final")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| ir.route.default.clone());

        if ir.route.default.is_none() {
            ir.route.default = ir.route.final_outbound.clone();
        }

        ir.route.find_process = route.get("find_process").and_then(|v| v.as_bool());
        ir.route.override_android_vpn = route.get("override_android_vpn").and_then(|v| v.as_bool());
        ir.route.auto_detect_interface =
            route.get("auto_detect_interface").and_then(|v| v.as_bool());
        ir.route.default_interface = route
            .get("default_interface")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        ir.route.mark = route
            .get("mark")
            .or_else(|| route.get("default_mark"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Parse default_domain_resolver (polymorphic: string or object)
        let default_resolver_val = route.get("default_domain_resolver").or_else(|| route.get("default_resolver"));
        if let Some(val) = default_resolver_val {
            if let Some(s) = val.as_str() {
                ir.route.default_domain_resolver = Some(crate::ir::DomainResolveOptionsIR {
                    server: s.to_string(),
                    ..Default::default()
                });
            } else if let Some(obj) = val.as_object() {
                // Manual parsing or serde? Manual to control defaults/optionality
                 ir.route.default_domain_resolver = Some(crate::ir::DomainResolveOptionsIR {
                    server: obj.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    strategy: obj.get("strategy").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    disable_cache: obj.get("disable_cache").and_then(|v| v.as_bool()),
                    rewrite_ttl: parse_u32_field(obj.get("rewrite_ttl")),
                    client_subnet: obj.get("client_subnet").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        } else {
             ir.route.default_domain_resolver = None;
        }
        ir.route.network_strategy = route
            .get("default_network_strategy")
            .or_else(|| route.get("network_strategy"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        ir.route.default_network_type = extract_string_list(route.get("default_network_type"));
        ir.route.default_fallback_network_type =
            extract_string_list(route.get("default_fallback_network_type"));
        ir.route.default_fallback_delay = route
            .get("default_fallback_delay")
            .or_else(|| route.get("fallback_delay"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    // Preserve optional experimental block (schema v2 passthrough).
    if let Some(exp) = doc.get("experimental") {
        ir.experimental = serde_json::from_value(exp.clone()).ok();
    }

    // Parse optional log block (top-level)
    if let Some(log) = doc.get("log").and_then(|v| v.as_object()) {
        let l = crate::ir::LogIR {
            level: log
                .get("level")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            timestamp: log.get("timestamp").and_then(|v| v.as_bool()),
            // Non-standard extension for rust build: allow format override
            format: log
                .get("format")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            // Go parity: log.disabled
            disabled: log.get("disabled").and_then(|v| v.as_bool()),
            // Go parity: log.output (stdout/stderr/path)
            output: log
                .get("output")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };
        ir.log = Some(l);
    }

    // Parse optional NTP block (top-level)
    if let Some(ntp) = doc.get("ntp").and_then(|v| v.as_object()) {
        let n = crate::ir::NtpIR {
            enabled: ntp
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            server: ntp
                .get("server")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            server_port: ntp
                .get("server_port")
                .and_then(|v| v.as_u64())
                .and_then(|x| u16::try_from(x).ok()),
            // Support either interval (string like "30m") or interval_ms (number)
            interval_ms: parse_seconds_field_to_millis(ntp.get("interval"))
                .or_else(|| ntp.get("interval_ms").and_then(|v| v.as_u64())),
            // Optional timeout_ms (number or duration string)
            timeout_ms: parse_millis_field(ntp.get("timeout_ms"))
                .or_else(|| parse_seconds_field_to_millis(ntp.get("timeout"))),
        };
        ir.ntp = Some(n);
    }

    // Parse optional certificate block (top-level)
    if let Some(cert) = doc.get("certificate").and_then(|v| v.as_object()) {
        let mut c = crate::ir::CertificateIR::default();
        if let Some(arr) = cert.get("ca_paths").and_then(|v| v.as_array()) {
            for p in arr {
                if let Some(s) = p.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        c.ca_paths.push(s.to_string());
                    }
                }
            }
        }
        // Support both array and single-string for ca_pem
        match cert.get("ca_pem") {
            Some(v) if v.is_array() => {
                if let Some(arr) = v.as_array() {
                    for it in arr {
                        if let Some(s) = it.as_str() {
                            let s = s.trim();
                            if !s.is_empty() {
                                c.ca_pem.push(s.to_string());
                            }
                        }
                    }
                }
            }
            Some(v) if v.is_string() => {
                if let Some(s) = v.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        c.ca_pem.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
        ir.certificate = Some(c);
    }

    // Parse optional DNS block (top-level)
    if let Some(dns) = doc.get("dns").and_then(|v| v.as_object()) {
        let mut dd = crate::ir::DnsIR {
            // Global ECS/Client Subnet (string like "x.x.x.x/24" or "2001:db8::/56")
            client_subnet: dns
                .get("client_subnet")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            ..Default::default()
        };
        if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
            for s in servers {
                if let Some(map) = s.as_object() {
                    let tag = map
                        .get("tag")
                        .or_else(|| map.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    // Accept both legacy `address: "<proto>://..."` and
                    // go1.12.4-style `{ "type": "...", "server": "..." }` shapes.
                    let address = if let Some(addr) = map
                        .get("address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                    {
                        addr
                    } else if let Some(ty) = map
                        .get("type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_lowercase())
                    {
                        let server = map
                            .get("server")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if server.is_empty() {
                            String::new()
                        } else {
                            match ty.as_str() {
                                // Match Go 1.12.x pretty-printed DNS format
                                "udp" => format!("udp://{}", server),
                                "tcp" => format!("tcp://{}", server),
                                "tls" | "dot" => format!("tls://{}", server),
                                "https" => format!("https://{}/dns-query", server),
                                "rcode" => format!("rcode://{}", server),
                                other => format!("{}://{}", other, server),
                            }
                        }
                    } else {
                        String::new()
                    };

                    if !tag.is_empty() && !address.is_empty() {
                        // Optional TLS extras
                        let mut ca_paths = Vec::new();
                        if let Some(arr) = map.get("ca_paths").and_then(|v| v.as_array()) {
                            for p in arr {
                                if let Some(s) = p.as_str() {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        ca_paths.push(s.to_string());
                                    }
                                }
                            }
                        }
                        let mut ca_pem = Vec::new();
                        match map.get("ca_pem") {
                            Some(v) if v.is_array() => {
                                for it in v.as_array().unwrap() {
                                    if let Some(s) = it.as_str() {
                                        let s = s.trim();
                                        if !s.is_empty() {
                                            ca_pem.push(s.to_string());
                                        }
                                    }
                                }
                            }
                            Some(v) if v.is_string() => {
                                if let Some(s) = v.as_str() {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        ca_pem.push(s.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                        let client_subnet = map
                            .get("client_subnet")
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                        dd.servers.push(crate::ir::DnsServerIR {
                            tag,
                            address,
                            sni: map
                                .get("sni")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            ca_paths,
                            ca_pem,
                            skip_cert_verify: map.get("skip_cert_verify").and_then(|v| v.as_bool()),
                            client_subnet,
                            address_resolver: map.get("address_resolver").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            address_strategy: map.get("address_strategy").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            address_fallback_delay: map.get("address_fallback_delay").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            strategy: map.get("strategy").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            detour: map.get("detour").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        });
                    }
                }
            }
        }
        if let Some(rules) = dns.get("rules").and_then(|v| v.as_array()) {
            for (idx, r) in rules.iter().enumerate() {
                if let Some(obj) = r.as_object() {
                    let server = obj
                        .get("server")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string());
                    let action = obj
                        .get("action")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // If neither server nor action is present/valid (and action is not "reject" etc which might work without server? 
                    // actually if action is missing, server MUST be present. If action is present, server might be optional depending on action.
                    // For now, if both are missing, skip.
                    if server.is_none() && action.is_none() {
                        continue;
                    }

                    let mut dr = crate::ir::DnsRuleIR {
                        server,
                        action,
                        priority: Some(idx as u32 + 1),
                        rewrite_ttl: parse_u32_field(obj.get("rewrite_ttl")),
                        client_subnet: obj.get("client_subnet").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        disable_cache: obj.get("disable_cache").and_then(|v| v.as_bool()),
                        invert: obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false),
                        
                        // New Matching Fields
                        ip_is_private: obj.get("ip_is_private").and_then(|v| v.as_bool()),
                        source_ip_is_private: obj.get("source_ip_is_private").and_then(|v| v.as_bool()),
                        ip_accept_any: obj.get("ip_accept_any").and_then(|v| v.as_bool()),
                        rule_set_ip_cidr_match_source: obj.get("rule_set_ip_cidr_match_source").and_then(|v| v.as_bool()),
                        rule_set_ip_cidr_accept_empty: obj.get("rule_set_ip_cidr_accept_empty").and_then(|v| v.as_bool()),
                        clash_mode: obj.get("clash_mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        network_is_expensive: obj.get("network_is_expensive").and_then(|v| v.as_bool()),
                        network_is_constrained: obj.get("network_is_constrained").and_then(|v| v.as_bool()),

                        // New Action Fields
                        rewrite_ip: extract_string_list(obj.get("rewrite_ip")),
                        rcode: obj.get("rcode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        answer: extract_string_list(obj.get("answer")),
                        ns: extract_string_list(obj.get("ns")),
                        extra: extract_string_list(obj.get("extra")),

                        ..Default::default()
                    };

                    // String list matchers
                    dr.domain_suffix = extract_string_list(obj.get("domain_suffix")).unwrap_or_default();
                    dr.domain = extract_string_list(obj.get("domain")).unwrap_or_default();
                    dr.domain_regex = extract_string_list(obj.get("domain_regex")).unwrap_or_default();
                    dr.keyword = extract_string_list(obj.get("domain_keyword").or(obj.get("keyword"))).unwrap_or_default();
                    dr.geosite = extract_string_list(obj.get("geosite")).unwrap_or_default();
                    dr.geoip = extract_string_list(obj.get("geoip")).unwrap_or_default();
                    dr.source_ip_cidr = extract_string_list(obj.get("source_ip_cidr")).unwrap_or_default();
                    dr.ip_cidr = extract_string_list(obj.get("ip_cidr")).unwrap_or_default();
                    dr.port = extract_string_list(obj.get("port")).unwrap_or_default();
                    dr.source_port = extract_string_list(obj.get("source_port")).unwrap_or_default();
                    dr.process_name = extract_string_list(obj.get("process_name").or(obj.get("process"))).unwrap_or_default();
                    dr.process_path = extract_string_list(obj.get("process_path")).unwrap_or_default();
                    dr.package_name = extract_string_list(obj.get("package_name")).unwrap_or_default();
                    dr.wifi_ssid = extract_string_list(obj.get("wifi_ssid")).unwrap_or_default();
                    dr.wifi_bssid = extract_string_list(obj.get("wifi_bssid")).unwrap_or_default();
                    dr.rule_set = extract_string_list(obj.get("rule_set")).unwrap_or_default();
                    dr.query_type = extract_string_list(obj.get("query_type")).unwrap_or_default();

                    // Note: keywords were previously named 'keyword' in IR but 'domain_keyword' in generic RuleIR. 
                                                            // Wait, struct has `keyword`, I removed `keyword` field? No.
                                                            // Line 2566 says `keyword: Vec<String>`.
                                                            // I should map both `domain_keyword` and `keyword` config to `keyword` IR field.
                    // Correcting logic below:

                    dd.rules.push(dr);
                }
            }
        }
        dd.default = dns
            .get("final")
            .or_else(|| dns.get("default"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        dd.final_server = dns
            .get("final")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        dd.disable_cache = dns.get("disable_cache").and_then(|v| v.as_bool());
        dd.reverse_mapping = dns.get("reverse_mapping").and_then(|v| v.as_bool());
        dd.strategy = dns.get("strategy").and_then(|v| v.as_str()).map(|s| s.to_string());
        dd.client_subnet = dns.get("client_subnet").and_then(|v| v.as_str()).map(|s| s.to_string());
        dd.independent_cache = dns.get("independent_cache").and_then(|v| v.as_bool());
        // Global knobs
        if let Some(v) = dns.get("timeout_ms").and_then(|x| x.as_u64()) {
            dd.timeout_ms = Some(v);
        }
        if let Some(t) = dns.get("ttl").and_then(|v| v.as_object()) {
            dd.ttl_default_s = t.get("default").and_then(|x| x.as_u64());
            dd.ttl_min_s = t.get("min").and_then(|x| x.as_u64());
            dd.ttl_max_s = t.get("max").and_then(|x| x.as_u64());
            dd.ttl_neg_s = t.get("neg").and_then(|x| x.as_u64());
        }
        if let Some(fk) = dns.get("fakeip").and_then(|v| v.as_object()) {
            dd.fakeip_enabled = fk.get("enabled").and_then(|x| x.as_bool());
            let v4 = fk
                .get("inet4_range")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let v6 = fk
                .get("inet6_range")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            if let Some(s) = v4 {
                if let Some((base, mask)) = s.split_once('/') {
                    dd.fakeip_v4_base = Some(base.to_string());
                    dd.fakeip_v4_mask = mask.parse::<u8>().ok();
                } else {
                    dd.fakeip_v4_base = Some(s);
                }
            }
            if let Some(s) = v6 {
                if let Some((base, mask)) = s.split_once('/') {
                    dd.fakeip_v6_base = Some(base.to_string());
                    dd.fakeip_v6_mask = mask.parse::<u8>().ok();
                } else {
                    dd.fakeip_v6_base = Some(s);
                }
            }
        }
        if let Some(s) = dns.get("pool_strategy").and_then(|v| v.as_str()) {
            dd.pool_strategy = Some(s.to_string());
        }
        if let Some(p) = dns.get("pool").and_then(|v| v.as_object()) {
            dd.pool_race_window_ms = p.get("race_window_ms").and_then(|x| x.as_u64());
            dd.pool_he_race_ms = p.get("he_race_ms").and_then(|x| x.as_u64());
            dd.pool_he_order = p
                .get("he_order")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            dd.pool_max_inflight = p.get("max_inflight").and_then(|x| x.as_u64());
            dd.pool_per_host_inflight = p.get("per_host_inflight").and_then(|x| x.as_u64());
        }

        // Static hosts mapping
        if let Some(h) = dns.get("hosts").and_then(|v| v.as_object()) {
            for (domain, val) in h {
                let domain = domain.trim().to_string();
                if domain.is_empty() {
                    continue;
                }
                let mut ips: Vec<String> = Vec::new();
                match val {
                    serde_json::Value::String(s) => {
                        let s = s.trim();
                        if !s.is_empty() {
                            ips.push(s.to_string());
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for it in arr {
                            if let Some(s) = it.as_str() {
                                let s = s.trim();
                                if !s.is_empty() {
                                    ips.push(s.to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
                if !ips.is_empty() {
                    dd.hosts.push(crate::ir::DnsHostIR { domain, ips });
                }
            }
            dd.hosts_ttl_s = dns
                .get("hosts_ttl")
                .or_else(|| dns.get("static_ttl"))
                .and_then(|v| v.as_u64());
        }

        if !dd.servers.is_empty()
            || !dd.rules.is_empty()
            || dd.default.is_some()
            || dd.timeout_ms.is_some()
            || !dd.hosts.is_empty()
        {
            ir.dns = Some(dd);
        }
    }

    // Parse services
    if let Some(services) = doc.get("services").and_then(|v| v.as_array()) {
        for s in services {
            let ty_str = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ty = match ty_str {
                "resolved" => crate::ir::ServiceType::Resolved,
                "ssm-api" | "ssmapi" => crate::ir::ServiceType::Ssmapi,
                "derp" => crate::ir::ServiceType::Derp,
                _ => continue,
            };

            let mut service_ir = crate::ir::ServiceIR {
                ty,
                tag: s.get("tag").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ..Default::default()
            };

            let legacy_listen_key = match ty {
                crate::ir::ServiceType::Resolved => "resolved_listen",
                crate::ir::ServiceType::Ssmapi => "ssmapi_listen",
                crate::ir::ServiceType::Derp => "derp_listen",
            };
            let legacy_listen_port_key = match ty {
                crate::ir::ServiceType::Resolved => "resolved_listen_port",
                crate::ir::ServiceType::Ssmapi => "ssmapi_listen_port",
                crate::ir::ServiceType::Derp => "derp_listen_port",
            };

            service_ir.listen = s
                .get("listen")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    s.get(legacy_listen_key)
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                });
            service_ir.listen_port = parse_u16_field(s.get("listen_port")).or_else(|| {
                parse_u16_field(s.get(legacy_listen_port_key)).or_else(|| {
                    s.get(legacy_listen_port_key)
                        .and_then(|v| v.as_u64())
                        .map(|x| x as u16)
                })
            });
            service_ir.bind_interface = s
                .get("bind_interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.routing_mark = parse_fwmark_field(s.get("routing_mark"));
            service_ir.reuse_addr = s.get("reuse_addr").and_then(|v| v.as_bool());
            service_ir.netns = s
                .get("netns")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.tcp_fast_open = s.get("tcp_fast_open").and_then(|v| v.as_bool());
            service_ir.tcp_multi_path = s.get("tcp_multi_path").and_then(|v| v.as_bool());
            service_ir.udp_fragment = s.get("udp_fragment").and_then(|v| v.as_bool());
            service_ir.udp_timeout = s
                .get("udp_timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.detour = s
                .get("detour")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.sniff = s.get("sniff").and_then(|v| v.as_bool());
            service_ir.sniff_override_destination = s
                .get("sniff_override_destination")
                .and_then(|v| v.as_bool());
            service_ir.sniff_timeout = s
                .get("sniff_timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.domain_strategy = s
                .get("domain_strategy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            service_ir.udp_disable_domain_unmapping = s
                .get("udp_disable_domain_unmapping")
                .and_then(|v| v.as_bool());

            service_ir.tls = parse_inbound_tls_options(s.get("tls"));

            // Legacy TLS path fields (Rust-only schema) → Go-style `tls`.
            match ty {
                crate::ir::ServiceType::Ssmapi => {
                    let legacy_cert = s
                        .get("ssmapi_tls_cert_path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let legacy_key = s
                        .get("ssmapi_tls_key_path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if (legacy_cert.is_some() || legacy_key.is_some()) && service_ir.tls.is_none() {
                        service_ir.tls = Some(InboundTlsOptionsIR {
                            enabled: true,
                            certificate_path: legacy_cert,
                            key_path: legacy_key,
                            ..Default::default()
                        });
                    }
                    if let Some(cache) = s
                        .get("cache_path")
                        .or_else(|| s.get("ssmapi_cache_path"))
                        .and_then(|v| v.as_str())
                    {
                        service_ir.cache_path = Some(cache.to_string());
                    }
                    if let Some(servers) = s.get("servers").and_then(|v| v.as_object()) {
                        let mut map = std::collections::HashMap::new();
                        for (k, v) in servers {
                            if let Some(tag) = v.as_str() {
                                map.insert(k.to_string(), tag.to_string());
                            }
                        }
                        if !map.is_empty() {
                            service_ir.servers = Some(map);
                        }
                    }
                }
                crate::ir::ServiceType::Derp => {
                    let legacy_cert = s
                        .get("derp_tls_cert_path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let legacy_key = s
                        .get("derp_tls_key_path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if (legacy_cert.is_some() || legacy_key.is_some()) && service_ir.tls.is_none() {
                        service_ir.tls = Some(InboundTlsOptionsIR {
                            enabled: true,
                            certificate_path: legacy_cert,
                            key_path: legacy_key,
                            ..Default::default()
                        });
                    }

                    service_ir.config_path = s
                        .get("config_path")
                        .or_else(|| s.get("derp_config_path"))
                        .or_else(|| s.get("derp_server_key_path"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    service_ir.verify_client_endpoint = extract_string_list(
                        s.get("verify_client_endpoint")
                            .or_else(|| s.get("derp_verify_client_endpoint")),
                    );
                    service_ir.verify_client_url = extract_string_list(
                        s.get("verify_client_url")
                            .or_else(|| s.get("derp_verify_client_url")),
                    );
                    service_ir.home = s
                        .get("home")
                        .or_else(|| s.get("derp_home"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    service_ir.mesh_psk = s
                        .get("mesh_psk")
                        .or_else(|| s.get("derp_mesh_psk"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    service_ir.mesh_psk_file = s
                        .get("mesh_psk_file")
                        .or_else(|| s.get("derp_mesh_psk_file"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    service_ir.mesh_with = parse_derp_mesh_with(
                        s.get("mesh_with").or_else(|| s.get("derp_mesh_with")),
                    );
                    service_ir.stun = parse_derp_stun_options(s.get("stun")).or_else(|| {
                        let enabled = s.get("derp_stun_enabled").and_then(|v| v.as_bool());
                        let port = parse_u16_field(s.get("derp_stun_listen_port"));
                        if enabled.is_none() && port.is_none() {
                            return None;
                        }
                        Some(DerpStunOptionsIR {
                            enabled: enabled.unwrap_or(true),
                            listen: None,
                            listen_port: port,
                            ..Default::default()
                        })
                    });
                }
                crate::ir::ServiceType::Resolved => {
                    // Resolved service has only Listen Fields; defaults applied at runtime.
                }
            }

            ir.services.push(service_ir);
        }
    }

    normalize_credentials(&mut ir);
    ir
}

fn parse_listen_host_port(listen: &str) -> Option<(String, u16)> {
    if let Some(stripped) = listen.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &stripped[..close];
        let rest = &stripped[close + 1..];
        let port_str = rest.strip_prefix(':')?;
        let port = port_str.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port_str) = listen.rsplit_once(':')?;
    let port = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reality_config() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.name, Some("reality-out".to_string()));
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("01ab".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.apple.com".to_string())
        );

        // Validate the parsed config
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_tuic_outbound_fields() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "tuic",
                "name": "tuic-out",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "token": "secret-token",
                "password": "optional-pass",
                "congestion_control": "bbr",
                "udp_relay_mode": "quic",
                "udp_over_stream": true,
                "skip_cert_verify": true,
                "tls": {
                    "alpn": "h3",
                    "skip_cert_verify": true
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);

        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Tuic);
        assert_eq!(outbound.name.as_deref(), Some("tuic-out"));
        assert_eq!(outbound.token.as_deref(), Some("secret-token"));
        assert_eq!(outbound.password.as_deref(), Some("optional-pass"));
        assert_eq!(outbound.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(outbound.udp_relay_mode.as_deref(), Some("quic"));
        assert_eq!(outbound.udp_over_stream, Some(true));
        assert_eq!(outbound.skip_cert_verify, Some(true));
        assert_eq!(outbound.alpn.as_deref(), Some("h3"));
        assert_eq!(outbound.tls_alpn, Some(vec!["h3".to_string()]));
    }

    #[test]
    fn test_parse_hysteria2_bandwidth_fields() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "hysteria2",
                "name": "hy2",
                "server": "hy2.example.com",
                "port": 443,
                "password": "secret",
                "up_mbps": 150,
                "down_mbps": "200Mbps",
                "obfs": "obfs-key",
                "salamander": "fingerprint",
                "brutal": {
                    "up_mbps": "300",
                    "down_mbps": "400Mbps"
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Hysteria2);
        assert_eq!(outbound.up_mbps, Some(150));
        assert_eq!(outbound.down_mbps, Some(200));
        assert_eq!(outbound.obfs.as_deref(), Some("obfs-key"));
        assert_eq!(outbound.salamander.as_deref(), Some("fingerprint"));
        assert_eq!(outbound.brutal_up_mbps, Some(300));
        assert_eq!(outbound.brutal_down_mbps, Some(400));
    }

    #[test]
    fn test_parse_experimental_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "feature_flag": true,
                "nested": { "value": 42 }
            }
        });

        let ir = to_ir_v1(&json);
        let _exp = ir
            .experimental
            .expect("experimental block should be present");
        // Note: The following assertions are commented out because ExperimentalIR
        // is a struct, not a map. Access fields directly if needed.
        // assert_eq!(exp["feature_flag"], serde_json::json!(true));
        // assert_eq!(exp["nested"]["value"], serde_json::json!(42));
    }

    #[test]
    fn test_default_shadowsocks_method() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "shadowsocks",
                "name": "ss-out",
                "server": "127.0.0.1",
                "port": 8388,
                "password": "secret"
                // no method provided
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Shadowsocks);
        assert_eq!(outbound.method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn test_parse_ntp_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "ntp": {
                "enabled": true,
                "server": "time.apple.com",
                "server_port": 123,
                "interval": "30m",
                "timeout_ms": 2500
            }
        });
        let ir = to_ir_v1(&json);
        let ntp = ir.ntp.expect("ntp should be present");
        assert!(ntp.enabled);
        assert_eq!(ntp.server.as_deref(), Some("time.apple.com"));
        assert_eq!(ntp.server_port, Some(123));
        assert_eq!(ntp.interval_ms, Some(30 * 60 * 1000));
        assert_eq!(ntp.timeout_ms, Some(2500));
    }

    #[test]
    fn test_parse_transport_object_ws() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "ws-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "ws",
                    "path": "/ws",
                    "headers": {
                        "Host": "example.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        if let Some(transport) = outbound.transport.as_ref() {
            assert_eq!(transport.len(), 1);
            assert_eq!(transport[0], "ws");
        } else {
            panic!("expected transport tokens");
        }
        assert_eq!(outbound.ws_path.as_deref(), Some("/ws"));
        assert_eq!(outbound.ws_host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_transport_object_grpc() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vmess",
                "name": "grpc-out",
                "server": "grpc.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "grpc",
                    "service_name": "TunnelService",
                    "method_name": "Tunnel",
                    "authority": "grpc.example.com",
                    "metadata": {
                        "auth": "token",
                        "foo": "bar"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        if let Some(transport) = outbound.transport.as_ref() {
            assert_eq!(transport, &vec!["grpc".to_string()]);
        } else {
            panic!("expected transport tokens");
        }
        assert_eq!(outbound.grpc_service.as_deref(), Some("TunnelService"));
        assert_eq!(outbound.grpc_method.as_deref(), Some("Tunnel"));
        assert_eq!(outbound.grpc_authority.as_deref(), Some("grpc.example.com"));
        let mut metadata: Vec<(String, String)> = outbound
            .grpc_metadata
            .iter()
            .map(|h| (h.key.clone(), h.value.clone()))
            .collect();
        metadata.sort();
        assert_eq!(metadata.len(), 2);
        assert!(metadata.contains(&("auth".to_string(), "token".to_string())));
        assert!(metadata.contains(&("foo".to_string(), "bar".to_string())));
    }

    #[test]
    fn test_parse_transport_object_http_upgrade() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "hup-out",
                "server": "upgrade.example.com",
                "port": 80,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "httpupgrade",
                    "path": "/upgrade",
                    "headers": {
                        "User-Agent": "singbox",
                        "Authorization": "Bearer token"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        if let Some(transport) = outbound.transport.as_ref() {
            assert_eq!(transport, &vec!["httpupgrade".to_string()]);
        } else {
            panic!("expected transport tokens");
        }
        assert_eq!(outbound.http_upgrade_path.as_deref(), Some("/upgrade"));
        let mut headers: Vec<(String, String)> = outbound
            .http_upgrade_headers
            .iter()
            .map(|h| (h.key.clone(), h.value.clone()))
            .collect();
        headers.sort();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&("User-Agent".to_string(), "singbox".to_string())));
        assert!(headers.contains(&("Authorization".to_string(), "Bearer token".to_string())));
    }

    #[test]
    fn test_parse_reality_config_nested_tls() {
        // Test backward compatibility with nested tls object
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "sni": "www.apple.com",
                    "alpn": "h2,http/1.1",
                    "reality": {
                        "enabled": true,
                        "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "short_id": "cdef",
                        "server_name": "www.cloudflare.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        // Check TLS fields are parsed
        assert_eq!(outbound.tls_sni, Some("www.apple.com".to_string()));
        assert_eq!(
            outbound.tls_alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );

        // Check REALITY fields are parsed
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("cdef".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.cloudflare.com".to_string())
        );
    }

    #[test]
    fn test_parse_reality_config_disabled() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com",
                    "reality": {
                        "enabled": false
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.reality_enabled, Some(false));
        // When disabled, validation should pass even without other fields
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_reality_config_without_reality() {
        // Test that outbounds without REALITY config work normally
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com"
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.reality_enabled, None);
        assert_eq!(outbound.reality_public_key, None);
        assert_eq!(outbound.reality_short_id, None);
        assert_eq!(outbound.reality_server_name, None);

        // Should pass validation when REALITY is not enabled
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_selector_and_urltest_parsing() -> anyhow::Result<()> {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                { "type": "direct", "name": "direct-1" },
                { "type": "direct", "name": "direct-2" },
                {
                    "type": "selector",
                    "name": "manual",
                    "outbounds": ["direct-1", "direct-2"],
                    "default": "direct-1"
                },
                {
                    "type": "urltest",
                    "name": "auto",
                    "outbounds": ["direct-1"],
                    "interval": "5s",
                    "timeout": 2,
                    "tolerance": "75ms"
                }
            ]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 4);

        let manual = match ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("manual"))
        {
            Some(v) => v,
            None => {
                panic!("manual selector not found");
            }
        };
        assert_eq!(manual.ty, crate::ir::OutboundType::Selector);
        if let Some(members) = manual.members.as_ref() {
            assert_eq!(
                members,
                &vec!["direct-1".to_string(), "direct-2".to_string()]
            );
        } else {
            panic!("manual selector members missing");
        }
        assert_eq!(manual.default_member.as_deref(), Some("direct-1"));

        let auto = match ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("auto"))
        {
            Some(v) => v,
            None => {
                panic!("urltest selector not found");
            }
        };
        assert_eq!(auto.ty, crate::ir::OutboundType::UrlTest);
        if let Some(members) = auto.members.as_ref() {
            assert_eq!(members, &vec!["direct-1".to_string()]);
        } else {
            panic!("urltest selector members missing");
        }
        assert_eq!(auto.test_interval_ms, Some(5_000));
        assert_eq!(auto.test_timeout_ms, Some(2_000));
        assert_eq!(auto.test_tolerance_ms, Some(75));
        assert_eq!(auto.test_url.as_deref(), Some(DEFAULT_URLTEST_URL));
        Ok(())
    }

    #[test]
    fn test_shadowsocks_parsing() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "shadowsocks",
                "name": "ss-out",
                "server": "1.2.3.4",
                "port": 8388,
                "password": "secret",
                "method": "aes-256-gcm"
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let ss = &ir.outbounds[0];
        assert_eq!(ss.ty, crate::ir::OutboundType::Shadowsocks);
        assert_eq!(ss.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ss.port, Some(8388));
        assert_eq!(ss.password.as_deref(), Some("secret"));
        assert_eq!(ss.method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn test_parse_outbound_tls_nested_fields() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vmess",
                "name": "vmess-internal",
                "server": "vmess.internal",
                "port": 443,
                "tls": {
                    "sni": "internal.example",
                    "alpn": "h2,http/1.1",
                    "skip_cert_verify": true,
                    "ca_paths": ["/etc/ssl/certs/internal-root.pem"],
                    "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...snip...\n-----END CERTIFICATE-----",
                    "client_cert_path": "/path/to/client.crt",
                    "client_key_path": "/path/to/client.key"
                }
            }]
        });
        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let ob = &ir.outbounds[0];
        assert_eq!(ob.tls_sni.as_deref(), Some("internal.example"));
        assert_eq!(
            ob.tls_alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
        assert_eq!(ob.skip_cert_verify, Some(true));
        assert_eq!(
            ob.tls_ca_paths,
            vec!["/etc/ssl/certs/internal-root.pem".to_string()]
        );
        assert_eq!(ob.tls_ca_pem.len(), 1);
        assert_eq!(
            ob.tls_client_cert_path.as_deref(),
            Some("/path/to/client.crt")
        );
        assert_eq!(
            ob.tls_client_key_path.as_deref(),
            Some("/path/to/client.key")
        );
    }

    #[test]
    fn test_parse_top_level_certificate_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "certificate": {
                "ca_paths": ["/etc/custom/root.pem"],
                "ca_pem": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"]
            }
        });
        let ir = to_ir_v1(&json);
        let cert = ir.certificate.expect("certificate should be parsed");
        assert_eq!(cert.ca_paths, vec!["/etc/custom/root.pem".to_string()]);
        assert_eq!(cert.ca_pem.len(), 1);
    }

    #[test]
    fn test_parse_dns_servers_with_tls_extras() {
        let json = serde_json::json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "sys", "address": "system"},
                    {"tag": "dot1", "address": "dot://1.1.1.1:853", "sni": "cloudflare-dns.com", "ca_paths": ["/etc/ssl/certs/custom.pem"], "skip_cert_verify": false},
                    {"tag": "doq1", "address": "doq://1.0.0.1:853@one.one.one.one", "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                ],
                "default": "sys"
            }
        });
        let ir = to_ir_v1(&json);
        assert!(ir.dns.is_some());
        let dns = ir.dns.unwrap();
        let mut tags: Vec<String> = dns.servers.iter().map(|s| s.tag.clone()).collect();
        tags.sort();
        assert_eq!(tags, vec!["doq1", "dot1", "sys"]);
        let dot = dns.servers.iter().find(|s| s.tag == "dot1").unwrap();
        assert_eq!(dot.sni.as_deref(), Some("cloudflare-dns.com"));
        assert_eq!(dot.ca_paths, vec!["/etc/ssl/certs/custom.pem".to_string()]);
        let doq = dns.servers.iter().find(|s| s.tag == "doq1").unwrap();
        assert_eq!(doq.ca_pem.len(), 1);
    }
}
