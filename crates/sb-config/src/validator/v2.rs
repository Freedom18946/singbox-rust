use crate::ir::{ConfigIR, Credentials, HeaderEntry};
use sb_types::IssueCode;
use serde_json::{json, Value};

const DEFAULT_URLTEST_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_URLTEST_INTERVAL_MS: u64 = 60_000;
const DEFAULT_URLTEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

fn extract_string_list(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect()
    })
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

fn push_header_entry(target: &mut Vec<HeaderEntry>, name: &str, value: &str) {
    if name.trim().is_empty() {
        return;
    }
    target.push(HeaderEntry {
        name: name.trim().to_string(),
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
///
/// # Arguments
/// * `doc` - 待验证的 JSON 文档
/// * `allow_unknown` - 是否将未知字段视为警告（true）而非错误（false）
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
    // 2) inbounds required/type checks（节选）
    if let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for (i, ib) in arr.iter().enumerate() {
            // required: type (always required)
            if ib.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/inbounds/{}/type", i),
                    "missing required field",
                    "add it",
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

            // additionalProperties=false (V2 允许的字段)
            if let Some(map) = ib.as_object() {
                for k in map.keys() {
                    match k.as_str() {
                        "name" | "type" | "listen" | "port" | "udp" | "network" | "sniff" 
                        | "override_address" | "override_host" | "override_port"
                        | "interface_name" | "inet4_address" | "inet6_address" | "auto_route" 
                        | "auth" | "users" | "cert" | "key" 
                        | "congestion_control" | "salamander" | "obfs" 
                        | "up_mbps" | "down_mbps" => {}
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
                "direct" => crate::ir::InboundType::Direct,
                _ => crate::ir::InboundType::Socks,
            };
            // Common fields
            let listen = i
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1")
                .to_string();
            let port = i.get("port").and_then(|v| v.as_u64()).unwrap_or(1080) as u16;
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
                ty,
                listen,
                port,
                sniff,
                udp,
                basic_auth,
                override_host,
                override_port,
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
                _ => crate::ir::OutboundType::Direct,
            };
            let mut ob = crate::ir::OutboundIR {
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
                members: None,
                default_member: None,
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
                tls_alpn: o
                    .get("tls_alpn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                reality_enabled: None,
                reality_public_key: None,
                reality_short_id: None,
                reality_server_name: None,
                password: o
                    .get("password")
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
                test_url: None,
                test_interval_ms: None,
                test_timeout_ms: None,
                test_tolerance_ms: None,
                interrupt_exist_connections: None,
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
                    ob.tls_alpn = tls
                        .get("alpn")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
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
                arrs!("domain_suffix", r.domain);
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
                r.outbound = rr
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
        if ir.route.default.is_none() {
            ir.route.default = route
                .get("final")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    normalize_credentials(&mut ir);
    ir
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
        assert_eq!(outbound.tls_alpn.as_deref(), Some("h3"));
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
        let transport = outbound.transport.as_ref().expect("transport");
        assert_eq!(transport.len(), 1);
        assert_eq!(transport[0], "ws");
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
        let transport = outbound
            .transport
            .as_ref()
            .expect("transport tokens present");
        assert_eq!(transport, &vec!["grpc".to_string()]);
        assert_eq!(outbound.grpc_service.as_deref(), Some("TunnelService"));
        assert_eq!(outbound.grpc_method.as_deref(), Some("Tunnel"));
        assert_eq!(outbound.grpc_authority.as_deref(), Some("grpc.example.com"));
        let mut metadata: Vec<(String, String)> = outbound
            .grpc_metadata
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
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
        let transport = outbound
            .transport
            .as_ref()
            .expect("transport tokens present");
        assert_eq!(transport, &vec!["httpupgrade".to_string()]);
        assert_eq!(outbound.http_upgrade_path.as_deref(), Some("/upgrade"));
        let mut headers: Vec<(String, String)> = outbound
            .http_upgrade_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
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
        assert_eq!(outbound.tls_alpn, Some("h2,http/1.1".to_string()));

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
    fn test_selector_and_urltest_parsing() {
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

        let manual = ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("manual"))
            .expect("manual selector present");
        assert_eq!(manual.ty, crate::ir::OutboundType::Selector);
        assert_eq!(
            manual.members.as_ref().expect("members"),
            &vec!["direct-1".to_string(), "direct-2".to_string()]
        );
        assert_eq!(manual.default_member.as_deref(), Some("direct-1"));

        let auto = ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("auto"))
            .expect("urltest selector present");
        assert_eq!(auto.ty, crate::ir::OutboundType::UrlTest);
        assert_eq!(
            auto.members.as_ref().expect("members"),
            &vec!["direct-1".to_string()]
        );
        assert_eq!(auto.test_interval_ms, Some(5_000));
        assert_eq!(auto.test_timeout_ms, Some(2_000));
        assert_eq!(auto.test_tolerance_ms, Some(75));
        assert_eq!(auto.test_url.as_deref(), Some(DEFAULT_URLTEST_URL));
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
}
