use crate::ir::{ConfigIR, Credentials, InboundType};
use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

fn allowed_inbound_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::InboundIR::default());
    // ty → type in JSON
    if set.remove("ty") {
        set.insert("type".to_string());
    }
    // REALITY is user-facing only under `tls.reality`; top-level `reality`
    // is an internal serialized-IR field.
    set.remove("reality");
    // Raw-only / alias fields not present on InboundIR
    insert_keys(
        &mut set,
        &[
            "name",
            "listen_port",
            "override_address",
            "auth",
            "cert",
            "key",
            "up_mbps",
            "down_mbps",
            "tls",
            // Go 1.13.13 `ListenOptions` socket tuning fields. GUI.for
            // SingBox emits them on every listen-type inbound (mixed/http/
            // socks), so rejecting them blocks the same GUI launch path as
            // CAL-01. Accepted as schema-valid no-ops for now — not lowered
            // into IR (documented in post_fable_package02_tun_schema_diff.md,
            // H-4). (post_fable_package02)
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
        ],
    );
    set
}

/// Flat TUN-only fields (Go 1.13.13 `TunInboundOptions` subset accepted by
/// the strict schema). Only valid on `type: "tun"` inbounds — any other
/// inbound type carrying one of these is rejected as an unknown field.
/// (post_fable_package02 / CAL-01)
const TUN_ONLY_INBOUND_KEYS: &[&str] = &[
    "interface_name",
    "address",
    "mtu",
    "auto_route",
    "strict_route",
    "route_address",
    "route_exclude_address",
    "endpoint_independent_nat",
    "stack",
    // deprecated Go aliases of `address` (pre-1.10 style), kept accepted
    "inet4_address",
    "inet6_address",
];

fn allowed_tun_inbound_keys(base: &HashSet<String>) -> HashSet<String> {
    let mut set = base.clone();
    insert_keys(&mut set, TUN_ONLY_INBOUND_KEYS);
    set
}

fn validate_reality_short_ids(value: Option<&Value>, ptr: &str, issues: &mut Vec<Value>) {
    let Some(value) = value else {
        return;
    };
    let is_array = value.is_array();
    let values: Vec<&Value> = match value {
        Value::String(_) => vec![value],
        Value::Array(values) => values.iter().collect(),
        _ => {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                ptr,
                "short_id must be a string or string array",
                "use hex string values",
            ));
            return;
        }
    };
    for (index, value) in values.into_iter().enumerate() {
        let item_ptr = if is_array {
            format!("{ptr}/{index}")
        } else {
            ptr.to_string()
        };
        let Some(short_id) = value.as_str() else {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                &item_ptr,
                "short_id must be a string",
                "use a 0-16 character even-length hex string",
            ));
            continue;
        };
        if short_id.len() > 16
            || short_id.len() % 2 != 0
            || !short_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            issues.push(emit_issue(
                "error",
                IssueCode::RangeExceeded,
                &item_ptr,
                "short_id must be a 0-16 character even-length hex string",
                "fix short_id",
            ));
        }
    }
}

fn validate_vless_inbound(ib: &Value, index: usize, issues: &mut Vec<Value>) {
    let base = format!("/inbounds/{index}");
    let top_uuid = ib.get("uuid").and_then(Value::as_str);
    if ib.get("users").is_some() && ib.get("users_vless").is_some() {
        issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{base}/users"),
            "users and users_vless cannot both be configured",
            "keep canonical users",
        ));
    }
    let (users_key, users) = if let Some(users) = ib.get("users") {
        ("users", Some(users))
    } else {
        ("users_vless", ib.get("users_vless"))
    };
    let mut user_uuid = None;
    let mut user_flow = None;

    if let Some(users) = users {
        let Some(users) = users.as_array() else {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                &format!("{base}/{users_key}"),
                "VLESS users must be an array",
                "use a one-element users array",
            ));
            return;
        };
        if users.len() != 1 {
            issues.push(emit_issue(
                "error",
                IssueCode::RangeExceeded,
                &format!("{base}/{users_key}"),
                "Rust VLESS inbound currently requires exactly one user",
                "configure one user",
            ));
        }
        if let Some(user) = users.first() {
            let Some(user) = user.as_object() else {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("{base}/{users_key}/0"),
                    "VLESS user must be an object",
                    "use {name, uuid, flow}",
                ));
                return;
            };
            let allowed = ["name", "uuid", "flow", "security", "alter_id", "encryption"];
            for key in user.keys() {
                if !allowed.contains(&key.as_str()) {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::UnknownField,
                        &format!("{base}/{users_key}/0/{key}"),
                        "unknown VLESS user field",
                        "remove it",
                    ));
                }
            }
            user_uuid = user.get("uuid").and_then(Value::as_str);
            user_flow = user.get("flow").and_then(Value::as_str);
            if user_uuid.is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("{base}/{users_key}/0/uuid"),
                    "VLESS user uuid is required",
                    "add uuid",
                ));
            }
        }
    }

    if top_uuid.is_none() && users.is_none() {
        issues.push(emit_issue(
            "error",
            IssueCode::MissingRequired,
            &format!("{base}/uuid"),
            "VLESS inbound requires uuid or one users entry",
            "add uuid or users",
        ));
    }
    if top_uuid.is_some() && user_uuid.is_some() {
        issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{base}/uuid"),
            "VLESS uuid and users cannot both be configured",
            "keep one credential form",
        ));
    }
    if ib.get("flow").is_some() && user_flow.is_some() {
        issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{base}/flow"),
            "VLESS flow and users[0].flow cannot both be configured",
            "keep one flow value",
        ));
    }
    if let Some(uuid) = top_uuid.or(user_uuid) {
        if uuid::Uuid::parse_str(uuid).is_err() {
            issues.push(emit_issue(
                "error",
                IssueCode::InvalidType,
                &format!("{base}/uuid"),
                "invalid VLESS UUID",
                "use canonical UUID format",
            ));
        }
    }
}

fn validate_inbound_tls(ib: &Value, index: usize, issues: &mut Vec<Value>) {
    let Some(tls_value) = ib.get("tls") else {
        return;
    };
    let base = format!("/inbounds/{index}/tls");
    let Some(tls) = tls_value.as_object() else {
        issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            &base,
            "tls must be an object",
            "use a TLS options object",
        ));
        return;
    };
    let Some(reality_value) = tls.get("reality") else {
        return;
    };
    let reality_base = format!("{base}/reality");
    let Some(reality) = reality_value.as_object() else {
        issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            &reality_base,
            "reality must be an object",
            "use a REALITY options object",
        ));
        return;
    };
    let allowed = [
        "enabled",
        "handshake",
        "private_key",
        "short_id",
        "short_ids",
        "max_time_difference",
        "handshake_timeout",
        "server_name",
        "fallback_server",
        "fallback_port",
    ];
    for key in reality.keys() {
        if !allowed.contains(&key.as_str()) {
            issues.push(emit_issue(
                "error",
                IssueCode::UnknownField,
                &format!("{reality_base}/{key}"),
                "unknown inbound REALITY field",
                "remove it",
            ));
        }
    }
    if reality.contains_key("enabled") && !reality["enabled"].is_boolean() {
        issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            &format!("{reality_base}/enabled"),
            "REALITY enabled must be boolean",
            "use true or false",
        ));
        return;
    }
    if reality.get("enabled").and_then(Value::as_bool) != Some(true) {
        return;
    }
    match tls.get("enabled") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) | None => issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{base}/enabled"),
            "REALITY requires tls.enabled=true",
            "enable TLS",
        )),
        Some(_) => issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            &format!("{base}/enabled"),
            "TLS enabled must be boolean",
            "use true or false",
        )),
    }
    if tls
        .get("server_name")
        .or_else(|| tls.get("sni"))
        .or_else(|| reality.get("server_name"))
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        issues.push(emit_issue(
            "error",
            IssueCode::MissingRequired,
            &format!("{base}/server_name"),
            "REALITY server_name is required",
            "add tls.server_name",
        ));
    }
    match reality.get("private_key").and_then(Value::as_str) {
        None => issues.push(emit_issue(
            "error",
            IssueCode::MissingRequired,
            &format!("{reality_base}/private_key"),
            "REALITY private_key is required",
            "add X25519 private key",
        )),
        Some(key) if !crate::ir::is_valid_x25519_key(key) => issues.push(emit_issue(
            "error",
            IssueCode::InvalidType,
            &format!("{reality_base}/private_key"),
            "REALITY private_key must decode to 32 bytes",
            "use hex or base64 X25519 private key",
        )),
        _ => {}
    }
    if reality.contains_key("handshake") && !reality["handshake"].is_object() {
        issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            &format!("{reality_base}/handshake"),
            "REALITY handshake must be an object",
            "use {server, server_port}",
        ));
    }
    let handshake = reality.get("handshake").and_then(Value::as_object);
    if let Some(handshake) = handshake {
        for key in handshake.keys() {
            if !["server", "server_port"].contains(&key.as_str()) {
                issues.push(emit_issue(
                    "error",
                    IssueCode::UnknownField,
                    &format!("{reality_base}/handshake/{key}"),
                    "unknown REALITY handshake field",
                    "remove it",
                ));
            }
        }
    }
    let server = handshake
        .and_then(|v| v.get("server"))
        .or_else(|| reality.get("fallback_server"))
        .and_then(Value::as_str);
    let port = handshake
        .and_then(|v| v.get("server_port"))
        .or_else(|| reality.get("fallback_port"))
        .and_then(Value::as_u64);
    if handshake.is_some()
        && (reality.contains_key("fallback_server") || reality.contains_key("fallback_port"))
    {
        issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{reality_base}/handshake"),
            "canonical handshake and fallback aliases cannot be mixed",
            "keep handshake only",
        ));
    }
    if server.is_none_or(str::is_empty) {
        issues.push(emit_issue(
            "error",
            IssueCode::MissingRequired,
            &format!("{reality_base}/handshake/server"),
            "REALITY handshake server is required",
            "add handshake.server",
        ));
    }
    if !matches!(port, Some(1..=65535)) {
        issues.push(emit_issue(
            "error",
            IssueCode::RangeExceeded,
            &format!("{reality_base}/handshake/server_port"),
            "REALITY handshake server_port must be 1-65535",
            "set a valid port",
        ));
    }
    if reality.contains_key("short_id") && reality.contains_key("short_ids") {
        issues.push(emit_issue(
            "error",
            IssueCode::Conflict,
            &format!("{reality_base}/short_id"),
            "short_id and short_ids cannot both be configured",
            "keep canonical short_id",
        ));
    }
    validate_reality_short_ids(
        reality.get("short_id").or_else(|| reality.get("short_ids")),
        &format!("{reality_base}/short_id"),
        issues,
    );
    if reality
        .get("handshake_timeout")
        .is_some_and(|value| value.as_u64().is_none_or(|timeout| timeout == 0))
    {
        issues.push(emit_issue(
            "error",
            IssueCode::RangeExceeded,
            &format!("{reality_base}/handshake_timeout"),
            "handshake_timeout must be a positive integer",
            "set seconds greater than zero",
        ));
    }
    if let Some(value) = reality.get("max_time_difference") {
        if value
            .as_str()
            .and_then(|raw| humantime::parse_duration(raw).ok())
            .is_none()
        {
            issues.push(emit_issue(
                "error",
                IssueCode::InvalidType,
                &format!("{reality_base}/max_time_difference"),
                "max_time_difference must be a duration string",
                "use a value such as 1m",
            ));
        }
    }
}

/// Validate `/inbounds` array structure, types, required fields, and unknown fields.
///
/// 校验 `/inbounds` 数组结构、类型、必填字段及未知字段。
pub(crate) fn validate_inbounds(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    // /inbounds must be an array (if present)
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

    let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) else {
        return;
    };

    let allowed_base = allowed_inbound_keys();
    let allowed_tun = allowed_tun_inbound_keys(&allowed_base);

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
        } else if let Some(ty) = ib.get("type") {
            if !ty.is_string() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/type", i),
                    "type must be a string",
                    "use string value",
                ));
            }
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

        // Nested `tun` options were historically accepted but never
        // content-checked. Run them through the strict Raw bridge
        // (`RawTunOptionsIR`, deny_unknown_fields) so the nested form is
        // exactly as strict as the flat form. (post_fable_package02)
        if is_tun {
            if let Some(tun_val) = ib.get("tun") {
                if let Err(err) = serde_json::from_value::<crate::ir::TunOptionsIR>(tun_val.clone())
                {
                    let kind = if allow_unknown { "warning" } else { "error" };
                    issues.push(emit_issue(
                        kind,
                        IssueCode::UnknownField,
                        &format!("/inbounds/{}/tun", i),
                        &format!("invalid tun options: {err}"),
                        "fix the nested tun object",
                    ));
                }
            }
        }

        if ib.get("type").and_then(Value::as_str) == Some("vless") {
            validate_vless_inbound(ib, i, issues);
            validate_inbound_tls(ib, i, issues);
        }

        // additionalProperties=false (V2 allowed fields; TUN-only flat
        // fields are gated on `type: "tun"`)
        let allowed = if is_tun { &allowed_tun } else { &allowed_base };
        if let Some(map) = ib.as_object() {
            for k in map.keys() {
                if !allowed.contains(k) {
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

/// Parse `host:port` or `[ipv6]:port` from a listen string.
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

fn string_list(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect()
    })
}

fn reality_string_list(value: Option<&Value>) -> Option<Vec<String>> {
    let value = value?;
    if let Some(value) = value.as_str() {
        return Some(vec![value.to_string()]);
    }
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    })
}

fn join_reality_target(server: &str, port: u16) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

fn lower_vless_users(i: &Value) -> Option<Vec<crate::ir::VlessUserIR>> {
    let users = i
        .get("users")
        .or_else(|| i.get("users_vless"))?
        .as_array()?;
    Some(
        users
            .iter()
            .filter_map(|user| {
                let uuid = user.get("uuid").and_then(Value::as_str)?.to_string();
                Some(crate::ir::VlessUserIR {
                    name: user
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("user")
                        .to_string(),
                    uuid,
                    flow: user.get("flow").and_then(Value::as_str).map(str::to_string),
                    security: user
                        .get("security")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    alter_id: user
                        .get("alter_id")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok()),
                    encryption: user
                        .get("encryption")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
            })
            .collect(),
    )
}

fn lower_inbound_reality(
    i: &Value,
    tls_server_name: Option<&str>,
) -> Option<crate::ir::InboundRealityIR> {
    let tls = i.get("tls").and_then(Value::as_object)?;
    let reality = tls.get("reality").and_then(Value::as_object)?;
    if !reality
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }

    let handshake = reality.get("handshake").and_then(Value::as_object);
    let server = handshake
        .and_then(|v| v.get("server"))
        .or_else(|| reality.get("fallback_server"))
        .and_then(Value::as_str)?;
    let port = handshake
        .and_then(|v| v.get("server_port"))
        .or_else(|| reality.get("fallback_port"))
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())?;
    let server_name = reality
        .get("server_name")
        .and_then(Value::as_str)
        .or(tls_server_name)?;
    let private_key = reality
        .get("private_key")
        .and_then(Value::as_str)?
        .to_string();
    let short_ids =
        reality_string_list(reality.get("short_id").or_else(|| reality.get("short_ids")))
            .unwrap_or_default();

    Some(crate::ir::InboundRealityIR {
        target: join_reality_target(server, port),
        server_names: vec![server_name.to_string()],
        private_key,
        short_ids,
        handshake_timeout: reality
            .get("handshake_timeout")
            .and_then(Value::as_u64)
            .unwrap_or(5),
        max_time_difference: reality
            .get("max_time_difference")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Build `TunOptionsIR` for a `type: "tun"` inbound. (post_fable_package02 / CAL-01)
///
/// Precedence: the nested `tun` object (strict Raw bridge) is the base;
/// top-level Go/GUI flat fields overlay it — a flat field always wins over
/// its nested equivalent.
///
/// Normalization mirrors Go `omitempty` semantics for the GUI defaults:
/// flat `mtu: 0` and `interface_name: ""` mean "unset" and do not override.
/// `address`/`route_address`/`route_exclude_address` are kept verbatim as
/// lists — no v4/v6 split here (dataplane interpretation = package03).
fn lower_tun_options(i: &Value) -> crate::ir::TunOptionsIR {
    // Nested base. Strict validation runs before lowering in the production
    // pipeline (config_from_raw_value), so a deserialize failure here only
    // happens for callers that skipped validation — fall back to defaults.
    let mut tun = i
        .get("tun")
        .cloned()
        .and_then(|v| serde_json::from_value::<crate::ir::TunOptionsIR>(v).ok())
        .unwrap_or_default();

    if let Some(name) = i.get("interface_name").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            tun.interface_name = Some(name.to_string());
        }
    }
    if let Some(mtu) = i.get("mtu").and_then(|v| v.as_u64()) {
        if mtu > 0 {
            tun.mtu = u32::try_from(mtu).ok();
        }
    }
    if let Some(v) = i.get("auto_route").and_then(|v| v.as_bool()) {
        tun.auto_route = Some(v);
    }
    if let Some(v) = i.get("strict_route").and_then(|v| v.as_bool()) {
        tun.strict_route = Some(v);
    }
    if let Some(v) = i.get("endpoint_independent_nat").and_then(|v| v.as_bool()) {
        tun.endpoint_independent_nat = Some(v);
    }
    if let Some(v) = i.get("stack").and_then(|v| v.as_str()) {
        tun.stack = Some(v.to_string());
    }
    if let Some(v) = i.get("inet4_address").and_then(|v| v.as_str()) {
        tun.inet4_address = Some(v.to_string());
    }
    if let Some(v) = i.get("inet6_address").and_then(|v| v.as_str()) {
        tun.inet6_address = Some(v.to_string());
    }
    if let Some(v) = string_list(i.get("address")) {
        tun.address = Some(v);
    }
    if let Some(v) = string_list(i.get("route_address")) {
        tun.route_address = Some(v);
    }
    if let Some(v) = string_list(i.get("route_exclude_address")) {
        tun.route_exclude_address = Some(v);
    }

    // Compat alias: runtime consumers (sb-adapters `TunInboundConfig`) read
    // `name`; mirror Go's `interface_name` into it unless the nested options
    // already set an explicit `name`.
    if tun.name.is_none() {
        tun.name = tun.interface_name.clone();
    }
    tun
}

/// Lower `/inbounds` from raw JSON into `ConfigIR.inbounds`.
///
/// This is the inbound lowering owner — all inbound-specific field parsing
/// and IR population lives here. `to_ir_v1()` in mod.rs delegates to this.
pub(crate) fn lower_inbounds(doc: &Value, ir: &mut ConfigIR) {
    let Some(ins) = doc.get("inbounds").and_then(|v| v.as_array()) else {
        return;
    };
    for (idx, i) in ins.iter().enumerate() {
        let ty = match i.get("type").and_then(|v| v.as_str()).unwrap_or("socks") {
            "socks" => InboundType::Socks,
            "http" => InboundType::Http,
            "tun" => InboundType::Tun,
            "mixed" => InboundType::Mixed,
            "redirect" => InboundType::Redirect,
            "tproxy" => InboundType::Tproxy,
            "direct" => InboundType::Direct,
            "dns" => InboundType::Dns,
            "ssh" => InboundType::Ssh,
            "shadowsocks" => InboundType::Shadowsocks,
            "vless" => InboundType::Vless,
            "hysteria" => InboundType::Hysteria,
            "hysteria2" => InboundType::Hysteria2,
            "tuic" => InboundType::Tuic,
            _ => InboundType::Socks,
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
        let sniff_override_destination = i
            .get("sniff_override_destination")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
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
        let (override_host, override_port) = if matches!(ty, InboundType::Direct) {
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

        // TUN options: nested `tun` is the base, flat Go/GUI fields overlay
        // it. Non-TUN inbounds never carry tun options.
        // (post_fable_package02 / CAL-01)
        let tun = if matches!(ty, InboundType::Tun) {
            Some(lower_tun_options(i))
        } else {
            None
        };

        let tls = i.get("tls").and_then(Value::as_object);
        let tls_server_name = tls
            .and_then(|v| v.get("server_name").or_else(|| v.get("sni")))
            .and_then(Value::as_str)
            .map(str::to_string);
        let tls_enabled = tls.and_then(|v| v.get("enabled")).and_then(Value::as_bool);
        let users_vless = if matches!(ty, InboundType::Vless) {
            lower_vless_users(i)
        } else {
            None
        };
        let uuid = i
            .get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                users_vless
                    .as_ref()
                    .and_then(|users| users.first().map(|u| u.uuid.clone()))
            });
        let flow = i
            .get("flow")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                users_vless
                    .as_ref()
                    .and_then(|users| users.first().and_then(|u| u.flow.clone()))
            });
        let reality = lower_inbound_reality(i, tls_server_name.as_deref());

        ir.inbounds.push(crate::ir::InboundIR {
            // Read both "tag" (raw V2 input, used by direct callers like
            // tests) and "name" (canonical post-migration field, since
            // compat::migrate_to_v2 renames inbound `tag` → `name`). Without
            // the "name" fallback, IR.tag is None for every config that
            // flows through migrate_to_v2 (i.e. all production loads via
            // config_from_raw_value), which silently breaks ssmapi tag
            // lookup and any other consumer that relies on the configured
            // inbound tag.
            tag: Some(crate::effective_tag::effective_tag(
                i.get("tag").and_then(|v| v.as_str()),
                i.get("name").and_then(|v| v.as_str()),
                idx,
            )),
            ty,
            listen,
            port,
            sniff,
            sniff_override_destination,
            udp,
            udp_timeout: i
                .get("udp_timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            detour: i
                .get("detour")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            domain_strategy: i
                .get("domain_strategy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            set_system_proxy: i
                .get("set_system_proxy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            allow_private_network: i
                .get("allow_private_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
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
            // Protocol-specific fields (most still default to None;
            // shadowsocks `method`/`password` lowered for adapter parity).
            method: i
                .get("method")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            password: i
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            users_shadowsocks: None,
            network: None,
            uuid,
            alter_id: None,
            users_vmess: None,
            flow,
            users_vless,
            users_trojan: None,
            version: None,
            users_shadowtls: None,
            shadowtls_handshake: None,
            shadowtls_handshake_for_server_name: None,
            shadowtls_strict_mode: None,
            shadowtls_wildcard_sni: None,
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
            tls_enabled,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name,
            tls_alpn: tls
                .and_then(|v| v.get("alpn"))
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                }),
            reality,
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
            tun,
            ssh_host_key_path: i
                .get("ssh_host_key_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_inbounds(doc, allow_unknown, &mut issues);
        issues
    }

    // --- /inbounds non-array ---

    #[test]
    fn inbounds_not_array() {
        let doc = json!({"inbounds": "not_array"});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "inbounds must be an array"));
    }

    // --- item non-object ---

    #[test]
    fn inbound_item_not_object() {
        let doc = json!({"inbounds": ["string_item"]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds/0"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "inbound item must be an object"));
    }

    // --- type missing ---

    #[test]
    fn type_missing() {
        let doc = json!({"inbounds": [{"listen": "0.0.0.0"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/type" && i["code"] == "MissingRequired"));
    }

    // --- type non-string ---

    #[test]
    fn type_not_string() {
        let doc = json!({"inbounds": [{"type": 42, "listen": "0.0.0.0"}]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds/0/type"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "type must be a string"));
    }

    // --- non-tun missing listen ---

    #[test]
    fn non_tun_missing_listen() {
        let doc = json!({"inbounds": [{"type": "http"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/listen" && i["code"] == "MissingRequired"));
    }

    // --- tun does NOT require listen ---

    #[test]
    fn tun_no_listen_required() {
        let doc = json!({"inbounds": [{"type": "tun"}]});
        let issues = run_validate(&doc, false);
        assert!(
            !issues.iter().any(|i| i["ptr"] == "/inbounds/0/listen"),
            "tun inbound should not require listen"
        );
    }

    // --- listen non-string ---

    #[test]
    fn listen_not_string() {
        let doc = json!({"inbounds": [{"type": "http", "listen": 123}]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds/0/listen"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "listen must be a string"));
    }

    // --- port non-number ---

    #[test]
    fn port_not_number() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": "abc"}]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds/0/port"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "port must be a number"));
    }

    // --- listen_port non-number ---

    #[test]
    fn listen_port_not_number() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": "abc"}]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/inbounds/0/listen_port"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "listen_port must be a number"));
    }

    // --- unknown field strict → error ---

    #[test]
    fn unknown_field_strict() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "totally_unknown": true}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/totally_unknown"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    // --- unknown field allow_unknown → warning ---

    #[test]
    fn unknown_field_allow_unknown() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "totally_unknown": true}]});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/totally_unknown"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    // --- ptr precision ---

    #[test]
    fn ptr_precision_inbound() {
        let doc = json!({
            "inbounds": [
                {"type": "http", "listen": "0.0.0.0", "field_a": 1},
                {"type": "socks", "listen": "0.0.0.0", "field_b": 2}
            ]
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| i["ptr"] == "/inbounds/0/field_a"),
            "missing ptr for inbounds/0 unknown field"
        );
        assert!(
            issues.iter().any(|i| i["ptr"] == "/inbounds/1/field_b"),
            "missing ptr for inbounds/1 unknown field"
        );
    }

    // --- no inbounds → no issues ---

    #[test]
    fn no_inbounds_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no inbound issues when inbounds is absent"
        );
    }

    // --- valid inbound passes ---

    #[test]
    fn valid_inbound_passes() {
        let doc = json!({
            "inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 8080, "tag": "http-in"}]
        });
        let issues = run_validate(&doc, false);
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(
            errors.is_empty(),
            "valid inbound should produce no errors: {:?}",
            errors
        );
    }

    // --- pin: inbound validation owner is in inbound.rs ---

    #[test]
    fn wp30t_pin_inbound_validation_owner_is_inbound_rs() {
        // This test pins that inbound schema/type/required/unknown-field validation
        // is owned by validator/v2/inbound.rs (this file), not mod.rs.
        // If this function compiles and runs, the owner is here.
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let mut issues = vec![];
        validate_inbounds(&doc, false, &mut issues);
        // No errors expected for a valid minimal inbound
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(
            errors.is_empty(),
            "pin: validate_inbounds owns inbound validation"
        );
    }

    // ========================================================================
    // WP-30u: Inbound lowering tests
    // ========================================================================

    fn lower(doc: &Value) -> ConfigIR {
        let mut ir = ConfigIR::default();
        lower_inbounds(doc, &mut ir);
        ir
    }

    // --- type mapping ---

    #[test]
    fn lowering_type_mapping() {
        let types = [
            ("socks", InboundType::Socks),
            ("http", InboundType::Http),
            ("tun", InboundType::Tun),
            ("mixed", InboundType::Mixed),
            ("redirect", InboundType::Redirect),
            ("tproxy", InboundType::Tproxy),
            ("direct", InboundType::Direct),
            ("dns", InboundType::Dns),
            ("ssh", InboundType::Ssh),
            ("shadowsocks", InboundType::Shadowsocks),
            ("vless", InboundType::Vless),
            ("hysteria", InboundType::Hysteria),
            ("hysteria2", InboundType::Hysteria2),
            ("tuic", InboundType::Tuic),
            ("unknown_type", InboundType::Socks), // fallback
        ];
        for (type_str, expected) in types {
            let doc = json!({"inbounds": [{"type": type_str, "listen": "0.0.0.0"}]});
            let ir = lower(&doc);
            assert_eq!(
                ir.inbounds[0].ty, expected,
                "type '{}' should map to {:?}",
                type_str, expected
            );
        }
    }

    /// Regression: every inbound `type` listed in v2_schema.json must dispatch
    /// to its dedicated `InboundType` variant via `lower_inbounds`. Prevents
    /// silent fallthrough to `InboundType::Socks` for schema-blessed types
    /// (the bug surfaced via Sub-WP D Phase 2-A2 G2 with `shadowsocks`).
    #[test]
    fn lower_inbounds_handles_all_schema_types() {
        let schema_aligned: &[(&str, InboundType)] = &[
            ("socks", InboundType::Socks),
            ("http", InboundType::Http),
            ("tun", InboundType::Tun),
            ("mixed", InboundType::Mixed),
            ("direct", InboundType::Direct),
            ("hysteria", InboundType::Hysteria),
            ("hysteria2", InboundType::Hysteria2),
            ("tuic", InboundType::Tuic),
            ("shadowsocks", InboundType::Shadowsocks),
            ("vless", InboundType::Vless),
        ];
        for (ty_str, expected) in schema_aligned {
            let doc = json!({"inbounds": [{"type": ty_str, "listen": "127.0.0.1:0"}]});
            let ir = lower(&doc);
            assert_eq!(
                ir.inbounds.first().map(|i| i.ty.clone()),
                Some(expected.clone()),
                "schema type '{}' must dispatch to {:?}",
                ty_str,
                expected
            );
        }
    }

    #[test]
    fn vless_reality_server_config_validates_and_lowers() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "name": "vless-reality-in",
            "listen": "127.0.0.1:18446",
            "users": [{
                "name": "fixture",
                "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
                "flow": "xtls-rprx-vision"
            }],
            "tls": {
                "enabled": true,
                "server_name": "www.fixture.local",
                "reality": {
                    "enabled": true,
                    "handshake": {"server": "127.0.0.1", "server_port": 18444},
                    "private_key": "wFUij4j61zedpCjqgkLTZw4qc_NZtg4-UtFa4n7pTlI",
                    "short_id": ["b9687a2be7deb9db"],
                    "max_time_difference": "1m"
                }
            }
        }]});

        let errors: Vec<_> = run_validate(&doc, false)
            .into_iter()
            .filter(|issue| issue["kind"] == "error")
            .collect();
        assert!(
            errors.is_empty(),
            "valid VLESS REALITY config rejected: {errors:?}"
        );

        let ir = lower(&doc);
        let inbound = &ir.inbounds[0];
        assert_eq!(inbound.ty, InboundType::Vless);
        assert_eq!(
            inbound.uuid.as_deref(),
            Some("fc7a057a-7d96-4cc8-854f-3b8045a4477e")
        );
        assert_eq!(inbound.flow.as_deref(), Some("xtls-rprx-vision"));
        let reality = inbound.reality.as_ref().expect("REALITY IR");
        assert_eq!(reality.target, "127.0.0.1:18444");
        assert_eq!(reality.server_names, ["www.fixture.local"]);
        assert_eq!(reality.short_ids, ["b9687a2be7deb9db"]);
        assert_eq!(reality.handshake_timeout, 5);
        assert_eq!(reality.max_time_difference.as_deref(), Some("1m"));
    }

    #[test]
    fn production_config_pipeline_preserves_vless_reality_server() {
        let doc = json!({
            "schema_version": 2,
            "inbounds": [{
                "type": "vless",
                "name": "vless-reality-in",
                "listen": "127.0.0.1",
                "port": 18446,
                "users": [{
                    "name": "fixture",
                    "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
                    "flow": "xtls-rprx-vision"
                }],
                "tls": {
                    "enabled": true,
                    "server_name": "www.fixture.local",
                    "reality": {
                        "enabled": true,
                        "handshake": {"server": "127.0.0.1", "server_port": 18444},
                        "private_key": "wFUij4j61zedpCjqgkLTZw4qc_NZtg4-UtFa4n7pTlI",
                        "short_id": ["b9687a2be7deb9db"]
                    }
                }
            }],
            "outbounds": [{"type": "direct", "name": "direct"}],
            "route": {"default": "direct"}
        });

        let (_, ir) = crate::config_from_raw_value(doc).expect("production config loads");
        assert_eq!(ir.inbounds[0].ty, InboundType::Vless);
        assert_eq!(ir.inbounds[0].tag.as_deref(), Some("vless-reality-in"));
        assert_eq!(
            ir.inbounds[0]
                .reality
                .as_ref()
                .map(|value| value.target.as_str()),
            Some("127.0.0.1:18444")
        );
    }

    #[test]
    fn vless_reality_missing_private_key_is_rejected() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:18446",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
            "tls": {
                "enabled": true,
                "server_name": "www.fixture.local",
                "reality": {
                    "enabled": true,
                    "handshake": {"server": "127.0.0.1", "server_port": 18444}
                }
            }
        }]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|issue| {
            issue["ptr"] == "/inbounds/0/tls/reality/private_key"
                && issue["code"] == "MissingRequired"
                && issue["kind"] == "error"
        }));
    }

    #[test]
    fn published_reality_server_aliases_remain_accepted() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:18446",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
            "tls": {
                "enabled": true,
                "sni": "www.fixture.local",
                "reality": {
                    "enabled": true,
                    "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "short_ids": ["b9687a2be7deb9db"],
                    "fallback_server": "127.0.0.1",
                    "fallback_port": 18444
                }
            }
        }]});
        let errors: Vec<_> = run_validate(&doc, false)
            .into_iter()
            .filter(|issue| issue["kind"] == "error")
            .collect();
        assert!(errors.is_empty(), "published aliases rejected: {errors:?}");
        assert_eq!(
            lower(&doc).inbounds[0]
                .reality
                .as_ref()
                .map(|reality| reality.target.as_str()),
            Some("127.0.0.1:18444")
        );
    }

    #[test]
    fn documented_users_vless_alias_lowers_single_user() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:18446",
            "users_vless": [{
                "name": "fixture",
                "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
                "flow": "xtls-rprx-vision"
            }]
        }]});
        let errors: Vec<_> = run_validate(&doc, false)
            .into_iter()
            .filter(|issue| issue["kind"] == "error")
            .collect();
        assert!(errors.is_empty(), "users_vless alias rejected: {errors:?}");
        let inbound = &lower(&doc).inbounds[0];
        assert_eq!(
            inbound.uuid.as_deref(),
            Some("fc7a057a-7d96-4cc8-854f-3b8045a4477e")
        );
        assert_eq!(inbound.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn canonical_and_documented_vless_user_forms_cannot_mix() {
        let user = json!({
            "name": "fixture",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e"
        });
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:18446",
            "users": [user.clone()],
            "users_vless": [user]
        }]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|issue| {
            issue["ptr"] == "/inbounds/0/users"
                && issue["code"] == "Conflict"
                && issue["kind"] == "error"
        }));
    }

    #[test]
    fn reality_handshake_and_fallback_aliases_cannot_mix() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:18446",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
            "tls": {
                "enabled": true,
                "server_name": "www.fixture.local",
                "reality": {
                    "enabled": true,
                    "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "handshake": {"server": "127.0.0.1", "server_port": 18444},
                    "fallback_port": 443
                }
            }
        }]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|issue| {
            issue["ptr"] == "/inbounds/0/tls/reality/handshake"
                && issue["code"] == "Conflict"
                && issue["kind"] == "error"
        }));
    }

    #[test]
    fn vless_standard_tls_fields_remain_accepted_without_reality() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:443",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
            "tls": {
                "enabled": true,
                "certificate_path": "server.crt",
                "key_path": "server.key"
            }
        }]});
        let errors: Vec<_> = run_validate(&doc, false)
            .into_iter()
            .filter(|issue| issue["kind"] == "error")
            .collect();
        assert!(
            errors.is_empty(),
            "standard TLS fields regressed: {errors:?}"
        );
    }

    #[test]
    fn top_level_reality_is_rejected_in_user_config() {
        let doc = json!({"inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1:443",
            "uuid": "fc7a057a-7d96-4cc8-854f-3b8045a4477e",
            "reality": {
                "target": "127.0.0.1:443",
                "server_names": ["example.com"],
                "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }
        }]});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|issue| {
            issue["ptr"] == "/inbounds/0/reality"
                && issue["code"] == "UnknownField"
                && issue["kind"] == "error"
        }));
    }

    /// Regression: shadowsocks inbound builder requires `method` (and recommends
    /// `password`); the v2 validator must wire both from JSON to IR. Previously
    /// both were hardcoded to None, so even after fix-1 routed the type to
    /// `InboundType::Shadowsocks`, the builder would warn-drop the inbound and
    /// the managed_ssm_server registry would never see the tag (surfaced via
    /// Sub-WP D Phase 2-A2 RESUME G2).
    #[test]
    fn lower_inbounds_lowers_shadowsocks_method_and_password() {
        let doc = json!({
            "inbounds": [{
                "type": "shadowsocks",
                "tag": "ss-test",
                "listen": "127.0.0.1:0",
                "method": "aes-256-gcm",
                "password": "test-secret"
            }]
        });
        let ir = lower(&doc);
        let inbound = ir.inbounds.first().expect("inbound lowered");
        assert_eq!(inbound.ty, InboundType::Shadowsocks);
        assert_eq!(inbound.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(inbound.password.as_deref(), Some("test-secret"));
    }

    /// Regression (LC-003 fix-managed-ssm-server-tag): `compat::migrate_to_v2`
    /// renames inbound `tag` → `name`, so post-migration JSON only carries
    /// `name`. `lower_inbounds` must read both keys so production configs
    /// (which always flow through migrate_to_v2 in `config_from_raw_value`)
    /// preserve the user-configured tag in `InboundIR.tag`. Without this,
    /// `build_shadowsocks_inbound` falls back to `ShadowsocksInboundAdapter::new`
    /// which hardcodes `tag="shadowsocks"`, and the ssmapi service registry
    /// stores the adapter under the wrong key.
    #[test]
    fn lower_inbounds_reads_name_field_for_tag_post_migration() {
        let doc = json!({
            "inbounds": [{
                "type": "shadowsocks",
                "name": "ss-in",
                "listen": "127.0.0.1:18908",
                "method": "aes-256-gcm",
                "password": "x"
            }]
        });
        let ir = lower(&doc);
        let inbound = ir.inbounds.first().expect("inbound lowered");
        assert_eq!(
            inbound.tag.as_deref(),
            Some("ss-in"),
            "lower_inbounds must read 'name' as IR.tag (post-migration field)"
        );
    }

    /// When both `tag` and `name` are present (raw V2 input, no migration),
    /// `tag` wins. This preserves the historical lowering semantics that
    /// existing tests rely on.
    #[test]
    fn lower_inbounds_prefers_tag_over_name() {
        let doc = json!({
            "inbounds": [{
                "type": "http",
                "tag": "tag-wins",
                "name": "name-loses",
                "listen": "127.0.0.1:0"
            }]
        });
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].tag.as_deref(), Some("tag-wins"));
    }

    #[test]
    fn lowering_missing_type_defaults_to_socks() {
        let doc = json!({"inbounds": [{"listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].ty, InboundType::Socks);
    }

    // --- listen_port / port / listen host:port priority ---

    #[test]
    fn lowering_listen_port_priority() {
        // listen_port takes precedence over port
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": 8080, "port": 9090}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 8080);
    }

    #[test]
    fn lowering_port_fallback() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 9090}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 9090);
    }

    #[test]
    fn lowering_listen_host_port_parsing() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0:3000"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].listen, "0.0.0.0");
        assert_eq!(ir.inbounds[0].port, 3000);
    }

    #[test]
    fn lowering_listen_ipv6_host_port() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "[::1]:4000"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].listen, "::1");
        assert_eq!(ir.inbounds[0].port, 4000);
    }

    #[test]
    fn lowering_default_port_1080() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 1080);
    }

    // --- direct-only override fields ---

    #[test]
    fn lowering_direct_writes_override() {
        let doc = json!({"inbounds": [{
            "type": "direct", "listen": "0.0.0.0",
            "override_address": "10.0.0.1", "override_port": 443
        }]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].override_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(ir.inbounds[0].override_port, Some(443));
    }

    #[test]
    fn lowering_non_direct_no_override() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "override_address": "10.0.0.1", "override_port": 443
        }]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].override_host.is_none());
        assert!(ir.inbounds[0].override_port.is_none());
    }

    #[test]
    fn lowering_direct_override_host_alias() {
        // override_host is an alias for override_address (with override_address taking precedence)
        let doc = json!({"inbounds": [{
            "type": "direct", "listen": "0.0.0.0",
            "override_host": "10.0.0.2"
        }]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].override_host.as_deref(), Some("10.0.0.2"));
    }

    // --- basicAuth ---

    #[test]
    fn lowering_basic_auth() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "basicAuth": {"username": "alice", "password": "secret"}
        }]});
        let ir = lower(&doc);
        let auth = ir.inbounds[0].basic_auth.as_ref().unwrap();
        assert_eq!(auth.username.as_deref(), Some("alice"));
        assert_eq!(auth.password.as_deref(), Some("secret"));
    }

    #[test]
    fn lowering_basic_auth_env() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "basicAuth": {"username_env": "USER", "password_env": "PASS"}
        }]});
        let ir = lower(&doc);
        let auth = ir.inbounds[0].basic_auth.as_ref().unwrap();
        assert_eq!(auth.username_env.as_deref(), Some("USER"));
        assert_eq!(auth.password_env.as_deref(), Some("PASS"));
    }

    #[test]
    fn lowering_no_basic_auth() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].basic_auth.is_none());
    }

    // --- sniff / sniff_override_destination / udp ---

    #[test]
    fn lowering_sniff_defaults_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].sniff);
        assert!(!ir.inbounds[0].sniff_override_destination);
    }

    #[test]
    fn lowering_sniff_enabled() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "sniff": true, "sniff_override_destination": true
        }]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].sniff);
        assert!(ir.inbounds[0].sniff_override_destination);
    }

    #[test]
    fn lowering_udp_via_network() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0", "network": "udp"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].udp);
    }

    #[test]
    fn lowering_udp_via_flag() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0", "udp": true}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].udp);
    }

    // --- set_system_proxy / allow_private_network ---

    #[test]
    fn lowering_set_system_proxy_default_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].set_system_proxy);
    }

    #[test]
    fn lowering_set_system_proxy_true() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "set_system_proxy": true}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].set_system_proxy);
    }

    #[test]
    fn lowering_allow_private_network_default_true() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].allow_private_network);
    }

    #[test]
    fn lowering_allow_private_network_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "allow_private_network": false}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].allow_private_network);
    }

    // --- ssh_host_key_path ---

    #[test]
    fn lowering_ssh_host_key_path() {
        let doc = json!({"inbounds": [{
            "type": "ssh", "listen": "0.0.0.0",
            "ssh_host_key_path": "/etc/ssh/host_key"
        }]});
        let ir = lower(&doc);
        assert_eq!(
            ir.inbounds[0].ssh_host_key_path.as_deref(),
            Some("/etc/ssh/host_key")
        );
    }

    #[test]
    fn lowering_ssh_host_key_path_absent() {
        let doc = json!({"inbounds": [{"type": "ssh", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].ssh_host_key_path.is_none());
    }

    // --- no inbounds → empty ---

    #[test]
    fn lowering_no_inbounds() {
        let doc = json!({"outbounds": []});
        let ir = lower(&doc);
        assert!(ir.inbounds.is_empty());
    }

    // --- parse_listen_host_port unit tests ---

    #[test]
    fn parse_host_port_ipv4() {
        let result = parse_listen_host_port("1.2.3.4:5000").unwrap();
        assert_eq!(result, ("1.2.3.4".to_string(), 5000));
    }

    #[test]
    fn parse_host_port_ipv6() {
        let result = parse_listen_host_port("[::1]:6000").unwrap();
        assert_eq!(result, ("::1".to_string(), 6000));
    }

    #[test]
    fn parse_host_port_no_port() {
        assert!(parse_listen_host_port("0.0.0.0").is_none());
    }

    // ========================================================================
    // WP-30u pins
    // ========================================================================

    #[test]
    fn wp30u_pin_inbound_lowering_owner_is_inbound_rs() {
        // Pin: inbound lowering (lower_inbounds) is owned by this file (inbound.rs).
        // If this compiles and runs, the owner is here.
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 8080}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds.len(), 1);
        assert_eq!(ir.inbounds[0].ty, InboundType::Http);
        assert_eq!(ir.inbounds[0].port, 8080);
    }

    #[test]
    fn wp30u_pin_mod_rs_to_ir_v1_delegates_inbound() {
        // Pin: to_ir_v1() delegates inbound lowering — it should produce
        // the same result as calling lower_inbounds directly.
        let doc = json!({
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "port": 7890, "tag": "mix"}]
        });
        let ir_via_to_ir = crate::validator::v2::to_ir_v1(&doc);
        let ir_via_lower = lower(&doc);
        assert_eq!(ir_via_to_ir.inbounds.len(), ir_via_lower.inbounds.len());
        assert_eq!(ir_via_to_ir.inbounds[0].ty, ir_via_lower.inbounds[0].ty);
        assert_eq!(ir_via_to_ir.inbounds[0].port, ir_via_lower.inbounds[0].port);
        assert_eq!(ir_via_to_ir.inbounds[0].tag, ir_via_lower.inbounds[0].tag);
    }

    // ========================================================================
    // post_fable_package02 (CAL-01): GUI/Go 1.13.13 flat TUN schema parity
    // ========================================================================

    /// GUI.for SingBox 1.25.1 default TUN inbound (generator.ts output),
    /// verbatim including the "unset" defaults `interface_name: ""` and
    /// `mtu: 0` and the deprecated `endpoint_independent_nat`.
    fn gui_default_tun_inbound() -> Value {
        json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "",
            "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 0,
            "auto_route": true,
            "strict_route": true,
            "endpoint_independent_nat": false,
            "stack": "mixed"
        })
    }

    #[test]
    fn pf02_gui_default_tun_passes_strict_validation() {
        let doc = json!({"inbounds": [gui_default_tun_inbound()]});
        let issues = run_validate(&doc, false);
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(
            errors.is_empty(),
            "GUI default TUN inbound must pass strict validation, got: {errors:?}"
        );
    }

    #[test]
    fn pf02_gui_default_tun_lowers_into_ir() {
        let mut inbound = gui_default_tun_inbound();
        // Non-default route lists to also pin list preservation.
        inbound["route_address"] = json!(["10.0.0.0/8"]);
        inbound["route_exclude_address"] = json!(["192.168.0.0/16"]);
        let doc = json!({"inbounds": [inbound]});
        let ir = lower(&doc);
        let tun = ir.inbounds[0].tun.as_ref().expect("tun options populated");

        // Go omitempty normalization: "" / 0 mean unset.
        assert_eq!(tun.interface_name, None, "empty interface_name = unset");
        assert_eq!(tun.mtu, None, "mtu 0 = unset");
        assert_eq!(tun.name, None, "no alias from unset interface_name");

        assert_eq!(
            tun.address.as_deref(),
            Some(
                &[
                    "172.18.0.1/30".to_string(),
                    "fdfe:dcba:9876::1/126".to_string()
                ][..]
            )
        );
        assert_eq!(tun.auto_route, Some(true));
        assert_eq!(tun.strict_route, Some(true));
        assert_eq!(tun.endpoint_independent_nat, Some(false));
        assert_eq!(tun.stack.as_deref(), Some("mixed"));
        assert_eq!(
            tun.route_address.as_deref(),
            Some(&["10.0.0.0/8".to_string()][..])
        );
        assert_eq!(
            tun.route_exclude_address.as_deref(),
            Some(&["192.168.0.0/16".to_string()][..])
        );
    }

    #[test]
    fn pf02_tun_set_fields_lower_with_alias() {
        let doc = json!({"inbounds": [{
            "type": "tun",
            "interface_name": "utun9",
            "mtu": 1492,
            "stack": "system"
        }]});
        let ir = lower(&doc);
        let tun = ir.inbounds[0].tun.as_ref().expect("tun options populated");
        assert_eq!(tun.interface_name.as_deref(), Some("utun9"));
        // Compat alias for runtime TunInboundConfig.name consumers.
        assert_eq!(tun.name.as_deref(), Some("utun9"));
        assert_eq!(tun.mtu, Some(1492));
        assert_eq!(tun.stack.as_deref(), Some("system"));
    }

    #[test]
    fn pf02_tun_unknown_field_still_rejected() {
        let mut inbound = gui_default_tun_inbound();
        inbound["bogus_tun_field"] = json!(true);
        let doc = json!({"inbounds": [inbound]});
        let issues = run_validate(&doc, false);
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/inbounds/0/bogus_tun_field"
                    && i["code"] == "UnknownField"
                    && i["kind"] == "error"),
            "strict unknown-field rejection must survive the TUN whitelist, got: {issues:?}"
        );
    }

    #[test]
    fn pf02_tun_only_fields_rejected_on_non_tun() {
        for key in super::TUN_ONLY_INBOUND_KEYS {
            let mut inbound = json!({"type": "http", "listen": "0.0.0.0"});
            inbound[*key] = json!(0); // value irrelevant; key gating is what matters
            let doc = json!({"inbounds": [inbound]});
            let issues = run_validate(&doc, false);
            assert!(
                issues
                    .iter()
                    .any(|i| i["ptr"] == format!("/inbounds/0/{key}")
                        && i["code"] == "UnknownField"
                        && i["kind"] == "error"),
                "TUN-only key `{key}` must be rejected on non-tun inbounds"
            );
        }
    }

    #[test]
    fn pf02_flat_fields_override_nested_tun() {
        let doc = json!({"inbounds": [{
            "type": "tun",
            "mtu": 1500,
            "interface_name": "utun7",
            "stack": "gvisor",
            "tun": {
                "mtu": 1400,
                "name": "nested-name",
                "stack": "system",
                "dry_run": true
            }
        }]});
        let ir = lower(&doc);
        let tun = ir.inbounds[0].tun.as_ref().expect("tun options populated");
        // Flat wins over nested equivalents.
        assert_eq!(tun.mtu, Some(1500));
        assert_eq!(tun.stack.as_deref(), Some("gvisor"));
        assert_eq!(tun.interface_name.as_deref(), Some("utun7"));
        // Nested explicit `name` is preserved (alias only fills a gap).
        assert_eq!(tun.name.as_deref(), Some("nested-name"));
        // Nested-only fields survive the overlay.
        assert_eq!(tun.dry_run, Some(true));
    }

    #[test]
    fn pf02_nested_tun_unknown_field_rejected() {
        let doc = json!({"inbounds": [{
            "type": "tun",
            "tun": {"mtu": 1400, "bogus_nested": 1}
        }]});
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| i["ptr"] == "/inbounds/0/tun"
                && i["code"] == "UnknownField"
                && i["kind"] == "error"),
            "nested tun options must be as strict as flat ones, got: {issues:?}"
        );
    }

    /// H-4: GUI.for SingBox emits Go 1.13.13 `ListenOptions` socket tuning
    /// fields on every listen-type inbound — rejecting them blocks the same
    /// GUI launch path as CAL-01. Accepted as schema-valid no-ops.
    #[test]
    fn pf02_gui_listen_block_fields_accepted_on_listen_inbounds() {
        let doc = json!({"inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 20808,
            "tcp_fast_open": false,
            "tcp_multi_path": false,
            "udp_fragment": false
        }]});
        let issues = run_validate(&doc, false);
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(
            errors.is_empty(),
            "GUI listen-block fields must pass strict validation, got: {errors:?}"
        );
    }
}
