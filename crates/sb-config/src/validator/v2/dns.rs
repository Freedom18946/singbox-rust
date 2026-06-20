use sb_types::IssueCode;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};

use super::{
    emit_issue, extract_string_list, insert_keys, object_keys, parse_u16_field, parse_u32_field,
};
use crate::ir::{ConfigIR, DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR};

fn allowed_dns_keys() -> HashSet<String> {
    let mut set = object_keys(DnsIR::default());
    insert_keys(
        &mut set,
        &["ttl", "fakeip", "pool", "hosts", "hosts_ttl", "static_ttl"],
    );
    set
}

fn allowed_dns_server_keys() -> HashSet<String> {
    let mut set = object_keys(DnsServerIR::default());
    insert_keys(
        &mut set,
        &[
            "name",
            "type",
            "server",
            "domain_resolver",
            "server_port",
            "path",
            "interface",
            "prefer_go",
            "method",
            "headers",
            "cache_capacity",
        ],
    );
    set
}

fn is_supported_dns_server_type(ty: &str) -> bool {
    matches!(
        ty.trim().to_ascii_lowercase().as_str(),
        "local"
            | "hosts"
            | "udp"
            | "tcp"
            | "tls"
            | "dot"
            | "quic"
            | "doq"
            | "https"
            | "h3"
            | "http3"
            | "doh3"
            | "dhcp"
            | "fakeip"
            | "fake-ip"
            | "tailscale"
            | "resolved"
            | "rcode"
    )
}

fn allowed_dns_rule_keys() -> HashSet<String> {
    let mut set = object_keys(DnsRuleIR::default());
    insert_keys(
        &mut set,
        &[
            "domain_keyword",
            "process",
            "rule_set_ipcidr_match_source",
            "rule_set_ipcidr_accept_empty",
        ],
    );
    set
}

/// Validate `/dns` unknown fields for top-level, servers, and rules.
///
/// 校验 `/dns` 顶层、servers、rules 的未知字段。
pub(crate) fn validate_dns(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    let Some(dns) = doc.get("dns").and_then(|v| v.as_object()) else {
        return;
    };

    // DNS top-level unknown fields
    let allowed = allowed_dns_keys();
    for k in dns.keys() {
        if !allowed.contains(k) {
            let kind = if allow_unknown { "warning" } else { "error" };
            issues.push(emit_issue(
                kind,
                IssueCode::UnknownField,
                &format!("/dns/{}", k),
                "unknown field",
                "remove it",
            ));
        }
    }

    // DNS servers unknown fields
    if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
        let allowed_server = allowed_dns_server_keys();
        for (i, server) in servers.iter().enumerate() {
            if let Some(map) = server.as_object() {
                for k in map.keys() {
                    if !allowed_server.contains(k) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/dns/servers/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
                if let Some(ty) = map.get("type").and_then(|v| v.as_str()) {
                    if !is_supported_dns_server_type(ty) {
                        issues.push(emit_issue(
                            "error",
                            IssueCode::InvalidEnum,
                            &format!("/dns/servers/{}/type", i),
                            &format!("unknown transport type: {}", ty),
                            "use a supported DNS server type",
                        ));
                    }
                    if ty.eq_ignore_ascii_case("rcode") {
                        let rcode = map
                            .get("server")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if !matches!(
                            rcode,
                            "success"
                                | "format_error"
                                | "server_failure"
                                | "name_error"
                                | "not_implemented"
                                | "refused"
                        ) {
                            issues.push(emit_issue(
                                "error",
                                IssueCode::InvalidEnum,
                                &format!("/dns/servers/{}/server", i),
                                &format!("unknown rcode: {}", rcode),
                                "use a supported rcode name",
                            ));
                        }
                    }
                }
                if let Some(address) = map.get("address").and_then(|v| v.as_str()) {
                    if let Some(rcode) = address.trim().strip_prefix("rcode://") {
                        if rcode_name_from_legacy(address).is_none() {
                            issues.push(emit_issue(
                                "error",
                                IssueCode::InvalidEnum,
                                &format!("/dns/servers/{}/address", i),
                                &format!("unknown rcode: {}", rcode),
                                "use a supported rcode name",
                            ));
                        }
                    }
                }
            }
        }
    }

    // DNS rules unknown fields
    if let Some(rules) = dns.get("rules").and_then(|v| v.as_array()) {
        let allowed_rules = allowed_dns_rule_keys();
        for (i, rule) in rules.iter().enumerate() {
            if let Some(map) = rule.as_object() {
                for k in map.keys() {
                    if !allowed_rules.contains(k) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/dns/rules/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
            }
        }
    }

    validate_fakeip_masks(dns, issues);
}

fn validate_fakeip_masks(dns: &Map<String, Value>, issues: &mut Vec<Value>) {
    let Some(fakeip) = dns.get("fakeip").and_then(|v| v.as_object()) else {
        return;
    };

    validate_fakeip_cidr_mask(
        fakeip.get("inet4_range"),
        "/dns/fakeip/inet4_range",
        32,
        "IPv4",
        issues,
    );
    validate_fakeip_cidr_mask(
        fakeip.get("inet6_range"),
        "/dns/fakeip/inet6_range",
        128,
        "IPv6",
        issues,
    );
}

fn validate_fakeip_cidr_mask(
    value: Option<&Value>,
    ptr: &str,
    max_mask: u16,
    family: &str,
    issues: &mut Vec<Value>,
) {
    let Some(range) = value.and_then(|v| v.as_str()) else {
        return;
    };
    let Some((_, mask)) = range.rsplit_once('/') else {
        return;
    };
    let mask = mask.trim();

    match mask.parse::<u16>() {
        Ok(mask) if mask <= max_mask => {}
        Ok(mask) => issues.push(emit_issue(
            "error",
            IssueCode::RangeExceeded,
            ptr,
            &format!("fakeip {family} CIDR mask {mask} exceeds /{max_mask}"),
            "use a valid fakeip CIDR prefix length",
        )),
        Err(err) => issues.push(emit_issue(
            "error",
            IssueCode::TypeMismatch,
            ptr,
            &format!("fakeip {family} CIDR mask must be numeric: {err}"),
            "use inet4_range like 198.18.0.0/15 or inet6_range like fc00::/18",
        )),
    }
}

// ───── DNS lowering ─────

fn infer_dns_server_type_from_address(address: &str) -> Option<String> {
    let addr = address.trim();
    if addr.is_empty() {
        return None;
    }
    if addr.eq_ignore_ascii_case("resolved") {
        return Some("resolved".to_string());
    }
    let (scheme, _) = addr.split_once("://")?;
    let scheme = scheme.trim();
    if scheme.is_empty() {
        None
    } else {
        Some(scheme.to_ascii_lowercase())
    }
}

fn trimmed_string_field(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn server_with_port(server: &str, port: Option<u16>) -> String {
    match port.filter(|p| *p != 0) {
        Some(port) => format!("{server}:{port}"),
        None => server.to_string(),
    }
}

fn dns_https_path(map: &Map<String, Value>) -> String {
    let path = trimmed_string_field(map, "path").unwrap_or_else(|| "/dns-query".to_string());
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn has_dns_scheme(address: &str) -> bool {
    address.split_once("://").is_some()
}

fn canonical_dns_address_from_legacy(address: &str) -> String {
    let address = address.trim();
    if address.is_empty() {
        return String::new();
    }
    if has_dns_scheme(address)
        || matches!(
            address.to_ascii_lowercase().as_str(),
            "local" | "fakeip" | "hosts" | "dhcp" | "tailscale" | "resolved" | "system"
        )
    {
        address.to_string()
    } else {
        format!("udp://{address}")
    }
}

fn canonical_dns_address_from_type(map: &Map<String, Value>, ty: &str) -> String {
    let ty = ty.trim().to_ascii_lowercase();
    let server = trimmed_string_field(map, "server").unwrap_or_default();
    let port = parse_u16_field(map.get("server_port"));

    match ty.as_str() {
        "local" => "local".to_string(),
        "hosts" => "hosts".to_string(),
        "fakeip" | "fake-ip" => "fakeip".to_string(),
        "resolved" => "resolved".to_string(),
        "tailscale" => {
            if server.is_empty() {
                "tailscale".to_string()
            } else {
                format!("tailscale://{}", server_with_port(&server, port))
            }
        }
        "dhcp" => trimmed_string_field(map, "interface")
            .map(|iface| format!("dhcp://{iface}"))
            .unwrap_or_else(|| "dhcp".to_string()),
        "udp" => {
            if server.is_empty() {
                String::new()
            } else {
                format!("udp://{}", server_with_port(&server, port))
            }
        }
        "tcp" => {
            if server.is_empty() {
                String::new()
            } else {
                format!("tcp://{}", server_with_port(&server, port))
            }
        }
        "tls" | "dot" => {
            if server.is_empty() {
                String::new()
            } else {
                format!("tls://{}", server_with_port(&server, port))
            }
        }
        "quic" | "doq" => {
            if server.is_empty() {
                String::new()
            } else {
                format!("quic://{}", server_with_port(&server, port))
            }
        }
        "https" => {
            if server.is_empty() {
                String::new()
            } else {
                format!(
                    "https://{}{}",
                    server_with_port(&server, port),
                    dns_https_path(map)
                )
            }
        }
        "h3" | "http3" | "doh3" => {
            if server.is_empty() {
                String::new()
            } else {
                format!(
                    "h3://{}{}",
                    server_with_port(&server, port),
                    dns_https_path(map)
                )
            }
        }
        "rcode" => {
            if server.is_empty() {
                String::new()
            } else {
                format!("rcode://{server}")
            }
        }
        other => {
            if server.is_empty() {
                String::new()
            } else {
                format!("{}://{}", other, server_with_port(&server, port))
            }
        }
    }
}

fn dns_header_map(map: &Map<String, Value>) -> BTreeMap<String, Vec<String>> {
    let mut headers = BTreeMap::new();
    let Some(obj) = map.get("headers").and_then(|v| v.as_object()) else {
        return headers;
    };
    for (key, value) in obj {
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let values: Vec<String> = match value {
            Value::String(s) => vec![s.trim().to_string()],
            Value::Array(items) => items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        if !values.is_empty() {
            headers.insert(key.to_string(), values);
        }
    }
    headers
}

fn rcode_name_from_legacy(address: &str) -> Option<String> {
    let rcode = address
        .trim()
        .strip_prefix("rcode://")?
        .to_ascii_lowercase();
    match rcode.as_str() {
        "success" => Some("NOERROR".to_string()),
        "format_error" => Some("FORMERR".to_string()),
        "server_failure" => Some("SERVFAIL".to_string()),
        "name_error" => Some("NXDOMAIN".to_string()),
        "not_implemented" => Some("NOTIMP".to_string()),
        "refused" => Some("REFUSED".to_string()),
        _ => None,
    }
}

/// Lower the `/dns` block from raw JSON into `ConfigIR.dns`.
///
/// This is the single DNS lowering owner — `to_ir_v1()` delegates here.
pub(super) fn lower_dns(doc: &Value, ir: &mut ConfigIR) {
    let Some(dns) = doc.get("dns").and_then(|v| v.as_object()) else {
        return;
    };

    let mut dd = DnsIR {
        client_subnet: dns
            .get("client_subnet")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        ..Default::default()
    };

    // ── servers ──
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

                let ty = map
                    .get("type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_ascii_lowercase());

                // Accept both legacy `address: "<proto>://..."` and
                // Go 1.12 type-based `{ "type": "...", "server": ... }` shapes.
                let address = if let Some(addr) = map
                    .get("address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                {
                    canonical_dns_address_from_legacy(&addr)
                } else if let Some(ref ty) = ty {
                    canonical_dns_address_from_type(map, ty)
                } else {
                    String::new()
                };

                let address = if address.is_empty() && ty.as_deref() == Some("resolved") {
                    "resolved".to_string()
                } else {
                    address
                };

                if !tag.is_empty() && !address.is_empty() {
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
                            if let Some(items) = v.as_array() {
                                for it in items {
                                    if let Some(s) = it.as_str() {
                                        let s = s.trim();
                                        if !s.is_empty() {
                                            ca_pem.push(s.to_string());
                                        }
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
                    let server_type = map
                        .get("type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| infer_dns_server_type_from_address(&address));
                    dd.servers.push(DnsServerIR {
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
                        address_resolver: map
                            .get("address_resolver")
                            .or_else(|| map.get("domain_resolver"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                        address_strategy: map
                            .get("address_strategy")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        address_fallback_delay: map
                            .get("address_fallback_delay")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        strategy: map
                            .get("strategy")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        detour: map
                            .get("detour")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        server_type,
                        service: map
                            .get("service")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        accept_default_resolvers: map
                            .get("accept_default_resolvers")
                            .and_then(|v| v.as_bool()),
                        prefer_go: map.get("prefer_go").and_then(|v| v.as_bool()),
                        method: map
                            .get("method")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        headers: dns_header_map(map),
                        cache_capacity: parse_u32_field(map.get("cache_capacity")),
                        inet4_range: map
                            .get("inet4_range")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        inet6_range: map
                            .get("inet6_range")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        hosts_path: {
                            let mut paths =
                                extract_string_list(map.get("hosts_path")).unwrap_or_default();
                            if ty.as_deref() == Some("hosts") {
                                if let Some(path) = extract_string_list(map.get("path")) {
                                    paths.extend(path);
                                }
                            }
                            paths
                        },
                        predefined: map.get("predefined").and_then(|v| {
                            if v.is_null() {
                                None
                            } else {
                                Some(v.clone())
                            }
                        }),
                    });
                }
            }
        }
    }

    // ── rules ──
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

                let mut dr = DnsRuleIR {
                    server,
                    action,
                    priority: Some(idx as u32 + 1),
                    rewrite_ttl: parse_u32_field(obj.get("rewrite_ttl")),
                    client_subnet: obj
                        .get("client_subnet")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    disable_cache: obj.get("disable_cache").and_then(|v| v.as_bool()),
                    invert: obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false),

                    ip_is_private: obj.get("ip_is_private").and_then(|v| v.as_bool()),
                    source_ip_is_private: obj.get("source_ip_is_private").and_then(|v| v.as_bool()),
                    ip_accept_any: obj.get("ip_accept_any").and_then(|v| v.as_bool()),
                    rule_set_ip_cidr_match_source: obj
                        .get("rule_set_ip_cidr_match_source")
                        .and_then(|v| v.as_bool()),
                    rule_set_ip_cidr_accept_empty: obj
                        .get("rule_set_ip_cidr_accept_empty")
                        .and_then(|v| v.as_bool()),
                    clash_mode: obj
                        .get("clash_mode")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    network_is_expensive: obj.get("network_is_expensive").and_then(|v| v.as_bool()),
                    network_is_constrained: obj
                        .get("network_is_constrained")
                        .and_then(|v| v.as_bool()),

                    rewrite_ip: extract_string_list(obj.get("rewrite_ip")),
                    rcode: obj
                        .get("rcode")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    answer: extract_string_list(obj.get("answer")),
                    ns: extract_string_list(obj.get("ns")),
                    extra: extract_string_list(obj.get("extra")),

                    ..Default::default()
                };

                // String list matchers
                dr.domain_suffix =
                    extract_string_list(obj.get("domain_suffix")).unwrap_or_default();
                dr.domain = extract_string_list(obj.get("domain")).unwrap_or_default();
                dr.domain_regex = extract_string_list(obj.get("domain_regex")).unwrap_or_default();
                dr.keyword = extract_string_list(obj.get("domain_keyword").or(obj.get("keyword")))
                    .unwrap_or_default();
                dr.geosite = extract_string_list(obj.get("geosite")).unwrap_or_default();
                dr.geoip = extract_string_list(obj.get("geoip")).unwrap_or_default();
                dr.source_ip_cidr =
                    extract_string_list(obj.get("source_ip_cidr")).unwrap_or_default();
                dr.ip_cidr = extract_string_list(obj.get("ip_cidr")).unwrap_or_default();
                dr.port = extract_string_list(obj.get("port")).unwrap_or_default();
                dr.source_port = extract_string_list(obj.get("source_port")).unwrap_or_default();
                dr.process_name =
                    extract_string_list(obj.get("process_name").or(obj.get("process")))
                        .unwrap_or_default();
                dr.process_path = extract_string_list(obj.get("process_path")).unwrap_or_default();
                dr.package_name = extract_string_list(obj.get("package_name")).unwrap_or_default();
                dr.wifi_ssid = extract_string_list(obj.get("wifi_ssid")).unwrap_or_default();
                dr.wifi_bssid = extract_string_list(obj.get("wifi_bssid")).unwrap_or_default();
                dr.rule_set = extract_string_list(obj.get("rule_set")).unwrap_or_default();
                dr.query_type = extract_string_list(obj.get("query_type")).unwrap_or_default();

                // Go parity: rules that omit both `server` and `action` infer
                // the server tag by rule index, falling back to the last server.
                if dr.server.is_none() && dr.action.is_none() {
                    if let Some(srv) = dd.servers.get(idx).or_else(|| dd.servers.last()) {
                        dr.server = Some(srv.tag.clone());
                    } else {
                        continue;
                    }
                }

                if let Some(server) = dr.server.as_deref() {
                    if let Some(rcode) = dd
                        .servers
                        .iter()
                        .find(|srv| srv.tag == server)
                        .and_then(|srv| rcode_name_from_legacy(&srv.address))
                    {
                        dr.action = Some("predefined".to_string());
                        dr.rcode = Some(rcode);
                        dr.server = None;
                    }
                }

                dd.rules.push(dr);
            }
        }
    }

    dd.servers
        .retain(|srv| rcode_name_from_legacy(&srv.address).is_none());

    // ── global knobs ──
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
    dd.strategy = dns
        .get("strategy")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    dd.client_subnet = dns
        .get("client_subnet")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    dd.independent_cache = dns.get("independent_cache").and_then(|v| v.as_bool());
    dd.disable_expire = dns.get("disable_expire").and_then(|v| v.as_bool());
    dd.cache_capacity = parse_u32_field(dns.get("cache_capacity"));
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
                dd.hosts.push(DnsHostIR { domain, ips });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::v2::to_ir_v1;
    use serde_json::json;

    // ───── Validation tests (carried forward) ─────

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_dns(doc, allow_unknown, &mut issues);
        issues
    }

    #[test]
    fn dns_unknown_field_strict() {
        let doc = json!({"dns": {"unknown_dns_field": true, "servers": []}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/dns/unknown_dns_field"
            && i["kind"] == "error"
            && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_unknown_field_allow_unknown() {
        let doc = json!({"dns": {"unknown_dns_field": true, "servers": []}});
        let issues = run_validate(&doc, true);
        assert!(issues.iter().any(|i| i["ptr"] == "/dns/unknown_dns_field"
            && i["kind"] == "warning"
            && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_server_unknown_field_strict() {
        let doc = json!({"dns": {"servers": [{"tag": "s1", "unknown_server_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/dns/servers/0/unknown_server_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_server_unknown_field_allow_unknown() {
        let doc = json!({"dns": {"servers": [{"tag": "s1", "unknown_server_field": true}]}});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/dns/servers/0/unknown_server_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_rule_unknown_field_strict() {
        let doc = json!({"dns": {"rules": [{"unknown_dns_rule_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/dns/rules/0/unknown_dns_rule_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_rule_unknown_field_allow_unknown() {
        let doc = json!({"dns": {"rules": [{"unknown_dns_rule_field": true}]}});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/dns/rules/0/unknown_dns_rule_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn dns_fakeip_invalid_v4_mask_reports_type_mismatch() {
        let doc = json!({
            "dns": {
                "fakeip": {
                    "enabled": true,
                    "inet4_range": "198.18.0.0/not-a-mask"
                }
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| {
                i["ptr"] == "/dns/fakeip/inet4_range"
                    && i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
            }),
            "invalid fakeip v4 mask should be visible: {issues:?}"
        );
    }

    #[test]
    fn dns_fakeip_out_of_range_v6_mask_reports_range_exceeded() {
        let doc = json!({
            "dns": {
                "fakeip": {
                    "enabled": true,
                    "inet6_range": "fc00::/129"
                }
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| {
                i["ptr"] == "/dns/fakeip/inet6_range"
                    && i["kind"] == "error"
                    && i["code"] == "RangeExceeded"
            }),
            "out-of-range fakeip v6 mask should be visible: {issues:?}"
        );
    }

    #[test]
    fn config_from_raw_value_rejects_invalid_fakeip_mask() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "fakeip": {
                    "enabled": true,
                    "inet4_range": "198.18.0.0/33"
                }
            }
        });
        let err = crate::config_from_raw_value(doc)
            .expect_err("full config load path must reject invalid fakeip mask");
        assert!(
            err.to_string().contains("/dns/fakeip/inet4_range"),
            "error should identify fakeip mask path: {err}"
        );
    }

    #[test]
    fn no_dns_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no dns issues when dns is absent"
        );
    }

    #[test]
    fn ptr_precision_all_levels() {
        let doc = json!({
            "dns": {
                "unknown_dns_field": true,
                "servers": [{"unknown_server_field": true}],
                "rules": [{"unknown_dns_rule_field": true}]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| i["ptr"] == "/dns/unknown_dns_field"),
            "missing ptr for top-level dns unknown field"
        );
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/dns/servers/0/unknown_server_field"),
            "missing ptr for dns server unknown field"
        );
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/dns/rules/0/unknown_dns_rule_field"),
            "missing ptr for dns rule unknown field"
        );
        assert_eq!(issues.len(), 3, "expected exactly 3 issues");
    }

    // ───── Lowering tests (migrated from mod.rs + new coverage) ─────

    // DNS server lowering with TLS extras (migrated from mod.rs)
    #[test]
    fn dns_server_lowering_with_tls_extras() {
        let doc = json!({
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
        let ir = to_ir_v1(&doc);
        assert!(ir.dns.is_some());
        let dns = ir.dns.unwrap();
        let mut tags: Vec<String> = dns.servers.iter().map(|s| s.tag.clone()).collect();
        tags.sort();
        assert_eq!(tags, vec!["doq1", "dot1", "sys"]);
        let dot = dns.servers.iter().find(|s| s.tag == "dot1").unwrap();
        assert_eq!(dot.sni.as_deref(), Some("cloudflare-dns.com"));
        assert_eq!(dot.ca_paths, vec!["/etc/ssl/certs/custom.pem".to_string()]);
        assert_eq!(dot.skip_cert_verify, Some(false));
        let doq = dns.servers.iter().find(|s| s.tag == "doq1").unwrap();
        assert_eq!(doq.ca_pem.len(), 1);
    }

    // Resolved type without address (migrated from mod.rs)
    #[test]
    fn dns_server_resolved_type_without_address() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "resolved", "type": "resolved", "service": "resolved", "accept_default_resolvers": false}
                ],
                "default": "resolved"
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.servers.len(), 1);
        let s = &dns.servers[0];
        assert_eq!(s.tag, "resolved");
        assert_eq!(s.address, "resolved");
        assert_eq!(s.server_type.as_deref(), Some("resolved"));
        assert_eq!(s.service.as_deref(), Some("resolved"));
        assert_eq!(s.accept_default_resolvers, Some(false));
    }

    // type/server compat shapes (Go 1.12.x pretty-printed)
    #[test]
    fn dns_server_type_server_compat() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "u1", "type": "udp", "server": "8.8.8.8"},
                    {"tag": "t1", "type": "tcp", "server": "8.8.4.4"},
                    {"tag": "tls1", "type": "tls", "server": "1.1.1.1"},
                    {"tag": "dot1", "type": "dot", "server": "9.9.9.9"},
                    {"tag": "h1", "type": "https", "server": "dns.example.com"},
                    {"tag": "r1", "type": "rcode", "server": "success"}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.servers.len(), 5);
        let find = |tag: &str| dns.servers.iter().find(|s| s.tag == tag).unwrap();
        assert_eq!(find("u1").address, "udp://8.8.8.8");
        assert_eq!(find("t1").address, "tcp://8.8.4.4");
        assert_eq!(find("tls1").address, "tls://1.1.1.1");
        assert_eq!(find("dot1").address, "tls://9.9.9.9");
        assert_eq!(find("h1").address, "https://dns.example.com/dns-query");
    }

    #[test]
    fn pf12_gui_default_dns_server_shape_passes_strict_validation() {
        let doc = json!({
            "dns": {
                "servers": [
                    {
                        "tag": "FakeIP",
                        "type": "fakeip",
                        "inet4_range": "198.18.0.0/15",
                        "inet6_range": "fc00::/18"
                    },
                    {
                        "tag": "Local-DNS",
                        "type": "https",
                        "server": "223.5.5.5",
                        "server_port": 443,
                        "path": "/dns-query",
                        "domain_resolver": "Local-DNS-Resolver"
                    },
                    {
                        "tag": "Local-DNS-Resolver",
                        "type": "udp",
                        "server": "223.5.5.5",
                        "server_port": 53
                    },
                    {
                        "tag": "Remote-DNS",
                        "type": "tls",
                        "server": "8.8.8.8",
                        "server_port": 853,
                        "domain_resolver": "Remote-DNS-Resolver",
                        "detour": "select"
                    },
                    {
                        "tag": "Remote-DNS-Resolver",
                        "type": "udp",
                        "server": "8.8.8.8",
                        "server_port": 53,
                        "detour": "select"
                    }
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "GUI default DNS server shape should pass strict validation: {issues:?}"
        );
    }

    #[test]
    fn pf12_domain_resolver_lowers_to_address_resolver() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "resolver", "type": "udp", "server": "223.5.5.5", "server_port": 53},
                    {
                        "tag": "doh",
                        "type": "https",
                        "server": "223.5.5.5",
                        "server_port": 443,
                        "path": "/dns-query",
                        "domain_resolver": "resolver"
                    }
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        let doh = dns.servers.iter().find(|s| s.tag == "doh").unwrap();
        assert_eq!(doh.address_resolver.as_deref(), Some("resolver"));
    }

    #[test]
    fn pf12_server_port_and_path_are_in_canonical_addresses() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "udp", "type": "udp", "server": "8.8.8.8", "server_port": 5353},
                    {"tag": "tcp", "type": "tcp", "server": "8.8.4.4", "server_port": "5354"},
                    {"tag": "tls", "type": "tls", "server": "1.1.1.1", "server_port": 853},
                    {"tag": "quic", "type": "quic", "server": "dns.example.com", "server_port": 8853},
                    {"tag": "https", "type": "https", "server": "dns.example.com", "server_port": 8443, "path": "/custom-query"},
                    {"tag": "h3", "type": "h3", "server": "h3.example.com", "server_port": 9443, "path": "dns-query"}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        let find = |tag: &str| dns.servers.iter().find(|s| s.tag == tag).unwrap();
        assert_eq!(find("udp").address, "udp://8.8.8.8:5353");
        assert_eq!(find("tcp").address, "tcp://8.8.4.4:5354");
        assert_eq!(find("tls").address, "tls://1.1.1.1:853");
        assert_eq!(find("quic").address, "quic://dns.example.com:8853");
        assert_eq!(
            find("https").address,
            "https://dns.example.com:8443/custom-query"
        );
        assert_eq!(find("h3").address, "h3://h3.example.com:9443/dns-query");
    }

    #[test]
    fn pf12_dhcp_interface_validates_and_lowers() {
        let doc = json!({
            "dns": {
                "servers": [
                    {"tag": "dhcp", "type": "dhcp", "interface": "en0"}
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "dhcp interface should validate: {issues:?}"
        );

        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.servers[0].address, "dhcp://en0");
    }

    #[test]
    fn pf12_hosts_path_validates_and_lowers_to_hosts_path() {
        let doc = json!({
            "dns": {
                "servers": [
                    {"tag": "hosts", "type": "hosts", "path": ["/etc/hosts", "/tmp/hosts"], "predefined": {"example.com": ["1.2.3.4"]}}
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(issues.is_empty(), "hosts path should validate: {issues:?}");

        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.servers[0].address, "hosts");
        assert_eq!(
            dns.servers[0].hosts_path,
            vec!["/etc/hosts".to_string(), "/tmp/hosts".to_string()]
        );
        assert!(dns.servers[0].predefined.is_some());
    }

    #[test]
    fn pf12_bogus_dns_server_field_still_rejected() {
        let doc = json!({
            "dns": {
                "servers": [
                    {"tag": "bad", "type": "udp", "server": "8.8.8.8", "bogus_dns_server_field": true}
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/dns/servers/0/bogus_dns_server_field"
                    && i["kind"] == "error"
                    && i["code"] == "UnknownField"),
            "bogus dns server field should still be rejected: {issues:?}"
        );
    }

    #[test]
    fn pf12_gui_defaultish_dns_config_passes_config_from_raw_value() {
        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {"type": "selector", "tag": "select", "outbounds": ["direct"]},
                {"type": "direct", "tag": "direct"}
            ],
            "dns": {
                "servers": [
                    {
                        "tag": "FakeIP",
                        "type": "fakeip",
                        "inet4_range": "198.18.0.0/15",
                        "inet6_range": "fc00::/18"
                    },
                    {
                        "tag": "Local-DNS",
                        "type": "https",
                        "server": "223.5.5.5",
                        "server_port": 443,
                        "path": "/dns-query",
                        "domain_resolver": "Local-DNS-Resolver"
                    },
                    {
                        "tag": "Local-DNS-Resolver",
                        "type": "udp",
                        "server": "223.5.5.5",
                        "server_port": 53
                    },
                    {
                        "tag": "Remote-DNS",
                        "type": "tls",
                        "server": "8.8.8.8",
                        "server_port": 853,
                        "domain_resolver": "Remote-DNS-Resolver",
                        "detour": "select"
                    },
                    {
                        "tag": "Remote-DNS-Resolver",
                        "type": "udp",
                        "server": "8.8.8.8",
                        "server_port": 53,
                        "detour": "select"
                    }
                ],
                "rules": [
                    {"clash_mode": "Direct", "server": "Local-DNS"},
                    {"clash_mode": "Global", "server": "Remote-DNS"},
                    {"rule_set": "geosite-cn", "server": "Local-DNS"},
                    {"rule_set": "geolocation-!cn", "server": "Remote-DNS"}
                ],
                "disable_cache": false,
                "disable_expire": false,
                "independent_cache": false,
                "final": "Remote-DNS"
            }
        });

        let (_cfg, ir) = crate::config_from_raw_value(doc).expect("GUI DNS shape should load");
        let dns = ir.dns.expect("dns");
        let find = |tag: &str| dns.servers.iter().find(|s| s.tag == tag).unwrap();
        assert_eq!(find("FakeIP").address, "fakeip");
        assert_eq!(find("Local-DNS").address, "https://223.5.5.5:443/dns-query");
        assert_eq!(
            find("Local-DNS").address_resolver.as_deref(),
            Some("Local-DNS-Resolver")
        );
        assert_eq!(find("Local-DNS-Resolver").address, "udp://223.5.5.5:53");
        assert_eq!(find("Remote-DNS").address, "tls://8.8.8.8:853");
        assert_eq!(
            find("Remote-DNS").address_resolver.as_deref(),
            Some("Remote-DNS-Resolver")
        );
        assert_eq!(find("Remote-DNS-Resolver").address, "udp://8.8.8.8:53");
        assert_eq!(dns.final_server.as_deref(), Some("Remote-DNS"));
    }

    // address_resolver / service / detour on servers
    #[test]
    fn dns_server_address_resolver_service_detour() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {
                        "tag": "doh1",
                        "address": "https://dns.example.com/dns-query",
                        "address_resolver": "local-dns",
                        "service": "my-service",
                        "detour": "proxy-out"
                    }
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        let s = &dns.servers[0];
        assert_eq!(s.address_resolver.as_deref(), Some("local-dns"));
        assert_eq!(s.service.as_deref(), Some("my-service"));
        assert_eq!(s.detour.as_deref(), Some("proxy-out"));
    }

    // DNS rules with index fallback to server tag
    #[test]
    fn dns_rules_index_fallback_to_server_tag() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "s0", "address": "udp://8.8.8.8"},
                    {"tag": "s1", "address": "udp://1.1.1.1"}
                ],
                "rules": [
                    {"domain_suffix": [".example.com"]},
                    {"domain_suffix": [".test.com"]}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.rules.len(), 2);
        assert_eq!(dns.rules[0].server.as_deref(), Some("s0"));
        assert_eq!(dns.rules[1].server.as_deref(), Some("s1"));
    }

    // Index fallback beyond server count → last server
    #[test]
    fn dns_rules_index_fallback_beyond_server_count() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "only", "address": "udp://8.8.8.8"}
                ],
                "rules": [
                    {"domain_suffix": [".a.com"]},
                    {"domain_suffix": [".b.com"]},
                    {"domain_suffix": [".c.com"]}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.rules.len(), 3);
        assert_eq!(dns.rules[0].server.as_deref(), Some("only"));
        assert_eq!(dns.rules[1].server.as_deref(), Some("only"));
        assert_eq!(dns.rules[2].server.as_deref(), Some("only"));
    }

    // Rules with explicit server tag
    #[test]
    fn dns_rules_explicit_server() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "s0", "address": "udp://8.8.8.8"}
                ],
                "rules": [
                    {"server": "s0", "domain": ["example.com"]}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.rules[0].server.as_deref(), Some("s0"));
        assert_eq!(dns.rules[0].domain, vec!["example.com".to_string()]);
    }

    // default / final
    #[test]
    fn dns_default_and_final() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "final": "s1"
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.default.as_deref(), Some("s1"));
        assert_eq!(dns.final_server.as_deref(), Some("s1"));
    }

    // "default" field (legacy alias for final)
    #[test]
    fn dns_default_legacy_alias() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "default": "s1"
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.default.as_deref(), Some("s1"));
        assert!(dns.final_server.is_none());
    }

    // Global knobs
    #[test]
    fn dns_global_knobs() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "disable_cache": true,
                "reverse_mapping": true,
                "strategy": "prefer_ipv4",
                "client_subnet": "1.2.3.0/24",
                "independent_cache": true,
                "disable_expire": false,
                "timeout_ms": 5000
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.disable_cache, Some(true));
        assert_eq!(dns.reverse_mapping, Some(true));
        assert_eq!(dns.strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(dns.client_subnet.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(dns.independent_cache, Some(true));
        assert_eq!(dns.disable_expire, Some(false));
        assert_eq!(dns.timeout_ms, Some(5000));
    }

    // TTL block
    #[test]
    fn dns_ttl_block() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "ttl": {"default": 300, "min": 60, "max": 86400, "neg": 10}
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.ttl_default_s, Some(300));
        assert_eq!(dns.ttl_min_s, Some(60));
        assert_eq!(dns.ttl_max_s, Some(86400));
        assert_eq!(dns.ttl_neg_s, Some(10));
    }

    // FakeIP block
    #[test]
    fn dns_fakeip_block() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "fakeip": {
                    "enabled": true,
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.fakeip_enabled, Some(true));
        assert_eq!(dns.fakeip_v4_base.as_deref(), Some("198.18.0.0"));
        assert_eq!(dns.fakeip_v4_mask, Some(15));
        assert_eq!(dns.fakeip_v6_base.as_deref(), Some("fc00::"));
        assert_eq!(dns.fakeip_v6_mask, Some(18));
    }

    // Pool block
    #[test]
    fn dns_pool_block() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "pool_strategy": "round_robin",
                "pool": {
                    "race_window_ms": 100,
                    "he_race_ms": 50,
                    "he_order": "v4_first",
                    "max_inflight": 10,
                    "per_host_inflight": 3
                }
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.pool_strategy.as_deref(), Some("round_robin"));
        assert_eq!(dns.pool_race_window_ms, Some(100));
        assert_eq!(dns.pool_he_race_ms, Some(50));
        assert_eq!(dns.pool_he_order.as_deref(), Some("v4_first"));
        assert_eq!(dns.pool_max_inflight, Some(10));
        assert_eq!(dns.pool_per_host_inflight, Some(3));
    }

    // Static hosts
    #[test]
    fn dns_static_hosts() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "hosts": {
                    "example.com": "1.2.3.4",
                    "multi.com": ["10.0.0.1", "10.0.0.2"]
                },
                "hosts_ttl": 3600
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.hosts.len(), 2);
        let ex = dns
            .hosts
            .iter()
            .find(|h| h.domain == "example.com")
            .unwrap();
        assert_eq!(ex.ips, vec!["1.2.3.4".to_string()]);
        let multi = dns.hosts.iter().find(|h| h.domain == "multi.com").unwrap();
        assert_eq!(
            multi.ips,
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
        assert_eq!(dns.hosts_ttl_s, Some(3600));
    }

    // static_ttl alias for hosts_ttl
    #[test]
    fn dns_static_ttl_alias() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "hosts": {"a.com": "1.1.1.1"},
                "static_ttl": 1800
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.hosts_ttl_s, Some(1800));
    }

    // No DNS block → ir.dns is None
    #[test]
    fn no_dns_block_ir_none() {
        let doc = json!({"schema_version": 2, "outbounds": []});
        let ir = to_ir_v1(&doc);
        assert!(ir.dns.is_none());
    }

    // Empty DNS block (no servers/rules/default/timeout/hosts) → ir.dns is None
    #[test]
    fn empty_dns_block_ir_none() {
        let doc = json!({"schema_version": 2, "dns": {}});
        let ir = to_ir_v1(&doc);
        assert!(ir.dns.is_none());
    }

    // infer_dns_server_type_from_address unit tests
    #[test]
    fn infer_type_from_address() {
        assert_eq!(
            infer_dns_server_type_from_address("udp://8.8.8.8"),
            Some("udp".to_string())
        );
        assert_eq!(
            infer_dns_server_type_from_address("tls://1.1.1.1"),
            Some("tls".to_string())
        );
        assert_eq!(
            infer_dns_server_type_from_address("resolved"),
            Some("resolved".to_string())
        );
        assert_eq!(infer_dns_server_type_from_address(""), None);
        assert_eq!(infer_dns_server_type_from_address("no-scheme"), None);
    }

    // ca_pem as string (not array)
    #[test]
    fn dns_server_ca_pem_as_string() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "s1", "address": "tls://1.1.1.1", "ca_pem": "PEM_DATA"}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.servers[0].ca_pem, vec!["PEM_DATA".to_string()]);
    }

    #[test]
    fn p1313_02_go_style_typed_server_fields_lower() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {
                        "tag": "https",
                        "type": "https",
                        "server": "dns.example.com",
                        "server_port": 8443,
                        "path": "query",
                        "method": "GET",
                        "headers": {
                            "User-Agent": "singbox-rust",
                            "Accept": ["application/dns-message", "application/json"]
                        },
                        "prefer_go": true,
                        "domain_resolver": "bootstrap",
                        "detour": "proxy",
                        "cache_capacity": 64
                    },
                    {"tag": "bootstrap", "type": "udp", "server": "1.1.1.1"}
                ],
                "cache_capacity": 128,
                "final": "https"
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        let server = &dns.servers[0];
        assert_eq!(server.address, "https://dns.example.com:8443/query");
        assert_eq!(server.method.as_deref(), Some("GET"));
        assert_eq!(server.prefer_go, Some(true));
        assert_eq!(server.address_resolver.as_deref(), Some("bootstrap"));
        assert_eq!(server.detour.as_deref(), Some("proxy"));
        assert_eq!(server.cache_capacity, Some(64));
        assert_eq!(
            server.headers["User-Agent"],
            vec!["singbox-rust".to_string()]
        );
        assert_eq!(
            server.headers["Accept"],
            vec![
                "application/dns-message".to_string(),
                "application/json".to_string()
            ]
        );
        assert_eq!(dns.cache_capacity, Some(128));
    }

    #[test]
    fn p1313_02_unknown_dns_type_is_stable_error() {
        let doc = json!({
            "dns": {
                "servers": [
                    {"tag": "bad", "type": "bogus", "server": "1.1.1.1"}
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "InvalidEnum"
                    && i["ptr"] == "/dns/servers/0/type"
                    && i["msg"] == "unknown transport type: bogus"
            }),
            "unknown type should produce stable error: {issues:?}"
        );
    }

    #[test]
    fn p1313_02_unknown_legacy_rcode_is_stable_error() {
        let doc = json!({
            "dns": {
                "servers": [
                    {"tag": "bad", "address": "rcode://mystery"}
                ]
            }
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "InvalidEnum"
                    && i["ptr"] == "/dns/servers/0/address"
                    && i["msg"] == "unknown rcode: mystery"
            }),
            "unknown rcode should produce stable error: {issues:?}"
        );
    }

    #[test]
    fn p1313_02_plain_legacy_address_upgrades_to_udp() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "plain", "address": "1.1.1.1"}],
                "final": "plain"
            }
        });
        let dns = to_ir_v1(&doc).dns.expect("dns");
        assert_eq!(dns.servers[0].address, "udp://1.1.1.1");
        assert_eq!(dns.servers[0].server_type.as_deref(), Some("udp"));
    }

    #[test]
    fn p1313_02_legacy_rcode_server_rewrites_rule_to_predefined() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "reject-name", "address": "rcode://name_error"},
                    {"tag": "upstream", "address": "udp://1.1.1.1"}
                ],
                "rules": [
                    {"domain": ["blocked.example"], "server": "reject-name"}
                ],
                "final": "upstream"
            }
        });
        let dns = to_ir_v1(&doc).dns.expect("dns");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].tag, "upstream");
        assert_eq!(dns.rules[0].action.as_deref(), Some("predefined"));
        assert_eq!(dns.rules[0].rcode.as_deref(), Some("NXDOMAIN"));
        assert!(dns.rules[0].server.is_none());
    }

    // DNS rule with action (no server inference)
    #[test]
    fn dns_rule_with_action() {
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [{"tag": "s1", "address": "udp://8.8.8.8"}],
                "rules": [
                    {"action": "reject", "domain": ["blocked.com"]}
                ]
            }
        });
        let ir = to_ir_v1(&doc);
        let dns = ir.dns.expect("dns");
        assert_eq!(dns.rules.len(), 1);
        assert!(dns.rules[0].server.is_none());
        assert_eq!(dns.rules[0].action.as_deref(), Some("reject"));
    }

    // ───── WP-30x Pins ─────

    #[test]
    fn wp30x_pin_dns_lowering_owner_is_dns_rs() {
        // Pin: DNS lowering logic lives in validator/v2/dns.rs (lower_dns function).
        // This test verifies lower_dns produces the expected IR.
        let mut ir = ConfigIR::default();
        let doc = json!({
            "dns": {
                "servers": [{"tag": "pin", "address": "udp://8.8.8.8"}],
                "default": "pin"
            }
        });
        lower_dns(&doc, &mut ir);
        let dns = ir.dns.expect("lower_dns should populate ir.dns");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].tag, "pin");
        assert_eq!(dns.default.as_deref(), Some("pin"));
    }

    #[test]
    fn wp30x_pin_mod_rs_to_ir_v1_delegates_dns() {
        // Pin: to_ir_v1() delegates DNS lowering to dns::lower_dns.
        // Verified by the fact that to_ir_v1 produces identical results
        // to calling lower_dns directly.
        let doc = json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "s1", "address": "udp://8.8.8.8"},
                    {"tag": "s2", "type": "resolved", "service": "rsv"}
                ],
                "rules": [{"domain": ["a.com"]}],
                "final": "s1",
                "disable_cache": true,
                "timeout_ms": 3000,
                "hosts": {"b.com": "2.2.2.2"}
            }
        });
        let ir_via_to_ir = to_ir_v1(&doc);
        let mut ir_via_lower = ConfigIR::default();
        lower_dns(&doc, &mut ir_via_lower);

        let d1 = ir_via_to_ir.dns.expect("to_ir_v1 dns");
        let d2 = ir_via_lower.dns.expect("lower_dns dns");
        assert_eq!(d1.servers.len(), d2.servers.len());
        assert_eq!(d1.rules.len(), d2.rules.len());
        assert_eq!(d1.default, d2.default);
        assert_eq!(d1.final_server, d2.final_server);
        assert_eq!(d1.disable_cache, d2.disable_cache);
        assert_eq!(d1.timeout_ms, d2.timeout_ms);
        assert_eq!(d1.hosts.len(), d2.hosts.len());
    }
}
