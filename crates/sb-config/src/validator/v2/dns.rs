use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, extract_string_list, insert_keys, object_keys, parse_u32_field};
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
    insert_keys(&mut set, &["name", "type", "server"]);
    set
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
                // go1.12.4-style `{ "type": "...", "server": "..." }` shapes.
                let address = if let Some(addr) = map
                    .get("address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                {
                    addr
                } else if let Some(ref ty) = ty {
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
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
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
                        inet4_range: map
                            .get("inet4_range")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        inet6_range: map
                            .get("inet6_range")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        hosts_path: map
                            .get("hosts_path")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
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

                dd.rules.push(dr);
            }
        }
    }

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
        assert_eq!(dns.servers.len(), 6);
        let find = |tag: &str| dns.servers.iter().find(|s| s.tag == tag).unwrap();
        assert_eq!(find("u1").address, "udp://8.8.8.8");
        assert_eq!(find("t1").address, "tcp://8.8.4.4");
        assert_eq!(find("tls1").address, "tls://1.1.1.1");
        assert_eq!(find("dot1").address, "tls://9.9.9.9");
        assert_eq!(find("h1").address, "https://dns.example.com/dns-query");
        assert_eq!(find("r1").address, "rcode://success");
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
