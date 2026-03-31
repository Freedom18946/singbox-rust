use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{
    emit_issue, extract_string_list, insert_keys, object_keys, parse_u16_field, parse_u32_field,
};
use crate::ir::{ConfigIR, DomainResolveOptionsIR, RuleIR, RuleSetIR};

fn allowed_route_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::RouteIR::default());
    insert_keys(
        &mut set,
        &[
            "final",
            "geoip",
            "geosite",
            "default_mark",
            "default_resolver",
            "default_network_strategy",
            "fallback_delay",
            "tls_fragment",
            "tls_record_fragment",
            "tls_fragment_fallback_delay",
        ],
    );
    set
}

fn allowed_route_rule_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::RuleIR::default());
    insert_keys(
        &mut set,
        &[
            "when", "to", "suffix", "keyword", "regex", "ip_cidr", "process",
        ],
    );
    set
}

fn allowed_rule_set_keys() -> HashSet<&'static str> {
    [
        "tag",
        "type",
        "format",
        "path",
        "url",
        "download_detour",
        "update_interval",
        "rules",
        "version",
    ]
    .into_iter()
    .collect()
}

pub(super) fn rule_set_format_from_path(path: &str) -> Option<&'static str> {
    if path.ends_with(".json") {
        Some("source")
    } else if path.ends_with(".srs") {
        Some("binary")
    } else {
        None
    }
}

pub(super) fn rule_set_format_from_url(url: &str) -> Option<&'static str> {
    let path = url.split('?').next().unwrap_or(url);
    rule_set_format_from_path(path)
}

fn parse_rule_entry(val: &Value) -> RuleIR {
    let mut r = RuleIR::default();
    if let Some(obj) = val.as_object() {
        let condition_obj = obj.get("when").and_then(|v| v.as_object()).unwrap_or(obj);
        // Parse type/mode/sub-rules for logical rules
        let rule_type = obj.get("type").and_then(|v| v.as_str());
        if let Some(rule_type) = rule_type {
            r.rule_type = Some(rule_type.to_string());
        }
        if rule_type == Some("logical") {
            r.mode = obj
                .get("mode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
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
        r.not_process_name =
            extract_string_list(obj.get("not_process_name").or(obj.get("not_process")))
                .unwrap_or_default();
        r.not_process_path = extract_string_list(obj.get("not_process_path")).unwrap_or_default();
        r.not_network = extract_string_list(obj.get("not_network")).unwrap_or_default();
        r.not_protocol = extract_string_list(obj.get("not_protocol")).unwrap_or_default();
        r.not_wifi_ssid = extract_string_list(obj.get("not_wifi_ssid")).unwrap_or_default();
        r.not_wifi_bssid = extract_string_list(obj.get("not_wifi_bssid")).unwrap_or_default();
        r.not_rule_set = extract_string_list(obj.get("not_rule_set")).unwrap_or_default();

        r.action = match obj.get("action").and_then(|v| v.as_str()) {
            Some(s) => crate::ir::RuleAction::from_str_opt(s).unwrap_or_default(),
            None => crate::ir::RuleAction::default(),
        };

        r.override_address = obj
            .get("override_address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        r.override_port = parse_u16_field(obj.get("override_port"));
        r.rewrite_ttl = parse_u32_field(obj.get("rewrite_ttl"));
        r.client_subnet = obj
            .get("client_subnet")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        r.outbound = obj
            .get("outbound")
            .or_else(|| obj.get("to"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        r.invert = obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false);
    }
    r
}

/// Lower the `/route` block from raw JSON into `ConfigIR.route`.
///
/// This is the single route lowering owner — `to_ir_v1()` delegates here.
pub(super) fn lower_route(doc: &Value, ir: &mut ConfigIR) {
    let Some(route) = doc.get("route").and_then(|v| v.as_object()) else {
        return;
    };

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
                let mut ty = obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("inline")
                    .to_string();
                if ty.trim().is_empty() {
                    ty = "inline".to_string();
                }
                let path = obj
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let url = obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let mut format = if ty == "inline" {
                    String::new()
                } else {
                    obj.get("format")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                };
                if ty != "inline" && format.is_empty() {
                    if let Some(p) = &path {
                        if let Some(fmt) = rule_set_format_from_path(p) {
                            format = fmt.to_string();
                        }
                    }
                    if format.is_empty() {
                        if let Some(u) = &url {
                            if let Some(fmt) = rule_set_format_from_url(u) {
                                format = fmt.to_string();
                            }
                        }
                    }
                }

                let download_detour = obj
                    .get("download_detour")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let update_interval = obj
                    .get("update_interval")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let rules = if ty == "inline" {
                    obj.get("rules")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().map(parse_rule_entry).collect())
                } else {
                    None
                };

                let version = if ty == "inline" {
                    None
                } else {
                    obj.get("version")
                        .and_then(|v| v.as_u64())
                        .and_then(|v| u8::try_from(v).ok())
                };

                if !tag.is_empty() {
                    ir.route.rule_set.push(RuleSetIR {
                        tag,
                        ty,
                        format,
                        path,
                        url,
                        download_detour,
                        update_interval,
                        rules,
                        version,
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
    ir.route.auto_detect_interface = route.get("auto_detect_interface").and_then(|v| v.as_bool());
    ir.route.default_interface = route
        .get("default_interface")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    ir.route.mark = route
        .get("mark")
        .or_else(|| route.get("default_mark"))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());

    let default_resolver_val = route
        .get("default_domain_resolver")
        .or_else(|| route.get("default_resolver"));
    if let Some(val) = default_resolver_val {
        if let Some(s) = val.as_str() {
            ir.route.default_domain_resolver = Some(DomainResolveOptionsIR {
                server: s.to_string(),
                ..Default::default()
            });
        } else if let Some(obj) = val.as_object() {
            ir.route.default_domain_resolver = Some(DomainResolveOptionsIR {
                server: obj
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                strategy: obj
                    .get("strategy")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                disable_cache: obj.get("disable_cache").and_then(|v| v.as_bool()),
                rewrite_ttl: parse_u32_field(obj.get("rewrite_ttl")),
                client_subnet: obj
                    .get("client_subnet")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
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

/// Validate `/route` unknown fields and `/route/rule_set` structure/type/format/version.
///
/// 校验 `/route` 未知字段及 `/route/rule_set` 结构、类型、格式、版本。
pub(crate) fn validate_route(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    let Some(route) = doc.get("route").and_then(|v| v.as_object()) else {
        return;
    };

    // Route top-level unknown fields
    let allowed = allowed_route_keys();
    for k in route.keys() {
        if !allowed.contains(k) {
            let kind = if allow_unknown { "warning" } else { "error" };
            issues.push(emit_issue(
                kind,
                IssueCode::UnknownField,
                &format!("/route/{}", k),
                "unknown field",
                "remove it",
            ));
        }
    }

    // Route rules unknown fields
    if let Some(rules) = route.get("rules").and_then(|v| v.as_array()) {
        let allowed_rules = allowed_route_rule_keys();
        for (i, rule) in rules.iter().enumerate() {
            if let Some(map) = rule.as_object() {
                for k in map.keys() {
                    if !allowed_rules.contains(k) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/route/rules/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
            }
        }
    }

    // Route rule_set unknown fields
    if let Some(rule_sets) = route.get("rule_set").and_then(|v| v.as_array()) {
        let allowed_rule_set = allowed_rule_set_keys();
        for (i, rs) in rule_sets.iter().enumerate() {
            if let Some(map) = rs.as_object() {
                for k in map.keys() {
                    if !allowed_rule_set.contains(k.as_str()) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/route/rule_set/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
            }
        }
    }

    // rule_set structure validation (type/format/version parity)
    if let Some(rule_sets) = route.get("rule_set").and_then(|v| v.as_array()) {
        for (i, rs) in rule_sets.iter().enumerate() {
            let Some(obj) = rs.as_object() else {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/route/rule_set/{}", i),
                    "rule_set item must be an object",
                    "use object",
                ));
                continue;
            };

            let tag = obj.get("tag").and_then(|v| v.as_str()).unwrap_or("");
            if tag.trim().is_empty() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/route/rule_set/{}/tag", i),
                    "missing required field",
                    "add tag",
                ));
            }

            let ty_raw = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ty = if ty_raw.trim().is_empty() {
                "inline"
            } else {
                ty_raw
            };
            match ty {
                "inline" | "local" | "remote" => {}
                _ => {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/route/rule_set/{}/type", i),
                        "unknown rule_set type",
                        "use inline|local|remote",
                    ));
                }
            }

            if ty != "inline" {
                let mut format = obj
                    .get("format")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                if format.is_empty() {
                    if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                        if let Some(inferred) = rule_set_format_from_path(path) {
                            format = inferred.to_string();
                        }
                    }
                    if format.is_empty() {
                        if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
                            if let Some(inferred) = rule_set_format_from_url(url) {
                                format = inferred.to_string();
                            }
                        }
                    }
                }

                if format.is_empty() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::MissingRequired,
                        &format!("/route/rule_set/{}/format", i),
                        "missing format",
                        "set format to source|binary",
                    ));
                } else if format != "source" && format != "binary" {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/route/rule_set/{}/format", i),
                        "unknown rule_set format",
                        "use source|binary",
                    ));
                }
            }
            if let Some(version_val) = obj.get("version") {
                let version = version_val.as_u64().and_then(|v| u8::try_from(v).ok());
                let valid = matches!(version, Some(1..=3));
                if !valid {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/route/rule_set/{}/version", i),
                        "unknown rule_set version",
                        "use 1|2|3",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::v2::to_ir_v1;
    use serde_json::json;

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_route(doc, allow_unknown, &mut issues);
        issues
    }

    #[test]
    fn route_unknown_field_strict() {
        let doc = json!({"route": {"unknown_route_field": true, "rules": []}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/unknown_route_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn route_unknown_field_allow_unknown() {
        let doc = json!({"route": {"unknown_route_field": true, "rules": []}});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/unknown_route_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    #[test]
    fn route_rule_unknown_field_strict() {
        let doc = json!({"route": {"rules": [{"unknown_rule_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/rules/0/unknown_rule_field" && i["kind"] == "error"));
    }

    #[test]
    fn route_rule_unknown_field_allow_unknown() {
        let doc = json!({"route": {"rules": [{"unknown_rule_field": true}]}});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/rules/0/unknown_rule_field" && i["kind"] == "warning"));
    }

    #[test]
    fn route_rule_set_unknown_field_strict() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "unknown_rule_set_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(
            |i| i["ptr"] == "/route/rule_set/0/unknown_rule_set_field" && i["kind"] == "error"
        ));
    }

    #[test]
    fn rule_set_not_object_error() {
        let doc = json!({"route": {"rule_set": ["not_object"]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "rule_set item must be an object"));
    }

    #[test]
    fn rule_set_missing_tag() {
        let doc = json!({"route": {"rule_set": [{"type": "local", "format": "source", "path": "a.json"}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/rule_set/0/tag" && i["code"] == "MissingRequired"));
    }

    #[test]
    fn rule_set_invalid_type() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "bad"}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/type"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "unknown rule_set type"));
    }

    #[test]
    fn rule_set_missing_format() {
        let doc =
            json!({"route": {"rule_set": [{"tag": "x", "type": "local", "path": "/some/path"}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/rule_set/0/format" && i["code"] == "MissingRequired"));
    }

    #[test]
    fn rule_set_format_inference_from_path() {
        let doc =
            json!({"route": {"rule_set": [{"tag": "x", "type": "local", "path": "rules.json"}]}});
        let issues = run_validate(&doc, false);
        assert!(
            !issues
                .iter()
                .any(|i| i["ptr"] == "/route/rule_set/0/format"),
            "format should be inferred from .json extension"
        );
    }

    #[test]
    fn rule_set_format_inference_from_url() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "remote", "url": "https://example.com/rules.srs"}]}});
        let issues = run_validate(&doc, false);
        assert!(
            !issues
                .iter()
                .any(|i| i["ptr"] == "/route/rule_set/0/format"),
            "format should be inferred from .srs URL extension"
        );
    }

    #[test]
    fn rule_set_invalid_version() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "version": 99}]}});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/route/rule_set/0/version"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "unknown rule_set version"));
    }

    #[test]
    fn rule_set_valid_versions() {
        for v in [1, 2, 3] {
            let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "version": v}]}});
            let issues = run_validate(&doc, false);
            assert!(
                !issues
                    .iter()
                    .any(|i| i["ptr"] == "/route/rule_set/0/version"),
                "version {} should be valid",
                v
            );
        }
    }

    #[test]
    fn no_route_section_no_issues() {
        let doc = json!({"inbounds": []});
        let issues = run_validate(&doc, false);
        assert!(issues.is_empty());
    }

    // ───── Lowering tests (WP-30y) ─────

    #[test]
    fn route_rules_lowering_uses_aliases() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "rules": [{
                    "when": {
                        "suffix": [".example.com"],
                        "keyword": ["stream"],
                        "regex": ["^api\\."],
                        "ip_cidr": ["10.0.0.0/8"],
                        "process": ["curl"]
                    },
                    "to": "proxy",
                    "rewrite_ttl": 60,
                    "override_port": 8443,
                    "client_subnet": "1.1.1.0/24",
                    "invert": true
                }]
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.rules.len(), 1);
        let rule = &ir.route.rules[0];
        assert_eq!(rule.domain_suffix, vec![".example.com".to_string()]);
        assert_eq!(rule.domain_keyword, vec!["stream".to_string()]);
        assert_eq!(rule.domain_regex, vec!["^api\\.".to_string()]);
        assert_eq!(rule.ipcidr, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(rule.process_name, vec!["curl".to_string()]);
        assert_eq!(rule.outbound.as_deref(), Some("proxy"));
        assert_eq!(rule.rewrite_ttl, Some(60));
        assert_eq!(rule.override_port, Some(8443));
        assert_eq!(rule.client_subnet.as_deref(), Some("1.1.1.0/24"));
        assert!(rule.invert);
    }

    #[test]
    fn route_logical_rule_lowering() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "rules": [{
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"domain": ["a.com"]},
                        {"process": ["curl"], "to": "proxy"}
                    ]
                }]
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.rules.len(), 1);
        let rule = &ir.route.rules[0];
        assert_eq!(rule.rule_type.as_deref(), Some("logical"));
        assert_eq!(rule.mode.as_deref(), Some("or"));
        assert_eq!(rule.rules.len(), 2);
        assert_eq!(rule.rules[0].domain, vec!["a.com".to_string()]);
        assert_eq!(rule.rules[1].process_name, vec!["curl".to_string()]);
        assert_eq!(rule.rules[1].outbound.as_deref(), Some("proxy"));
    }

    #[test]
    fn route_rule_set_lowering_inline_and_remote_format_inference() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "rule_set": [
                    {
                        "tag": "inline-rs",
                        "type": "inline",
                        "rules": [{"domain": ["inline.example"]}]
                    },
                    {
                        "tag": "remote-rs",
                        "type": "remote",
                        "url": "https://example.com/geo.srs?sig=1",
                        "download_detour": "proxy",
                        "update_interval": "24h",
                        "version": 3
                    }
                ]
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.rule_set.len(), 2);

        let inline = ir
            .route
            .rule_set
            .iter()
            .find(|rs| rs.tag == "inline-rs")
            .expect("inline rule_set");
        assert_eq!(inline.ty, "inline");
        assert!(inline.format.is_empty());
        assert_eq!(
            inline.rules.as_ref().expect("inline rules")[0].domain,
            vec!["inline.example".to_string()]
        );
        assert!(inline.version.is_none());

        let remote = ir
            .route
            .rule_set
            .iter()
            .find(|rs| rs.tag == "remote-rs")
            .expect("remote rule_set");
        assert_eq!(remote.ty, "remote");
        assert_eq!(remote.format, "binary");
        assert_eq!(remote.download_detour.as_deref(), Some("proxy"));
        assert_eq!(remote.update_interval.as_deref(), Some("24h"));
        assert_eq!(remote.version, Some(3));
    }

    #[test]
    fn route_default_and_final_alias_fill() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "final": "final-out"
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.final_outbound.as_deref(), Some("final-out"));
        assert_eq!(ir.route.default.as_deref(), Some("final-out"));
    }

    #[test]
    fn route_default_domain_resolver_string_and_object_aliases() {
        let string_doc = json!({
            "schema_version": 2,
            "route": {
                "default_domain_resolver": "dns-1"
            }
        });
        let string_ir = to_ir_v1(&string_doc);
        let string_resolver = string_ir
            .route
            .default_domain_resolver
            .expect("string resolver");
        assert_eq!(string_resolver.server, "dns-1");
        assert!(string_resolver.strategy.is_none());

        let object_doc = json!({
            "schema_version": 2,
            "route": {
                "default_resolver": {
                    "server": "dns-2",
                    "strategy": "prefer_ipv4",
                    "disable_cache": true,
                    "rewrite_ttl": 120,
                    "client_subnet": "2.2.2.0/24"
                }
            }
        });
        let object_ir = to_ir_v1(&object_doc);
        let object_resolver = object_ir
            .route
            .default_domain_resolver
            .expect("object resolver");
        assert_eq!(object_resolver.server, "dns-2");
        assert_eq!(object_resolver.strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(object_resolver.disable_cache, Some(true));
        assert_eq!(object_resolver.rewrite_ttl, Some(120));
        assert_eq!(object_resolver.client_subnet.as_deref(), Some("2.2.2.0/24"));
    }

    #[test]
    fn route_mark_and_default_mark_alias() {
        let mark_doc = json!({
            "schema_version": 2,
            "route": {
                "mark": 99
            }
        });
        assert_eq!(to_ir_v1(&mark_doc).route.mark, Some(99));

        let default_mark_doc = json!({
            "schema_version": 2,
            "route": {
                "default_mark": 101
            }
        });
        assert_eq!(to_ir_v1(&default_mark_doc).route.mark, Some(101));
    }

    #[test]
    fn route_network_strategy_and_fallback_fields() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "network_strategy": "prefer_ipv6",
                "default_network_type": ["wifi", "cellular"],
                "default_fallback_network_type": "ethernet",
                "fallback_delay": "250ms",
                "find_process": true,
                "override_android_vpn": false,
                "auto_detect_interface": true,
                "default_interface": "en0"
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.network_strategy.as_deref(), Some("prefer_ipv6"));
        assert_eq!(
            ir.route.default_network_type,
            Some(vec!["wifi".to_string(), "cellular".to_string()])
        );
        assert_eq!(
            ir.route.default_fallback_network_type,
            Some(vec!["ethernet".to_string()])
        );
        assert_eq!(ir.route.default_fallback_delay.as_deref(), Some("250ms"));
        assert_eq!(ir.route.find_process, Some(true));
        assert_eq!(ir.route.override_android_vpn, Some(false));
        assert_eq!(ir.route.auto_detect_interface, Some(true));
        assert_eq!(ir.route.default_interface.as_deref(), Some("en0"));
    }

    #[test]
    fn route_geoip_and_geosite_lowering() {
        let doc = json!({
            "schema_version": 2,
            "route": {
                "geoip": {
                    "path": "/data/geoip.db",
                    "download_url": "https://example.com/geoip.db",
                    "download_detour": "proxy"
                },
                "geosite": {
                    "path": "/data/geosite.db",
                    "download_url": "https://example.com/geosite.db",
                    "download_detour": "direct"
                }
            }
        });

        let ir = to_ir_v1(&doc);
        assert_eq!(ir.route.geoip_path.as_deref(), Some("/data/geoip.db"));
        assert_eq!(
            ir.route.geoip_download_url.as_deref(),
            Some("https://example.com/geoip.db")
        );
        assert_eq!(ir.route.geoip_download_detour.as_deref(), Some("proxy"));
        assert_eq!(ir.route.geosite_path.as_deref(), Some("/data/geosite.db"));
        assert_eq!(
            ir.route.geosite_download_url.as_deref(),
            Some("https://example.com/geosite.db")
        );
        assert_eq!(ir.route.geosite_download_detour.as_deref(), Some("direct"));
    }

    // ───── WP-30y Pins ─────

    #[test]
    fn wp30y_pin_route_lowering_owner_is_route_rs() {
        let source = include_str!("route.rs");
        assert!(
            source.contains("pub(super) fn lower_route"),
            "route lowering entry should live in validator/v2/route.rs"
        );

        let mut ir = ConfigIR::default();
        let doc = json!({
            "route": {
                "rules": [{"domain": ["pin.example"], "to": "proxy"}],
                "final": "proxy"
            }
        });
        lower_route(&doc, &mut ir);
        assert_eq!(ir.route.rules.len(), 1);
        assert_eq!(ir.route.rules[0].outbound.as_deref(), Some("proxy"));
        assert_eq!(ir.route.final_outbound.as_deref(), Some("proxy"));
        assert_eq!(ir.route.default.as_deref(), Some("proxy"));
    }

    #[test]
    fn wp30y_pin_mod_rs_to_ir_v1_delegates_route() {
        let mod_source = include_str!("mod.rs");
        let start = mod_source
            .find("endpoint::lower_endpoints(doc, &mut ir);")
            .expect("endpoint lowering marker");
        let end = mod_source
            .find("// Preserve optional experimental block")
            .expect("experimental block marker");
        let route_window = &mod_source[start..end];

        assert!(
            route_window.contains("route::lower_route(doc, &mut ir);"),
            "to_ir_v1 should delegate route lowering to route::lower_route"
        );
        assert!(
            !route_window.contains("doc.get(\"route\")"),
            "mod.rs route section should no longer hold inline lowering logic"
        );
        assert!(
            !route_window.contains("ir.route."),
            "mod.rs route section should no longer mutate ir.route directly"
        );

        let doc = json!({
            "schema_version": 2,
            "route": {
                "geoip": {"path": "/tmp/geoip.db"},
                "rules": [{"domain": ["pin.example"], "to": "proxy"}],
                "rule_set": [{"tag": "local-rs", "type": "local", "path": "rules.json"}],
                "default_mark": 7,
                "default_resolver": "dns",
                "default_network_strategy": "prefer_ipv4",
                "default_fallback_delay": "123ms",
                "final": "proxy"
            }
        });

        let ir_via_to_ir = to_ir_v1(&doc);
        let mut ir_via_lower = ConfigIR::default();
        lower_route(&doc, &mut ir_via_lower);

        assert_eq!(ir_via_to_ir.route.rules, ir_via_lower.route.rules);
        assert_eq!(ir_via_to_ir.route.rule_set, ir_via_lower.route.rule_set);
        assert_eq!(ir_via_to_ir.route.default, ir_via_lower.route.default);
        assert_eq!(
            ir_via_to_ir.route.final_outbound,
            ir_via_lower.route.final_outbound
        );
        assert_eq!(ir_via_to_ir.route.mark, ir_via_lower.route.mark);
        assert_eq!(
            ir_via_to_ir.route.default_domain_resolver,
            ir_via_lower.route.default_domain_resolver
        );
        assert_eq!(
            ir_via_to_ir.route.network_strategy,
            ir_via_lower.route.network_strategy
        );
        assert_eq!(
            ir_via_to_ir.route.default_fallback_delay,
            ir_via_lower.route.default_fallback_delay
        );
        assert_eq!(ir_via_to_ir.route.geoip_path, ir_via_lower.route.geoip_path);
    }
}
