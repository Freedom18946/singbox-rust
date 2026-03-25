use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

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
        assert!(issues.iter().any(|i| i["ptr"] == "/route/unknown_route_field"
            && i["kind"] == "error"
            && i["code"] == "UnknownField"));
    }

    #[test]
    fn route_unknown_field_allow_unknown() {
        let doc = json!({"route": {"unknown_route_field": true, "rules": []}});
        let issues = run_validate(&doc, true);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/unknown_route_field"
            && i["kind"] == "warning"
            && i["code"] == "UnknownField"));
    }

    #[test]
    fn route_rule_unknown_field_strict() {
        let doc = json!({"route": {"rules": [{"unknown_rule_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rules/0/unknown_rule_field"
            && i["kind"] == "error"));
    }

    #[test]
    fn route_rule_unknown_field_allow_unknown() {
        let doc = json!({"route": {"rules": [{"unknown_rule_field": true}]}});
        let issues = run_validate(&doc, true);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rules/0/unknown_rule_field"
            && i["kind"] == "warning"));
    }

    #[test]
    fn route_rule_set_unknown_field_strict() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "unknown_rule_set_field": true}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/unknown_rule_set_field"
            && i["kind"] == "error"));
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
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/tag"
            && i["code"] == "MissingRequired"));
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
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "local", "path": "/some/path"}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/format"
            && i["code"] == "MissingRequired"));
    }

    #[test]
    fn rule_set_format_inference_from_path() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "local", "path": "rules.json"}]}});
        let issues = run_validate(&doc, false);
        assert!(!issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/format"),
            "format should be inferred from .json extension");
    }

    #[test]
    fn rule_set_format_inference_from_url() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "remote", "url": "https://example.com/rules.srs"}]}});
        let issues = run_validate(&doc, false);
        assert!(!issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/format"),
            "format should be inferred from .srs URL extension");
    }

    #[test]
    fn rule_set_invalid_version() {
        let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "version": 99}]}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/version"
            && i["code"] == "TypeMismatch"
            && i["msg"] == "unknown rule_set version"));
    }

    #[test]
    fn rule_set_valid_versions() {
        for v in [1, 2, 3] {
            let doc = json!({"route": {"rule_set": [{"tag": "x", "type": "inline", "rules": [], "version": v}]}});
            let issues = run_validate(&doc, false);
            assert!(!issues.iter().any(|i| i["ptr"] == "/route/rule_set/0/version"),
                "version {} should be valid", v);
        }
    }

    #[test]
    fn no_route_section_no_issues() {
        let doc = json!({"inbounds": []});
        let issues = run_validate(&doc, false);
        assert!(issues.is_empty());
    }
}
