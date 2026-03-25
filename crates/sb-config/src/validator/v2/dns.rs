use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

fn allowed_dns_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::DnsIR::default());
    insert_keys(
        &mut set,
        &["ttl", "fakeip", "pool", "hosts", "hosts_ttl", "static_ttl"],
    );
    set
}

fn allowed_dns_server_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::DnsServerIR::default());
    insert_keys(&mut set, &["name", "type", "server"]);
    set
}

fn allowed_dns_rule_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::DnsRuleIR::default());
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_dns(doc, allow_unknown, &mut issues);
        issues
    }

    // 1) /dns top-level unknown field, strict → error
    #[test]
    fn dns_unknown_field_strict() {
        let doc = json!({"dns": {"unknown_dns_field": true, "servers": []}});
        let issues = run_validate(&doc, false);
        assert!(issues.iter().any(|i| i["ptr"] == "/dns/unknown_dns_field"
            && i["kind"] == "error"
            && i["code"] == "UnknownField"));
    }

    // 2) /dns top-level unknown field, allow_unknown → warning
    #[test]
    fn dns_unknown_field_allow_unknown() {
        let doc = json!({"dns": {"unknown_dns_field": true, "servers": []}});
        let issues = run_validate(&doc, true);
        assert!(issues.iter().any(|i| i["ptr"] == "/dns/unknown_dns_field"
            && i["kind"] == "warning"
            && i["code"] == "UnknownField"));
    }

    // 3) /dns/servers/0 unknown field, strict → error
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

    // 4) /dns/servers/0 unknown field, allow_unknown → warning
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

    // 5) /dns/rules/0 unknown field, strict → error
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

    // 6) /dns/rules/0 unknown field, allow_unknown → warning
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

    // 7) no dns block → no issues
    #[test]
    fn no_dns_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no dns issues when dns is absent"
        );
    }

    // 8) ptr precision: verify exact ptr for each level
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
}
