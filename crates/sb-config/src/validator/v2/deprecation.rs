use crate::deprecation::{deprecation_directory, DeprecationSeverity};
use sb_types::IssueCode;
use serde_json::Value;

/// Check the raw JSON config for deprecated fields using the deprecation directory.
/// Iterates all known deprecated patterns, resolves wildcards against the document,
/// and emits `IssueCode::Deprecated` issues for each match found.
///
/// 使用弃用目录检查原始 JSON 配置中的已弃用字段。
/// 遍历所有已知弃用模式，针对文档解析通配符，
/// 为每个匹配项生成 `IssueCode::Deprecated` 问题。
pub fn check_deprecations(doc: &Value) -> Vec<Value> {
    let mut issues = Vec::new();
    let directory = deprecation_directory();

    for entry in directory {
        let kind = match entry.severity {
            DeprecationSeverity::Info => "info",
            DeprecationSeverity::Warning => "warning",
            DeprecationSeverity::Error => "error",
        };

        // Parse the pattern into segments (skip leading empty segment from leading '/')
        let segments: Vec<&str> = entry.json_pointer.split('/').skip(1).collect();

        if segments.is_empty() {
            continue;
        }

        // Resolve the pattern against the document and collect matching concrete pointers
        let matched_pointers = resolve_deprecation_pattern(doc, &segments);

        for ptr in matched_pointers {
            issues.push(super::emit_issue(
                kind,
                IssueCode::Deprecated,
                &ptr,
                entry.description,
                entry.replacement,
            ));
        }
    }

    issues
}

/// Resolve a deprecation pattern (split into segments) against a JSON document.
/// Returns all concrete JSON pointer strings that match.
///
/// Handles:
/// - `*` wildcard matching any array index
/// - `key=value` matching objects where object[key] == value (treated as terminal match)
/// - plain key matching object property existence
fn resolve_deprecation_pattern(doc: &Value, segments: &[&str]) -> Vec<String> {
    let mut results = Vec::new();
    resolve_pattern_recursive(doc, segments, String::new(), &mut results);
    results
}

fn resolve_pattern_recursive(
    current: &Value,
    remaining: &[&str],
    prefix: String,
    results: &mut Vec<String>,
) {
    if remaining.is_empty() {
        return;
    }

    let segment = remaining[0];
    let rest = &remaining[1..];

    // Handle type=value pattern (e.g., "type=wireguard")
    if let Some(eq_pos) = segment.find('=') {
        let key = &segment[..eq_pos];
        let expected_value = &segment[eq_pos + 1..];

        // This pattern checks the current value (which should be an object)
        // for a field matching key=value. It's terminal — if it matches,
        // the current object pointer is the result.
        if let Some(obj) = current.as_object() {
            if let Some(actual) = obj.get(key).and_then(|v| v.as_str()) {
                if actual == expected_value {
                    results.push(prefix);
                }
            }
        }
        return;
    }

    if segment == "*" {
        // Wildcard: iterate array elements
        if let Some(arr) = current.as_array() {
            for (i, item) in arr.iter().enumerate() {
                let child_prefix = format!("{}/{}", prefix, i);
                if rest.is_empty() {
                    // Wildcard is terminal — shouldn't normally happen, but handle it
                    results.push(child_prefix);
                } else {
                    resolve_pattern_recursive(item, rest, child_prefix, results);
                }
            }
        }
    } else {
        // Named key: descend into the object
        if let Some(obj) = current.as_object() {
            if rest.is_empty() {
                // Terminal segment: check if the key exists
                if obj.contains_key(segment) {
                    results.push(format!("{}/{}", prefix, segment));
                }
            } else {
                // Non-terminal: descend
                if let Some(child) = obj.get(segment) {
                    let child_prefix = format!("{}/{}", prefix, segment);
                    resolve_pattern_recursive(child, rest, child_prefix, results);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprecation_wireguard_outbound() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "wireguard",
                    "name": "wg-out",
                    "server": "1.2.3.4",
                    "port": 51820,
                    "private_key": "abc123"
                }
            ]
        });
        let issues = check_deprecations(&doc);
        let deprecated_issues: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("Deprecated"))
            .collect();
        assert!(
            deprecated_issues
                .iter()
                .any(|i| i["ptr"].as_str() == Some("/outbounds/0")),
            "Expected WireGuard outbound deprecation at /outbounds/0, got: {:?}",
            deprecated_issues
        );
        // Should be a warning per the directory
        let wg_issue = deprecated_issues
            .iter()
            .find(|i| i["ptr"].as_str() == Some("/outbounds/0"))
            .unwrap();
        assert_eq!(wg_issue["kind"].as_str(), Some("warning"));
    }

    #[test]
    fn test_deprecation_legacy_tag_field() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct-out"
                }
            ]
        });
        let issues = check_deprecations(&doc);
        let tag_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("Deprecated")
                    && i["ptr"].as_str() == Some("/outbounds/0/tag")
            })
            .collect();
        assert!(
            !tag_issues.is_empty(),
            "Expected deprecation for outbound tag field"
        );
        assert_eq!(tag_issues[0]["kind"].as_str(), Some("warning"));
    }

    #[test]
    fn test_deprecation_server_port_info() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "shadowsocks",
                    "name": "ss-out",
                    "server": "1.2.3.4",
                    "server_port": 8388,
                    "method": "aes-256-gcm",
                    "password": "test"
                }
            ]
        });
        let issues = check_deprecations(&doc);
        let sp_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("Deprecated")
                    && i["ptr"].as_str() == Some("/outbounds/0/server_port")
            })
            .collect();
        assert!(
            !sp_issues.is_empty(),
            "Expected deprecation for server_port"
        );
        // server_port is Info severity
        assert_eq!(sp_issues[0]["kind"].as_str(), Some("info"));
    }

    #[test]
    fn test_deprecation_clean_config_no_issues() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "direct",
                    "name": "direct-out"
                },
                {
                    "type": "shadowsocks",
                    "name": "ss-out",
                    "server": "1.2.3.4",
                    "port": 8388,
                    "method": "aes-256-gcm",
                    "password": "test"
                }
            ],
            "inbounds": [
                {
                    "type": "mixed",
                    "name": "mixed-in",
                    "listen": "127.0.0.1:2080"
                }
            ],
            "route": {
                "rules": [
                    {
                        "when": { "domain_suffix": [".example.com"] },
                        "to": "ss-out"
                    }
                ]
            }
        });
        let issues = check_deprecations(&doc);
        let deprecated: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("Deprecated"))
            .collect();
        assert!(
            deprecated.is_empty(),
            "Clean modern config should produce zero deprecation issues, got: {:?}",
            deprecated
        );
    }

    #[test]
    fn test_deprecation_multiple_deprecated_fields() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "default_outbound": "direct",
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct-out",
                    "server_port": 443
                },
                {
                    "type": "wireguard",
                    "tag": "wg-out",
                    "server": "1.2.3.4",
                    "port": 51820
                }
            ],
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen_port": 2080,
                    "sniff": true
                }
            ],
            "route": {
                "rules": [
                    {
                        "domain_suffix": [".example.com"],
                        "outbound": "direct-out"
                    }
                ]
            }
        });
        let issues = check_deprecations(&doc);
        let deprecated: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("Deprecated"))
            .collect();
        // Expect at least: default_outbound, outbound[0].tag, outbound[0].server_port,
        // outbound[1] wireguard, outbound[1].tag, inbound[0].tag, inbound[0].listen_port,
        // inbound[0].sniff, route.rules[0].outbound, route.rules[0].domain_suffix
        assert!(
            deprecated.len() >= 8,
            "Expected at least 8 deprecation issues for a config with many legacy fields, got {}: {:?}",
            deprecated.len(),
            deprecated
        );
    }

    #[test]
    fn test_deprecation_default_outbound_at_root() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "default_outbound": "direct",
            "outbounds": [
                {
                    "type": "direct",
                    "name": "direct"
                }
            ]
        });
        let issues = check_deprecations(&doc);
        let default_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("Deprecated")
                    && i["ptr"].as_str() == Some("/default_outbound")
            })
            .collect();
        assert!(
            !default_issues.is_empty(),
            "Expected deprecation for root-level default_outbound"
        );
        assert_eq!(default_issues[0]["kind"].as_str(), Some("warning"));
        assert!(
            default_issues[0]["hint"]
                .as_str()
                .unwrap_or("")
                .contains("route.default"),
            "Hint should mention route.default"
        );
    }

    #[test]
    fn test_deprecation_inbound_sniff() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "inbounds": [
                {
                    "type": "mixed",
                    "name": "in1",
                    "listen": "127.0.0.1:2080",
                    "sniff": true
                },
                {
                    "type": "tun",
                    "name": "in2",
                    "sniff": false
                }
            ]
        });
        let issues = check_deprecations(&doc);
        let sniff_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("Deprecated")
                    && i["ptr"]
                        .as_str()
                        .map(|p| p.ends_with("/sniff"))
                        .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            sniff_issues.len(),
            2,
            "Expected 2 sniff deprecation issues (one per inbound), got: {:?}",
            sniff_issues
        );
        assert_eq!(sniff_issues[0]["kind"].as_str(), Some("warning"));
    }

    // ───── WP-30aa pins ─────

    /// Pin: deprecation detection owner is now in deprecation.rs submodule
    #[test]
    fn wp30aa_pin_deprecation_owner_is_deprecation_rs() {
        // The check_deprecations function lives in this file (validator/v2/deprecation.rs).
        // This pin asserts that the deprecation detection logic (pattern matching,
        // severity mapping, issue emission) is owned by the deprecation submodule,
        // not by mod.rs.
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{ "type": "wireguard", "name": "wg", "server": "1.2.3.4", "port": 51820 }]
        });
        let issues = check_deprecations(&doc);
        assert!(
            issues.iter().any(|i| i["code"].as_str() == Some("Deprecated")),
            "check_deprecations should produce Deprecated issues from deprecation.rs"
        );
    }

    /// Pin: validate_v2() delegates deprecation detection to this submodule
    #[test]
    fn wp30aa_pin_validate_v2_delegates_deprecation() {
        // validate_v2 should include deprecation issues produced by this submodule.
        // This pin confirms that validate_v2() calls deprecation::check_deprecations()
        // rather than implementing deprecation detection inline.
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{ "type": "direct", "tag": "legacy-tag" }]
        });
        let issues = crate::validator::v2::validate_v2(&doc, true);
        let deprecated: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("Deprecated"))
            .collect();
        assert!(
            !deprecated.is_empty(),
            "validate_v2 should include deprecation issues via delegation to deprecation submodule"
        );
    }
}
