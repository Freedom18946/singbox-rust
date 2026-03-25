use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::emit_issue;

fn allowed_endpoint_keys() -> HashSet<String> {
    [
        "type",
        "tag",
        "network",
        "system_interface",
        "interface_name",
        "mtu",
        "address",
        "private_key",
        "listen_port",
        "peers",
        "udp_timeout",
        "workers",
        "state_directory",
        "auth_key",
        "control_url",
        "ephemeral",
        "hostname",
        "accept_routes",
        "exit_node",
        "exit_node_allow_lan_access",
        "advertise_routes",
        "advertise_exit_node",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn allowed_endpoint_peer_keys() -> HashSet<String> {
    [
        "address",
        "port",
        "public_key",
        "pre_shared_key",
        "allowed_ips",
        "persistent_keepalive_interval",
        "reserved",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Validate `/endpoints` unknown fields.
///
/// 校验 `/endpoints` 数组及其嵌套 `/peers` 的未知字段。
pub(crate) fn validate_endpoints(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    let Some(endpoints) = doc.get("endpoints").and_then(|v| v.as_array()) else {
        return;
    };

    let allowed = allowed_endpoint_keys();
    for (i, endpoint) in endpoints.iter().enumerate() {
        if let Some(map) = endpoint.as_object() {
            for k in map.keys() {
                if !allowed.contains(k) {
                    let kind = if allow_unknown { "warning" } else { "error" };
                    issues.push(emit_issue(
                        kind,
                        IssueCode::UnknownField,
                        &format!("/endpoints/{}/{}", i, k),
                        "unknown field",
                        "remove it",
                    ));
                }
            }
            if let Some(peers) = map.get("peers").and_then(|v| v.as_array()) {
                let allowed_peers = allowed_endpoint_peer_keys();
                for (j, peer) in peers.iter().enumerate() {
                    if let Some(peer_map) = peer.as_object() {
                        for k in peer_map.keys() {
                            if !allowed_peers.contains(k) {
                                let kind = if allow_unknown { "warning" } else { "error" };
                                issues.push(emit_issue(
                                    kind,
                                    IssueCode::UnknownField,
                                    &format!("/endpoints/{}/peers/{}/{}", i, j, k),
                                    "unknown field",
                                    "remove it",
                                ));
                            }
                        }
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
        validate_endpoints(doc, allow_unknown, &mut issues);
        issues
    }

    // 1) /endpoints/0 unknown field, strict → error
    #[test]
    fn endpoint_unknown_field_strict() {
        let doc = json!({"endpoints": [{"unknown_endpoint_field": true}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/endpoints/0/unknown_endpoint_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    // 2) /endpoints/0 unknown field, allow_unknown → warning
    #[test]
    fn endpoint_unknown_field_allow_unknown() {
        let doc = json!({"endpoints": [{"unknown_endpoint_field": true}]});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/endpoints/0/unknown_endpoint_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    // 3) /endpoints/0/peers/0 unknown field, strict → error
    #[test]
    fn endpoint_peer_unknown_field_strict() {
        let doc = json!({"endpoints": [{"peers": [{"unknown_peer_field": true}]}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/endpoints/0/peers/0/unknown_peer_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    // 4) /endpoints/0/peers/0 unknown field, allow_unknown → warning
    #[test]
    fn endpoint_peer_unknown_field_allow_unknown() {
        let doc = json!({"endpoints": [{"peers": [{"unknown_peer_field": true}]}]});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/endpoints/0/peers/0/unknown_peer_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    // 5) no endpoints block → no issues
    #[test]
    fn no_endpoints_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no endpoint issues when endpoints is absent"
        );
    }

    // 6) ptr precision: verify exact ptr for endpoint and peer unknown fields
    #[test]
    fn ptr_precision_endpoint_and_peer() {
        let doc = json!({
            "endpoints": [
                {
                    "unknown_endpoint_field": true,
                    "peers": [
                        {"unknown_peer_field": 42}
                    ]
                }
            ]
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/endpoints/0/unknown_endpoint_field"),
            "missing ptr for endpoints/0 unknown field"
        );
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/endpoints/0/peers/0/unknown_peer_field"),
            "missing ptr for endpoints/0/peers/0 unknown field"
        );
    }
}
