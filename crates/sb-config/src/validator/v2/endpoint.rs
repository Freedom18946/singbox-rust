use crate::ir::{ConfigIR, EndpointIR, EndpointType, WireGuardPeerIR};
use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, extract_string_list};

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

/// Lower `/endpoints` from raw JSON into `ConfigIR.endpoints`.
///
/// Converts each endpoint entry into `EndpointIR`, including:
/// - `type` → `EndpointType` mapping (wireguard / tailscale)
/// - `peers[*]` → `WireGuardPeerIR`
/// - All top-level wireguard and tailscale fields
pub(crate) fn lower_endpoints(doc: &Value, ir: &mut ConfigIR) {
    let Some(eps) = doc.get("endpoints").and_then(|v| v.as_array()) else {
        return;
    };

    for e in eps {
        let ty = match e
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("wireguard")
        {
            "wireguard" => EndpointType::Wireguard,
            "tailscale" => EndpointType::Tailscale,
            _ => EndpointType::Wireguard,
        };

        let peers = e.get("peers").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .map(|p| WireGuardPeerIR {
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

        ir.endpoints.push(EndpointIR {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_endpoints(doc, allow_unknown, &mut issues);
        issues
    }

    fn run_lower(doc: &Value) -> ConfigIR {
        let mut ir = ConfigIR::default();
        lower_endpoints(doc, &mut ir);
        ir
    }

    // ── Validation tests (pre-existing) ──

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

    #[test]
    fn no_endpoints_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no endpoint issues when endpoints is absent"
        );
    }

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

    // ── Lowering tests (WP-30v) ──

    #[test]
    fn type_mapping_wireguard() {
        let doc = json!({"endpoints": [{"type": "wireguard", "tag": "wg0"}]});
        let ir = run_lower(&doc);
        assert_eq!(ir.endpoints.len(), 1);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Wireguard));
        assert_eq!(ir.endpoints[0].tag.as_deref(), Some("wg0"));
    }

    #[test]
    fn type_mapping_tailscale() {
        let doc = json!({"endpoints": [{"type": "tailscale", "tag": "ts0"}]});
        let ir = run_lower(&doc);
        assert_eq!(ir.endpoints.len(), 1);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Tailscale));
    }

    #[test]
    fn type_mapping_default_is_wireguard() {
        let doc = json!({"endpoints": [{"tag": "no-type"}]});
        let ir = run_lower(&doc);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Wireguard));
    }

    #[test]
    fn type_mapping_unknown_falls_back_to_wireguard() {
        let doc = json!({"endpoints": [{"type": "unknown_protocol"}]});
        let ir = run_lower(&doc);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Wireguard));
    }

    #[test]
    fn wireguard_top_level_fields() {
        let doc = json!({"endpoints": [{
            "type": "wireguard",
            "tag": "wg0",
            "network": ["tcp", "udp"],
            "system_interface": true,
            "interface_name": "wg0",
            "mtu": 1420,
            "address": ["10.0.0.1/32"],
            "private_key": "abc123",
            "listen_port": 51820,
            "udp_timeout": "5m",
            "workers": 4
        }]});
        let ir = run_lower(&doc);
        let ep = &ir.endpoints[0];
        assert_eq!(ep.tag.as_deref(), Some("wg0"));
        assert_eq!(ep.network.as_ref().unwrap(), &vec!["tcp".to_string(), "udp".to_string()]);
        assert_eq!(ep.wireguard_system, Some(true));
        assert_eq!(ep.wireguard_name.as_deref(), Some("wg0"));
        assert_eq!(ep.wireguard_mtu, Some(1420));
        assert_eq!(ep.wireguard_address.as_ref().unwrap(), &vec!["10.0.0.1/32".to_string()]);
        assert_eq!(ep.wireguard_private_key.as_deref(), Some("abc123"));
        assert_eq!(ep.wireguard_listen_port, Some(51820));
        assert_eq!(ep.wireguard_udp_timeout.as_deref(), Some("5m"));
        assert_eq!(ep.wireguard_workers, Some(4));
    }

    #[test]
    fn tailscale_top_level_fields() {
        let doc = json!({"endpoints": [{
            "type": "tailscale",
            "tag": "ts0",
            "state_directory": "/var/lib/tailscale",
            "auth_key": "tskey-xxx",
            "control_url": "https://controlplane.tailscale.com",
            "ephemeral": true,
            "hostname": "my-node",
            "accept_routes": true,
            "exit_node": "100.64.0.1",
            "exit_node_allow_lan_access": false,
            "advertise_routes": ["192.168.1.0/24", "10.0.0.0/8"],
            "advertise_exit_node": true,
            "udp_timeout": "3m"
        }]});
        let ir = run_lower(&doc);
        let ep = &ir.endpoints[0];
        assert!(matches!(ep.ty, EndpointType::Tailscale));
        assert_eq!(ep.tailscale_state_directory.as_deref(), Some("/var/lib/tailscale"));
        assert_eq!(ep.tailscale_auth_key.as_deref(), Some("tskey-xxx"));
        assert_eq!(ep.tailscale_control_url.as_deref(), Some("https://controlplane.tailscale.com"));
        assert_eq!(ep.tailscale_ephemeral, Some(true));
        assert_eq!(ep.tailscale_hostname.as_deref(), Some("my-node"));
        assert_eq!(ep.tailscale_accept_routes, Some(true));
        assert_eq!(ep.tailscale_exit_node.as_deref(), Some("100.64.0.1"));
        assert_eq!(ep.tailscale_exit_node_allow_lan_access, Some(false));
        assert_eq!(
            ep.tailscale_advertise_routes.as_ref().unwrap(),
            &vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()]
        );
        assert_eq!(ep.tailscale_advertise_exit_node, Some(true));
        assert_eq!(ep.tailscale_udp_timeout.as_deref(), Some("3m"));
    }

    #[test]
    fn peers_lowering() {
        let doc = json!({"endpoints": [{
            "type": "wireguard",
            "peers": [
                {
                    "address": "1.2.3.4",
                    "port": 51820,
                    "public_key": "pubkey1",
                    "pre_shared_key": "psk1",
                    "allowed_ips": ["0.0.0.0/0"],
                    "persistent_keepalive_interval": 25,
                    "reserved": [1, 2, 3]
                },
                {
                    "address": "5.6.7.8",
                    "public_key": "pubkey2"
                }
            ]
        }]});
        let ir = run_lower(&doc);
        let peers = ir.endpoints[0].wireguard_peers.as_ref().unwrap();
        assert_eq!(peers.len(), 2);

        let p0 = &peers[0];
        assert_eq!(p0.address.as_deref(), Some("1.2.3.4"));
        assert_eq!(p0.port, Some(51820));
        assert_eq!(p0.public_key.as_deref(), Some("pubkey1"));
        assert_eq!(p0.pre_shared_key.as_deref(), Some("psk1"));
        assert_eq!(p0.allowed_ips.as_ref().unwrap(), &vec!["0.0.0.0/0".to_string()]);
        assert_eq!(p0.persistent_keepalive_interval, Some(25));
        assert_eq!(p0.reserved.as_ref().unwrap(), &vec![1u8, 2, 3]);

        let p1 = &peers[1];
        assert_eq!(p1.address.as_deref(), Some("5.6.7.8"));
        assert_eq!(p1.public_key.as_deref(), Some("pubkey2"));
        assert!(p1.pre_shared_key.is_none());
        assert!(p1.allowed_ips.is_none());
        assert!(p1.persistent_keepalive_interval.is_none());
        assert!(p1.reserved.is_none());
    }

    #[test]
    fn empty_peers_array() {
        let doc = json!({"endpoints": [{"type": "wireguard", "peers": []}]});
        let ir = run_lower(&doc);
        let peers = ir.endpoints[0].wireguard_peers.as_ref().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn no_peers_key() {
        let doc = json!({"endpoints": [{"type": "wireguard"}]});
        let ir = run_lower(&doc);
        assert!(ir.endpoints[0].wireguard_peers.is_none());
    }

    #[test]
    fn no_endpoints_no_lowering() {
        let doc = json!({"outbounds": []});
        let ir = run_lower(&doc);
        assert!(ir.endpoints.is_empty());
    }

    #[test]
    fn network_listable_string() {
        let doc = json!({"endpoints": [{"network": ["tcp"]}]});
        let ir = run_lower(&doc);
        assert_eq!(ir.endpoints[0].network.as_ref().unwrap(), &vec!["tcp".to_string()]);
    }

    #[test]
    fn advertise_routes_listable_string() {
        let doc = json!({"endpoints": [{
            "type": "tailscale",
            "advertise_routes": ["10.0.0.0/8", "172.16.0.0/12"]
        }]});
        let ir = run_lower(&doc);
        assert_eq!(
            ir.endpoints[0].tailscale_advertise_routes.as_ref().unwrap(),
            &vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]
        );
    }

    #[test]
    fn multiple_endpoints() {
        let doc = json!({"endpoints": [
            {"type": "wireguard", "tag": "wg0"},
            {"type": "tailscale", "tag": "ts0"},
            {"tag": "wg1"}
        ]});
        let ir = run_lower(&doc);
        assert_eq!(ir.endpoints.len(), 3);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Wireguard));
        assert!(matches!(ir.endpoints[1].ty, EndpointType::Tailscale));
        assert!(matches!(ir.endpoints[2].ty, EndpointType::Wireguard));
    }

    // ── Pins (WP-30v) ──

    #[test]
    fn wp30v_pin_endpoint_lowering_owner_is_endpoint_rs() {
        // Pin: endpoint lowering owner is in validator/v2/endpoint.rs,
        // not in validator/v2/mod.rs. The lower_endpoints function is defined here.
        let doc = json!({"endpoints": [{"type": "wireguard", "tag": "wg-pin"}]});
        let ir = run_lower(&doc);
        assert_eq!(ir.endpoints.len(), 1);
        assert_eq!(ir.endpoints[0].tag.as_deref(), Some("wg-pin"));
    }

    #[test]
    fn wp30v_pin_mod_rs_to_ir_v1_delegates_endpoint() {
        // Pin: to_ir_v1() in mod.rs delegates endpoint lowering to endpoint::lower_endpoints().
        // This test calls to_ir_v1() and verifies endpoint lowering still works end-to-end.
        let doc = json!({"endpoints": [{
            "type": "tailscale",
            "tag": "ts-delegate",
            "hostname": "test-host"
        }]});
        let ir = crate::validator::v2::to_ir_v1(&doc);
        assert_eq!(ir.endpoints.len(), 1);
        assert!(matches!(ir.endpoints[0].ty, EndpointType::Tailscale));
        assert_eq!(ir.endpoints[0].tag.as_deref(), Some("ts-delegate"));
        assert_eq!(ir.endpoints[0].tailscale_hostname.as_deref(), Some("test-host"));
    }
}
