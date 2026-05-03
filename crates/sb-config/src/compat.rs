use serde_json::Value;

// Legacy compatibility layer removed - model::Config is deprecated
// All v1→v2 migration now happens through migrate_to_v2() using serde_json::Value

/// Action taken during migration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum MigrationAction {
    /// Field was renamed
    Renamed,
    /// Field was moved to a different section
    Moved,
    /// Value was normalized (e.g., socks5 → socks)
    Normalized,
    /// Fields were wrapped into a new container
    Wrapped,
}

/// A single migration diagnostic, documenting what was changed and why.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MigrationDiagnostic {
    /// JSON pointer to the source field
    pub from_path: String,
    /// JSON pointer to the destination field
    pub to_path: String,
    /// Type of action performed
    pub action: MigrationAction,
    /// Human-readable description
    pub detail: String,
}

/// V1 condition fields that get wrapped into the V2 `when` object.
/// 会被包装进 V2 `when` 对象的 V1 条件字段。
const V1_CONDITION_FIELDS: &[&str] = &[
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "geosite",
    "geoip",
    "ip_cidr",
    "port",
    "network",
    "protocol",
    "process",
];

/// Migrate legacy config (v1-style) into v2 canonical layout.
/// 将旧版配置 (v1 风格) 迁移到 v2 规范布局。
///
/// Transformations applied / 应用的转换:
/// - Moves root `rules` → `route.rules` / 移动根 `rules` 到 `route.rules`
/// - Renames `default_outbound` → `route.default` / 重命名 `default_outbound` 到 `route.default`
/// - Normalizes outbound type `socks5` → `socks` / 归一化出站类型 `socks5` 到 `socks`
/// - Renames inbound/outbound `tag` → `name` / 重命名入站/出站 `tag` 到 `name`
/// - Merges inbound `listen` + `listen_port` → `listen: "IP:PORT"` / 合并入站 `listen` + `listen_port` 到 `listen: "IP:PORT"`
/// - Renames route rule `outbound` → `to` / 重命名路由规则 `outbound` 到 `to`
/// - Wraps rule conditions in `when` object / 将规则条件包装在 `when` 对象中
/// - Injects `schema_version: 2` / 注入 `schema_version: 2`
///
/// # Panics
/// Does not panic; silently skips malformed fields.
/// 不会 panic；静默跳过格式错误的字段。
#[must_use]
pub fn migrate_to_v2(raw: &Value) -> (Value, Vec<MigrationDiagnostic>) {
    let mut diags = Vec::new();
    let mut v = raw.clone();
    let obj = match v {
        Value::Object(ref mut m) => m,
        _ => return (v, diags),
    };
    // schema_version - force override to ensure v2
    obj.insert("schema_version".to_string(), Value::from(2));

    // Migrate inbounds: tag->name, listen+listen_port->listen
    if let Some(inbounds) = obj.get_mut("inbounds").and_then(|x| x.as_array_mut()) {
        for (idx, inbound) in inbounds.iter_mut().enumerate() {
            if let Some(inb_obj) = inbound.as_object_mut() {
                // tag -> name
                if let Some(tag) = inb_obj.remove("tag") {
                    diags.push(MigrationDiagnostic {
                        from_path: format!("/inbounds/{idx}/tag"),
                        to_path: format!("/inbounds/{idx}/name"),
                        action: MigrationAction::Renamed,
                        detail: "inbound tag renamed to name".to_string(),
                    });
                    inb_obj.insert("name".to_string(), tag);
                }
                // listen + listen_port -> listen: "IP:PORT"
                // Ensure port is within valid range (0-65535)
                if let Some(port) = inb_obj.remove("listen_port") {
                    if let Some(listen) = inb_obj.get("listen") {
                        if let (Some(listen_str), Some(port_num)) = (listen.as_str(), port.as_u64())
                        {
                            if port_num <= u64::from(u16::MAX) {
                                diags.push(MigrationDiagnostic {
                                    from_path: format!("/inbounds/{idx}/listen_port"),
                                    to_path: format!("/inbounds/{idx}/listen"),
                                    action: MigrationAction::Moved,
                                    detail: format!(
                                        "listen_port {port_num} merged into listen address"
                                    ),
                                });
                                inb_obj.insert(
                                    "listen".to_string(),
                                    Value::from(format!("{listen_str}:{port_num}")),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Migrate outbounds: tag->name, socks5->socks
    if let Some(outbounds) = obj.get_mut("outbounds").and_then(|x| x.as_array_mut()) {
        for (idx, outbound) in outbounds.iter_mut().enumerate() {
            if let Some(ob_obj) = outbound.as_object_mut() {
                // tag -> name
                if let Some(tag) = ob_obj.remove("tag") {
                    diags.push(MigrationDiagnostic {
                        from_path: format!("/outbounds/{idx}/tag"),
                        to_path: format!("/outbounds/{idx}/name"),
                        action: MigrationAction::Renamed,
                        detail: "outbound tag renamed to name".to_string(),
                    });
                    ob_obj.insert("name".to_string(), tag);
                }
                // server_port -> port
                if let Some(server_port) = ob_obj.remove("server_port") {
                    diags.push(MigrationDiagnostic {
                        from_path: format!("/outbounds/{idx}/server_port"),
                        to_path: format!("/outbounds/{idx}/port"),
                        action: MigrationAction::Renamed,
                        detail: "server_port renamed to port".to_string(),
                    });
                    ob_obj.insert("port".to_string(), server_port);
                }
                // Normalize type: socks5 -> socks
                if let Some(ty) = ob_obj.get_mut("type") {
                    if ty == "socks5" {
                        diags.push(MigrationDiagnostic {
                            from_path: format!("/outbounds/{idx}/type"),
                            to_path: format!("/outbounds/{idx}/type"),
                            action: MigrationAction::Normalized,
                            detail: "outbound type socks5 normalized to socks".to_string(),
                        });
                        *ty = Value::from("socks");
                    }
                }
            }
        }
    }

    // Move rules/default into route
    if obj.get("route").is_none() {
        obj.insert("route".to_string(), Value::Object(serde_json::Map::new()));
    }

    // Extract rules and default_outbound before getting mutable reference to route
    let rules_to_move = obj.remove("rules");
    let default_to_move = obj.remove("default_outbound");

    if let Some(route) = obj.get_mut("route").and_then(|x| x.as_object_mut()) {
        if let Some(rules) = rules_to_move {
            diags.push(MigrationDiagnostic {
                from_path: "/rules".to_string(),
                to_path: "/route/rules".to_string(),
                action: MigrationAction::Moved,
                detail: "root-level rules moved to route.rules".to_string(),
            });
            route.entry("rules").or_insert(rules);
        }
        if let Some(def) = default_to_move {
            diags.push(MigrationDiagnostic {
                from_path: "/default_outbound".to_string(),
                to_path: "/route/default".to_string(),
                action: MigrationAction::Moved,
                detail: "default_outbound moved to route.default".to_string(),
            });
            route.entry("default").or_insert(def);
        }

        // Migrate route rules: V1 flat style -> V2 when/to style
        if let Some(rules) = route.get_mut("rules").and_then(|x| x.as_array_mut()) {
            for (rule_idx, rule) in rules.iter_mut().enumerate() {
                if let Some(rule_obj) = rule.as_object_mut() {
                    // If rule has 'outbound' field, it's V1 style - convert to V2
                    if let Some(outbound) = rule_obj.remove("outbound") {
                        diags.push(MigrationDiagnostic {
                            from_path: format!("/route/rules/{rule_idx}/outbound"),
                            to_path: format!("/route/rules/{rule_idx}/to"),
                            action: MigrationAction::Renamed,
                            detail: "rule outbound renamed to to".to_string(),
                        });
                        rule_obj.insert("to".to_string(), outbound);
                    }

                    // Wrap V1 condition fields in 'when' object
                    let mut when_obj = serde_json::Map::new();
                    let mut has_conditions = false;
                    let mut wrapped_fields = Vec::new();

                    for field in V1_CONDITION_FIELDS {
                        if let Some(value) = rule_obj.get(*field) {
                            // For V2 'when' object, use singular string values if array has one element
                            if let Some(arr) = value.as_array() {
                                if arr.len() == 1 {
                                    // Map field names: domain_suffix -> suffix, domain_keyword -> keyword, etc.
                                    let v2_field = field.strip_prefix("domain_").unwrap_or(field);
                                    when_obj.insert(v2_field.to_string(), arr[0].clone());
                                    has_conditions = true;
                                    wrapped_fields.push(*field);
                                }
                            }
                        }
                    }

                    if has_conditions && !rule_obj.contains_key("when") {
                        diags.push(MigrationDiagnostic {
                            from_path: format!("/route/rules/{rule_idx}"),
                            to_path: format!("/route/rules/{rule_idx}/when"),
                            action: MigrationAction::Wrapped,
                            detail: format!(
                                "flat conditions [{}] wrapped into when object",
                                wrapped_fields.join(", ")
                            ),
                        });
                        rule_obj.insert("when".to_string(), Value::Object(when_obj));
                    }
                }
            }
        }
    }

    (v, diags)
}

/// Migrate a WireGuard outbound configuration to the equivalent endpoint configuration.
/// Returns `None` if the input is not a WireGuard outbound.
///
/// Field mapping:
/// - `server` → `peers[0].address`
/// - `port` / `server_port` → `peers[0].port`
/// - `public_key` → `peers[0].public_key`
/// - `pre_shared_key` → `peers[0].pre_shared_key`
/// - `allowed_ips` → `peers[0].allowed_ips`
/// - `reserved` → `peers[0].reserved`
/// - `private_key`, `mtu`, `local_address` → copied directly
/// - `name` / `tag` → `name`
#[must_use]
pub fn migrate_wireguard_outbound_to_endpoint(raw: &Value) -> Option<Value> {
    let obj = raw.as_object()?;

    // Must be a WireGuard outbound
    let ty = obj.get("type").and_then(|v| v.as_str())?;
    if ty != "wireguard" {
        return None;
    }

    let mut endpoint = serde_json::Map::new();
    endpoint.insert("type".to_string(), Value::from("wireguard"));

    // Copy name/tag
    if let Some(name) = obj.get("name").or_else(|| obj.get("tag")) {
        endpoint.insert("name".to_string(), name.clone());
    }

    // Build peer object from outbound fields
    let mut peer = serde_json::Map::new();

    // server/port -> peer address/port
    if let Some(server) = obj.get("server") {
        peer.insert("address".to_string(), server.clone());
    }
    if let Some(port) = obj.get("port").or_else(|| obj.get("server_port")) {
        peer.insert("port".to_string(), port.clone());
    }

    // public_key -> peer public_key
    if let Some(pk) = obj.get("public_key") {
        peer.insert("public_key".to_string(), pk.clone());
    }

    // pre_shared_key -> peer pre_shared_key
    if let Some(psk) = obj.get("pre_shared_key") {
        peer.insert("pre_shared_key".to_string(), psk.clone());
    }

    // allowed_ips -> peer allowed_ips
    if let Some(allowed) = obj.get("allowed_ips") {
        peer.insert("allowed_ips".to_string(), allowed.clone());
    }

    // reserved -> peer reserved
    if let Some(reserved) = obj.get("reserved") {
        peer.insert("reserved".to_string(), reserved.clone());
    }

    if !peer.is_empty() {
        endpoint.insert("peers".to_string(), Value::Array(vec![Value::Object(peer)]));
    }

    // private_key -> endpoint private_key
    if let Some(pk) = obj.get("private_key") {
        endpoint.insert("private_key".to_string(), pk.clone());
    }

    // mtu -> endpoint mtu
    if let Some(mtu) = obj.get("mtu") {
        endpoint.insert("mtu".to_string(), mtu.clone());
    }

    // local_address -> endpoint local_address
    if let Some(local) = obj.get("local_address") {
        endpoint.insert("local_address".to_string(), local.clone());
    }

    Some(Value::Object(endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── L12.1.4: MigrationDiagnostic tests ──────────────────────────────

    #[test]
    fn migrate_v2_diag_tag_renamed() {
        let input = json!({
            "inbounds": [{"tag": "in0", "type": "mixed"}],
            "outbounds": [{"tag": "out0", "type": "direct"}]
        });
        let (migrated, diags) = migrate_to_v2(&input);

        // Verify value changes
        assert_eq!(migrated.pointer("/inbounds/0/name"), Some(&json!("in0")));
        assert!(migrated.pointer("/inbounds/0/tag").is_none());
        assert_eq!(migrated.pointer("/outbounds/0/name"), Some(&json!("out0")));

        // Verify diagnostics
        let rename_diags: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.action == MigrationAction::Renamed && d.detail.contains("tag renamed to name")
            })
            .collect();
        assert!(
            rename_diags.len() >= 2,
            "expected at least 2 tag->name rename diagnostics, got {}: {:?}",
            rename_diags.len(),
            rename_diags
        );
    }

    /// Regression (LC-003 fix-managed-ssm-server-tag): the production loader
    /// chain `compat::migrate_to_v2` → `validator::v2::to_ir_v1` must preserve
    /// the user-configured inbound tag, even though migration renames the
    /// JSON field `tag` → `name`. Without this, every inbound IR.tag is None
    /// in production, which silently breaks ssmapi tag lookup, route detour,
    /// and any other consumer that relies on the inbound tag.
    #[test]
    fn migrate_then_lower_preserves_inbound_tag() {
        let raw = json!({
            "inbounds": [{
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1:18908",
                "method": "aes-256-gcm",
                "password": "x"
            }]
        });
        let (migrated, _diags) = migrate_to_v2(&raw);
        assert!(
            migrated.pointer("/inbounds/0/tag").is_none(),
            "migrate_to_v2 must remove inbound 'tag' (verified by sibling test)"
        );
        assert_eq!(
            migrated.pointer("/inbounds/0/name"),
            Some(&json!("ss-in")),
            "migrate_to_v2 must rename inbound tag to name"
        );

        let ir = crate::validator::v2::to_ir_v1(&migrated);
        let inbound = ir.inbounds.first().expect("inbound lowered");
        assert_eq!(
            inbound.tag.as_deref(),
            Some("ss-in"),
            "post-migration to_ir_v1 must populate IR.tag from the renamed 'name' field"
        );
    }

    #[test]
    fn migrate_v2_diag_socks5_normalized() {
        let input = json!({
            "outbounds": [{"type": "socks5", "tag": "proxy"}]
        });
        let (migrated, diags) = migrate_to_v2(&input);

        assert_eq!(migrated.pointer("/outbounds/0/type"), Some(&json!("socks")));

        let norm_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.action == MigrationAction::Normalized)
            .collect();
        assert_eq!(
            norm_diags.len(),
            1,
            "expected exactly 1 Normalized diagnostic"
        );
        assert!(norm_diags[0].detail.contains("socks5"));
        assert!(norm_diags[0].detail.contains("socks"));
    }

    #[test]
    fn migrate_v2_diag_server_port_renamed() {
        let input = json!({
            "outbounds": [{"type": "vmess", "tag": "v", "server_port": 443}]
        });
        let (migrated, diags) = migrate_to_v2(&input);

        assert_eq!(migrated.pointer("/outbounds/0/port"), Some(&json!(443)));
        assert!(migrated.pointer("/outbounds/0/server_port").is_none());

        let sp_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.detail.contains("server_port"))
            .collect();
        assert_eq!(sp_diags.len(), 1);
        assert_eq!(sp_diags[0].action, MigrationAction::Renamed);
    }

    #[test]
    fn migrate_v2_diag_rules_moved_and_outbound_renamed() {
        let input = json!({
            "rules": [
                {"domain_suffix": [".example.com"], "outbound": "direct"}
            ],
            "default_outbound": "proxy"
        });
        let (migrated, diags) = migrate_to_v2(&input);

        // rules should be under route
        assert!(migrated.pointer("/route/rules").is_some());
        assert!(migrated.get("rules").is_none());
        // default_outbound -> route.default
        assert_eq!(migrated.pointer("/route/default"), Some(&json!("proxy")));

        // Check Moved diagnostics
        let moved: Vec<_> = diags
            .iter()
            .filter(|d| d.action == MigrationAction::Moved)
            .collect();
        assert!(
            moved.len() >= 2,
            "expected at least 2 Moved diagnostics (rules + default_outbound)"
        );

        // Check Renamed (outbound -> to)
        let outbound_to: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.action == MigrationAction::Renamed && d.detail.contains("outbound renamed to to")
            })
            .collect();
        assert_eq!(outbound_to.len(), 1);

        // Check Wrapped (conditions -> when)
        let wrapped: Vec<_> = diags
            .iter()
            .filter(|d| d.action == MigrationAction::Wrapped)
            .collect();
        assert_eq!(wrapped.len(), 1);
        assert!(wrapped[0].detail.contains("domain_suffix"));
    }

    #[test]
    fn migrate_v2_diag_listen_port_merged() {
        let input = json!({
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 1080}]
        });
        let (migrated, diags) = migrate_to_v2(&input);

        assert_eq!(
            migrated.pointer("/inbounds/0/listen"),
            Some(&json!("0.0.0.0:1080"))
        );

        let merge_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.action == MigrationAction::Moved && d.detail.contains("listen_port"))
            .collect();
        assert_eq!(merge_diags.len(), 1);
    }

    #[test]
    fn migrate_v2_no_diags_for_already_v2() {
        let input = json!({
            "schema_version": 2,
            "inbounds": [{"type": "mixed", "name": "in0", "listen": "0.0.0.0:1080"}],
            "outbounds": [{"type": "direct", "name": "direct"}],
            "route": {
                "rules": [{"to": "direct", "when": {"suffix": ".local"}}]
            }
        });
        let (_migrated, diags) = migrate_to_v2(&input);
        assert!(
            diags.is_empty(),
            "already-v2 config should produce no diagnostics, got: {:?}",
            diags
        );
    }

    // ── L12.2.1: WireGuard outbound → endpoint migration tests ──────────

    #[test]
    fn wireguard_full_outbound_to_endpoint() {
        let input = json!({
            "type": "wireguard",
            "name": "wg0",
            "server": "1.2.3.4",
            "port": 51820,
            "private_key": "aaaa",
            "public_key": "bbbb",
            "pre_shared_key": "cccc",
            "allowed_ips": ["0.0.0.0/0"],
            "reserved": [0, 0, 0],
            "mtu": 1280,
            "local_address": ["10.0.0.2/32"]
        });
        let result = migrate_wireguard_outbound_to_endpoint(&input).unwrap();

        assert_eq!(result.get("type"), Some(&json!("wireguard")));
        assert_eq!(result.get("name"), Some(&json!("wg0")));
        assert_eq!(result.get("private_key"), Some(&json!("aaaa")));
        assert_eq!(result.get("mtu"), Some(&json!(1280)));
        assert_eq!(result.get("local_address"), Some(&json!(["10.0.0.2/32"])));

        // Peer verification
        let peers = result.get("peers").unwrap().as_array().unwrap();
        assert_eq!(peers.len(), 1);
        let peer = &peers[0];
        assert_eq!(peer.get("address"), Some(&json!("1.2.3.4")));
        assert_eq!(peer.get("port"), Some(&json!(51820)));
        assert_eq!(peer.get("public_key"), Some(&json!("bbbb")));
        assert_eq!(peer.get("pre_shared_key"), Some(&json!("cccc")));
        assert_eq!(peer.get("allowed_ips"), Some(&json!(["0.0.0.0/0"])));
        assert_eq!(peer.get("reserved"), Some(&json!([0, 0, 0])));
    }

    #[test]
    fn wireguard_non_wg_returns_none() {
        let input = json!({"type": "vmess", "tag": "proxy"});
        assert!(migrate_wireguard_outbound_to_endpoint(&input).is_none());

        let input2 = json!({"name": "no-type"});
        assert!(migrate_wireguard_outbound_to_endpoint(&input2).is_none());

        let input3 = json!("not an object");
        assert!(migrate_wireguard_outbound_to_endpoint(&input3).is_none());
    }

    #[test]
    fn wireguard_tag_fallback_to_name() {
        let input = json!({
            "type": "wireguard",
            "tag": "wg-legacy",
            "server": "5.6.7.8",
            "server_port": 9999,
            "public_key": "pk1"
        });
        let result = migrate_wireguard_outbound_to_endpoint(&input).unwrap();

        // tag should map to name (tag is the fallback when name is absent)
        assert_eq!(result.get("name"), Some(&json!("wg-legacy")));

        // server_port should be used as port fallback
        let peers = result.get("peers").unwrap().as_array().unwrap();
        assert_eq!(peers[0].get("port"), Some(&json!(9999)));
        assert_eq!(peers[0].get("address"), Some(&json!("5.6.7.8")));
    }

    #[test]
    fn wireguard_minimal_config() {
        let input = json!({
            "type": "wireguard",
            "private_key": "key123"
        });
        let result = migrate_wireguard_outbound_to_endpoint(&input).unwrap();

        assert_eq!(result.get("type"), Some(&json!("wireguard")));
        assert_eq!(result.get("private_key"), Some(&json!("key123")));
        // No name, no peers (no server/public_key)
        assert!(result.get("name").is_none());
        assert!(result.get("peers").is_none());
    }
}
