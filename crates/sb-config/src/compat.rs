use serde_json::Value;

// Legacy compatibility layer removed - model::Config is deprecated
// All v1→v2 migration now happens through migrate_to_v2() using serde_json::Value

/// V1 condition fields that get wrapped into the V2 `when` object.
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
///
/// Transformations applied:
/// - Moves root `rules` → `route.rules`
/// - Renames `default_outbound` → `route.default`
/// - Normalizes outbound type `socks5` → `socks`
/// - Renames inbound/outbound `tag` → `name`
/// - Merges inbound `listen` + `listen_port` → `listen: "IP:PORT"`
/// - Renames route rule `outbound` → `to`
/// - Wraps rule conditions in `when` object
/// - Injects `schema_version: 2`
///
/// # Panics
/// Does not panic; silently skips malformed fields.
#[must_use]
pub fn migrate_to_v2(raw: &Value) -> Value {
    let mut v = raw.clone();
    let obj = match v {
        Value::Object(ref mut m) => m,
        _ => return v,
    };
    // schema_version - force override to ensure v2
    obj.insert("schema_version".to_string(), Value::from(2));

    // Migrate inbounds: tag->name, listen+listen_port->listen
    if let Some(inbounds) = obj.get_mut("inbounds").and_then(|x| x.as_array_mut()) {
        for inbound in inbounds.iter_mut() {
            if let Some(inb_obj) = inbound.as_object_mut() {
                // tag -> name
                if let Some(tag) = inb_obj.remove("tag") {
                    inb_obj.insert("name".to_string(), tag);
                }
                // listen + listen_port -> listen: "IP:PORT"
                // Ensure port is within valid range (0-65535)
                if let Some(port) = inb_obj.remove("listen_port") {
                    if let Some(listen) = inb_obj.get("listen") {
                        if let (Some(listen_str), Some(port_num)) = (listen.as_str(), port.as_u64())
                        {
                            if port_num <= u64::from(u16::MAX) {
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
        for outbound in outbounds.iter_mut() {
            if let Some(ob_obj) = outbound.as_object_mut() {
                // tag -> name
                if let Some(tag) = ob_obj.remove("tag") {
                    ob_obj.insert("name".to_string(), tag);
                }
                // Normalize type: socks5 -> socks
                if let Some(ty) = ob_obj.get_mut("type") {
                    if ty == "socks5" {
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
            route.entry("rules").or_insert(rules);
        }
        if let Some(def) = default_to_move {
            route.entry("default").or_insert(def);
        }

        // Migrate route rules: V1 flat style -> V2 when/to style
        if let Some(rules) = route.get_mut("rules").and_then(|x| x.as_array_mut()) {
            for rule in rules.iter_mut() {
                if let Some(rule_obj) = rule.as_object_mut() {
                    // If rule has 'outbound' field, it's V1 style - convert to V2
                    if let Some(outbound) = rule_obj.remove("outbound") {
                        rule_obj.insert("to".to_string(), outbound);
                    }

                    // Wrap V1 condition fields in 'when' object
                    let mut when_obj = serde_json::Map::new();
                    let mut has_conditions = false;

                    for field in V1_CONDITION_FIELDS {
                        if let Some(value) = rule_obj.get(*field) {
                            // For V2 'when' object, use singular string values if array has one element
                            if let Some(arr) = value.as_array() {
                                if arr.len() == 1 {
                                    // Map field names: domain_suffix -> suffix, domain_keyword -> keyword, etc.
                                    let v2_field = field.strip_prefix("domain_").unwrap_or(field);
                                    when_obj.insert(v2_field.to_string(), arr[0].clone());
                                    has_conditions = true;
                                }
                            }
                        }
                    }

                    if has_conditions && !rule_obj.contains_key("when") {
                        rule_obj.insert("when".to_string(), Value::Object(when_obj));
                    }
                }
            }
        }
    }

    v
}
