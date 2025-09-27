use serde_json::Value;

use super::model::Config;

pub fn compat_1_12_4(cfg: Config) -> Config { cfg }

/// Migrate legacy config (v1-style) into v2 canonical layout.
        // - Moves root `rules` -> `route.rules`
        // - Renames `default_outbound` -> `route.default`
        // - Normalizes outbound type `socks5` -> `socks`
        // - Injects `schema_version: 2`
pub fn migrate_to_v2(raw: &Value) -> Value {
    let mut v = raw.clone();
    let obj = match v {
        Value::Object(ref mut m) => m,
        _ => return v,
    };
    // schema_version
    obj.entry("schema_version").or_insert(Value::from(2));

    // Move rules/default into route
    if obj.get("route").is_none() {
        obj.insert("route".to_string(), Value::Object(serde_json::Map::new()));
    }

    // Extract rules and default_outbound before getting mutable reference to route
    let rules_to_move = obj.remove("rules");
    let default_to_move = obj.remove("default_outbound");

    if let Some(route) = obj.get_mut("route").and_then(|x| x.as_object_mut()) {
        if let Some(rules) = rules_to_move { route.entry("rules").or_insert(rules); }
        if let Some(def) = default_to_move { route.entry("default").or_insert(def); }
    }

    // Normalize outbound type field values
    if let Some(outbounds) = obj.get_mut("outbounds").and_then(|x| x.as_array_mut()) {
        for ob in outbounds.iter_mut() {
            if let Some(ty) = ob.get_mut("type") {
                if ty == "socks5" { *ty = Value::from("socks"); }
            }
        }
    }
    v
}
