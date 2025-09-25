use serde_json::Value;

use super::model::Config;

pub fn compat_1_12_4(cfg: Config) -> Config { cfg }

/// Migrate legacy config (v1-style) into v2 canonical layout.
/// - Moves root `rules` -> `route.rules`
/// - Renames `default_outbound` -> `route.default`
/// - Normalizes outbound type `socks5` -> `socks`
/// - Injects `schema_version: 2`
pub fn migrate_to_v2(raw: &Value) -> Value {
    let mut v = raw.clone();
    let mut obj = match v {
        Value::Object(ref mut m) => m,
        _ => return v,
    };
    // schema_version
    obj.entry("schema_version".into()).or_insert(Value::from(2));

    // Move rules/default into route
    if obj.get("route").is_none() {
        obj.insert("route".into(), Value::Object(serde_json::Map::new()));
    }
    if let Some(route) = obj.get_mut("route").and_then(|x| x.as_object_mut()) {
        if let Some(rules) = obj.remove("rules") { route.entry("rules".into()).or_insert(rules); }
        if let Some(def) = obj.remove("default_outbound") { route.entry("default".into()).or_insert(def); }
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
