//! Simple subscription merge/diff/precheck utilities.
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct MergeResult {
    pub added_inbounds: usize,
    pub added_outbounds: usize,
    pub added_rules: usize,
}

fn v_to_set(a: &Value, key: &str) -> HashSet<Value> {
    a.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.clone().into_iter().collect())
        .unwrap_or_default()
}

fn merge_array(dst: &mut Vec<Value>, src: &Value, key: &str) -> usize {
    let mut set: HashSet<Value> = dst.clone().into_iter().collect();
    let mut add = 0;
    if let Some(arr) = src.get(key).and_then(|v| v.as_array()) {
        for it in arr {
            if set.insert(it.clone()) {
                add += 1;
            }
        }
    }
    *dst = set.into_iter().collect();
    add
}

pub fn merge(base: Value, others: &[Value]) -> (Value, MergeResult) {
    let mut mr = MergeResult::default();

    // Work on an object map, creating one if base isn't an object
    let mut root = match base {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };

    // Extract existing arrays or defaults
    let mut dst_in: Vec<Value> = root
        .get("inbounds")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut dst_out: Vec<Value> = root
        .get("outbounds")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    // route.rules and route.default handling
    let mut route_map: serde_json::Map<String, Value> = root
        .get("route")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut dst_rules: Vec<Value> = route_map
        .get("rules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut need_default = route_map.get("default").is_none();
    let mut default_value: Option<Value> = None;

    for o in others {
        mr.added_inbounds += merge_array(&mut dst_in, o, "inbounds");
        mr.added_outbounds += merge_array(&mut dst_out, o, "outbounds");
        mr.added_rules += merge_array(&mut dst_rules, &o["route"], "rules");
        if need_default {
            if let Some(d) = o.get("route").and_then(|v| v.get("default")).cloned() {
                default_value = Some(d);
                need_default = false;
            }
        }
    }

    // Reassemble object
    root.insert("inbounds".into(), Value::Array(dst_in));
    root.insert("outbounds".into(), Value::Array(dst_out));
    route_map.insert("rules".into(), Value::Array(dst_rules));
    if route_map.get("default").is_none() {
        if let Some(d) = default_value {
            route_map.insert("default".into(), d);
        }
    }
    root.insert("route".into(), Value::Object(route_map));

    (Value::Object(root), mr)
}

#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub added: BTreeMap<String, usize>,
    pub removed: BTreeMap<String, usize>,
}

pub fn diff(old: &Value, new: &Value) -> Diff {
    let mut d = Diff::default();
    for key in &["inbounds", "outbounds"] {
        let o = v_to_set(old, key);
        let n = v_to_set(new, key);
        let add = n.difference(&o).count();
        let rem = o.difference(&n).count();
        if add > 0 {
            d.added.insert((*key).into(), add);
        }
        if rem > 0 {
            d.removed.insert((*key).into(), rem);
        }
    }
    // rules
    let or = old.get("route").cloned().unwrap_or(Value::Null);
    let nr = new.get("route").cloned().unwrap_or(Value::Null);
    let oset = v_to_set(&or, "rules");
    let nset = v_to_set(&nr, "rules");
    let add = nset.difference(&oset).count();
    let rem = oset.difference(&nset).count();
    if add > 0 {
        d.added.insert("rules".into(), add);
    }
    if rem > 0 {
        d.removed.insert("rules".into(), rem);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_and_diff() {
        let a: Value = serde_json::from_str(
            r#"{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080}]}"#,
        )
        .unwrap();
        let b: Value = serde_json::from_str(r#"{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080}],"route":{"rules":[{"domain":["a.com"]}]}}"#).unwrap();
        let (m, mr) = merge(a.clone(), std::slice::from_ref(&b));
        assert!(mr.added_rules >= 1);
        let d = diff(&a, &m);
        assert!(d.added.contains_key("rules"));
    }
}
