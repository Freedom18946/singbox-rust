//! Simple subscription merge/diff/precheck utilities.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct MergeResult {
    pub added_inbounds: usize,
    pub added_outbounds: usize,
    pub added_rules: usize,
}

fn v_to_set(a: &Value, key: &str) -> BTreeSet<Value> {
    a.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.clone().into_iter().collect())
        .unwrap_or_default()
}

fn merge_array(dst: &mut Vec<Value>, src: &Value, key: &str) -> usize {
    let mut set: BTreeSet<Value> = dst.clone().into_iter().collect();
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

pub fn merge(mut base: Value, others: &[Value]) -> (Value, MergeResult) {
    let mut mr = MergeResult::default();
    for o in others {
        // inbounds/outbounds/route.rules
        let dst_in = base
            .get_mut("inbounds")
            .and_then(|v| v.as_array_mut())
            .unwrap_or_else(|| {
                base.as_object_mut()
                    .unwrap()
                    .insert("inbounds".into(), Value::Array(vec![]));
                base.get_mut("inbounds").unwrap().as_array_mut().unwrap()
            });
        mr.added_inbounds += merge_array(dst_in, o, "inbounds");

        let dst_out = base
            .get_mut("outbounds")
            .and_then(|v| v.as_array_mut())
            .unwrap_or_else(|| {
                base.as_object_mut()
                    .unwrap()
                    .insert("outbounds".into(), Value::Array(vec![]));
                base.get_mut("outbounds").unwrap().as_array_mut().unwrap()
            });
        mr.added_outbounds += merge_array(dst_out, o, "outbounds");

        // route.rules
        let dst_route = base
            .get_mut("route")
            .and_then(|v| v.as_object_mut())
            .unwrap_or_else(|| {
                base.as_object_mut()
                    .unwrap()
                    .insert("route".into(), Value::Object(serde_json::Map::new()));
                base.get_mut("route").unwrap().as_object_mut().unwrap()
            });
        let dst_rules = dst_route
            .entry("rules")
            .or_insert(Value::Array(vec![]))
            .as_array_mut()
            .unwrap();
        mr.added_rules += merge_array(dst_rules, &o["route"], "rules");

        // default outbound：后者未设时保留先者
        if dst_route.get("default").is_none() {
            if let Some(d) = o.get("route").and_then(|v| v.get("default")).cloned() {
                dst_route.insert("default".into(), d);
            }
        }
    }
    (base, mr)
}

#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub added: BTreeMap<String, usize>,
    pub removed: BTreeMap<String, usize>,
}

pub fn diff(old: &Value, new: &Value) -> Diff {
    let mut d = Diff::default();
    for key in ["inbounds", "outbounds"].iter() {
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
        let (m, mr) = merge(a.clone(), &[b.clone()]);
        assert!(mr.added_rules >= 1);
        let d = diff(&a, &m);
        assert!(d.added.get("rules").is_some());
    }
}
