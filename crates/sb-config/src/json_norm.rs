use anyhow::Context;
use serde_json::{Map, Value};
use std::{fs, path::Path};

/// 递归排序对象的键；数组保序；标量原样返回
pub fn normalize_value(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            // 先把所有子项 normalize，再按 key 排序
            let mut nm = Map::new();
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.sort_unstable();
            for k in keys {
                if let Some(vv) = m.remove(&k) {
                    nm.insert(k, normalize_value(vv));
                }
            }
            Value::Object(nm)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_value).collect()),
        x => x,
    }
}

/// 从文件读取 JSON，做 normalize，返回字符串
pub fn normalize_file_to_string(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read file failed: {}", path.as_ref().display()))?;
    // 只支持 JSON（sing-box 官方即 JSON）
    let v: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse json failed: {}", path.as_ref().display()))?;
    let nv = normalize_value(v);
    Ok(serde_json::to_string_pretty(&nv)?)
}
