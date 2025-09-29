use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};

/// builder 签名：输入 analyze 请求 JSON（或片段），返回补丁 JSON
pub type BuilderFn = fn(&Value) -> Result<Value>;
pub type AsyncBuilderFn = fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>;

static REGISTRY: OnceLock<Mutex<HashMap<&'static str, BuilderFn>>> = OnceLock::new();
static ASYNC_REGISTRY: OnceLock<Mutex<HashMap<&'static str, AsyncBuilderFn>>> = OnceLock::new();

fn ensure_registry() -> &'static Mutex<HashMap<&'static str, BuilderFn>> {
    let m = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    {
        // 首次初始化：集中进行注册
        let guard = m.lock().expect("registry lock");
        if guard.is_empty() {
            crate::analyze::builders::register_all();
        }
    }
    m
}

/// 外部扩展注册（用于 feature 扩展或测试）
pub fn register(kind: &'static str, f: BuilderFn) {
    let m = ensure_registry();
    let mut g = m.lock().expect("registry lock");
    g.insert(kind, f);
}

pub fn supported_kinds() -> Vec<&'static str> {
    let g = ensure_registry().lock().expect("registry lock");
    let mut v: Vec<_> = g.keys().copied().collect();
    v.sort();
    v
}

pub fn build_by_kind(kind: &str, input: &Value) -> Result<Value> {
    let g = ensure_registry().lock().expect("registry lock");
    if let Some(f) = g.get(kind) {
        return f(input);
    }
    bail!("unsupported kind: {kind}");
}

pub fn register_async(kind: &'static str, f: AsyncBuilderFn) {
    let m = ASYNC_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = m.lock().expect("async registry lock");
    g.insert(kind, f);
}

pub fn supported_async_kinds() -> Vec<&'static str> {
    if let Some(cell) = ASYNC_REGISTRY.get() {
        let g = cell.lock().expect("async registry lock");
        let mut v: Vec<_> = g.keys().copied().collect();
        v.sort();
        v
    } else {
        vec![]
    }
}

pub async fn build_by_kind_async(kind: &str, input: &Value) -> Result<Value> {
    if let Some(cell) = ASYNC_REGISTRY.get() {
        let f = {
            let guard = cell.lock().expect("async registry");
            guard.get(kind).copied()
        };
        if let Some(f) = f {
            return f(input).await;
        }
    }
    build_by_kind(kind, input)
}

// ---------- 示例 builders（可在 feature=sbcore_rules_tool 时启用真实现） ----------
#[cfg(test)]
mod t_builders {
    use super::*;
    pub fn echo(v: &Value) -> Result<Value> {
        Ok(serde_json::json!({"echo": v}))
    }
    #[test]
    fn demo() {
        register("echo", echo);
        let got = build_by_kind("echo", &serde_json::json!({"a":1})).unwrap();
        assert_eq!(got["echo"]["a"], 1);
        assert!(build_by_kind("nope", &serde_json::json!({})).is_err());
    }
}
