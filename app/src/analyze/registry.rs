//! Builder registry for analyze tool
//!
//! Note: All `.expect()` calls in this module are on mutex locks.
//! Mutex poisoning only occurs when a thread panics while holding the lock,
//! which is an unrecoverable error that should propagate.
#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::significant_drop_tightening
)]

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock,
};

/// builder 签名：输入 analyze 请求 JSON（或片段），返回补丁 JSON
pub type BuilderFn = fn(&Value) -> Result<Value>;
pub type AsyncBuilderFn = fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>;

static REGISTRY: OnceLock<Mutex<HashMap<&'static str, BuilderFn>>> = OnceLock::new();
static ASYNC_REGISTRY: OnceLock<Mutex<HashMap<&'static str, AsyncBuilderFn>>> = OnceLock::new();
static REGISTERING: AtomicBool = AtomicBool::new(false);

/// # Panics
/// Panics if the registry mutex is poisoned (only happens if another thread panicked while holding the lock)
fn ensure_registry() -> &'static Mutex<HashMap<&'static str, BuilderFn>> {
    let m = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    // 首次初始化：集中进行注册
    // Avoid deadlock and re-entrancy by using a guard flag and dropping the lock
    let need_init = {
        let guard = m.lock().expect("registry lock poisoned");
        guard.is_empty()
    };
    if need_init {
        // Set registering flag; if another thread is already initializing, skip
        if !REGISTERING.swap(true, Ordering::SeqCst) {
            crate::analyze::builders::register_all();
            REGISTERING.store(false, Ordering::SeqCst);
        }
    }
    m
}

/// 外部扩展注册（用于 feature 扩展或测试）
///
/// # Panics
/// Panics if the registry mutex is poisoned
pub fn register(kind: &'static str, f: BuilderFn) {
    let m = ensure_registry();
    let mut g = m.lock().expect("registry lock poisoned");
    g.insert(kind, f);
}

/// # Panics
/// Panics if the registry mutex is poisoned
#[must_use]
pub fn supported_kinds() -> Vec<&'static str> {
    let registry = ensure_registry();
    let g = registry.lock().expect("registry lock poisoned");
    let mut v: Vec<_> = g.keys().copied().collect();
    v.sort_unstable();
    v
}

/// # Errors
/// Returns error if the kind is not registered
///
/// # Panics
/// Panics if the registry mutex is poisoned
#[allow(dead_code)]
pub fn build_by_kind(kind: &str, input: &Value) -> Result<Value> {
    let registry = ensure_registry();
    let g = registry.lock().expect("registry lock poisoned");
    let Some(f) = g.get(kind) else {
        bail!("unsupported kind: {kind}");
    };
    f(input)
}

/// # Panics
/// Panics if the async registry mutex is poisoned
#[allow(dead_code)]
pub fn register_async(kind: &'static str, f: AsyncBuilderFn) {
    let m = ASYNC_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = m.lock().expect("async registry lock poisoned");
    g.insert(kind, f);
}

/// # Panics
/// Panics if the async registry mutex is poisoned
#[must_use]
pub fn supported_async_kinds() -> Vec<&'static str> {
    let Some(cell) = ASYNC_REGISTRY.get() else {
        return vec![];
    };
    let g = cell.lock().expect("async registry lock poisoned");
    let mut v: Vec<_> = g.keys().copied().collect();
    v.sort_unstable();
    v
}

/// # Errors
/// Returns error if the kind is not registered
///
/// # Panics
/// Panics if the async registry mutex is poisoned
#[allow(dead_code)]
pub async fn build_by_kind_async(kind: &str, input: &Value) -> Result<Value> {
    if let Some(cell) = ASYNC_REGISTRY.get() {
        let f = {
            let guard = cell.lock().expect("async registry lock poisoned");
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
