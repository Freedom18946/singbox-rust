#![allow(dead_code)]

//! Builder registry for analyze tool.

use anyhow::{bail, Result};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// builder 签名：输入 analyze 请求 JSON（或片段），返回补丁 JSON
pub type BuilderFn = fn(&Value) -> Result<Value>;
pub type AsyncBuilderFn = fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>;

pub struct AnalyzeRegistry {
    registry: Mutex<HashMap<&'static str, BuilderFn>>,
    async_registry: Mutex<HashMap<&'static str, AsyncBuilderFn>>,
}

impl AnalyzeRegistry {
    #[must_use]
    pub fn new() -> Self {
        let registry = Self {
            registry: Mutex::new(HashMap::new()),
            async_registry: Mutex::new(HashMap::new()),
        };
        crate::analyze::builders::register_all(&registry);
        registry
    }

    pub fn register(&self, kind: &'static str, f: BuilderFn) {
        self.registry.lock().insert(kind, f);
    }

    #[must_use]
    pub fn supported_kinds(&self) -> Vec<&'static str> {
        let mut kinds: Vec<_> = self.registry.lock().keys().copied().collect();
        kinds.sort_unstable();
        kinds
    }

    /// # Errors
    /// Returns an error if the requested kind has not been registered.
    pub fn build_by_kind(&self, kind: &str, input: &Value) -> Result<Value> {
        let builder = {
            let registry = self.registry.lock();
            registry.get(kind).copied()
        };
        let Some(builder) = builder else {
            bail!("unsupported kind: {kind}");
        };
        builder(input)
    }

    pub fn register_async(&self, kind: &'static str, f: AsyncBuilderFn) {
        self.async_registry.lock().insert(kind, f);
    }

    #[must_use]
    pub fn supported_async_kinds(&self) -> Vec<&'static str> {
        let mut kinds: Vec<_> = self.async_registry.lock().keys().copied().collect();
        kinds.sort_unstable();
        kinds
    }

    /// # Errors
    /// Returns an error if the requested kind has not been registered.
    pub async fn build_by_kind_async(&self, kind: &str, input: &Value) -> Result<Value> {
        let builder = { self.async_registry.lock().get(kind).copied() };
        if let Some(builder) = builder {
            return builder(input).await;
        }
        self.build_by_kind(kind, input)
    }
}

impl Default for AnalyzeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo(v: &Value) -> Result<Value> {
        Ok(serde_json::json!({"echo": v}))
    }

    #[test]
    fn demo() {
        let registry = AnalyzeRegistry {
            registry: Mutex::new(HashMap::new()),
            async_registry: Mutex::new(HashMap::new()),
        };
        registry.register("echo", echo);
        let got = registry
            .build_by_kind("echo", &serde_json::json!({"a":1}))
            .expect("registered test builder");
        assert_eq!(got["echo"]["a"], 1);
        assert!(registry.build_by_kind("nope", &serde_json::json!({})).is_err());
    }
}
