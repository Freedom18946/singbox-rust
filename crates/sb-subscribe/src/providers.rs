//! R140: RULE-SET/GEOSITE Provider 缓存（内存只读）
#[cfg(feature = "subs_ruleset_cache")]
#[allow(clippy::module_inception)]
pub mod providers {
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub struct MemoryProvider {
        map: HashMap<String, String>,
        hits: u64,
        misses: u64,
    }

    impl MemoryProvider {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn put_b64(&mut self, name: &str, b64: &str) {
            self.map.insert(name.to_string(), b64.to_string());
        }

        pub fn get(&mut self, name: &str) -> Option<&str> {
            if let Some(value) = self.map.get(name) {
                self.hits += 1;
                Some(value)
            } else {
                self.misses += 1;
                None
            }
        }

        pub fn stats(&self) -> (u64, u64) {
            (self.hits, self.misses)
        }
    }

    /// 解析带 provider 支持的规则（占位实现）
    pub fn parse_with_providers(text: &str, provider: &mut MemoryProvider) -> String {
        // 简单实现：检查是否包含 provider 引用
        if text.contains("provider:") {
            // 模拟查找和展开
            let _stats = provider.stats();
            format!("// Provider-expanded from {} chars\n{}", text.len(), text)
        } else {
            text.to_string()
        }
    }
}

#[cfg(feature = "subs_ruleset_cache")]
pub use providers::*;
