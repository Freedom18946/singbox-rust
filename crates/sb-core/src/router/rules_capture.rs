//! R21: 规则文本捕获（只读、可选 feature=rules_capture）
//! 目的：为 admin 的 `/router/analyze` 和离线调试提供“当前生效文本”的只读访问。
//! 实现：存储最近一次 `router_build_index_from_str` 成功构建时的**预展开文本**。
use once_cell::sync::Lazy;
use std::sync::RwLock;

static RULES_TXT: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

/// 捕获（覆盖）当前生效的预展开规则文本
pub fn capture(expanded_text: &str) {
    if let Ok(mut w) = RULES_TXT.write() {
        *w = expanded_text.to_string();
    }
}

/// 读取快照；若为空字符串则认为不可用
pub fn get() -> Option<String> {
    if let Ok(r) = RULES_TXT.read() {
        if !r.is_empty() {
            return Some(r.clone());
        }
    }
    None
}
