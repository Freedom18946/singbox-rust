use serde_json::Value;

mod core_adapters;
pub use core_adapters::register_core_adapters;

/// 允许后续特性包追加自己的注册入口
pub fn register_all() {
    register_core_adapters();
}

/// 小工具：把 `sb_core` 的补丁对象（或文本）包成 JSON，便于前端/CLI统一消费
#[must_use]
pub fn wrap_patch_text(patch_text: String) -> Value {
    serde_json::json!({ "patch": { "text": patch_text } })
}
