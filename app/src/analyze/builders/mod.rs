mod core_adapters;
pub use core_adapters::register_core_adapters;

/// 允许后续特性包追加自己的注册入口
pub fn register_all(registry: &crate::analyze::registry::AnalyzeRegistry) {
    register_core_adapters(registry);
}
