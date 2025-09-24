//! R25: 决策缓存统计注册点（可选 feature=cache_stats）
use once_cell::sync::OnceCell;

#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    pub enabled: bool,
    pub size: u64,
    pub capacity: u64,
    pub hits: u64,
    pub misses: u64,
}

type Provider = fn() -> CacheStats;
static REG: OnceCell<Provider> = OnceCell::new();

/// 缓存实现方在初始化时调用，注册统计快照函数。
/// 仅能成功一次；重复注册返回 false。
pub fn register_provider(f: Provider) -> bool {
    REG.set(f).is_ok()
}

/// 读取当前统计（若未注册则返回 None）。
pub fn snapshot() -> Option<CacheStats> {
    REG.get().map(|f| f())
}

/// R86（可选）：供上层在 Router 初始化完成时一次性注册真实 provider
#[cfg(feature = "cache_stats_wire")]
pub fn register_router_decision_cache_adapter(f: Provider) -> bool {
    register_provider(f)
}
