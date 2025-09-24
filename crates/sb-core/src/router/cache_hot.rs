//! R33: 决策缓存热点（Top-N）注册点与适配
use super::minijson;
use once_cell::sync::OnceCell;

#[derive(Clone, Debug, Default)]
pub struct HotItem {
    pub hash_prefix: String, // 例如 blake3 前 8 hex
    pub hits: u64,
}

type Provider = fn(limit: usize) -> Vec<HotItem>;
static REG: OnceCell<Provider> = OnceCell::new();

/// 缓存实现注册热点查询 Provider（仅一次成功）
pub fn register_hot_provider(f: Provider) -> bool {
    REG.set(f).is_ok()
}

/// 读取热点 Top-N（若未注册则返回 None）
pub fn snapshot(limit: usize) -> Option<Vec<HotItem>> {
    REG.get().map(|f| f(limit))
}

// ---------------- R33: Trait 适配与辅助哈希 ----------------
pub trait CacheHotSource: Send + Sync + 'static {
    /// 返回 Top-N（已匿名化的 hash_prefix + hits）
    fn top_n(&self, limit: usize) -> Vec<HotItem>;
}

static HOT_SRC: OnceCell<&'static dyn CacheHotSource> = OnceCell::new();

/// 注册一个热点数据源（仅一次成功）
pub fn register_hot_source(src: &'static dyn CacheHotSource) -> bool {
    if HOT_SRC.set(src).is_ok() {
        let _ = register_hot_provider(|limit| {
            if let Some(s) = HOT_SRC.get() {
                s.top_n(limit)
            } else {
                Vec::new()
            }
        });
        true
    } else {
        false
    }
}

/// 可选：供外部匿名化使用的简易哈希前缀（blake3 hex 前 8）
pub fn hash_prefix(s: &str) -> String {
    let h = blake3::hash(s.as_bytes());
    let hex = h.to_hex();
    hex[..8].to_string()
}

/// R81: 将热点项目导出为 minijson JSON（无需 serde）
pub fn hot_json(limit: usize) -> String {
    let items = snapshot(limit);
    let has_provider = items.is_some();
    let items = items.unwrap_or_default();
    let count = items.len();

    // 构造 [{"hash_prefix":"xxxxxxxx","hits":N}, ...]
    let mut parts = Vec::with_capacity(items.len());
    for it in items {
        parts.push(minijson::obj([
            ("hash_prefix", minijson::Val::Str(&it.hash_prefix)),
            ("hits", minijson::Val::NumU(it.hits as u64)),
        ]));
    }
    let arr = format!("[{}]", parts.join(","));

    if has_provider {
        minijson::obj([
            ("limit", minijson::Val::NumU(limit as u64)),
            ("count", minijson::Val::NumU(count as u64)),
            ("items", minijson::Val::Raw(&arr)),
        ])
    } else {
        minijson::obj([
            ("disabled", minijson::Val::Bool(true)),
            ("limit", minijson::Val::NumU(limit as u64)),
            ("count", minijson::Val::NumU(0)),
            ("items", minijson::Val::Raw("[]")),
        ])
    }
}

#[cfg(feature = "cache_stats_wire")]
pub fn register_router_hot_adapter(src: &'static dyn CacheHotSource) {
    register_hot_source(src);
}
