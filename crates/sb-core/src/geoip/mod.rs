//! GeoIP provider 封装：lookup 计数细分（provider, rcode）
use once_cell::sync::OnceCell;
use std::net::IpAddr;
use std::sync::Arc;

pub mod cidr;
pub mod mmdb;
#[cfg(feature = "geoip_mmdb")]
pub mod multi;

pub trait Provider: Send + Sync + 'static {
    /// 返回 Some(decision) 表示命中；None 表示未命中或不支持该 IP
    fn lookup(&self, ip: IpAddr) -> Option<&'static str>;
}

// 安全的全局单例（只 set 一次；读为 Arc clone，无需 unsafe）
static GLOBAL_PROVIDER: OnceCell<Arc<dyn Provider>> = OnceCell::new();

/// 设置全局 GeoIP Provider（仅初始化阶段或测试使用；多次 set 会被忽略）
pub fn set_global_provider(p: Arc<dyn Provider>) {
    let _ = GLOBAL_PROVIDER.set(p);
}

pub fn get_global_provider() -> Option<Arc<dyn Provider>> {
    GLOBAL_PROVIDER.get().cloned()
}

/// 对外统一入口，带 metrics；未配置 Provider 时直接返回 None
pub fn lookup_with_metrics(ip: IpAddr) -> Option<&'static str> {
    #[cfg(feature = "metrics")]
    let started = std::time::Instant::now();
    let mut hit = None;
    if let Some(p) = get_global_provider() {
        hit = p.lookup(ip);
    }
    #[cfg(feature = "metrics")]
    {
        let code = if hit.is_some() { "ok" } else { "miss" };
        metrics::counter!("geoip_lookup_total", "provider"=>"cidr", "rcode"=>code).increment(1);
        metrics::histogram!("geoip_lookup_ms_bucket").record(started.elapsed().as_millis() as f64);
    }
    hit
}

/// R27: 只读快捷查询，返回国家码（两位）或 None。
pub fn quick_country(ip: IpAddr) -> Option<String> {
    #[cfg(feature = "geoip_provider")]
    {
        if let Some(f) = GEOIP_PROVIDER.get() {
            return f(ip);
        }
    }
    #[cfg(not(feature = "geoip_provider"))]
    let _ = ip; // Suppress unused warning when feature is disabled
    None
}

// R27: Provider 挂钩（可选）
#[cfg(feature = "geoip_provider")]
static GEOIP_PROVIDER: once_cell::sync::OnceCell<fn(IpAddr) -> Option<String>> =
    once_cell::sync::OnceCell::new();
/// 由外部 GeoIP 模块在初始化时注册查询函数；仅能成功一次。
#[cfg(feature = "geoip_provider")]
pub fn register_quick_country_provider(f: fn(IpAddr) -> Option<String>) -> bool {
    GEOIP_PROVIDER.set(f).is_ok()
}
