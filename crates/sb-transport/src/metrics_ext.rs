//! # Metrics Extension Module / 指标扩展模块
//!
//! Minimal metrics registry helpers local to `sb-transport` to avoid depending on `sb-core`.
//! `sb-transport` 本地的最小化指标注册表助手，以避免依赖 `sb-core`。
//!
//! These helpers mirror the small subset used within this crate and register
//! metrics into the shared `sb-metrics` registry. They are only compiled when the
//! `metrics` feature is enabled for `sb-transport`.
//! 这些助手镜像了本 crate 中使用的一小部分功能，并将指标注册到共享的 `sb-metrics` 注册表中。
//! 仅当 `sb-transport` 启用了 `metrics` 特性时才会编译它们。
//!
//! ## Strategic Relevance / 战略关联
//! - **Decoupling**: Allows `sb-transport` to report metrics without a heavy dependency on the core application.
//!   **解耦**: 允许 `sb-transport` 报告指标，而无需严重依赖核心应用程序。
//! - **Observability**: Provides essential visibility into transport layer performance (e.g., connection counts, latency).
//!   **可观测性**: 提供对传输层性能（例如，连接数、延迟）的基本可见性。

use once_cell::sync::OnceCell;
use prometheus::{GaugeVec, IntCounterVec, Opts};
use std::collections::HashMap;
use std::sync::Mutex;

// Caches to prevent duplicate registrations by metric name.
// 缓存以防止按指标名称重复注册。
static COUNTER_VECS: OnceCell<Mutex<HashMap<String, IntCounterVec>>> = OnceCell::new();
static GAUGE_VECS: OnceCell<Mutex<HashMap<String, GaugeVec>>> = OnceCell::new();

fn counter_map() -> &'static Mutex<HashMap<String, IntCounterVec>> {
    COUNTER_VECS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn gauge_map() -> &'static Mutex<HashMap<String, GaugeVec>> {
    GAUGE_VECS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or lazily register) an IntCounterVec under the global sb-metrics registry.
/// 在全局 sb-metrics 注册表下获取（或延迟注册）一个 IntCounterVec。
pub fn get_or_register_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    // Fast path: try to get from cache first.
    // 快速路径：首先尝试从缓存获取。
    if let Ok(map) = counter_map().lock() {
        if let Some(existing) = map.get(name) {
            return existing.clone();
        }
    }

    // Create and register a new counter vec.
    // 创建并注册一个新的计数器向量。
    let vec = IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        // Fallback dummy counter on initialization failure — guarantees type availability.
        // 初始化失败时的回退虚拟计数器 — 保证类型可用性。
        #[allow(clippy::unwrap_used)]
        IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    });
    // Best-effort registration; ignore errors to avoid panics on duplicate names across processes.
    // 尽力注册；忽略错误以避免跨进程重复名称时的恐慌。
    let _ = sb_metrics::REGISTRY.register(Box::new(vec.clone()));

    if let Ok(mut map) = counter_map().lock() {
        map.insert(name.to_string(), vec.clone());
    }
    vec
}

/// Get (or lazily register) a GaugeVec (f64) under the global sb-metrics registry.
/// 在全局 sb-metrics 注册表下获取（或延迟注册）一个 GaugeVec (f64)。
pub fn get_or_register_gauge_vec_f64(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    if let Ok(map) = gauge_map().lock() {
        if let Some(existing) = map.get(name) {
            return existing.clone();
        }
    }

    let vec = GaugeVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        // Fallback dummy gauge vector
        // 回退虚拟仪表向量
        #[allow(clippy::unwrap_used)]
        GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
    });
    let _ = sb_metrics::REGISTRY.register(Box::new(vec.clone()));

    if let Ok(mut map) = gauge_map().lock() {
        map.insert(name.to_string(), vec.clone());
    }
    vec
}
