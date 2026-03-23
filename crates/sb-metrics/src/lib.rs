//! sb-metrics: Lightweight Prometheus Exporter + Unified Metrics Registry.
//! sb-metrics: 轻量 Prometheus 导出器 + 统一指标注册。
//!
//! ## Strategic Role / 战略定位
//! This crate serves as the **central observability hub** for the entire sing-box ecosystem.
//! It decouples metric definition (in `sb-core`, `sb-adapters`) from metric exposition (HTTP server).
//! By using `LazyLock` and global statics, it allows any module to record metrics without passing context,
//! while ensuring low overhead via `prometheus` crate's atomic counters.
//!
//! 本 crate 是 sing-box 生态系统的**核心观测枢纽**。
//! 它将指标定义（在 `sb-core`、`sb-adapters` 中）与指标暴露（HTTP 服务器）解耦。
//! 通过使用 `LazyLock` 和全局静态变量，它允许任何模块在不传递上下文的情况下记录指标，
//! 同时通过 `prometheus` crate 的原子计数器确保低开销。
//!
//! ## Usage / 使用方式
//! - **Default**: Disabled by default. Set `SB_METRICS_ADDR=127.0.0.1:9090` env var to enable.
//! - **Startup**: Build a `MetricsRegistryHandle` and call `spawn_http_exporter_from_env(...)` in `app`.
//! - **Scrape**: Access `http://127.0.0.1:9090/metrics` to get Prometheus formatted metrics.
//!
//! - **默认**：默认不启动；设置 `SB_METRICS_ADDR=127.0.0.1:9090` 环境变量时自动监听。
//! - **启动**：在 `app` 中构造 `MetricsRegistryHandle`，并调用 `spawn_http_exporter_from_env(...)` 启动 metrics HTTP 服务器。
//! - **采集**：访问 `http://127.0.0.1:9090/metrics` 获取 Prometheus 格式指标。
//!
//! ## Metric Categories / 指标类别
//! - **Router** (`router`): Rule matching counters. Critical for analyzing traffic distribution.
//!   - **路由指标** (`router`): 路由规则匹配计数。对分析流量分布至关重要。
//! - **Outbound** (`outbound`): Connection attempts, errors, latency. Vital for upstream health monitoring.
//!   - **出站指标** (`outbound`): 出站连接尝试、错误、延迟。对上游健康监控至关重要。
//! - **Adapter** (`adapter`): SOCKS/HTTP adapter dial stats. Used by `sb-adapters`.
//!   - **适配器指标** (`adapter`): SOCKS/HTTP 适配器 dial 统计。由 `sb-adapters` 使用。
//! - **Inbound** (`socks_in`, `http`): Inbound connection stats.
//!   - **入站指标** (`socks_in`, `http`): 入站连接统计。
//! - **Legacy** (`legacy`): UDP NAT, proxy selection, health checks.
//!   - **传统指标** (`legacy`): UDP NAT、代理选择、健康检查等。
//!
//! ## Example / 示例
//! ```rust
//! use sb_metrics::{inc_router_match, inc_outbound_connect_attempt, observe_outbound_connect_seconds};
//!
//! // Record router match / 记录路由匹配
//! inc_router_match("domain_suffix", "direct");
//!
//! // Record outbound connection / 记录出站连接
//! inc_outbound_connect_attempt("socks");
//! observe_outbound_connect_seconds("socks", 0.123);
//! ```

#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, clippy::nursery)]

pub mod cardinality; // Cardinality monitoring for label explosion prevention
pub mod http; // HTTP 侧指标（入站/上游代理共用）
pub mod inbound;
// pub mod server; // Removed unused server metrics
pub mod socks; // SOCKS 侧指标
pub mod transfer; // 通用传输指标（带宽/字节数） // 入站统一错误指标
use std::{
    collections::HashSet,
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, LazyLock, Mutex, Weak},
    time::{Duration, Instant},
};

use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use prometheus::{
    core::Collector, Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, Opts, Registry, TextEncoder,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub mod labels;

fn guarded_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    labels::ensure_allowed_labels(name, labels);
    // Safe construction; if it fails, fall back to dummy with a generic label
    IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)]
        IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
}

fn guarded_int_counter(name: &str, help: &str) -> IntCounter {
    IntCounter::new(name, help).unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)]
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
}

fn guarded_int_gauge(name: &str, help: &str) -> IntGauge {
    IntGauge::new(name, help).unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)]
        IntGauge::new("dummy_gauge", "dummy").unwrap()
    })
}

fn guarded_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Vec<f64>,
) -> HistogramVec {
    labels::ensure_allowed_labels(name, labels);
    let opts = HistogramOpts::new(name, help).buckets(buckets);
    #[allow(clippy::unwrap_used)]
    HistogramVec::new(opts, labels).unwrap()
}

fn guarded_histogram(name: &str, help: &str, buckets: Vec<f64>) -> Histogram {
    Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets)).unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)]
        Histogram::with_opts(HistogramOpts::new("dummy_histogram", "dummy")).unwrap()
    })
}

/// Error rate limiter for metrics server to prevent log noise
struct ErrorRateLimiter {
    accept_errors: AtomicU64,
    connection_errors: AtomicU64,
    last_accept_log: std::sync::Mutex<Instant>,
    last_connection_log: std::sync::Mutex<Instant>,
}

impl ErrorRateLimiter {
    fn new() -> Self {
        Self {
            accept_errors: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            last_accept_log: std::sync::Mutex::new(Instant::now()),
            last_connection_log: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Log accept errors with rate limiting (max once per 30 seconds)
    fn log_accept_error(&self, e: &dyn std::fmt::Display) {
        let count = self.accept_errors.fetch_add(1, Ordering::Relaxed) + 1;

        if let Ok(mut last_log) = self.last_accept_log.try_lock() {
            if last_log.elapsed() >= Duration::from_secs(30) {
                warn!(error=%e, count=%count, "metrics accept failed (rate limited)");
                *last_log = Instant::now();
                self.accept_errors.store(0, Ordering::Relaxed);
            }
        }
        // If we can't get the lock, just increment counter silently
    }

    /// Log connection errors with rate limiting (max once per 30 seconds)
    fn log_connection_error(&self, e: &dyn std::fmt::Display) {
        let count = self.connection_errors.fetch_add(1, Ordering::Relaxed) + 1;

        if let Ok(mut last_log) = self.last_connection_log.try_lock() {
            if last_log.elapsed() >= Duration::from_secs(30) {
                warn!(error=%e, count=%count, "metrics serve_connection error (rate limited)");
                *last_log = Instant::now();
                self.connection_errors.store(0, Ordering::Relaxed);
            }
        }
        // If we can't get the lock, just increment counter silently
    }
}

static ERROR_RATE_LIMITER: LazyLock<ErrorRateLimiter> = LazyLock::new(ErrorRateLimiter::new);
static DEFAULT_REGISTRY: LazyLock<Mutex<Option<Weak<Registry>>>> =
    LazyLock::new(|| Mutex::new(None));

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Explicit handle over a metrics registry. This keeps current behavior on the
/// shared global registry while allowing call sites to depend on a typed handle.
#[derive(Clone, Debug, Default)]
pub enum MetricsRegistryHandle {
    #[default]
    Shared,
    Owned(Arc<Registry>),
}

#[derive(Clone, Debug)]
pub struct MetricsRegistryOwner {
    registry: Arc<Registry>,
}

impl MetricsRegistryHandle {
    /// Return a handle to the shared process-wide registry.
    #[must_use]
    pub const fn global() -> Self {
        Self::Shared
    }

    /// Register a cloned collector into this registry.
    ///
    /// # Errors
    ///
    /// Returns the `prometheus` registration error when the collector cannot be
    /// registered, for example because a metric with the same descriptor was
    /// already installed.
    pub fn register_cloned<C>(&self, metric: &str, collector: &C) -> Result<(), prometheus::Error>
    where
        C: Collector + Clone + 'static,
    {
        self.registry_ref()
            .register(Box::new(collector.clone()))
            .map_err(|err| {
                tracing::debug!(metric, error = %err, "metrics collector registration skipped");
                err
            })
    }

    /// Gather metric families from this registry.
    #[must_use]
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        match self {
            Self::Shared => gather_shared_metric_families(),
            Self::Owned(_) => self.registry_ref().gather(),
        }
    }

    /// Encode the current registry into Prometheus text exposition format.
    ///
    /// # Errors
    ///
    /// Returns the encoder error if `prometheus` fails to serialize the current
    /// metric families into text format.
    pub fn encode_text(&self) -> Result<Vec<u8>, prometheus::Error> {
        let metric_families = self.gather();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buf)?;
        Ok(buf)
    }

    fn registry_ref(&self) -> RegistryRef<'_> {
        match self {
            Self::Shared => current_registry_ref(),
            Self::Owned(registry) => RegistryRef::Owned(Arc::clone(registry)),
        }
    }
}

impl MetricsRegistryOwner {
    const fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    #[must_use]
    pub fn handle(&self) -> MetricsRegistryHandle {
        MetricsRegistryHandle::Owned(Arc::clone(&self.registry))
    }
}

#[must_use]
pub fn install_default_registry(registry: Arc<Registry>) -> MetricsRegistryOwner {
    let mut slot = DEFAULT_REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let existing = slot.as_ref().and_then(Weak::upgrade);
    if let Some(existing) = existing {
        drop(slot);
        return MetricsRegistryOwner::new(existing);
    }
    *slot = Some(Arc::downgrade(&registry));
    drop(slot);
    MetricsRegistryOwner::new(registry)
}

#[must_use]
pub fn install_default_registry_owner() -> MetricsRegistryOwner {
    install_default_registry(Arc::new(Registry::new()))
}

fn current_registry() -> Option<Arc<Registry>> {
    DEFAULT_REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade)
}

fn current_registry_ref() -> RegistryRef<'static> {
    current_registry().map_or_else(|| RegistryRef::Global(&REGISTRY), RegistryRef::Owned)
}

enum RegistryRef<'a> {
    Owned(Arc<Registry>),
    Global(&'a Registry),
}

impl RegistryRef<'_> {
    fn as_registry(&self) -> &Registry {
        match self {
            Self::Owned(registry) => registry,
            Self::Global(registry) => registry,
        }
    }

    fn register(&self, collector: Box<dyn Collector>) -> Result<(), prometheus::Error> {
        self.as_registry().register(collector)
    }

    fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.as_registry().gather()
    }
}

fn gather_shared_metric_families() -> Vec<prometheus::proto::MetricFamily> {
    let Some(current_registry) = current_registry() else {
        return REGISTRY.gather();
    };

    let mut metric_families = current_registry.gather();
    let mut names = metric_families
        .iter()
        .map(|family| family.name().to_string())
        .collect::<HashSet<_>>();

    for family in REGISTRY.gather() {
        let name = family.name().to_string();
        if names.insert(name) {
            metric_families.push(family);
        }
    }

    metric_families
}

/// Get the shared default metrics registry handle.
#[must_use]
pub const fn shared_registry() -> MetricsRegistryHandle {
    MetricsRegistryHandle::Shared
}

fn register_collector<C>(metric: &str, collector: &C)
where
    C: Collector + Clone + 'static,
{
    let _ = shared_registry().register_cloned(metric, collector);
}

fn registered_collector<C>(metric: &str, collector: C) -> C
where
    C: Collector + Clone + 'static,
{
    register_collector(metric, &collector);
    collector
}

fn registered_int_gauge(name: &str, help: &str) -> IntGauge {
    registered_collector(name, guarded_int_gauge(name, help))
}

fn registered_int_counter(name: &str, help: &str) -> IntCounter {
    registered_collector(name, guarded_int_counter(name, help))
}

fn registered_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    registered_collector(name, guarded_counter_vec(name, help, labels))
}

fn registered_histogram(
    name: &str,
    help: &str,
    buckets: Vec<f64>,
) -> prometheus::Histogram {
    registered_collector(name, guarded_histogram(name, help, buckets))
}

// =============================
// Constants
// =============================

/// Error classification labels
const ERROR_CLASS_TIMEOUT: &str = "timeout";
const ERROR_CLASS_DNS: &str = "dns";
const ERROR_CLASS_TLS: &str = "tls";
const ERROR_CLASS_IO: &str = "io";
const ERROR_CLASS_AUTH: &str = "auth_err";
const ERROR_CLASS_PROTO: &str = "proto_err";
const ERROR_CLASS_OTHER: &str = "other";

// ===================== Router Metrics =====================
/// Router metrics: track rule matches by category and outbound
mod router {
    use super::{register_collector, IntCounterVec, LazyLock};
    /// 路由命中计数：按规则类别与出站类型维度统计
    /// labels: category = {"`domain_suffix`","`ip_cidr`","`advanced`","`default`",...},
    ///         outbound = {"direct","block","socks","http",...}
    pub static ROUTER_MATCH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "router_rule_match_total",
            "Router rule matches total by category and outbound",
            &["category", "outbound"],
        );
        register_collector("router_rule_match_total", &vec);
        vec
    });
}

/// 便捷函数：递增路由匹配计数（供 sb-core 直接调用）
pub fn inc_router_match(category: &str, outbound_label: &str) {
    router::ROUTER_MATCH_TOTAL
        .with_label_values(&[category, outbound_label])
        .inc();
}

// ===================== Outbound Metrics =====================
/// Outbound connection metrics: attempts, errors, and latency
mod outbound {
    use super::{register_collector, HistogramVec, IntCounterVec, LazyLock};

    /// 出站连接尝试总数（含成功/失败），用于比对失败率
    pub static CONNECT_ATTEMPT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "outbound_connect_attempt_total",
            "Outbound connect attempts",
            &["kind"], // direct | socks | http | other
        );
        register_collector("outbound_connect_attempt_total", &v);
        v
    });

    /// 出站连接失败计数
    pub static CONNECT_ERROR_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "outbound_connect_error_total",
            "Outbound connect errors",
            &["kind", "class"], // class: dns | timeout | io | tls | other
        );
        register_collector("outbound_connect_error_total", &v);
        v
    });

    /// 出站连接成功直方图（秒）
    pub static CONNECT_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
        // 预置桶：1ms~10s，覆盖直连与代理常见场景
        let v = super::guarded_histogram_vec(
            "outbound_connect_seconds",
            "Outbound connect latency (seconds)",
            &["kind"],
            vec![
                0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0,
            ],
        );
        register_collector("outbound_connect_seconds", &v);
        v
    });
}

/// 递增出站连接尝试
pub fn inc_outbound_connect_attempt(kind: &str) {
    outbound::CONNECT_ATTEMPT_TOTAL
        .with_label_values(&[kind])
        .inc();
}

/// 递增出站连接错误
pub fn inc_outbound_connect_error(kind: &str, class: &str) {
    outbound::CONNECT_ERROR_TOTAL
        .with_label_values(&[kind, class])
        .inc();
}

/// 观察一次连接成功耗时（单位秒）
pub fn observe_outbound_connect_seconds(kind: &str, secs: f64) {
    outbound::CONNECT_SECONDS
        .with_label_values(&[kind])
        .observe(secs.max(0.0));
}

/// 小工具：计时封装。返回闭包，调用即记录耗时。
pub fn start_timer(kind: &'static str) -> impl FnOnce() {
    let t0 = Instant::now();
    move || {
        let dt = t0.elapsed();
        observe_outbound_connect_seconds(kind, dt.as_secs_f64());
    }
}

/// 通用错误分类器，用于 `inc_outbound_connect_error` 和适配器错误分类
///
/// 接受任何实现 `Display` 的错误类型，避免跨 crate trait 约束导致的类型不匹配。
/// 基于错误消息字符串进行简单分类。
pub fn classify_error<E: core::fmt::Display + ?Sized>(e: &E) -> &'static str {
    let s = e.to_string().to_lowercase();
    if s.contains("timed out") || s.contains("timeout") {
        ERROR_CLASS_TIMEOUT
    } else if s.contains("authentication") || s.contains("auth") {
        ERROR_CLASS_AUTH
    } else if s.contains("protocol") || s.contains("invalid") || s.contains("unsupported") {
        ERROR_CLASS_PROTO
    } else if s.contains("dns") || s.contains("resolve") || s.contains("name or service not known")
    {
        ERROR_CLASS_DNS
    } else if s.contains("tls") || s.contains("certificate") {
        ERROR_CLASS_TLS
    } else if s.contains("io") || s.contains("connection") || s.contains("refused") {
        ERROR_CLASS_IO
    } else {
        ERROR_CLASS_OTHER
    }
}

// ===================== Adapter Metrics (SOCKS/HTTP) =====================
/// Adapter (SOCKS/HTTP) dial metrics: attempts, latency, retries
mod adapter {
    use super::{register_collector, HistogramVec, IntCounterVec, LazyLock};

    /// Adapter dial total counter - tracks all dial attempts with results
    /// labels: adapter = {"socks5", "http"}, result = {"ok", "timeout", "`proto_err`", "`auth_err`", "`io_err`"}
    pub static DIAL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "adapter_dial_total",
            "Adapter dial attempts total by adapter and result",
            &["adapter", "result"],
        );
        register_collector("adapter_dial_total", &vec);
        vec
    });

    /// Adapter dial latency histogram in milliseconds
    /// labels: adapter = {"socks5", "http"}
    pub static DIAL_LATENCY_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
        let v = super::guarded_histogram_vec(
            "adapter_dial_latency_ms",
            "Adapter dial latency in milliseconds",
            &["adapter"],
            vec![
                1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
                10000.0,
            ],
        );
        register_collector("adapter_dial_latency_ms", &v);
        v
    });

    /// Adapter retry attempts counter
    /// labels: adapter = {"socks5", "http"}
    pub static RETRIES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "adapter_retries_total",
            "Adapter retry attempts total",
            &["adapter"],
        );
        register_collector("adapter_retries_total", &vec);
        vec
    });
}

// ===================== Selector/URLTest Metrics =====================
/// Selector and `URLTest` metrics
mod selector {
    use super::{register_collector, IntCounterVec, LazyLock};
    use prometheus::IntGaugeVec;

    /// Health check total counter
    /// labels: proxy, status = {"ok", "fail", "timeout", "unsupported"}
    pub static HEALTH_CHECK_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "selector_health_check_total",
            "Selector health check attempts total",
            &["proxy", "status"],
        );
        register_collector("selector_health_check_total", &vec);
        vec
    });

    /// Active connections gauge per proxy
    /// labels: proxy
    pub static ACTIVE_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
        super::labels::ensure_allowed_labels("active_connections", &["proxy"]);
        let vec = IntGaugeVec::new(
            prometheus::Opts::new(
                "selector_active_connections",
                "Active connections per proxy",
            ),
            &["proxy"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            IntGaugeVec::new(prometheus::Opts::new("dummy_gauge", "dummy"), &["proxy"]).unwrap()
        });
        register_collector("selector_active_connections", &vec);
        vec
    });

    /// Failover total counter
    /// labels: selector, from, to
    pub static FAILOVER_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "selector_failover_total",
            "Selector failover events total",
            &["selector", "from", "to"],
        );
        register_collector("selector_failover_total", &vec);
        vec
    });
}

/// Record health check result
pub fn inc_health_check(proxy: &str, status: &str) {
    selector::HEALTH_CHECK_TOTAL
        .with_label_values(&[proxy, status])
        .inc();
}

/// Set active connections for a proxy
pub fn set_active_connections(proxy: &str, count: i64) {
    selector::ACTIVE_CONNECTIONS
        .with_label_values(&[proxy])
        .set(count);
}

/// Record failover event
pub fn inc_failover(selector: &str, from: &str, to: &str) {
    selector::FAILOVER_TOTAL
        .with_label_values(&[selector, from, to])
        .inc();
}

/// Record adapter dial attempt result
pub fn inc_adapter_dial_total(adapter: &str, result: &str) {
    adapter::DIAL_TOTAL
        .with_label_values(&[adapter, result])
        .inc();
}

/// Record adapter dial latency in milliseconds
pub fn observe_adapter_dial_latency_ms(adapter: &str, latency_ms: f64) {
    adapter::DIAL_LATENCY_MS
        .with_label_values(&[adapter])
        .observe(latency_ms.max(0.0));
}

/// Record adapter retry attempt
pub fn inc_adapter_retries_total(adapter: &str) {
    adapter::RETRIES_TOTAL.with_label_values(&[adapter]).inc();
}

/// Helper function to classify adapter errors into metric result categories
///
/// This is an alias for `classify_error()` to maintain API compatibility.
pub fn classify_adapter_error<E: core::fmt::Display + ?Sized>(e: &E) -> &'static str {
    classify_error(e)
}

/// Helper to start timing an adapter operation
#[must_use]
pub fn start_adapter_timer() -> Instant {
    Instant::now()
}

/// Helper to record the latency and result for an adapter operation
pub fn record_adapter_dial(
    adapter: &str,
    start_time: Instant,
    result: Result<(), &dyn core::fmt::Display>,
) {
    // u128 -> f64 conversion: precision loss acceptable for latency values < 2^53 ms (~285 years)
    #[allow(clippy::cast_precision_loss)]
    let latency_ms = start_time.elapsed().as_millis() as f64;
    observe_adapter_dial_latency_ms(adapter, latency_ms);

    let result_label = match result {
        Ok(()) => "ok",
        Err(e) => classify_adapter_error(e),
    };
    inc_adapter_dial_total(adapter, result_label);
}

// ===================== DERP Service Metrics =====================
/// DERP service metrics: connections, relays, HTTP/STUN activity.
mod derp {
    use super::{guarded_counter_vec, guarded_histogram_vec, register_collector, LazyLock};
    use prometheus::{HistogramVec, IntCounterVec, IntGaugeVec, Opts};

    pub static CONNECTION_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = guarded_counter_vec(
            "derp_connection_total",
            "DERP client connection attempts",
            &["tag", "result"],
        );
        register_collector("derp_connection_total", &vec);
        vec
    });

    pub static ACTIVE_CLIENTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
        super::labels::ensure_allowed_labels("derp_clients", &["tag"]);
        let gauge = IntGaugeVec::new(Opts::new("derp_clients", "Active DERP clients"), &["tag"])
            .unwrap_or_else(|_| {
                #[allow(clippy::unwrap_used)]
                IntGaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["tag"]).unwrap()
            });
        register_collector("derp_clients", &gauge);
        gauge
    });

    pub static RELAY_PACKETS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = guarded_counter_vec(
            "derp_relay_packets_total",
            "DERP packets relayed",
            &["tag", "result"],
        );
        register_collector("derp_relay_packets_total", &vec);
        vec
    });

    pub static RELAY_BYTES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = guarded_counter_vec("derp_relay_bytes_total", "DERP bytes relayed", &["tag"]);
        register_collector("derp_relay_bytes_total", &vec);
        vec
    });

    pub static HTTP_REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = guarded_counter_vec(
            "derp_http_requests_total",
            "DERP HTTP stub requests",
            &["tag", "status"],
        );
        register_collector("derp_http_requests_total", &vec);
        vec
    });

    pub static STUN_REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = guarded_counter_vec(
            "derp_stun_requests_total",
            "DERP STUN request handling",
            &["tag", "result"],
        );
        register_collector("derp_stun_requests_total", &vec);
        vec
    });

    pub static CLIENT_LIFETIME_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
        let vec = guarded_histogram_vec(
            "derp_client_lifetime_seconds",
            "DERP client session lifetime (seconds)",
            &["tag"],
            vec![0.1, 0.5, 1.0, 5.0, 30.0, 120.0, 600.0, 1800.0, 3600.0],
        );
        register_collector("derp_client_lifetime_seconds", &vec);
        vec
    });
}

/// Record DERP client connection attempt
pub fn inc_derp_connection(tag: &str, result: &str) {
    derp::CONNECTION_TOTAL
        .with_label_values(&[tag, result])
        .inc();
}

/// Set active DERP clients gauge
pub fn set_derp_clients(tag: &str, count: i64) {
    derp::ACTIVE_CLIENTS.with_label_values(&[tag]).set(count);
}

/// Record DERP relay attempt (counts packets and bytes on success)
pub fn inc_derp_relay(tag: &str, result: &str, bytes: Option<u64>) {
    derp::RELAY_PACKETS_TOTAL
        .with_label_values(&[tag, result])
        .inc();
    if let Some(b) = bytes {
        derp::RELAY_BYTES_TOTAL.with_label_values(&[tag]).inc_by(b);
    }
}

/// Record DERP HTTP stub request by status code
pub fn inc_derp_http(tag: &str, status: &str) {
    derp::HTTP_REQUEST_TOTAL
        .with_label_values(&[tag, status])
        .inc();
}

/// Record DERP STUN handling result
pub fn inc_derp_stun(tag: &str, result: &str) {
    derp::STUN_REQUEST_TOTAL
        .with_label_values(&[tag, result])
        .inc();
}

/// Observe a DERP client session lifetime in seconds
pub fn observe_derp_client_lifetime(tag: &str, seconds: f64) {
    derp::CLIENT_LIFETIME_SECONDS
        .with_label_values(&[tag])
        .observe(seconds.max(0.0));
}

// ===================== SOCKS Inbound Metrics =====================
/// SOCKS inbound metrics: TCP connections, UDP associations and packets
mod socks_in {
    use super::{
        guarded_int_counter, guarded_int_gauge, register_collector, IntCounter, IntCounterVec,
        IntGauge, LazyLock,
    };

    /// SOCKS TCP 连接总数（握手成功即计数）
    pub static TCP_CONN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        let c = guarded_int_counter(
            "inbound_socks_tcp_connections_total",
            "SOCKS inbound accepted TCP connections total",
        );
        register_collector("inbound_socks_tcp_connections_total", &c);
        c
    });

    /// UDP 关联创建总数
    pub static UDP_ASSOC_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        let c = guarded_int_counter(
            "inbound_socks_udp_associate_total",
            "SOCKS inbound UDP ASSOCIATE total",
        );
        register_collector("inbound_socks_udp_associate_total", &c);
        c
    });

    /// UDP 包计数：方向 in -> server / out -> client
    pub static UDP_PKTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "inbound_socks_udp_packets_total",
            "SOCKS inbound UDP packets",
            &["dir"], // "in" | "out"
        );
        register_collector("inbound_socks_udp_packets_total", &v);
        v
    });

    /// UDP 当前关联估算（需要上层周期更新，可选）
    pub static UDP_ASSOC_ESTIMATE: LazyLock<IntGauge> = LazyLock::new(|| {
        let g = guarded_int_gauge(
            "inbound_socks_udp_assoc_estimate",
            "SOCKS inbound UDP associations (approximate)",
        );
        register_collector("inbound_socks_udp_assoc_estimate", &g);
        g
    });
}

/// 便捷：SOCKS TCP 连接+1
pub fn inc_socks_tcp_conn() {
    socks_in::TCP_CONN_TOTAL.inc();
}
/// 便捷：SOCKS UDP 关联+1
pub fn inc_socks_udp_assoc() {
    socks_in::UDP_ASSOC_TOTAL.inc();
}
/// 便捷：SOCKS UDP 包+1（dir: "in" | "out"）
pub fn inc_socks_udp_packet(dir: &str) {
    socks_in::UDP_PKTS_TOTAL.with_label_values(&[dir]).inc();
}
/// 便捷：设置 UDP 关联估算（上层有 `map.size()` 时可更新）
pub fn set_socks_udp_assoc_estimate(n: i64) {
    socks_in::UDP_ASSOC_ESTIMATE.set(n);
}

// ===================== Legacy Metrics (from registry.rs) =====================
/// Legacy metrics: UDP NAT, proxy selection, health checks, build info
mod legacy {
    use super::{LazyLock, Opts};
    use prometheus::{GaugeVec, Histogram, IntCounter, IntCounterVec, IntGauge};

    pub static UDP_MAP_SIZE: LazyLock<IntGauge> =
        LazyLock::new(|| super::registered_int_gauge("udp_map_size", "UDP NAT table size"));

    pub static UDP_EVICT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        super::registered_counter_vec("udp_evict_total", "UDP NAT eviction total", &["reason"])
    });

    pub static UDP_FAIL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        super::registered_counter_vec("udp_fail_total", "UDP failure total", &["class"])
    });

    pub static ROUTE_EXPLAIN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        super::registered_int_counter("route_explain_total", "Route explain invocations")
    });

    pub static TCP_CONNECT_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
        super::registered_histogram(
            "tcp_connect_duration_seconds",
            "TCP connect duration",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0],
        )
    });

    pub static PROXY_SELECT_SCORE: LazyLock<GaugeVec> = LazyLock::new(|| {
        let v = GaugeVec::new(
            Opts::new("proxy_select_score", "Proxy selection score"),
            &["proxy"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
        });
        super::register_collector("proxy_select_score", &v);
        v
    });

    pub static OUTBOUND_UP: LazyLock<GaugeVec> = LazyLock::new(|| {
        let v = GaugeVec::new(
            Opts::new("outbound_up", "Outbound health status (1=up, 0=down)"),
            &["outbound"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
        });
        super::register_collector("outbound_up", &v);
        v
    });

    pub static PROM_HTTP_FAIL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        super::registered_counter_vec(
            "prom_http_fail_total",
            "Prometheus HTTP export failures",
            &["class"],
        )
    });

    pub static UDP_TTL_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
        super::registered_histogram(
            "udp_nat_ttl_seconds",
            "UDP NAT entry TTL distribution",
            vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
        )
    });

    pub static PROXY_SELECT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        super::registered_counter_vec(
            "proxy_select_total",
            "Proxy selection invocations",
            &["proxy"],
        )
    });
}

/// 便捷：设置 UDP NAT map 大小
pub fn set_udp_map_size(size: u64) {
    let value = i64::try_from(size).unwrap_or(i64::MAX);
    legacy::UDP_MAP_SIZE.set(value);
}

/// 便捷：递增 UDP eviction（reason: "ttl" | "pressure"）
pub fn inc_udp_evict(reason: &str) {
    legacy::UDP_EVICT_TOTAL.with_label_values(&[reason]).inc();
}

/// 便捷：递增 UDP failure（class: "timeout" | "io" | "other"）
pub fn inc_udp_fail(class: &str) {
    legacy::UDP_FAIL_TOTAL.with_label_values(&[class]).inc();
}

/// 便捷：递增 route explain 计数
pub fn inc_route_explain() {
    legacy::ROUTE_EXPLAIN_TOTAL.inc();
}

/// 便捷：观察 TCP 连接耗时（秒）
pub fn observe_tcp_connect_seconds(secs: f64) {
    legacy::TCP_CONNECT_DURATION.observe(secs.max(0.0));
}

/// 便捷：设置代理选择分数
pub fn set_proxy_select_score(proxy: &str, score: f64) {
    legacy::PROXY_SELECT_SCORE
        .with_label_values(&[proxy])
        .set(score);
}

/// 便捷：设置出站健康状态（1=up, 0=down）
pub fn set_outbound_up(outbound: &str, ok: f64) {
    legacy::OUTBOUND_UP.with_label_values(&[outbound]).set(ok);
}

/// 便捷：递增 Prometheus HTTP 导出失败
pub fn inc_prom_http_fail(class: &str) {
    legacy::PROM_HTTP_FAIL.with_label_values(&[class]).inc();
}

/// 便捷：观察 UDP TTL（秒）
pub fn observe_udp_ttl_seconds(secs: f64) {
    legacy::UDP_TTL_SECONDS.observe(secs.max(0.0));
}

/// 便捷：递增代理选择计数
pub fn inc_proxy_select(proxy: &str) {
    legacy::PROXY_SELECT_TOTAL.with_label_values(&[proxy]).inc();
}

fn metrics_http_with_registry(
    registry: &MetricsRegistryHandle,
    req: &Request<Body>,
) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let encoder = TextEncoder::new();
            let Ok(buf) = registry.encode_text() else {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("encoding error"))
                    .unwrap_or_default();
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buf))
                .unwrap_or_default()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap_or_default(),
    }
}

/// Spawn the metrics HTTP exporter for a specific registry handle.
#[must_use]
pub fn spawn_http_exporter(registry: MetricsRegistryHandle, addr: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        // 手工监听 + 逐连接 serve，避免不同 hyper 版本的 Server API 差异
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error=%e, "metrics TcpListener bind failed");
                return;
            }
        };
        info!(addr=?listener.local_addr().ok(), "metrics exporter listening");
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    ERROR_RATE_LIMITER.log_accept_error(&e);
                    continue;
                }
            };
            let registry = registry.clone();
            tokio::spawn(async move {
                if let Err(e) = Http::new()
                    .serve_connection(
                        stream,
                        service_fn(move |req| {
                            let registry = registry.clone();
                            async move {
                                Ok::<_, Infallible>(metrics_http_with_registry(&registry, &req))
                            }
                        }),
                    )
                    .await
                {
                    ERROR_RATE_LIMITER.log_connection_error(&e);
                }
            });
        }
    })
}

pub fn spawn_http_exporter_from_env(registry: MetricsRegistryHandle) -> Option<JoinHandle<()>> {
    let addr = std::env::var("SB_METRICS_ADDR").ok()?;
    let sa: SocketAddr = match addr.parse() {
        Ok(x) => x,
        Err(e) => {
            warn!(addr=%addr, error=%e, "invalid SB_METRICS_ADDR, metrics disabled");
            return None;
        }
    };
    Some(spawn_http_exporter(registry, sa))
}

#[must_use]
pub fn maybe_spawn_http_exporter_from_env_with(
    registry: MetricsRegistryHandle,
) -> Option<JoinHandle<()>> {
    spawn_http_exporter_from_env(registry)
}

#[must_use]
pub fn maybe_spawn_http_exporter_from_env() -> Option<JoinHandle<()>> {
    maybe_spawn_http_exporter_from_env_with(shared_registry())
}

// NOTE:
// 这里不要重复 re-export prometheus 的项；顶部已有一次公开导出，重复会触发 E0252。

/// Export all registered metrics in Prometheus text format.
///
/// This function is primarily used for testing purposes. For production metric
/// collection, use the HTTP exporter via `spawn_metrics_server()` or set
/// `SB_METRICS_ADDR` environment variable.
///
/// # Panics
///
/// Panics if encoding fails (should never happen in practice) or if the output
/// contains invalid UTF-8.
#[allow(clippy::expect_used)] // Test utility function, panic is acceptable
#[must_use]
pub fn export_prometheus_with(registry: &MetricsRegistryHandle) -> String {
    let buf = registry
        .encode_text()
        .expect("Prometheus encoding should never fail");
    String::from_utf8(buf).expect("Prometheus output should be valid UTF-8")
}

#[allow(clippy::expect_used)] // Test utility function, panic is acceptable
#[must_use]
pub fn export_prometheus() -> String {
    export_prometheus_with(&shared_registry())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::IntGauge;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn exporter_noise_smoke() {
        // Directly exercise the /metrics handler without binding sockets.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let registry = shared_registry();
        let resp = metrics_http_with_registry(&registry, &req);
        assert_eq!(resp.status(), StatusCode::OK);

        // Exercise non-/metrics path
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/not-found")
            .body(Body::empty())
            .unwrap();
        let registry = shared_registry();
        let resp2 = metrics_http_with_registry(&registry, &req2);
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn derp_metrics_export() {
        // Emit a handful of DERP metrics and ensure they surface in the exporter.
        inc_derp_connection("unit", "ok");
        inc_derp_connection("unit", "rate_limited");
        inc_derp_relay("unit", "ok", Some(42));
        inc_derp_http("unit", "200");
        inc_derp_stun("unit", "ok");
        observe_derp_client_lifetime("unit", 1.5);
        set_derp_clients("unit", 3);

        let text = export_prometheus();
        for needle in [
            "derp_connection_total",
            "derp_relay_packets_total",
            "derp_relay_bytes_total",
            "derp_http_requests_total",
            "derp_stun_requests_total",
            "derp_client_lifetime_seconds_bucket",
            "derp_clients",
        ] {
            assert!(
                text.contains(needle),
                "export should contain {needle}, got:\n{text}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used)]
    fn explicit_owner_registry_lifecycle_controls_shared_handle() {
        let owner = install_default_registry_owner();
        let gauge = IntGauge::new(
            "codex_metrics_owner_lifecycle",
            "codex metrics owner lifecycle test",
        )
        .unwrap();
        shared_registry()
            .register_cloned("codex_metrics_owner_lifecycle", &gauge)
            .unwrap();
        gauge.set(7);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(text.contains("codex_metrics_owner_lifecycle"));
        assert!(text.contains(" 7"));

        drop(owner);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(
            !text.contains("codex_metrics_owner_lifecycle"),
            "dropping explicit owner should fall back away from the temporary registry"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used)]
    fn shared_handle_keeps_global_metrics_visible_after_owner_install() {
        let global_gauge = IntGauge::new(
            "codex_metrics_global_before_owner",
            "codex metrics global before owner test",
        )
        .unwrap();
        shared_registry()
            .register_cloned("codex_metrics_global_before_owner", &global_gauge)
            .unwrap();
        global_gauge.set(11);

        let owner = install_default_registry_owner();
        let owned_gauge = IntGauge::new(
            "codex_metrics_owned_after_owner",
            "codex metrics owned after owner test",
        )
        .unwrap();
        owner
            .handle()
            .register_cloned("codex_metrics_owned_after_owner", &owned_gauge)
            .unwrap();
        owned_gauge.set(13);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(text.contains("codex_metrics_global_before_owner"));
        assert!(text.contains(" 11"));
        assert!(text.contains("codex_metrics_owned_after_owner"));
        assert!(text.contains(" 13"));
    }

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used)]
    fn owner_handle_exports_metrics_without_shared_lookup() {
        let owner = install_default_registry_owner();
        let owned_handle = owner.handle();
        let gauge = IntGauge::new(
            "codex_metrics_owner_handle_export",
            "codex metrics owner handle export test",
        )
        .unwrap();
        owned_handle
            .register_cloned("codex_metrics_owner_handle_export", &gauge)
            .unwrap();
        gauge.set(17);

        let text = String::from_utf8(owned_handle.encode_text().unwrap()).unwrap();
        assert!(text.contains("codex_metrics_owner_handle_export"));
        assert!(text.contains(" 17"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_prometheus_with_owned_handle_avoids_shared_lookup() {
        let owned_registry = Arc::new(Registry::new());
        let owned_handle = MetricsRegistryHandle::Owned(Arc::clone(&owned_registry));
        let gauge = IntGauge::new(
            "codex_metrics_export_with_owned_handle",
            "codex metrics export with owned handle test",
        )
        .unwrap();
        owned_handle
            .register_cloned("codex_metrics_export_with_owned_handle", &gauge)
            .unwrap();
        gauge.set(23);

        let text = export_prometheus_with(&owned_handle);
        assert!(text.contains("codex_metrics_export_with_owned_handle"));
        assert!(text.contains(" 23"));

        let shared_text = export_prometheus();
        assert!(
            !shared_text.contains("codex_metrics_export_with_owned_handle"),
            "owned-handle export should not require shared registry lookup"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used)]
    fn owner_drop_cleans_up_without_residual_metrics() {
        let owner = install_default_registry_owner();
        let gauge = IntGauge::new(
            "compat_owner_drop_residual",
            "test that owner drop does not leave residual metrics",
        )
        .unwrap();
        shared_registry()
            .register_cloned("compat_owner_drop_residual", &gauge)
            .unwrap();
        gauge.set(42);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(
            text.contains("compat_owner_drop_residual"),
            "metric should be visible while owner is alive"
        );

        drop(owner);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(
            !text.contains("compat_owner_drop_residual"),
            "metric must disappear after owner is dropped"
        );

        // A new owner should be able to register the same metric name without error.
        let owner2 = install_default_registry_owner();
        let gauge2 = IntGauge::new(
            "compat_owner_drop_residual",
            "re-registration after owner drop",
        )
        .unwrap();
        shared_registry()
            .register_cloned("compat_owner_drop_residual", &gauge2)
            .unwrap();
        gauge2.set(99);

        let text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(text.contains("compat_owner_drop_residual"));
        assert!(text.contains(" 99"));
        drop(owner2);
    }

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used)]
    fn shared_register_after_owner_install_lands_in_owner_registry() {
        let owner = install_default_registry_owner();

        // Register via the shared path while an owner is installed.
        let gauge = IntGauge::new(
            "compat_shared_reg_lands_in_owner",
            "shared registration should land in the owner registry",
        )
        .unwrap();
        shared_registry()
            .register_cloned("compat_shared_reg_lands_in_owner", &gauge)
            .unwrap();
        gauge.set(77);

        // Visible via the shared handle (merged view).
        let shared_text = String::from_utf8(shared_registry().encode_text().unwrap()).unwrap();
        assert!(
            shared_text.contains("compat_shared_reg_lands_in_owner"),
            "metric should be visible via shared handle"
        );

        // Also visible via the owner's own handle (proves it landed in owner registry).
        let owned_text = String::from_utf8(owner.handle().encode_text().unwrap()).unwrap();
        assert!(
            owned_text.contains("compat_shared_reg_lands_in_owner"),
            "metric registered via shared path must land in owner registry when owner is installed"
        );

        drop(owner);
    }
}
