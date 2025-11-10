//! sb-metrics: 轻量 Prometheus 导出器 + 统一指标注册。
//!
//! ## 使用方式
//! - 默认不启动；设置 `SB_METRICS_ADDR=127.0.0.1:9090` 环境变量时自动监听。
//! - 调用 `maybe_spawn_http_exporter_from_env()` 启动 metrics HTTP 服务器。
//! - 访问 `http://127.0.0.1:9090/metrics` 获取 Prometheus 格式指标。
//!
//! ## 指标类别
//! - **路由指标** (`router`): 路由规则匹配计数
//! - **出站指标** (`outbound`): 出站连接尝试、错误、延迟
//! - **适配器指标** (`adapter`): SOCKS/HTTP 适配器 dial 统计
//! - **入站指标** (`socks_in`): SOCKS 入站 TCP/UDP 连接
//! - **传统指标** (`legacy`): UDP NAT、代理选择、健康检查等
//!
//! ## 示例
//! ```rust
//! use sb_metrics::{inc_router_match, inc_outbound_connect_attempt, observe_outbound_connect_seconds};
//!
//! // 记录路由匹配
//! inc_router_match("domain_suffix", "direct");
//!
//! // 记录出站连接
//! inc_outbound_connect_attempt("socks");
//! observe_outbound_connect_seconds("socks", 0.123);
//! ```

#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, clippy::nursery)]

pub mod cardinality; // Cardinality monitoring for label explosion prevention
pub mod http; // HTTP 侧指标（入站/上游代理共用）
pub mod server; // Metrics server implementation
pub mod socks; // SOCKS 侧指标
pub mod transfer; // 通用传输指标（带宽/字节数）
pub mod inbound; // 入站统一错误指标
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    sync::LazyLock,
    time::{Duration, Instant},
};

use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

mod labels;

fn guarded_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    labels::ensure_allowed_labels(name, labels);
    // Safe construction; if it fails, fall back to dummy with a generic label
    IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)]
        IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
}

fn guarded_histogram_vec(name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> HistogramVec {
    labels::ensure_allowed_labels(name, labels);
    let opts = HistogramOpts::new(name, help).buckets(buckets);
    #[allow(clippy::unwrap_used)]
    HistogramVec::new(opts, labels).unwrap()
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

pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

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
    use super::{IntCounterVec, LazyLock, REGISTRY};
    /// 路由命中计数：按规则类别与出站类型维度统计
    /// labels: category = {"`domain_suffix`","`ip_cidr`","`advanced`","`default`",...},
    ///         outbound = {"direct","block","socks","http",...}
    pub static ROUTER_MATCH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "router_rule_match_total",
            "Router rule matches total by category and outbound",
            &["category", "outbound"],
        );
        REGISTRY.register(Box::new(vec.clone())).ok();
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
    use super::{HistogramVec, IntCounterVec, LazyLock, REGISTRY};

    /// 出站连接尝试总数（含成功/失败），用于比对失败率
    pub static CONNECT_ATTEMPT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "outbound_connect_attempt_total",
            "Outbound connect attempts",
            &["kind"], // direct | socks | http | other
        );
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// 出站连接失败计数
    pub static CONNECT_ERROR_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "outbound_connect_error_total",
            "Outbound connect errors",
            &["kind", "class"], // class: dns | timeout | io | tls | other
        );
        REGISTRY.register(Box::new(v.clone())).ok();
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
        REGISTRY.register(Box::new(v.clone())).ok();
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
    use super::{HistogramVec, IntCounterVec, LazyLock, REGISTRY};

    /// Adapter dial total counter - tracks all dial attempts with results
    /// labels: adapter = {"socks5", "http"}, result = {"ok", "timeout", "`proto_err`", "`auth_err`", "`io_err`"}
    pub static DIAL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let vec = super::guarded_counter_vec(
            "adapter_dial_total",
            "Adapter dial attempts total by adapter and result",
            &["adapter", "result"],
        );
        REGISTRY.register(Box::new(vec.clone())).ok();
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
        REGISTRY.register(Box::new(v.clone())).ok();
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
        REGISTRY.register(Box::new(vec.clone())).ok();
        vec
    });
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

// ===================== SOCKS Inbound Metrics =====================
/// SOCKS inbound metrics: TCP connections, UDP associations and packets
mod socks_in {
    use super::{IntCounter, IntCounterVec, IntGauge, LazyLock, REGISTRY};

    /// SOCKS TCP 连接总数（握手成功即计数）
    pub static TCP_CONN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        #[allow(clippy::unwrap_used)] // Metrics initialization failure at startup is acceptable
        let c = IntCounter::new(
            "inbound_socks_tcp_connections_total",
            "SOCKS inbound accepted TCP connections total",
        )
        .unwrap();
        REGISTRY.register(Box::new(c.clone())).ok();
        c
    });

    /// UDP 关联创建总数
    pub static UDP_ASSOC_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        #[allow(clippy::unwrap_used)] // Metrics initialization failure at startup is acceptable
        let c = IntCounter::new(
            "inbound_socks_udp_associate_total",
            "SOCKS inbound UDP ASSOCIATE total",
        )
        .unwrap();
        REGISTRY.register(Box::new(c.clone())).ok();
        c
    });

    /// UDP 包计数：方向 in -> server / out -> client
    pub static UDP_PKTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "inbound_socks_udp_packets_total",
            "SOCKS inbound UDP packets",
            &["dir"], // "in" | "out"
        );
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// UDP 当前关联估算（需要上层周期更新，可选）
    pub static UDP_ASSOC_ESTIMATE: LazyLock<IntGauge> = LazyLock::new(|| {
        #[allow(clippy::unwrap_used)] // Metrics initialization failure at startup is acceptable
        let g = IntGauge::new(
            "inbound_socks_udp_assoc_estimate",
            "SOCKS inbound UDP associations (approximate)",
        )
        .unwrap();
        REGISTRY.register(Box::new(g.clone())).ok();
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
    use super::{HistogramOpts, IntCounter, IntCounterVec, IntGauge, LazyLock, Opts, REGISTRY};
    use prometheus::{GaugeVec, Histogram};

    /// UDP NAT map size
    pub static UDP_MAP_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
        let g = IntGauge::new("udp_map_size", "UDP NAT table size").unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback to dummy gauge
            IntGauge::new("dummy_gauge", "dummy").unwrap()
        });
        REGISTRY.register(Box::new(g.clone())).ok();
        g
    });

    /// UDP NAT eviction counter
    pub static UDP_EVICT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "udp_evict_total",
            "UDP NAT eviction total",
            &["reason"], // ttl | pressure
        );
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// UDP failure counter
    pub static UDP_FAIL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec("udp_fail_total", "UDP failure total", &["class"]);
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// Route explain counter
    pub static ROUTE_EXPLAIN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
        let c = IntCounter::new("route_explain_total", "Route explain invocations").unwrap_or_else(
            |_| {
                #[allow(clippy::unwrap_used)] // Fallback to dummy counter
                IntCounter::new("dummy_counter", "dummy").unwrap()
            },
        );
        REGISTRY.register(Box::new(c.clone())).ok();
        c
    });

    /// TCP connect duration histogram
    pub static TCP_CONNECT_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
        let opts = HistogramOpts::new("tcp_connect_duration_seconds", "TCP connect duration")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]);
        let h = Histogram::with_opts(opts).unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback to dummy histogram
            Histogram::with_opts(HistogramOpts::new("dummy_histogram", "dummy")).unwrap()
        });
        REGISTRY.register(Box::new(h.clone())).ok();
        h
    });

    /// Proxy selection score gauge
    pub static PROXY_SELECT_SCORE: LazyLock<GaugeVec> = LazyLock::new(|| {
        let v = GaugeVec::new(
            Opts::new("proxy_select_score", "Proxy selection score"),
            &["proxy"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
        });
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// Outbound health status
    pub static OUTBOUND_UP: LazyLock<GaugeVec> = LazyLock::new(|| {
        let v = GaugeVec::new(
            Opts::new("outbound_up", "Outbound health status (1=up, 0=down)"),
            &["outbound"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
        });
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// Build info gauge
    #[allow(dead_code)] // Initialized for Prometheus export, never directly accessed
    pub static BUILD_INFO: LazyLock<IntGauge> = LazyLock::new(|| {
        let g = IntGauge::new("sb_build_info", "Build information").unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback to dummy gauge
            IntGauge::new("dummy_gauge", "dummy").unwrap()
        });
        REGISTRY.register(Box::new(g.clone())).ok();
        g.set(1);
        g
    });

    /// Prometheus HTTP export failure counter
    pub static PROM_HTTP_FAIL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "prom_http_fail_total",
            "Prometheus HTTP export failures",
            &["class"], // bind | conn | io | other
        );
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// UDP NAT entry TTL histogram
    pub static UDP_TTL_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
        let opts = HistogramOpts::new("udp_nat_ttl_seconds", "UDP NAT entry TTL distribution")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]);
        let h = Histogram::with_opts(opts).unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback to dummy histogram
            Histogram::with_opts(HistogramOpts::new("dummy_histogram", "dummy")).unwrap()
        });
        REGISTRY.register(Box::new(h.clone())).ok();
        h
    });

    /// Proxy selection counter
    pub static PROXY_SELECT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        let v = super::guarded_counter_vec(
            "proxy_select_total",
            "Proxy selection invocations",
            &["proxy"],
        );
        REGISTRY.register(Box::new(v.clone())).ok();
        v
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

async fn metrics_http(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metric_families = REGISTRY.gather();
            let mut buf = Vec::new();
            let encoder = TextEncoder::new();
            if encoder.encode(&metric_families, &mut buf).is_err() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("encoding error"))
                    .unwrap_or_default());
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buf))
                .unwrap_or_default())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap_or_default()),
    }
}

pub fn maybe_spawn_http_exporter_from_env() -> Option<JoinHandle<()>> {
    let addr = std::env::var("SB_METRICS_ADDR").ok()?;
    let sa: SocketAddr = match addr.parse() {
        Ok(x) => x,
        Err(e) => {
            warn!(addr=%addr, error=%e, "invalid SB_METRICS_ADDR, metrics disabled");
            return None;
        }
    };
    Some(tokio::spawn(async move {
        // 手工监听 + 逐连接 serve，避免不同 hyper 版本的 Server API 差异
        let listener = match TcpListener::bind(sa).await {
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
            tokio::spawn(async move {
                if let Err(e) = Http::new()
                    .serve_connection(stream, service_fn(metrics_http))
                    .await
                {
                    ERROR_RATE_LIMITER.log_connection_error(&e);
                }
            });
        }
    }))
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
pub fn export_prometheus() -> String {
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    encoder
        .encode(&metric_families, &mut buf)
        .expect("Prometheus encoding should never fail");
    String::from_utf8(buf).expect("Prometheus output should be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exporter_noise_smoke() {
        // Directly exercise the /metrics handler without binding sockets.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = metrics_http(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Exercise non-/metrics path
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/not-found")
            .body(Body::empty())
            .unwrap();
        let resp2 = metrics_http(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }
}
