//! sb-metrics: 轻量 Prometheus 导出器 + 统一指标注册。
//! - 默认不启；设置 `SB_METRICS_ADDR=127.0.0.1:9090` 时自动监听。

pub mod constants;
pub mod http;
pub mod registry;
pub mod server;
pub mod socks;
pub mod transfer; // 新增：通用传输指标（带宽/字节数），后续按需接线
use std::{convert::Infallible, net::SocketAddr, sync::atomic::{AtomicU64, Ordering}, time::{Duration, Instant}};

use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn, debug};

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

static ERROR_RATE_LIMITER: Lazy<ErrorRateLimiter> = Lazy::new(ErrorRateLimiter::new);

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

// ===================== Router Metrics =====================
mod router {
    use super::*;
    /// 路由命中计数：按规则类别与出站类型维度统计
    /// labels: category = {"domain_suffix","ip_cidr","advanced","default",...},
    ///         outbound = {"direct","block","socks","http",...}
    pub static ROUTER_MATCH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let vec = IntCounterVec::new(
            prometheus::Opts::new(
                "router_rule_match_total",
                "Router rule matches total by category and outbound",
            ),
            &["category", "outbound"],
        )
        .unwrap_or_else(|_| {
            // Fallback to a dummy counter on initialization failure
            #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
            IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
        });
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
mod outbound {
    use super::*;

    /// 出站连接尝试总数（含成功/失败），用于比对失败率
    pub static CONNECT_ATTEMPT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let v = IntCounterVec::new(
            Opts::new(
                "outbound_connect_attempt_total",
                "Outbound connect attempts",
            ),
            &["kind"], // direct | socks | http | other
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
            IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
        });
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// 出站连接失败计数
    pub static CONNECT_ERROR_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let v = IntCounterVec::new(
            Opts::new("outbound_connect_error_total", "Outbound connect errors"),
            &["kind", "class"], // class: dns | timeout | io | tls | other
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
            IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
        });
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// 出站连接成功直方图（秒）
    pub static CONNECT_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
        // 预置桶：1ms~10s，覆盖直连与代理常见场景
        let opts = HistogramOpts::new(
            "outbound_connect_seconds",
            "Outbound connect latency (seconds)",
        )
        .buckets(vec![
            0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0,
        ]);
        #[allow(clippy::unwrap_used)] // Metrics initialization failure at startup is acceptable
        let v = HistogramVec::new(opts, &["kind"]).unwrap();
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

/// 简单的错误分类器，用于 `inc_outbound_connect_error`
/// 接受一切实现 `Display` 的错误类型，避免跨 crate trait 约束导致的类型不匹配。
pub fn classify_error<E: core::fmt::Display + ?Sized>(e: &E) -> &'static str {
    let s = e.to_string();
    // 极简分类——后续根据实际错误类型细化
    if s.contains("timed out") || s.contains("timeout") {
        "timeout"
    } else if s.contains("dns") || s.contains("resolve") || s.contains("Name or service not known")
    {
        "dns"
    } else if s.contains("tls") || s.contains("certificate") {
        "tls"
    } else {
        "io"
    }
}

// ===================== Adapter Metrics (SOCKS/HTTP) =====================
mod adapter {
    use super::*;

    /// Adapter dial total counter - tracks all dial attempts with results
    /// labels: adapter = {"socks5", "http"}, result = {"ok", "timeout", "proto_err", "auth_err", "io_err"}
    pub static DIAL_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let vec = IntCounterVec::new(
            prometheus::Opts::new(
                "adapter_dial_total",
                "Adapter dial attempts total by adapter and result",
            ),
            &["adapter", "result"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
        });
        REGISTRY.register(Box::new(vec.clone())).ok();
        vec
    });

    /// Adapter dial latency histogram in milliseconds
    /// labels: adapter = {"socks5", "http"}
    pub static DIAL_LATENCY_MS: Lazy<HistogramVec> = Lazy::new(|| {
        let opts = HistogramOpts::new(
            "adapter_dial_latency_ms",
            "Adapter dial latency in milliseconds",
        )
        .buckets(vec![
            1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0,
        ]);
        #[allow(clippy::unwrap_used)]
        let v = HistogramVec::new(opts, &["adapter"]).unwrap();
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// Adapter retry attempts counter
    /// labels: adapter = {"socks5", "http"}
    pub static RETRIES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let vec = IntCounterVec::new(
            prometheus::Opts::new(
                "adapter_retries_total",
                "Adapter retry attempts total",
            ),
            &["adapter"],
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
        });
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
    adapter::RETRIES_TOTAL
        .with_label_values(&[adapter])
        .inc();
}

/// Helper function to classify adapter errors into metric result categories
pub fn classify_adapter_error<E: core::fmt::Display + ?Sized>(e: &E) -> &'static str {
    let s = e.to_string();
    if s.contains("timeout") || s.contains("timed out") {
        "timeout"
    } else if s.contains("Authentication") || s.contains("auth") {
        "auth_err"
    } else if s.contains("Protocol") || s.contains("Invalid") || s.contains("Unsupported") {
        "proto_err"
    } else {
        "io_err"
    }
}

/// Helper to start timing an adapter operation
pub fn start_adapter_timer() -> Instant {
    Instant::now()
}

/// Helper to record the latency and result for an adapter operation
pub fn record_adapter_dial(adapter: &str, start_time: Instant, result: Result<(), &dyn core::fmt::Display>) {
    let latency_ms = start_time.elapsed().as_millis() as f64;
    observe_adapter_dial_latency_ms(adapter, latency_ms);

    let result_label = match result {
        Ok(()) => "ok",
        Err(e) => classify_adapter_error(e),
    };
    inc_adapter_dial_total(adapter, result_label);
}

// ===================== SOCKS Inbound Metrics =====================
mod socks_in {
    use super::*;

    /// SOCKS TCP 连接总数（握手成功即计数）
    pub static TCP_CONN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
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
    pub static UDP_ASSOC_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
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
    pub static UDP_PKTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        #[allow(clippy::unwrap_used)] // Metrics initialization failure at startup is acceptable
        let v = IntCounterVec::new(
            Opts::new(
                "inbound_socks_udp_packets_total",
                "SOCKS inbound UDP packets",
            ),
            &["dir"], // "in" | "out"
        )
        .unwrap();
        REGISTRY.register(Box::new(v.clone())).ok();
        v
    });

    /// UDP 当前关联估算（需要上层周期更新，可选）
    pub static UDP_ASSOC_ESTIMATE: Lazy<IntGauge> = Lazy::new(|| {
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
/// 便捷：设置 UDP 关联估算（上层有 map.size() 时可更新）
pub fn set_socks_udp_assoc_estimate(n: i64) {
    socks_in::UDP_ASSOC_ESTIMATE.set(n);
}

async fn metrics_http(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metric_families = REGISTRY.gather();
            let mut buf = Vec::new();
            let encoder = TextEncoder::new();
            if encoder.encode(&metric_families, &mut buf).is_err() {
                return Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("encoding error")).unwrap_or_default());
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
