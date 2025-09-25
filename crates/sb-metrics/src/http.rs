//! HTTP 侧指标（入站/上游代理共用）。不绑定具体实现，供 app / inbound / outbound 自由调用。
//! 设计原则：
//! - 低耦合：调用方只负责把事件打点进来，不依赖具体 HTTP 栈。
//! - 标签控制：核心使用无标签 Counter/Gauge；少量场景用 `*_vec`，避免高基数炸表。
use once_cell::sync::Lazy;
use prometheus::{
    opts, register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge,
};
use std::time::Instant;

// =============================
// 入站 HTTP（代理）面指标
// =============================

/// 当前活跃 HTTP 连接（长连接含 keep-alive）
#[allow(clippy::expect_used)] // constructor-time only; programmer error if metrics registry fails
pub static HTTP_INFLIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(opts!(
        "http_inflight",
        "In-flight HTTP connections (keep-alive included)"
    ))
    .expect("register http_inflight")
});

/// 已接受的 HTTP 连接总数
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_CONN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!("http_conn_total", "Total accepted HTTP connections"))
        .expect("register http_conn_total")
});

/// CONNECT 请求总数（入站 HTTP 代理处理的隧道建立请求）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_CONNECT_REQ_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "http_connect_req_total",
        "Total HTTP CONNECT requests received"
    ))
    .expect("register http_connect_req_total")
});

/// CONNECT 成功建立的总数
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_CONNECT_OK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "http_connect_ok_total",
        "Total successful HTTP CONNECT tunnels"
    ))
    .expect("register http_connect_ok_total")
});

/// CONNECT 失败总数（握手失败/上游失败/路由失败等）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_CONNECT_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "http_connect_fail_total",
        "Total failed HTTP CONNECT attempts"
    ))
    .expect("register http_connect_fail_total")
});

/// 入站 HTTP 层错误（解析/协议/早期关闭等）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_ERROR_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "http_error_total",
        "Total HTTP layer errors observed at inbound"
    ))
    .expect("register http_error_total")
});

/// 入站请求总数（不区分方法/状态）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_REQ_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "http_req_total",
        "Total HTTP requests handled by inbound"
    ))
    .expect("register http_req_total")
});

/// 按方法维度的请求计数（避免高基数，仅固定方法集合）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_METHOD_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_method_total",
        "HTTP requests by method",
        &["method"] // GET/HEAD/POST/PUT/DELETE/CONNECT 等
    )
    .expect("register http_method_total")
});

/// 按状态码段（2xx/3xx/4xx/5xx）的响应计数
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_STATUS_CLASS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_status_class_total",
        "HTTP responses by status class",
        &["class"] // "2xx" | "3xx" | "4xx" | "5xx"
    )
    .expect("register http_status_class_total")
});

/// 请求耗时直方图（毫秒）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_REQ_DURATION_MS: Lazy<Histogram> = Lazy::new(|| {
    // 指数桶：2ms ~ 4096ms
    // Expect is at constructor-time; invalid input here indicates a programmer error.
    let buckets = prometheus::exponential_buckets(0.002, 2.0, 13).expect("make buckets");
    register_histogram!(HistogramOpts {
        common_opts: opts!(
            "http_req_duration_ms",
            "HTTP request duration in milliseconds"
        ),
        buckets,
    })
    .expect("register http_req_duration_ms")
});

/// 按出站类型（direct/http/socks）的连接尝试
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_OUTBOUND_CONNECT_ATTEMPT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_outbound_connect_attempt_total",
        "Outbound connect attempts from HTTP pipeline",
        &["kind"] // "direct" | "http" | "socks"
    )
    .expect("register http_outbound_connect_attempt_total")
});

/// 按出站类型的连接失败分类（dns/tcp_timeout/tls/other）
#[allow(clippy::expect_used)] // constructor-time only; programmer error
pub static HTTP_OUTBOUND_CONNECT_ERROR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_outbound_connect_error_total",
        "Outbound connect errors from HTTP pipeline",
        &["kind", "class"]
    )
    .expect("register http_outbound_connect_error_total")
});

/// 便捷：方法自增（未知方法会被聚合到 "OTHER"）
pub fn inc_method(method: &str) {
    let m = match method {
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" => {
            method
        }
        _ => "OTHER",
    };
    HTTP_METHOD_TOTAL.with_label_values(&[m]).inc();
}

/// 便捷：按 2xx/3xx/4xx/5xx 聚合状态码
pub fn inc_status(status: u16) {
    let class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    HTTP_STATUS_CLASS_TOTAL.with_label_values(&[class]).inc();
}

/// 便捷：开始 HTTP 请求计时，返回 Drop 时上报
pub fn start_req_timer() -> HttpReqTimer {
    HttpReqTimer { t0: Instant::now() }
}

pub struct HttpReqTimer {
    t0: Instant,
}
impl Drop for HttpReqTimer {
    fn drop(&mut self) {
        let dt = self.t0.elapsed();
        let ms = dt.as_secs_f64() * 1000.0;
        HTTP_REQ_DURATION_MS.observe(ms);
    }
}

/// 便捷：记录一次出站连接尝试
pub fn inc_outbound_attempt(kind: &str) {
    let k = match kind {
        "direct" | "http" | "socks" => kind,
        _ => "other",
    };
    HTTP_OUTBOUND_CONNECT_ATTEMPT.with_label_values(&[k]).inc();
}

/// 便捷：记录一次出站连接错误
pub fn inc_outbound_error(kind: &str, class: &str) {
    let k = match kind {
        "direct" | "http" | "socks" => kind,
        _ => "other",
    };
    let c = match class {
        "dns" | "tcp_timeout" | "tls" | "io" | "other" => class,
        _ => "other",
    };
    HTTP_OUTBOUND_CONNECT_ERROR.with_label_values(&[k, c]).inc();
}

/// 便捷：记录一次 CONNECT 请求 / 成功 / 失败
pub fn on_connect_req() {
    HTTP_CONNECT_REQ_TOTAL.inc();
}
pub fn on_connect_ok() {
    HTTP_CONNECT_OK_TOTAL.inc();
}
pub fn on_connect_fail() {
    HTTP_CONNECT_FAIL_TOTAL.inc();
}
