//! HTTP 侧指标（入站/上游代理共用）。不绑定具体实现，供 app / inbound / outbound 自由调用。
//! 设计原则：
//! - 低耦合：调用方只负责把事件打点进来，不依赖具体 HTTP 栈。
//! - 标签控制：核心使用无标签 Counter/Gauge；少量场景用 `*_vec`，避免高基数炸表。
use prometheus::{
    opts, register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge,
};
use std::sync::LazyLock;
use std::time::Instant;

// =============================
// 入站 HTTP（代理）面指标
// =============================

/// 当前活跃 HTTP 连接（长连接含 keep-alive）
pub static HTTP_INFLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "http_inflight",
        "In-flight HTTP connections (keep-alive included)"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy gauge initialization
        IntGauge::new("dummy_gauge", "dummy").unwrap()
    })
});

/// 已接受的 HTTP 连接总数
pub static HTTP_CONN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!("http_conn_total", "Total accepted HTTP connections"))
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
            IntCounter::new("dummy_counter", "dummy").unwrap()
        })
});

/// CONNECT 请求总数（入站 HTTP 代理处理的隧道建立请求）
pub static HTTP_CONNECT_REQ_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "http_connect_req_total",
        "Total HTTP CONNECT requests received"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// CONNECT 成功建立的总数
pub static HTTP_CONNECT_OK_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "http_connect_ok_total",
        "Total successful HTTP CONNECT tunnels"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// CONNECT 失败总数（握手失败/上游失败/路由失败等）
pub static HTTP_CONNECT_FAIL_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "http_connect_fail_total",
        "Total failed HTTP CONNECT attempts"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 入站 HTTP 层错误（解析/协议/早期关闭等）
pub static HTTP_ERROR_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "http_error_total",
        "Total HTTP layer errors observed at inbound"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 入站请求总数（不区分方法/状态）
pub static HTTP_REQ_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "http_req_total",
        "Total HTTP requests handled by inbound"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 按方法维度的请求计数（避免高基数，仅固定方法集合）
pub static HTTP_METHOD_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "http_method_total",
        "HTTP requests by method",
        &["method"] // GET/HEAD/POST/PUT/DELETE/CONNECT 等
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
});

/// 按状态码段（2xx/3xx/4xx/5xx）的响应计数
pub static HTTP_STATUS_CLASS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "http_status_class_total",
        "HTTP responses by status class",
        &["class"] // "2xx" | "3xx" | "4xx" | "5xx"
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
});

/// 请求耗时直方图（毫秒）
pub static HTTP_REQ_DURATION_MS: LazyLock<Histogram> = LazyLock::new(|| {
    // 指数桶：2ms ~ 4096ms
    let buckets = prometheus::exponential_buckets(0.002, 2.0, 13).unwrap_or_else(|_| {
        // Fallback to linear buckets if exponential buckets fail
        vec![0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0]
    });
    register_histogram!(HistogramOpts {
        common_opts: opts!(
            "http_req_duration_ms",
            "HTTP request duration in milliseconds"
        ),
        buckets,
    })
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy histogram initialization
        Histogram::with_opts(HistogramOpts::new("dummy_histogram", "dummy")).unwrap()
    })
});

/// 按出站类型（direct/http/socks）的连接尝试
pub static HTTP_OUTBOUND_CONNECT_ATTEMPT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "http_outbound_connect_attempt_total",
        "Outbound connect attempts from HTTP pipeline",
        &["kind"] // "direct" | "http" | "socks"
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
});

/// 按出站类型的连接失败分类（`dns`/`tcp_timeout`/`tls`/`other`）
pub static HTTP_OUTBOUND_CONNECT_ERROR: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "http_outbound_connect_error_total",
        "Outbound connect errors from HTTP pipeline",
        &["kind", "class"]
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
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
#[must_use]
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

// =============================
// Metrics Export Failure Classification
// =============================

/// Metrics export failure classification
pub static METRICS_EXPORT_FAIL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "metrics_export_fail_total",
        "Metrics export failures by class",
        &["class"] // "encode_error" | "timeout" | "busy" | "net_error" | "other"
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
});

/// Record a metrics export failure with classification
pub fn record_export_failure(class: &str) {
    let normalized_class = match class {
        "encode_error" | "timeout" | "busy" | "net_error" => class,
        _ => "other",
    };
    METRICS_EXPORT_FAIL_TOTAL.with_label_values(&[normalized_class]).inc();
}

/// Convenience functions for common export failure scenarios
pub fn record_encode_error() {
    record_export_failure("encode_error");
}

pub fn record_timeout_error() {
    record_export_failure("timeout");
}

pub fn record_busy_error() {
    record_export_failure("busy");
}

pub fn record_net_error() {
    record_export_failure("net_error");
}

pub fn record_other_export_error() {
    record_export_failure("other");
}
