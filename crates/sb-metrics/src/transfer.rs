//! 通用传输统计指标：累计字节数与简单吞吐观测。
//!
//! 该模块不直接挂接具体协议，供 inbound/outbound/pipeline 在关键路径上自行上报。
//!
//! ## 使用示例
//! ```rust
//! use sb_metrics::transfer::{add_bytes, TxWindow};
//!
//! // 记录传输字节
//! add_bytes("up", "tcp", 1024);
//! add_bytes("down", "udp", 2048);
//!
//! // 自动计时吞吐率
//! let mut window = TxWindow::start();
//! window.add(4096);
//! // Drop 时自动观测吞吐率
//! ```

use crate::labels::ensure_allowed_labels;
use prometheus::{
    opts, register_histogram, register_int_counter, register_int_counter_vec, Histogram,
    IntCounter, IntCounterVec,
};
use std::sync::LazyLock;
use std::time::Instant;

// =============================
// Constants
// =============================

const DIR_UP: &str = "up";
const DIR_DOWN: &str = "down";
const DIR_OTHER: &str = "other";

const CHAN_TCP: &str = "tcp";
const CHAN_UDP: &str = "udp";
const CHAN_TLS: &str = "tls";
const CHAN_H2: &str = "h2";
const CHAN_H3: &str = "h3";
const CHAN_OTHER: &str = "other";

/// Tracked channel types
const TRACKED_CHANNELS: &[&str] = &[CHAN_TCP, CHAN_UDP, CHAN_TLS, CHAN_H2, CHAN_H3];

// =============================
// Metrics
// =============================

/// 全局累计下行字节（server->client）
pub static BYTES_DOWN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "bytes_down_total",
        "Total bytes sent from server to clients"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 全局累计上行字节（client->server）
pub static BYTES_UP_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "bytes_up_total",
        "Total bytes received from clients to server"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 按方向与通道类型聚合的字节计数
pub static BYTES_TOTAL_VEC: LazyLock<IntCounterVec> = LazyLock::new(|| {
    ensure_allowed_labels("bytes_total", &["dir", "chan"]);
    register_int_counter_vec!(
        "bytes_total",
        "Total bytes by direction and channel",
        &["dir", "chan"] // dir: up|down, chan: tcp|udp|tls|h2|h3|other
    )
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter vec initialization
        IntCounterVec::new(prometheus::Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    })
});

/// 简单的时窗吞吐观测（单位：字节/秒），建议用于 O(秒) 级别粗观测
pub static THROUGHPUT_BPS: LazyLock<Histogram> = LazyLock::new(|| {
    // 桶：0.5KB/s 到 256MB/s，指数扩展
    let buckets = prometheus::exponential_buckets(512.0, 2.0, 20).unwrap_or_else(|_| {
        // Fallback to fixed buckets on exponential_buckets failure
        vec![
            512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0,
        ]
    });
    register_histogram!(prometheus::HistogramOpts::new(
        "throughput_bps",
        "Observed coarse-grained throughput in bytes per second"
    )
    .buckets(buckets))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy histogram initialization
        Histogram::with_opts(prometheus::HistogramOpts::new("dummy_histogram", "dummy")).unwrap()
    })
});

/// 便捷：上报字节数
pub fn add_bytes(dir: &str, chan: &str, n: usize) {
    // Safely convert usize to u64, saturating at u64::MAX
    let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);

    match dir {
        DIR_UP => BYTES_UP_TOTAL.inc_by(n_u64),
        DIR_DOWN => BYTES_DOWN_TOTAL.inc_by(n_u64),
        _ => {}
    }

    let normalized_dir = match dir {
        DIR_UP | DIR_DOWN => dir,
        _ => DIR_OTHER,
    };

    let normalized_chan = if TRACKED_CHANNELS.contains(&chan) {
        chan
    } else {
        CHAN_OTHER
    };

    BYTES_TOTAL_VEC
        .with_label_values(&[normalized_dir, normalized_chan])
        .inc_by(n_u64);
}

/// 便捷：以"处理一个传输周期"的方式观测吞吐（结束时根据 duration 与 bytes 计算）
pub struct TxWindow {
    t0: Instant,
    bytes: usize,
}

impl TxWindow {
    /// Start a new transmission window timer
    #[must_use]
    pub fn start() -> Self {
        Self {
            t0: Instant::now(),
            bytes: 0,
        }
    }

    /// Add bytes to the transmission window
    pub const fn add(&mut self, n: usize) {
        self.bytes = self.bytes.saturating_add(n);
    }
}

impl Drop for TxWindow {
    fn drop(&mut self) {
        let sec = self.t0.elapsed().as_secs_f64();
        if sec > 0.0 && self.bytes > 0 {
            // usize -> f64: precision loss acceptable for byte counts < 2^53
            #[allow(clippy::cast_precision_loss)]
            let bps = (self.bytes as f64) / sec;
            THROUGHPUT_BPS.observe(bps);
        }
    }
}
