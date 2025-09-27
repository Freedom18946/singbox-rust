//! 通用传输统计指标：累计字节数与简单吞吐观测。
//! 该模块不直接挂接具体协议，供 inbound/outbound/pipeline 在关键路径上自行上报。
use once_cell::sync::Lazy;
use prometheus::{
    opts, register_histogram, register_int_counter, register_int_counter_vec, Histogram,
    IntCounter, IntCounterVec,
};
use std::time::Instant;

/// 全局累计下行字节（server->client）
pub static BYTES_DOWN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "bytes_down_total",
        "Total bytes sent from server to clients"
    ))
    .expect("register bytes_down_total")
});

/// 全局累计上行字节（client->server）
pub static BYTES_UP_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "bytes_up_total",
        "Total bytes received from clients to server"
    ))
    .expect("register bytes_up_total")
});

/// 按方向与通道类型聚合的字节计数
pub static BYTES_TOTAL_VEC: Lazy<IntCounterVec> = Lazy::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter_vec!(
        "bytes_total",
        "Total bytes by direction and channel",
        &["dir", "chan"] // dir: up|down, chan: tcp|udp|tls|h2|h3|other
    )
    .expect("register bytes_total_vec")
});

/// 简单的时窗吞吐观测（单位：字节/秒），建议用于 O(秒) 级别粗观测
pub static THROUGHPUT_BPS: Lazy<Histogram> = Lazy::new(|| {
    // 桶：0.5KB/s 到 256MB/s，指数扩展
    let buckets = prometheus::exponential_buckets(512.0, 2.0, 20).unwrap_or_else(|_| {
        // Fallback to fixed buckets on exponential_buckets failure
        vec![512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0]
    });
    #[allow(clippy::expect_used)]
    register_histogram!(prometheus::HistogramOpts::new(
        "throughput_bps",
        "Observed coarse-grained throughput in bytes per second"
    )
    .buckets(buckets))
    .expect("register throughput_bps")
});

/// 便捷：上报字节数
pub fn add_bytes(dir: &str, chan: &str, n: usize) {
    match dir {
        "up" => BYTES_UP_TOTAL.inc_by(n as u64),
        "down" => BYTES_DOWN_TOTAL.inc_by(n as u64),
        _ => {}
    }
    let d = match dir {
        "up" | "down" => dir,
        _ => "other",
    };
    let c = match chan {
        "tcp" | "udp" | "tls" | "h2" | "h3" => chan,
        _ => "other",
    };
    BYTES_TOTAL_VEC.with_label_values(&[d, c]).inc_by(n as u64);
}

/// 便捷：以"处理一个传输周期"的方式观测吞吐（结束时根据 duration 与 bytes 计算）
pub struct TxWindow {
    t0: Instant,
    bytes: usize,
}
impl TxWindow {
    pub fn start() -> Self {
        Self {
            t0: Instant::now(),
            bytes: 0,
        }
    }
    pub fn add(&mut self, n: usize) {
        self.bytes += n;
    }
}
impl Drop for TxWindow {
    fn drop(&mut self) {
        let sec = self.t0.elapsed().as_secs_f64();
        if sec > 0.0 && self.bytes > 0 {
            let bps = (self.bytes as f64) / sec;
            THROUGHPUT_BPS.observe(bps);
        }
    }
}
