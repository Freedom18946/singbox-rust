//! Minimal metrics registry for internal use (pull model by Prometheus).
//! 简化实现：以原子计数与固定桶直方图为主，避免额外依赖。
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::constants::{is_label_allowed, BUILD_INFO, UDP_UPSTREAM_MAP_SIZE, UDP_EVICT_TOTAL, UDP_UPSTREAM_FAIL_TOTAL, UDP_TTL_SECONDS, ROUTE_EXPLAIN_TOTAL, PROM_HTTP_FAIL, TCP_CONNECT_DURATION, PROXY_SELECT_SCORE, PROXY_SELECT_TOTAL, OUTBOUND_UP};

/// 计数器类型
#[derive(Default)]
pub struct Counter(AtomicU64);
impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add(&self, v: u64) {
        self.0.fetch_add(v, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 简化的 gauge
#[derive(Default)]
pub struct Gauge(AtomicU64);
impl Gauge {
    pub fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 带标签 Gauge（用于 `proxy_select_score` 等）
#[derive(Default)]
pub struct LabeledGauges {
    inner: Mutex<BTreeMap<Vec<(String, String)>, Gauge>>,
}
impl LabeledGauges {
    /// Sets a gauge value for the given labels
    ///
    /// # Panics
    ///
    /// Panics if any label key is not in the allowed whitelist
    pub fn set(&self, labels: &[(&str, &str)], v: f64) {
        for (k, _) in labels {
            assert!(is_label_allowed(k), "label '{k}' not allowed");
        }
        let key: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        if let Ok(mut g) = self.inner.lock() {
            let e = g.entry(key).or_default();
            e.set(v.to_bits());
        }
        // On lock poison, silently skip metrics update (graceful degradation)
    }
    #[must_use]
    pub fn snapshot(&self) -> Vec<(Vec<(String, String)>, f64)> {
        self.inner.lock().map_or_else(
            |_| Vec::new(), // Return empty on lock poison (graceful degradation)
            |g| g.iter()
                .map(|(k, v)| (k.clone(), f64::from_bits(v.get())))
                .collect()
        )
    }
}

/// 固定桶直方图（如 `ttl_seconds`）
pub struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
}
impl Histogram {
    #[must_use]
    pub fn new(buckets: Vec<f64>) -> Self {
        let counts = (0..buckets.len()).map(|_| AtomicU64::new(0)).collect();
        Self { buckets, counts }
    }
    pub fn observe(&self, v: f64) {
        for (i, b) in self.buckets.iter().enumerate() {
            if v <= *b {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // 溢出至最后一个桶（+Inf）
        self.counts[self.counts.len() - 1].fetch_add(1, Ordering::Relaxed);
    }
    #[must_use]
    pub fn snapshot(&self) -> Vec<(f64, u64)> {
        self.buckets
            .iter()
            .enumerate()
            .map(|(i, b)| (*b, self.counts[i].load(Ordering::Relaxed)))
            .collect()
    }
}

/// 带标签的计数器集合（标签严格白名单）
#[derive(Default)]
pub struct LabeledCounters {
    inner: Mutex<BTreeMap<Vec<(String, String)>, Counter>>,
}
impl LabeledCounters {
    /// Increments the counter for the given labels
    ///
    /// # Panics
    ///
    /// Panics if any label key is not in the allowed whitelist
    pub fn inc(&self, labels: &[(&str, &str)]) {
        for (k, _) in labels {
            assert!(is_label_allowed(k), "label '{k}' not allowed");
        }
        let key: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        if let Ok(mut g) = self.inner.lock() {
            let c = g.entry(key).or_default();
            c.inc();
        }
        // On lock poison, silently skip counter increment (graceful degradation)
    }
    pub fn snapshot(&self) -> Vec<(Vec<(String, String)>, u64)> {
        self.inner.lock().map_or_else(
            |_| Vec::new(), // Return empty on lock poison (graceful degradation)
            |g| g.iter().map(|(k, c)| (k.clone(), c.get())).collect()
        )
    }
}

/// 全局注册表
pub struct Registry {
    pub build_info: Gauge,
    pub udp_map_size: Gauge,
    pub udp_evict_total: LabeledCounters, // reason=lru|ttl|pressure
    pub udp_fail_total: LabeledCounters,  // class=timeout|icmp|refused|other
    pub udp_ttl_seconds: Histogram,       // 直方图
    pub route_explain_total: Counter,
    pub prom_http_fail: LabeledCounters, // class=bind|conn|io|other
    pub proxy_select_score: LabeledGauges, // outbound=*
    pub proxy_select_total: LabeledCounters, // outbound=*
    pub tcp_connect_duration: Histogram, // seconds buckets
    pub outbound_up: LabeledGauges,      // outbound=*
}

static REG: OnceLock<Registry> = OnceLock::new();

pub fn global() -> &'static Registry {
    REG.get_or_init(|| Registry {
        build_info: Gauge::default(),
        udp_map_size: Gauge::default(),
        udp_evict_total: LabeledCounters::default(),
        udp_fail_total: LabeledCounters::default(),
        udp_ttl_seconds: Histogram::new(vec![0.5, 1.0, 2.0, 5.0, 10.0, f64::INFINITY]),
        route_explain_total: Counter::default(),
        prom_http_fail: LabeledCounters::default(),
        proxy_select_score: LabeledGauges::default(),
        proxy_select_total: LabeledCounters::default(),
        tcp_connect_duration: Histogram::new(vec![
            0.05,
            0.1,
            0.2,
            0.5,
            1.0,
            2.0,
            5.0,
            f64::INFINITY,
        ]),
        outbound_up: LabeledGauges::default(),
    })
}

/// 文本导出（Prometheus 格式，极简）
#[must_use]
pub fn export_prometheus() -> String {
    let r = global();
    let mut out = String::new();
    let _ = writeln!(out, "# TYPE {BUILD_INFO} gauge");
    let _ = writeln!(out, "{BUILD_INFO} 1");
    let _ = writeln!(out, "# TYPE {UDP_UPSTREAM_MAP_SIZE} gauge");
    let _ = writeln!(out, "{UDP_UPSTREAM_MAP_SIZE} {}", r.udp_map_size.get());
    let _ = writeln!(out, "# TYPE {UDP_EVICT_TOTAL} counter");
    for (labels, v) in r.udp_evict_total.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{UDP_EVICT_TOTAL}{{{lbl}}} {v}");
    }
    let _ = writeln!(out, "# TYPE {UDP_UPSTREAM_FAIL_TOTAL} counter");
    for (labels, v) in r.udp_fail_total.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{UDP_UPSTREAM_FAIL_TOTAL}{{{lbl}}} {v}");
    }
    let _ = writeln!(out, "# TYPE {UDP_TTL_SECONDS} histogram");
    for (bucket, cnt) in r.udp_ttl_seconds.snapshot() {
        let _ = writeln!(
            out,
            "{UDP_TTL_SECONDS}_bucket{{le=\"{bucket}\"}} {cnt}"
        );
    }
    let _ = writeln!(out, "# TYPE {ROUTE_EXPLAIN_TOTAL} counter");
    let _ = writeln!(out, "{ROUTE_EXPLAIN_TOTAL} {}", r.route_explain_total.get());
    let _ = writeln!(out, "# TYPE {PROM_HTTP_FAIL} counter");
    for (labels, v) in r.prom_http_fail.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{PROM_HTTP_FAIL}{{{lbl}}} {v}");
    }
    let _ = writeln!(out, "# TYPE {TCP_CONNECT_DURATION} histogram");
    for (bucket, cnt) in r.tcp_connect_duration.snapshot() {
        let _ = writeln!(
            out,
            "{TCP_CONNECT_DURATION}_bucket{{le=\"{bucket}\"}} {cnt}"
        );
    }
    // 选择器指标
    let _ = writeln!(out, "# TYPE {PROXY_SELECT_SCORE} gauge");
    for (labels, v) in r.proxy_select_score.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{PROXY_SELECT_SCORE}{{{lbl}}} {v}");
    }
    let _ = writeln!(out, "# TYPE {PROXY_SELECT_TOTAL} counter");
    for (labels, v) in r.proxy_select_total.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{PROXY_SELECT_TOTAL}{{{lbl}}} {v}");
    }
    let _ = writeln!(out, "# TYPE {OUTBOUND_UP} gauge");
    for (labels, v) in r.outbound_up.snapshot() {
        let lbl = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(out, "{OUTBOUND_UP}{{{lbl}}} {v}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_works() {
        let h = Histogram::new(vec![1.0, 2.0, f64::INFINITY]);
        h.observe(0.1);
        h.observe(1.1);
        h.observe(10.0);
        let s = h.snapshot();
        assert_eq!(s.len(), 3);
        assert!(s[0].1 >= 1 && s[2].1 >= 1);
    }
}
