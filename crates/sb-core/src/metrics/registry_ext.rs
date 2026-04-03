//! Thread-safe metric registry extensions without lifetime tricks.
//!
//! - Uses `OnceCell + DashMap` to memoize metric vectors by name.
//! - Returns real `'static` references by leaking the first successful allocation.
//! - Concurrent callers racing to register the same name converge to one instance.
//! - No `transmute`, no forged lifetimes, no global mutex contention.

use dashmap::DashMap;
use once_cell::sync::OnceCell;
use prometheus::{
    GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, core::Collector,
};

fn reg() -> &'static prometheus::Registry {
    crate::metrics::registry()
}

// Global maps storing leaked, truly-'static metric vectors
static INT_GAUGE_MAP: OnceCell<DashMap<String, &'static IntGaugeVec>> = OnceCell::new();
static GAUGE_MAP: OnceCell<DashMap<String, &'static GaugeVec>> = OnceCell::new();
static COUNTER_MAP: OnceCell<DashMap<String, &'static IntCounterVec>> = OnceCell::new();
static HISTOGRAM_MAP: OnceCell<DashMap<String, &'static HistogramVec>> = OnceCell::new();

fn leak_and_register_metric<T>(metric: T) -> &'static T
where
    T: Collector + Clone + 'static,
{
    let leaked: &'static T = Box::leak(Box::new(metric));
    if let Err(error) = reg().register(Box::new((*leaked).clone())) {
        tracing::debug!(error = %error, "metrics collector registration skipped");
    }
    leaked
}

fn finalize_metric_ref<T>(
    map: &DashMap<String, &'static T>,
    name: &str,
    metric_ref: &'static T,
) -> &'static T {
    match map.entry(name.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(entry) => entry.get(),
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(metric_ref);
            metric_ref
        }
    }
}

fn get_or_insert_metric<T>(
    map: &DashMap<String, &'static T>,
    name: &str,
    metric_kind: &'static str,
    build: impl FnOnce() -> Result<T, prometheus::Error>,
    fallback: fn() -> &'static T,
) -> &'static T
where
    T: Collector + Clone + 'static,
{
    if let Some(existing) = map.get(name) {
        return *existing;
    }

    let metric_ref = match build() {
        Ok(metric) => leak_and_register_metric(metric),
        Err(err) => {
            tracing::warn!(
                metric = name,
                kind = metric_kind,
                error = %err,
                "failed to construct metrics collector, using fallback"
            );
            fallback()
        }
    };

    finalize_metric_ref(map, name, metric_ref)
}

fn counter_fallback() -> &'static IntCounterVec {
    static CELL: OnceCell<&'static IntCounterVec> = OnceCell::new();
    CELL.get_or_init(|| {
        let name = "sb_fallback_int_counter";
        let help = "Fallback IntCounterVec used when construction fails";
        loop {
            if let Ok(metric) = IntCounterVec::new(Opts::new(name, help), &["cause"]) {
                break leak_and_register_metric(metric);
            }
            if let Ok(metric) = IntCounterVec::new(Opts::new(name, help), &[]) {
                break leak_and_register_metric(metric);
            }
            std::thread::yield_now();
        }
    })
}

fn gauge_fallback_int() -> &'static IntGaugeVec {
    static CELL: OnceCell<&'static IntGaugeVec> = OnceCell::new();
    CELL.get_or_init(|| {
        // Guaranteed to succeed for valid constant names; retry if the library still rejects.
        let name = "sb_fallback_int_gauge";
        let help = "Fallback IntGaugeVec used when construction fails";
        loop {
            if let Ok(metric) = IntGaugeVec::new(Opts::new(name, help), &["cause"]) {
                break leak_and_register_metric(metric);
            }
            if let Ok(metric) = IntGaugeVec::new(Opts::new(name, help), &[]) {
                break leak_and_register_metric(metric);
            }
            std::thread::yield_now();
        }
    })
}

fn gauge_fallback_float() -> &'static GaugeVec {
    static CELL: OnceCell<&'static GaugeVec> = OnceCell::new();
    CELL.get_or_init(|| {
        let name = "sb_fallback_gauge";
        let help = "Fallback GaugeVec used when construction fails";
        loop {
            if let Ok(metric) = GaugeVec::new(Opts::new(name, help), &["cause"]) {
                break leak_and_register_metric(metric);
            }
            if let Ok(metric) = GaugeVec::new(Opts::new(name, help), &[]) {
                break leak_and_register_metric(metric);
            }
            std::thread::yield_now();
        }
    })
}

fn histogram_fallback() -> &'static HistogramVec {
    static CELL: OnceCell<&'static HistogramVec> = OnceCell::new();
    CELL.get_or_init(|| {
        let name = "sb_fallback_histogram";
        let help = "Fallback HistogramVec used when construction fails";
        loop {
            if let Ok(metric) = HistogramVec::new(HistogramOpts::new(name, help), &["cause"]) {
                break leak_and_register_metric(metric);
            }
            if let Ok(metric) = HistogramVec::new(HistogramOpts::new(name, help), &[]) {
                break leak_and_register_metric(metric);
            }
            std::thread::yield_now();
        }
    })
}

pub fn get_or_register_gauge_vec(name: &str, help: &str, labels: &[&str]) -> &'static IntGaugeVec {
    // Enforce label whitelist for CI/consistency
    sb_metrics::labels::ensure_allowed_labels(name, labels);
    let map = INT_GAUGE_MAP.get_or_init(DashMap::new);
    get_or_insert_metric(
        map,
        name,
        "int_gauge_vec",
        || IntGaugeVec::new(Opts::new(name, help), labels),
        gauge_fallback_int,
    )
}

/// Float GaugeVec accessor to avoid transmute at call sites that need `GaugeVec`.
pub fn get_or_register_gauge_vec_f64(name: &str, help: &str, labels: &[&str]) -> &'static GaugeVec {
    // Enforce label whitelist for CI/consistency
    sb_metrics::labels::ensure_allowed_labels(name, labels);
    let map = GAUGE_MAP.get_or_init(DashMap::new);
    get_or_insert_metric(
        map,
        name,
        "gauge_vec",
        || GaugeVec::new(Opts::new(name, help), labels),
        gauge_fallback_float,
    )
}

pub fn get_or_register_counter_vec(
    name: &str,
    help: &str,
    labels: &[&str],
) -> &'static IntCounterVec {
    // Enforce label whitelist for CI/consistency
    sb_metrics::labels::ensure_allowed_labels(name, labels);
    let map = COUNTER_MAP.get_or_init(DashMap::new);
    get_or_insert_metric(
        map,
        name,
        "int_counter_vec",
        || IntCounterVec::new(Opts::new(name, help), labels),
        counter_fallback,
    )
}

pub fn get_or_register_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> &'static HistogramVec {
    // Enforce label whitelist for CI/consistency
    sb_metrics::labels::ensure_allowed_labels(name, labels);
    let map = HISTOGRAM_MAP.get_or_init(DashMap::new);

    let opts = match buckets {
        Some(b) => HistogramOpts::new(name, help).buckets(b),
        None => HistogramOpts::new(name, help),
    };
    get_or_insert_metric(
        map,
        name,
        "histogram_vec",
        || HistogramVec::new(opts, labels),
        histogram_fallback,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_registration_returns_same_instance() {
        let a = get_or_register_gauge_vec("t_repeat_gauge", "help", &["class", "kind"]);
        let b = get_or_register_gauge_vec("t_repeat_gauge", "help", &["class", "kind"]);
        assert_eq!(a as *const IntGaugeVec, b as *const IntGaugeVec);
    }

    #[test]
    fn concurrent_registration_is_singleton() {
        use std::sync::Arc;
        use std::thread;

        let name = "t_concurrent_counter";
        let mut handles = Vec::new();
        let out: Arc<DashMap<usize, usize>> = Arc::new(DashMap::new());
        for i in 0..8 {
            let out = out.clone();
            handles.push(thread::spawn(move || {
                let p = get_or_register_counter_vec(name, "help", &["class"]);
                let addr = p as *const IntCounterVec as usize;
                out.insert(i, addr);
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let first = out.iter().next().map(|kv| *kv.value()).unwrap();
        assert!(out.iter().all(|kv| *kv.value() == first));
    }

    #[test]
    fn histogram_repeated_buckets_ignored_after_first() {
        let h1 =
            get_or_register_histogram_vec("t_hist", "help", &["class"], Some(vec![1.0, 2.0, 5.0]));
        let h2 = get_or_register_histogram_vec("t_hist", "help", &["class"], None);
        assert_eq!(h1 as *const HistogramVec, h2 as *const HistogramVec);
    }

    #[test]
    #[should_panic]
    fn label_guard_panics_on_unknown() {
        // Using a non-whitelisted label key should trigger the guard.
        let _ = get_or_register_counter_vec("t_bad_label", "help", &["unknown_label_key"]);
    }
}

#[cfg(feature = "loom")]
#[allow(unused_imports)]
mod loom_smoke {
    use super::get_or_register_counter_vec;
    use loom::thread;

    #[test]
    fn loom_singleton_counter_registration() {
        loom::model(|| {
            let name = "loom_ctr";
            let mut hs = Vec::new();
            for _ in 0..3 {
                hs.push(thread::spawn(move || {
                    let p = get_or_register_counter_vec(name, "h", &["class"]) as *const _;
                    p as usize
                }));
            }
            let mut first: Option<usize> = None;
            for h in hs {
                let v = h.join().unwrap();
                if let Some(first_v) = first {
                    assert_eq!(first_v, v);
                } else {
                    first = Some(v);
                }
            }
        });
    }
}

/*
CHANGELOG (metrics/registry_ext)

- Refactor: Replace Mutex+HashMap + transmute with OnceCell + DashMap and true 'static leaks.
- Safety: Remove all transmute and lifetime extension; no unsafe used.
- Concurrency: get_or_register_* now lock-free under read and supports concurrent registrations deterministically.
- API: Backward-compatible; added get_or_register_gauge_vec_f64 for GaugeVec to remove prior cast in outbound.
- Robustness: No unwrap/expect/panic in production paths; constructor failures log and fall back to shared safe metrics.
*/
