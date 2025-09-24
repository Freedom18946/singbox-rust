#![cfg(feature = "metrics")]
use once_cell::sync::OnceCell;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};
use std::collections::HashMap;
use std::sync::Mutex;

fn reg() -> &'static prometheus::Registry {
    crate::metrics::registry()
}

static GAUGE_MAP: OnceCell<Mutex<HashMap<String, IntGaugeVec>>> = OnceCell::new();
static COUNTER_MAP: OnceCell<Mutex<HashMap<String, IntCounterVec>>> = OnceCell::new();
static HISTOGRAM_MAP: OnceCell<Mutex<HashMap<String, HistogramVec>>> = OnceCell::new();

pub fn get_or_register_gauge_vec(name: &str, help: &str, labels: &[&str]) -> &'static IntGaugeVec {
    let map = GAUGE_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap();

    if let Some(existing) = guard.get(name) {
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(existing) }
    } else {
        let gv = IntGaugeVec::new(Opts::new(name, help), labels).expect("gaugevec");
        let _ = reg().register(Box::new(gv.clone())); // ignore already registered
        guard.insert(name.to_string(), gv);
        let stored = guard.get(name).unwrap();
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(stored) }
    }
}

pub fn get_or_register_counter_vec(
    name: &str,
    help: &str,
    labels: &[&str],
) -> &'static IntCounterVec {
    let map = COUNTER_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap();

    if let Some(existing) = guard.get(name) {
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(existing) }
    } else {
        let cv = IntCounterVec::new(Opts::new(name, help), labels).expect("countervec");
        let _ = reg().register(Box::new(cv.clone()));
        guard.insert(name.to_string(), cv);
        let stored = guard.get(name).unwrap();
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(stored) }
    }
}

pub fn get_or_register_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> &'static HistogramVec {
    let map = HISTOGRAM_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap();

    if let Some(existing) = guard.get(name) {
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(existing) }
    } else {
        let opts = if let Some(buckets) = buckets {
            HistogramOpts::new(name, help).buckets(buckets)
        } else {
            HistogramOpts::new(name, help)
        };
        let hv = HistogramVec::new(opts, labels).expect("histogramvec");
        let _ = reg().register(Box::new(hv.clone()));
        guard.insert(name.to_string(), hv);
        let stored = guard.get(name).unwrap();
        // Safety: we return a static reference from a stable HashMap location
        unsafe { std::mem::transmute(stored) }
    }
}
