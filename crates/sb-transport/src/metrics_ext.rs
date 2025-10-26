//! Minimal metrics registry helpers local to sb-transport to avoid depending on sb-core.
//!
//! These helpers mirror the small subset used within this crate and register
//! metrics into the shared sb-metrics registry. They are only compiled when the
//! `metrics` feature is enabled for sb-transport.


use once_cell::sync::OnceCell;
use prometheus::{IntCounterVec, Opts, GaugeVec};
use std::collections::HashMap;
use std::sync::Mutex;

// Caches to prevent duplicate registrations by metric name.
static COUNTER_VECS: OnceCell<Mutex<HashMap<String, IntCounterVec>>> = OnceCell::new();
static GAUGE_VECS: OnceCell<Mutex<HashMap<String, GaugeVec>>> = OnceCell::new();

fn counter_map() -> &'static Mutex<HashMap<String, IntCounterVec>> {
    COUNTER_VECS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn gauge_map() -> &'static Mutex<HashMap<String, GaugeVec>> {
    GAUGE_VECS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or lazily register) an IntCounterVec under the global sb-metrics registry.
pub fn get_or_register_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    // Fast path: try to get from cache first.
    if let Ok(map) = counter_map().lock() {
        if let Some(existing) = map.get(name) {
            return existing.clone();
        }
    }

    // Create and register a new counter vec.
    let vec = IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        // Fallback dummy counter on initialization failure — guarantees type availability.
        #[allow(clippy::unwrap_used)]
        IntCounterVec::new(Opts::new("dummy_counter", "dummy"), &["label"]).unwrap()
    });
    // Best-effort registration; ignore errors to avoid panics on duplicate names across processes.
    let _ = sb_metrics::REGISTRY.register(Box::new(vec.clone()));

    if let Ok(mut map) = counter_map().lock() {
        map.insert(name.to_string(), vec.clone());
    }
    vec
}

/// Get (or lazily register) a GaugeVec (f64) under the global sb-metrics registry.
pub fn get_or_register_gauge_vec_f64(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    if let Ok(map) = gauge_map().lock() {
        if let Some(existing) = map.get(name) {
            return existing.clone();
        }
    }

    let vec = GaugeVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| {
        // Fallback dummy gauge vector
        #[allow(clippy::unwrap_used)]
        GaugeVec::new(Opts::new("dummy_gauge", "dummy"), &["label"]).unwrap()
    });
    let _ = sb_metrics::REGISTRY.register(Box::new(vec.clone()));

    if let Ok(mut map) = gauge_map().lock() {
        map.insert(name.to_string(), vec.clone());
    }
    vec
}
