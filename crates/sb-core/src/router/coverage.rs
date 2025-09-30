use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

static COV: Lazy<DashMap<String, AtomicU64>> = Lazy::new(DashMap::new);
static ENABLED: Lazy<std::sync::atomic::AtomicBool> =
    Lazy::new(|| std::sync::atomic::AtomicBool::new(false));

pub fn enable_if_env() {
    if std::env::var("SB_RULE_COVERAGE").ok().as_deref() == Some("1") {
        ENABLED.store(true, Relaxed);
    }
}

pub fn bump(rule_id: &str) {
    if !ENABLED.load(Relaxed) {
        return;
    }
    COV.entry(rule_id.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Relaxed);
}

#[derive(Serialize, Clone)]
pub struct SnapshotEntry {
    pub rule_id: String,
    pub hits: u64,
}

pub fn snapshot() -> Vec<SnapshotEntry> {
    COV.iter()
        .map(|e| SnapshotEntry {
            rule_id: e.key().clone(),
            hits: e.value().load(Relaxed),
        })
        .collect()
}

pub fn reset() {
    COV.clear();
}
