use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::{atomic::{AtomicU64, Ordering::Relaxed}, Arc};

static COV: Lazy<DashMap<String, AtomicU64>> = Lazy::new(DashMap::new);
static ENABLED: Lazy<std::sync::atomic::AtomicBool> =
    Lazy::new(|| std::sync::atomic::AtomicBool::new(false));

fn parse_rule_coverage_env(value: Option<&str>) -> Result<bool, Arc<str>> {
    match value {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(raw) => Err(format!(
            "router env 'SB_RULE_COVERAGE' value '{raw}' is not a recognized boolean; silent parse fallback is disabled; use '1'/'true' or '0'/'false'"
        )
        .into()),
        None => Ok(false),
    }
}

fn rule_coverage_from_env() -> bool {
    let raw = std::env::var("SB_RULE_COVERAGE").ok();
    match parse_rule_coverage_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default false");
            false
        }
    }
}

pub fn enable_if_env() {
    if rule_coverage_from_env() {
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

#[cfg(test)]
mod tests {
    use super::parse_rule_coverage_env;

    #[test]
    fn invalid_rule_coverage_env_reports_explicitly() {
        let err = parse_rule_coverage_env(Some("enabled"))
            .expect_err("unrecognized boolean env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_RULE_COVERAGE"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }
}
