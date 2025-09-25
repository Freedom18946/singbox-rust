use once_cell::sync::OnceCell;
use std::sync::Mutex;

fn json_diff_enhanced(before: &serde_json::Value, after: &serde_json::Value) -> serde_json::Value {
    use serde_json::{json, Value};

    let mut add = serde_json::Map::new();
    let mut remove = serde_json::Map::new();
    let mut replace = serde_json::Map::new();

    if let (Value::Object(a), Value::Object(b)) = (before, after) {
        // Find added and changed fields
        for (k, vb) in b {
            if let Some(va) = a.get(k) {
                if va != vb {
                    replace.insert(k.clone(), json!({"from": va, "to": vb}));
                }
            } else {
                add.insert(k.clone(), vb.clone());
            }
        }
        // Find removed fields
        for (k, va) in a {
            if !b.contains_key(k) {
                remove.insert(k.clone(), va.clone());
            }
        }
    }

    json!({
        "add": Value::Object(add),
        "remove": Value::Object(remove),
        "replace": Value::Object(replace)
    })
}

fn diff_is_empty(diff: &serde_json::Value) -> bool {
    if let Some(obj) = diff.as_object() {
        let add_empty = obj.get("add").and_then(|v| v.as_object()).map_or(true, |o| o.is_empty());
        let remove_empty = obj.get("remove").and_then(|v| v.as_object()).map_or(true, |o| o.is_empty());
        let replace_empty = obj.get("replace").and_then(|v| v.as_object()).map_or(true, |o| o.is_empty());
        add_empty && remove_empty && replace_empty
    } else {
        true
    }
}

// Legacy function for compatibility
fn json_diff(before: &serde_json::Value, after: &serde_json::Value) -> serde_json::Value {
    json_diff_enhanced(before, after)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct EnvConfig {
    pub max_redirects: usize,
    pub timeout_ms: u64,
    pub max_bytes: usize,
    pub mime_allow: Option<Vec<String>>,
    pub mime_deny: Option<Vec<String>>,
    pub max_concurrency: usize,
    pub rps: u64,
    pub cache_capacity: usize,
    pub cache_ttl_ms: u64,
    pub breaker_window_ms: u64,
    pub breaker_open_ms: u64,
    pub breaker_failures: u32,
    pub breaker_ratio: f32,
}

impl EnvConfig {
    pub fn from_env() -> Self {
        let mime_allow = std::env::var("SB_SUBS_MIME_ALLOW")
            .ok()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());

        let mime_deny = std::env::var("SB_SUBS_MIME_DENY")
            .ok()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());

        Self {
            max_redirects: std::env::var("SB_SUBS_MAX_REDIRECTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),

            timeout_ms: std::env::var("SB_SUBS_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),

            max_bytes: std::env::var("SB_SUBS_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512 * 1024),

            mime_allow,
            mime_deny,

            max_concurrency: std::env::var("SB_SUBS_MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),

            rps: std::env::var("SB_SUBS_RPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),

            cache_capacity: std::env::var("SB_SUBS_CACHE_CAP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),

            cache_ttl_ms: std::env::var("SB_SUBS_CACHE_TTL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30_000),

            breaker_window_ms: std::env::var("SB_SUBS_BR_WIN_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30_000),

            breaker_open_ms: std::env::var("SB_SUBS_BR_OPEN_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15_000),

            breaker_failures: std::env::var("SB_SUBS_BR_FAILS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),

            breaker_ratio: std::env::var("SB_SUBS_BR_RATIO")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.5),
        }
    }
}

static CONFIG: OnceCell<Mutex<EnvConfig>> = OnceCell::new();
static VERSION: OnceCell<Mutex<u64>> = OnceCell::new();

pub fn get() -> EnvConfig {
    CONFIG
        .get_or_init(|| Mutex::new(EnvConfig::from_env()))
        .lock()
        .unwrap()
        .clone()
}

pub fn apply(delta: &crate::admin_debug::endpoints::config::ConfigDelta) -> Result<String, String> {
    let config_mutex = CONFIG.get_or_init(|| Mutex::new(EnvConfig::from_env()));

    let mut config = config_mutex.lock().map_err(|e| format!("Failed to acquire config lock: {}", e))?;
    let mut changes = Vec::new();

    // Apply changes from delta
    if let Some(max_redirects) = delta.max_redirects {
        if max_redirects > 20 {
            return Err("max_redirects too large (max: 20)".to_string());
        }
        config.max_redirects = max_redirects;
        changes.push(format!("max_redirects: {}", max_redirects));
    }

    if let Some(timeout_ms) = delta.timeout_ms {
        if timeout_ms < 100 || timeout_ms > 60000 {
            return Err("timeout_ms out of range (100-60000)".to_string());
        }
        config.timeout_ms = timeout_ms;
        changes.push(format!("timeout_ms: {}", timeout_ms));
    }

    if let Some(max_bytes) = delta.max_bytes {
        if max_bytes > 10 * 1024 * 1024 {
            return Err("max_bytes too large (max: 10MB)".to_string());
        }
        config.max_bytes = max_bytes;
        changes.push(format!("max_bytes: {}", max_bytes));
    }

    if let Some(max_concurrency) = delta.max_concurrency {
        if max_concurrency == 0 || max_concurrency > 1000 {
            return Err("max_concurrency out of range (1-1000)".to_string());
        }
        config.max_concurrency = max_concurrency;
        changes.push(format!("max_concurrency: {}", max_concurrency));
    }

    if let Some(rps) = delta.rps {
        if rps == 0 || rps > 10000 {
            return Err("rps out of range (1-10000)".to_string());
        }
        config.rps = rps;
        changes.push(format!("rps: {}", rps));
    }

    if let Some(cache_capacity) = delta.cache_capacity {
        if cache_capacity > 10000 {
            return Err("cache_capacity too large (max: 10000)".to_string());
        }
        config.cache_capacity = cache_capacity;
        changes.push(format!("cache_capacity: {}", cache_capacity));
    }

    if let Some(cache_ttl_ms) = delta.cache_ttl_ms {
        if cache_ttl_ms > 24 * 60 * 60 * 1000 {
            return Err("cache_ttl_ms too large (max: 24h)".to_string());
        }
        config.cache_ttl_ms = cache_ttl_ms;
        changes.push(format!("cache_ttl_ms: {}", cache_ttl_ms));
    }

    if let Some(breaker_window_ms) = delta.breaker_window_ms {
        if breaker_window_ms < 1000 || breaker_window_ms > 5 * 60 * 1000 {
            return Err("breaker_window_ms out of range (1s-5min)".to_string());
        }
        config.breaker_window_ms = breaker_window_ms;
        changes.push(format!("breaker_window_ms: {}", breaker_window_ms));
    }

    if let Some(breaker_open_ms) = delta.breaker_open_ms {
        if breaker_open_ms < 1000 || breaker_open_ms > 10 * 60 * 1000 {
            return Err("breaker_open_ms out of range (1s-10min)".to_string());
        }
        config.breaker_open_ms = breaker_open_ms;
        changes.push(format!("breaker_open_ms: {}", breaker_open_ms));
    }

    if let Some(breaker_failures) = delta.breaker_failures {
        if breaker_failures == 0 || breaker_failures > 100 {
            return Err("breaker_failures out of range (1-100)".to_string());
        }
        config.breaker_failures = breaker_failures;
        changes.push(format!("breaker_failures: {}", breaker_failures));
    }

    if let Some(breaker_ratio) = delta.breaker_ratio {
        if breaker_ratio < 0.1 || breaker_ratio > 1.0 {
            return Err("breaker_ratio out of range (0.1-1.0)".to_string());
        }
        config.breaker_ratio = breaker_ratio;
        changes.push(format!("breaker_ratio: {:.2}", breaker_ratio));
    }

    if changes.is_empty() {
        return Ok("No changes applied".to_string());
    }

    // Apply hot updates to subsystems
    #[cfg(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox"))]
    crate::admin_debug::endpoints::subs::resize_limiters(config.max_concurrency, config.rps);

    tracing::info!(changes = ?changes, "Configuration applied via API");

    Ok(format!("Applied changes: {}", changes.join(", ")))
}

pub fn version() -> u64 {
    VERSION
        .get_or_init(|| Mutex::new(0))
        .lock()
        .unwrap()
        .clone()
}

#[derive(serde::Serialize)]
pub struct ApplyResult {
    pub ok: bool,
    pub msg: String,
    pub version: u64,
    pub changed: bool,
    pub diff: serde_json::Value,
}

fn apply_to_config(config: &mut EnvConfig, delta: &crate::admin_debug::endpoints::config::ConfigDelta) -> Result<Vec<String>, String> {
    let mut changes = Vec::new();

    if let Some(max_redirects) = delta.max_redirects {
        if max_redirects > 20 {
            return Err("max_redirects too large (max: 20)".to_string());
        }
        config.max_redirects = max_redirects;
        changes.push(format!("max_redirects: {}", max_redirects));
    }

    if let Some(timeout_ms) = delta.timeout_ms {
        if timeout_ms < 100 || timeout_ms > 60000 {
            return Err("timeout_ms out of range (100-60000)".to_string());
        }
        config.timeout_ms = timeout_ms;
        changes.push(format!("timeout_ms: {}", timeout_ms));
    }

    if let Some(max_bytes) = delta.max_bytes {
        if max_bytes > 10 * 1024 * 1024 {
            return Err("max_bytes too large (max: 10MB)".to_string());
        }
        config.max_bytes = max_bytes;
        changes.push(format!("max_bytes: {}", max_bytes));
    }

    if let Some(max_concurrency) = delta.max_concurrency {
        if max_concurrency == 0 || max_concurrency > 1000 {
            return Err("max_concurrency out of range (1-1000)".to_string());
        }
        config.max_concurrency = max_concurrency;
        changes.push(format!("max_concurrency: {}", max_concurrency));
    }

    if let Some(rps) = delta.rps {
        if rps == 0 || rps > 10000 {
            return Err("rps out of range (1-10000)".to_string());
        }
        config.rps = rps;
        changes.push(format!("rps: {}", rps));
    }

    if let Some(cache_capacity) = delta.cache_capacity {
        if cache_capacity > 10000 {
            return Err("cache_capacity too large (max: 10000)".to_string());
        }
        config.cache_capacity = cache_capacity;
        changes.push(format!("cache_capacity: {}", cache_capacity));
    }

    if let Some(cache_ttl_ms) = delta.cache_ttl_ms {
        if cache_ttl_ms > 24 * 60 * 60 * 1000 {
            return Err("cache_ttl_ms too large (max: 24h)".to_string());
        }
        config.cache_ttl_ms = cache_ttl_ms;
        changes.push(format!("cache_ttl_ms: {}", cache_ttl_ms));
    }

    if let Some(breaker_window_ms) = delta.breaker_window_ms {
        if breaker_window_ms < 1000 || breaker_window_ms > 5 * 60 * 1000 {
            return Err("breaker_window_ms out of range (1s-5min)".to_string());
        }
        config.breaker_window_ms = breaker_window_ms;
        changes.push(format!("breaker_window_ms: {}", breaker_window_ms));
    }

    if let Some(breaker_open_ms) = delta.breaker_open_ms {
        if breaker_open_ms < 1000 || breaker_open_ms > 10 * 60 * 1000 {
            return Err("breaker_open_ms out of range (1s-10min)".to_string());
        }
        config.breaker_open_ms = breaker_open_ms;
        changes.push(format!("breaker_open_ms: {}", breaker_open_ms));
    }

    if let Some(breaker_failures) = delta.breaker_failures {
        if breaker_failures == 0 || breaker_failures > 100 {
            return Err("breaker_failures out of range (1-100)".to_string());
        }
        config.breaker_failures = breaker_failures;
        changes.push(format!("breaker_failures: {}", breaker_failures));
    }

    if let Some(breaker_ratio) = delta.breaker_ratio {
        if breaker_ratio < 0.1 || breaker_ratio > 1.0 {
            return Err("breaker_ratio out of range (0.1-1.0)".to_string());
        }
        config.breaker_ratio = breaker_ratio;
        changes.push(format!("breaker_ratio: {:.2}", breaker_ratio));
    }

    Ok(changes)
}

pub fn apply_with_dryrun(delta: &crate::admin_debug::endpoints::config::ConfigDelta, dry_run: bool) -> Result<ApplyResult, String> {
    let config_mutex = CONFIG.get_or_init(|| Mutex::new(EnvConfig::from_env()));
    let version_mutex = VERSION.get_or_init(|| Mutex::new(0));

    let config = config_mutex.lock().map_err(|e| format!("Failed to acquire config lock: {}", e))?;
    let before = serde_json::to_value(&*config).unwrap();

    // Create a temp copy and apply changes to compute diff
    let mut temp_config = config.clone();
    let _changes = apply_to_config(&mut temp_config, delta)?;

    let after = serde_json::to_value(&temp_config).unwrap();
    let diff = json_diff_enhanced(&before, &after);
    let changed = !diff_is_empty(&diff);

    let current_version = version_mutex.lock().unwrap().clone();

    if dry_run {
        Ok(ApplyResult {
            ok: false,
            msg: "dryrun".to_string(),
            version: current_version,
            changed,
            diff,
        })
    } else if changed {
        // Apply changes to actual config and bump version
        drop(config); // Release config lock before calling apply
        match apply(delta) {
            Ok(msg) => {
                let mut ver = version_mutex.lock().unwrap();
                *ver += 1;
                let new_version = *ver;

                Ok(ApplyResult {
                    ok: true,
                    msg,
                    version: new_version,
                    changed: true,
                    diff,
                })
            }
            Err(e) => Err(e),
        }
    } else {
        // No changes, don't bump version
        Ok(ApplyResult {
            ok: true,
            msg: "no changes".to_string(),
            version: current_version,
            changed: false,
            diff,
        })
    }
}

pub fn reload() {
    if let Some(mutex) = CONFIG.get() {
        if let Ok(mut config) = mutex.lock() {
            *config = EnvConfig::from_env();
            tracing::info!("Configuration reloaded from environment variables");

            // Apply hot updates to subsystems
            #[cfg(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox"))]
            crate::admin_debug::endpoints::subs::resize_limiters(config.max_concurrency, config.rps);
        }
    }
}

pub fn init_signal_handler() {
    tokio::spawn(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::hangup()) {
                while stream.recv().await.is_some() {
                    tracing::info!("Received SIGHUP, reloading configuration");
                    reload();
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, we can't handle SIGHUP, but we can still support manual reloading
            tracing::warn!("SIGHUP signal handling not supported on this platform");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = EnvConfig::from_env();
        assert_eq!(config.max_redirects, 3);
        assert_eq!(config.timeout_ms, 4000);
        assert_eq!(config.max_bytes, 512 * 1024);
        assert_eq!(config.max_concurrency, 8);
        assert_eq!(config.rps, 4);
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "5");
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "6000");
        std::env::set_var("SB_SUBS_MIME_ALLOW", "text/plain,application/json");

        let config = EnvConfig::from_env();
        assert_eq!(config.max_redirects, 5);
        assert_eq!(config.timeout_ms, 6000);
        assert_eq!(config.mime_allow.as_ref().unwrap().len(), 2);
        assert_eq!(config.mime_allow.as_ref().unwrap()[0], "text/plain");

        // Cleanup
        std::env::remove_var("SB_SUBS_MAX_REDIRECTS");
        std::env::remove_var("SB_SUBS_TIMEOUT_MS");
        std::env::remove_var("SB_SUBS_MIME_ALLOW");
    }

    #[test]
    fn test_reload() {
        // Set initial config
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "2");
        let config1 = get();
        assert_eq!(config1.max_redirects, 2);

        // Change env var
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "7");

        // Reload should pick up new value
        reload();
        let config2 = get();
        assert_eq!(config2.max_redirects, 7);

        // Cleanup
        std::env::remove_var("SB_SUBS_MAX_REDIRECTS");
    }
}

#[cfg(test)]
mod tests_apply_dryrun {
    use super::*;
    use serde_json::json;

    #[test]
    fn dryrun_returns_diff_and_does_not_bump_version() {
        // reset state
        reload();
        let before_ver = version();

        let delta = crate::admin_debug::endpoints::config::ConfigDelta {
            timeout_ms: Some(4321),
            ..Default::default()
        };
        let res = apply_with_dryrun(&delta, true).expect("dryrun ok");
        assert!(!res.ok);
        assert_eq!(res.msg, "dryrun");
        assert!(res.changed, "dryrun should detect changes");
        assert_eq!(version(), before_ver, "version not bumped on dryrun");
        // Verify diff contains the field in the new format
        assert!(res.diff.get("replace").and_then(|m| m.get("timeout_ms")).is_some());
    }

    #[test]
    fn apply_commits_and_bumps_version() {
        reload();
        let start_ver = version();
        let delta = crate::admin_debug::endpoints::config::ConfigDelta {
            max_redirects: Some(3),
            ..Default::default()
        };
        let res = apply_with_dryrun(&delta, false).expect("apply ok");
        assert!(res.ok);
        assert!(res.msg.contains("max_redirects"));
        let end_ver = version();
        assert!(end_ver >= start_ver + 1, "version bumped");
        let cfg = get();
        assert_eq!(cfg.max_redirects, 3);
    }
}

#[cfg(test)]
mod tests_idempotent {
    use super::*;

    #[test]
    fn same_patch_twice_second_time_no_change() {
        reload();
        let start_ver = version();

        let delta = crate::admin_debug::endpoints::config::ConfigDelta {
            timeout_ms: Some(5000),
            max_redirects: Some(7),
            ..Default::default()
        };

        // First apply - should change
        let res1 = apply_with_dryrun(&delta, false).expect("first apply ok");
        assert!(res1.ok);
        assert!(res1.changed, "first apply should show changes");
        assert_eq!(version(), start_ver + 1, "version should increment on first apply");

        // Second apply with same delta - should not change
        let res2 = apply_with_dryrun(&delta, false).expect("second apply ok");
        assert!(res2.ok);
        assert!(!res2.changed, "second apply should show no changes");
        assert_eq!(res2.msg, "no changes");
        assert_eq!(version(), start_ver + 1, "version should not increment on second apply");
        assert!(diff_is_empty(&res2.diff), "diff should be empty on second apply");
    }

    #[test]
    fn dryrun_with_changes_shows_changed_true_but_no_version_bump() {
        reload();
        let start_ver = version();

        let delta = crate::admin_debug::endpoints::config::ConfigDelta {
            rps: Some(10),
            ..Default::default()
        };

        // Dry run should detect changes but not apply them
        let res = apply_with_dryrun(&delta, true).expect("dryrun ok");
        assert!(!res.ok, "dry run should return ok=false");
        assert_eq!(res.msg, "dryrun");
        assert!(res.changed, "dry run should detect changes");
        assert_eq!(version(), start_ver, "version should not increment on dry run");
        assert!(!diff_is_empty(&res.diff), "diff should show the changes");

        // Verify config wasn't actually changed
        let cfg = get();
        assert_ne!(cfg.rps, 10, "config should not be applied during dry run");
    }

    #[test]
    fn no_changes_delta_returns_changed_false() {
        reload();
        let start_ver = version();

        // Get current config values
        let cfg = get();
        let delta = crate::admin_debug::endpoints::config::ConfigDelta {
            timeout_ms: Some(cfg.timeout_ms), // Same as current
            max_redirects: Some(cfg.max_redirects), // Same as current
            ..Default::default()
        };

        let res = apply_with_dryrun(&delta, false).expect("no-change apply ok");
        assert!(res.ok);
        assert!(!res.changed, "no actual changes should show changed=false");
        assert_eq!(res.msg, "no changes");
        assert_eq!(version(), start_ver, "version should not increment when no changes");
        assert!(diff_is_empty(&res.diff), "diff should be empty when no changes");
    }

    #[test]
    fn json_diff_enhanced_format() {
        let before = serde_json::json!({
            "timeout_ms": 4000,
            "max_redirects": 3,
            "rps": 4
        });

        let after = serde_json::json!({
            "timeout_ms": 5000,  // changed
            "max_redirects": 3,  // same
            "cache_capacity": 64 // added
        });

        let diff = json_diff_enhanced(&before, &after);

        // Should have replace for timeout_ms
        assert!(diff["replace"]["timeout_ms"].is_object());
        assert_eq!(diff["replace"]["timeout_ms"]["from"], 4000);
        assert_eq!(diff["replace"]["timeout_ms"]["to"], 5000);

        // Should have add for cache_capacity
        assert_eq!(diff["add"]["cache_capacity"], 64);

        // Should have remove for rps
        assert_eq!(diff["remove"]["rps"], 4);

        // Should not be empty
        assert!(!diff_is_empty(&diff));
    }
}