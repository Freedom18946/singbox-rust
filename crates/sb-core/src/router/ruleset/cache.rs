//! Cache management for rule-sets

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Cache directory
    pub dir: PathBuf,
    /// Maximum cache age before auto-update
    pub max_age: Duration,
    /// Enable auto-update
    pub auto_update: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/tmp/singbox-rulesets"),
            max_age: Duration::from_secs(86400), // 24 hours
            auto_update: true,
        }
    }
}

/// Check if cache is stale
pub fn is_cache_stale(last_updated: SystemTime, max_age: Duration) -> bool {
    match SystemTime::now().duration_since(last_updated) {
        Ok(age) => age > max_age,
        Err(_) => true, // System time went backwards, consider stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stale() {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(3600);

        // Fresh cache
        assert!(!is_cache_stale(now, max_age));

        // Stale cache
        let old = now - Duration::from_secs(7200);
        assert!(is_cache_stale(old, max_age));
    }
}
