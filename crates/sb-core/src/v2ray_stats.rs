//! Data-plane counters exposed by optional V2Ray control-plane service.

use parking_lot::RwLock;
use sb_config::ir::StatsIR;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Statistics counter
#[derive(Debug, Default)]
pub struct StatCounter {
    value: AtomicU64,
}

impl StatCounter {
    /// Create a new counter with initial value
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    /// Get current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Add to counter
    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::SeqCst);
    }

    /// Reset counter and return previous value
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::SeqCst)
    }
}

/// Statistics manager
#[derive(Debug)]
pub struct StatsManager {
    enabled: bool,
    created_at: Instant,
    inbounds: HashSet<String>,
    outbounds: HashSet<String>,
    users: HashSet<String>,
    track_all_inbounds: bool,
    track_all_outbounds: bool,
    counters: RwLock<HashMap<String, Arc<StatCounter>>>,
}

impl StatsManager {
    /// Create a new stats manager from config.
    pub fn new(cfg: Option<StatsIR>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let track_all_inbounds = cfg.inbound.unwrap_or(false);
        let track_all_outbounds = cfg.outbound.unwrap_or(false);
        let inbounds = cfg.inbounds.into_iter().collect();
        let outbounds = cfg.outbounds.into_iter().collect();
        let users = cfg.users.into_iter().collect();

        Self {
            enabled: cfg.enabled,
            created_at: Instant::now(),
            inbounds,
            outbounds,
            users,
            track_all_inbounds,
            track_all_outbounds,
            counters: RwLock::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get or create a counter.
    pub fn get_counter(&self, name: &str) -> Arc<StatCounter> {
        if let Some(counter) = self.counters.read().get(name) {
            return counter.clone();
        }
        let mut counters = self.counters.write();
        counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StatCounter::new(0)))
            .clone()
    }

    /// Get counter value by name.
    pub fn get_stat(&self, name: &str) -> Option<u64> {
        self.counters.read().get(name).map(|c| c.get())
    }

    /// Reset counter by name and return the value observed before reset.
    pub fn reset_stat(&self, name: &str) -> Option<u64> {
        self.counters.read().get(name).map(|c| c.reset())
    }

    /// Query stats matching patterns.
    pub fn query_stats(
        &self,
        patterns: &[String],
        regex: bool,
        reset: bool,
    ) -> Result<Vec<(String, u64)>, regex::Error> {
        let counters = self.counters.read();
        let mut out = Vec::new();

        let mut matchers = Vec::new();
        if regex {
            for pattern in patterns {
                matchers.push(regex::Regex::new(pattern)?);
            }
        }

        for (name, counter) in counters.iter() {
            let matched = if patterns.is_empty() {
                true
            } else if regex {
                matchers.iter().any(|re| re.is_match(name))
            } else {
                patterns.iter().any(|pat| name.contains(pat))
            };

            if matched {
                let value = if reset {
                    counter.reset()
                } else {
                    counter.get()
                };
                out.push((name.clone(), value));
            }
        }

        Ok(out)
    }

    fn should_track_inbound(&self, inbound: &str) -> bool {
        if !self.enabled || inbound.is_empty() {
            return false;
        }
        if self.track_all_inbounds {
            return true;
        }
        if self.inbounds.is_empty() {
            return false;
        }
        self.inbounds.contains(inbound)
    }

    fn should_track_outbound(&self, outbound: &str) -> bool {
        if !self.enabled || outbound.is_empty() {
            return false;
        }
        if self.track_all_outbounds {
            return true;
        }
        if self.outbounds.is_empty() {
            return false;
        }
        self.outbounds.contains(outbound)
    }

    fn should_track_user(&self, user: &str) -> bool {
        if !self.enabled || user.is_empty() {
            return false;
        }
        if self.users.is_empty() {
            return false;
        }
        self.users.contains(user)
    }

    pub fn traffic_recorder(
        &self,
        inbound: Option<&str>,
        outbound: Option<&str>,
        user: Option<&str>,
    ) -> Option<Arc<dyn crate::net::metered::TrafficRecorder>> {
        if !self.enabled {
            return None;
        }

        let mut uplink = Vec::new();
        let mut downlink = Vec::new();
        if let Some(tag) = inbound {
            if self.should_track_inbound(tag) {
                uplink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>uplink", tag)));
                downlink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>downlink", tag)));
            }
        }

        if let Some(tag) = outbound {
            if self.should_track_outbound(tag) {
                uplink.push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>uplink", tag)));
                downlink
                    .push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>downlink", tag)));
            }
        }

        if let Some(name) = user {
            if self.should_track_user(name) {
                uplink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>uplink", name)));
                downlink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>downlink", name)));
            }
        }

        if uplink.is_empty() && downlink.is_empty() {
            return None;
        }

        Some(Arc::new(TrafficCounters { uplink, downlink }))
    }

    /// Keep the old lifecycle hook as a no-op: Go creates V2Ray counters lazily
    /// when routed traffic requests them.
    pub fn init_standard_counters(&self) {}
}

#[derive(Debug)]
pub struct TrafficCounters {
    uplink: Vec<Arc<StatCounter>>,
    downlink: Vec<Arc<StatCounter>>,
}

impl crate::net::metered::TrafficRecorder for TrafficCounters {
    fn record_up(&self, bytes: u64) {
        for counter in &self.uplink {
            counter.add(bytes);
        }
    }

    fn record_down(&self, bytes: u64) {
        for counter in &self.downlink {
            counter.add(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stats_manager() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            ..Default::default()
        }));

        // Get counter
        let counter = manager.get_counter("test>>>traffic>>>uplink");
        assert_eq!(counter.get(), 0);

        // Add traffic
        counter.add(1024);
        assert_eq!(counter.get(), 1024);

        // Query stats
        let stats = manager
            .query_stats(&["traffic".to_string()], false, false)
            .expect("valid substring query");
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test>>>traffic>>>uplink");
        assert_eq!(stats[0].1, 1024);

        // Reset
        let old = counter.reset();
        assert_eq!(old, 1024);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_go_shaped_traffic_counters_from_recorder() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            inbounds: vec!["dns".to_string()],
            outbounds: vec!["direct".to_string()],
            users: vec!["alice".to_string()],
            inbound: None,
            outbound: None,
        }));

        let recorder = manager
            .traffic_recorder(Some("dns"), Some("direct"), Some("alice"))
            .expect("traffic recorder expected");

        recorder.record_up(10);
        recorder.record_down(20);
        recorder.record_up_packet(2);
        recorder.record_down_packet(3);

        let uplink = 10;
        let downlink = 20;

        let checks = [
            ("inbound>>>dns>>>traffic>>>uplink", uplink),
            ("inbound>>>dns>>>traffic>>>downlink", downlink),
            ("outbound>>>direct>>>traffic>>>uplink", uplink),
            ("outbound>>>direct>>>traffic>>>downlink", downlink),
            ("user>>>alice>>>traffic>>>uplink", uplink),
            ("user>>>alice>>>traffic>>>downlink", downlink),
        ];

        for (name, expected) in checks {
            let value = manager.get_stat(name).unwrap_or(0);
            assert_eq!(value, expected, "stat mismatch for {name}");
        }

        assert!(manager
            .get_stat("inbound>>>dns>>>packet>>>uplink")
            .is_none());
        assert!(manager
            .get_stat("outbound>>>direct>>>packet>>>downlink")
            .is_none());
        assert!(manager.get_stat("user>>>alice>>>packet>>>uplink").is_none());
    }

    #[test]
    fn test_stats_filters_and_reset_semantics() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            inbounds: vec!["mixed-in".to_string()],
            outbounds: vec!["direct".to_string()],
            users: vec!["alice".to_string()],
            inbound: None,
            outbound: None,
        }));

        assert!(manager
            .traffic_recorder(Some("other-in"), Some("block"), Some("bob"))
            .is_none());

        let recorder = manager
            .traffic_recorder(Some("mixed-in"), Some("direct"), Some("alice"))
            .expect("matching recorder expected");
        recorder.record_up(7);
        recorder.record_down(11);

        let mut all = manager
            .query_stats(&[], false, false)
            .expect("empty pattern queries all");
        all.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            all,
            vec![
                ("inbound>>>mixed-in>>>traffic>>>downlink".to_string(), 11),
                ("inbound>>>mixed-in>>>traffic>>>uplink".to_string(), 7),
                ("outbound>>>direct>>>traffic>>>downlink".to_string(), 11),
                ("outbound>>>direct>>>traffic>>>uplink".to_string(), 7),
                ("user>>>alice>>>traffic>>>downlink".to_string(), 11),
                ("user>>>alice>>>traffic>>>uplink".to_string(), 7),
            ]
        );

        let reset = manager
            .query_stats(&["uplink$".to_string()], true, true)
            .expect("valid regexp query");
        assert_eq!(reset.len(), 3);
        assert_eq!(
            manager.get_stat("inbound>>>mixed-in>>>traffic>>>uplink"),
            Some(0)
        );
        assert_eq!(
            manager.get_stat("inbound>>>mixed-in>>>traffic>>>downlink"),
            Some(11)
        );

        assert!(
            manager
                .query_stats(&["(".to_string()], true, false)
                .is_err(),
            "invalid regexp must be reported"
        );
    }
}
