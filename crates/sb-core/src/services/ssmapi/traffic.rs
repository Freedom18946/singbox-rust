//! Traffic statistics tracking for SSMAPI service.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Per-user traffic statistics.
#[derive(Debug, Default, Clone, Copy)]
struct UserTraffic {
    uplink_bytes: i64,
    downlink_bytes: i64,
    uplink_packets: i64,
    downlink_packets: i64,
    tcp_sessions: i64,
    udp_sessions: i64,
}

/// Global traffic statistics.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct GlobalTraffic {
    #[serde(rename = "uplinkBytes")]
    pub uplink_bytes: i64,
    #[serde(rename = "downlinkBytes")]
    pub downlink_bytes: i64,
    #[serde(rename = "uplinkPackets")]
    pub uplink_packets: i64,
    #[serde(rename = "downlinkPackets")]
    pub downlink_packets: i64,
    #[serde(rename = "tcpSessions")]
    pub tcp_sessions: i64,
    #[serde(rename = "udpSessions")]
    pub udp_sessions: i64,
}

/// Traffic manager for tracking per-user and global statistics.
pub struct TrafficManager {
    user_traffic: RwLock<HashMap<String, UserTraffic>>,
    global_traffic: RwLock<GlobalTraffic>,
}

impl TrafficManager {
    /// Create a new traffic manager.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            user_traffic: RwLock::new(HashMap::new()),
            global_traffic: RwLock::new(GlobalTraffic::default()),
        })
    }

    /// Record uplink traffic for a user.
    pub fn record_uplink(&self, username: &str, bytes: i64, packets: i64) {
        let mut user_stats = self.user_traffic.write();
        let entry = user_stats.entry(username.to_string()).or_default();
        entry.uplink_bytes += bytes;
        entry.uplink_packets += packets;

        let mut global = self.global_traffic.write();
        global.uplink_bytes += bytes;
        global.uplink_packets += packets;
    }

    /// Record downlink traffic for a user.
    pub fn record_downlink(&self, username: &str, bytes: i64, packets: i64) {
        let mut user_stats = self.user_traffic.write();
        let entry = user_stats.entry(username.to_string()).or_default();
        entry.downlink_bytes += bytes;
        entry.downlink_packets += packets;

        let mut global = self.global_traffic.write();
        global.downlink_bytes += bytes;
        global.downlink_packets += packets;
    }

    /// Increment TCP session count for a user.
    pub fn increment_tcp_sessions(&self, username: &str, delta: i64) {
        let mut user_stats = self.user_traffic.write();
        let entry = user_stats.entry(username.to_string()).or_default();
        entry.tcp_sessions += delta;

        let mut global = self.global_traffic.write();
        global.tcp_sessions += delta;
    }

    /// Increment UDP session count for a user.
    pub fn increment_udp_sessions(&self, username: &str, delta: i64) {
        let mut user_stats = self.user_traffic.write();
        let entry = user_stats.entry(username.to_string()).or_default();
        entry.udp_sessions += delta;

        let mut global = self.global_traffic.write();
        global.udp_sessions += delta;
    }

    /// Read traffic stats for a single user and optionally clear them.
    pub fn read_user(&self, user_obj: &mut crate::services::ssmapi::user::UserObject, clear: bool) {
        if clear {
            let mut user_stats = self.user_traffic.write();
            if let Some(stats) = user_stats.remove(&user_obj.user_name) {
                user_obj.uplink_bytes = stats.uplink_bytes;
                user_obj.downlink_bytes = stats.downlink_bytes;
                user_obj.uplink_packets = stats.uplink_packets;
                user_obj.downlink_packets = stats.downlink_packets;
                user_obj.tcp_sessions = stats.tcp_sessions;
                user_obj.udp_sessions = stats.udp_sessions;
            }
        } else {
            let user_stats = self.user_traffic.read();
            if let Some(stats) = user_stats.get(&user_obj.user_name) {
                user_obj.uplink_bytes = stats.uplink_bytes;
                user_obj.downlink_bytes = stats.downlink_bytes;
                user_obj.uplink_packets = stats.uplink_packets;
                user_obj.downlink_packets = stats.downlink_packets;
                user_obj.tcp_sessions = stats.tcp_sessions;
                user_obj.udp_sessions = stats.udp_sessions;
            }
        }
    }

    /// Read traffic stats for all users and optionally clear them.
    pub fn read_users(&self, users: &mut [crate::services::ssmapi::user::UserObject], clear: bool) {
        for user in users {
            self.read_user(user, clear);
        }
    }

    /// Read global traffic stats and optionally clear them.
    pub fn read_global(&self, clear: bool) -> GlobalTraffic {
        if clear {
            let mut global = self.global_traffic.write();
            let stats = *global;
            *global = GlobalTraffic::default();
            stats
        } else {
            let global = self.global_traffic.read();
            *global
        }
    }

    /// Clear stats for a specific user.
    pub fn clear_user(&self, username: &str) {
        let mut user_stats = self.user_traffic.write();
        user_stats.remove(username);
    }

    /// Clear all stats.
    pub fn clear_all(&self) {
        let mut user_stats = self.user_traffic.write();
        user_stats.clear();
        let mut global = self.global_traffic.write();
        *global = GlobalTraffic::default();
    }
}

impl Default for TrafficManager {
    fn default() -> Self {
        Self {
            user_traffic: RwLock::new(HashMap::new()),
            global_traffic: RwLock::new(GlobalTraffic::default()),
        }
    }
}

/// Implement TrafficTracker trait for integration with Shadowsocks adapters.
impl super::TrafficTracker for TrafficManager {
    fn record_uplink(&self, username: &str, bytes: i64, packets: i64) {
        TrafficManager::record_uplink(self, username, bytes, packets);
    }

    fn record_downlink(&self, username: &str, bytes: i64, packets: i64) {
        TrafficManager::record_downlink(self, username, bytes, packets);
    }

    fn increment_tcp_sessions(&self, username: &str, delta: i64) {
        TrafficManager::increment_tcp_sessions(self, username, delta);
    }

    fn increment_udp_sessions(&self, username: &str, delta: i64) {
        TrafficManager::increment_udp_sessions(self, username, delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ssmapi::user::UserObject;

    #[test]
    fn test_traffic_tracking() {
        let manager = TrafficManager::new();

        // Record traffic
        manager.record_uplink("alice", 1000, 10);
        manager.record_downlink("alice", 2000, 20);
        manager.increment_tcp_sessions("alice", 1);

        manager.record_uplink("bob", 500, 5);
        manager.record_downlink("bob", 1500, 15);
        manager.increment_udp_sessions("bob", 2);

        // Read user stats (non-clearing)
        let mut alice = UserObject::new("alice".to_string(), None);
        manager.read_user(&mut alice, false);
        assert_eq!(alice.uplink_bytes, 1000);
        assert_eq!(alice.downlink_bytes, 2000);
        assert_eq!(alice.tcp_sessions, 1);

        // Global stats should include both users
        let global = manager.read_global(false);
        assert_eq!(global.uplink_bytes, 1500);
        assert_eq!(global.downlink_bytes, 3500);
        assert_eq!(global.tcp_sessions, 1);
        assert_eq!(global.udp_sessions, 2);

        // Clear and read
        let global_cleared = manager.read_global(true);
        assert_eq!(global_cleared.uplink_bytes, 1500);

        // After clearing, global should be zero
        let global_after = manager.read_global(false);
        assert_eq!(global_after.uplink_bytes, 0);
    }

    #[test]
    fn test_clear_user() {
        let manager = TrafficManager::new();

        manager.record_uplink("alice", 1000, 10);
        manager.record_downlink("alice", 2000, 20);

        manager.clear_user("alice");

        let mut alice = UserObject::new("alice".to_string(), None);
        manager.read_user(&mut alice, false);
        assert_eq!(alice.uplink_bytes, 0);
        assert_eq!(alice.downlink_bytes, 0);
    }
}
