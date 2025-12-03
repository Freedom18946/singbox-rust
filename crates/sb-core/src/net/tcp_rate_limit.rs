use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

/// Configuration for TCP rate limiting
#[derive(Debug, Clone)]
pub struct TcpRateLimitConfig {
    /// Maximum connections allowed per IP within the window
    pub max_connections: usize,
    /// Time window for tracking connections
    pub window: Duration,
    /// Maximum number of IPs to track (LRU eviction)
    pub max_tracked_ips: usize,
    /// Maximum authentication failures allowed per IP within the window
    pub max_auth_failures: usize,
    /// Time window for tracking auth failures
    pub auth_failure_window: Duration,
    /// Maximum queries per second (QPS) limit per IP (optional)
    /// If None, no QPS limiting is applied
    pub max_qps: Option<usize>,
}

impl Default for TcpRateLimitConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            window: Duration::from_secs(10),
            max_tracked_ips: 10000,
            max_auth_failures: 10,
            auth_failure_window: Duration::from_secs(60),
            max_qps: None,
        }
    }
}

impl TcpRateLimitConfig {
    pub fn from_env() -> Self {
        let max_connections = std::env::var("SB_INBOUND_RATE_LIMIT_PER_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let window_sec = std::env::var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let max_qps = std::env::var("SB_INBOUND_RATE_LIMIT_QPS")
            .ok()
            .and_then(|v| v.parse().ok());

        Self {
            max_connections,
            window: Duration::from_secs(window_sec),
            max_qps,
            ..Default::default()
        }
    }
}

/// Thread-safe TCP connection rate limiter
#[derive(Clone, Debug)]
pub struct TcpRateLimiter {
    config: TcpRateLimitConfig,
    // We use two separate caches for connections and auth failures
    connection_tracker: Arc<Mutex<LruCache<IpAddr, VecDeque<Instant>>>>,
    auth_failure_tracker: Arc<Mutex<LruCache<IpAddr, VecDeque<Instant>>>>,
    // QPS tracker: stores (tokens, last_update) for token bucket algorithm
    qps_tracker: Arc<Mutex<LruCache<IpAddr, (f64, Instant)>>>,
}

impl TcpRateLimiter {
    pub fn new(config: TcpRateLimitConfig) -> Self {
        let cap =
            NonZeroUsize::new(config.max_tracked_ips).unwrap_or(NonZeroUsize::new(10000).unwrap());
        Self {
            config,
            connection_tracker: Arc::new(Mutex::new(LruCache::new(cap))),
            auth_failure_tracker: Arc::new(Mutex::new(LruCache::new(cap))),
            qps_tracker: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Check if a connection from the given IP is allowed
    /// Returns true if allowed, false if rate limited
    pub fn allow_connection(&self, ip: IpAddr) -> bool {
        if self.config.max_connections == 0 {
            return true;
        }

        let mut tracker = self.connection_tracker.lock();
        let now = Instant::now();
        let window = self.config.window;

        let timestamps = tracker.get_or_insert_mut(ip, VecDeque::new);

        // Remove expired timestamps
        while let Some(&t) = timestamps.front() {
            if now.duration_since(t) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() < self.config.max_connections {
            timestamps.push_back(now);
            true
        } else {
            false
        }
    }

    /// Record an authentication failure for the given IP
    /// Returns true if the IP is now banned (exceeded failure limit), false otherwise
    pub fn record_auth_failure(&self, ip: IpAddr) -> bool {
        if self.config.max_auth_failures == 0 {
            return false;
        }

        let mut tracker = self.auth_failure_tracker.lock();
        let now = Instant::now();
        let window = self.config.auth_failure_window;

        let timestamps = tracker.get_or_insert_mut(ip, VecDeque::new);

        // Remove expired timestamps
        while let Some(&t) = timestamps.front() {
            if now.duration_since(t) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);

        timestamps.len() > self.config.max_auth_failures
    }

    /// Check if an IP is currently banned due to excessive auth failures
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if self.config.max_auth_failures == 0 {
            return false;
        }

        let mut tracker = self.auth_failure_tracker.lock();
        let now = Instant::now();
        let window = self.config.auth_failure_window;

        if let Some(timestamps) = tracker.get_mut(&ip) {
            // Remove expired timestamps
            while let Some(&t) = timestamps.front() {
                if now.duration_since(t) > window {
                    timestamps.pop_front();
                } else {
                    break;
                }
            }

            timestamps.len() > self.config.max_auth_failures
        } else {
            false
        }
    }

    /// Check if a request from the given IP is allowed under QPS limits
    /// Uses token bucket algorithm for smooth rate limiting
    /// Returns true if allowed, false if rate limited
    pub fn allow_request(&self, ip: IpAddr) -> bool {
        let Some(max_qps) = self.config.max_qps else {
            // No QPS limit configured, allow all requests
            return true;
        };

        if max_qps == 0 {
            return true;
        }

        let mut tracker = self.qps_tracker.lock();
        let now = Instant::now();

        // Token bucket algorithm: refill rate = max_qps tokens/second
        let (mut tokens, last_update) = tracker.get(&ip).copied().unwrap_or((max_qps as f64, now));

        // Calculate elapsed time and refill tokens
        let elapsed = now.duration_since(last_update).as_secs_f64();
        let refill = elapsed * max_qps as f64;
        tokens = (tokens + refill).min(max_qps as f64);

        // Try to consume 1 token
        if tokens >= 1.0 {
            tokens -= 1.0;
            tracker.put(ip, (tokens, now));
            true
        } else {
            // Not enough tokens, update state and reject
            tracker.put(ip, (tokens, now));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limit_per_ip() {
        let config = TcpRateLimitConfig {
            max_connections: 5,
            window: Duration::from_secs(1),
            ..Default::default()
        };
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 5 should be allowed
        for _ in 0..5 {
            assert!(limiter.allow_connection(ip));
        }

        // 6th should be rejected
        assert!(!limiter.allow_connection(ip));
    }

    #[test]
    fn test_rate_limit_recovery() {
        let config = TcpRateLimitConfig {
            max_connections: 1,
            window: Duration::from_millis(100),
            ..Default::default()
        };
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.allow_connection(ip));
        assert!(!limiter.allow_connection(ip));

        std::thread::sleep(Duration::from_millis(150));

        // Should be allowed again after window expires
        assert!(limiter.allow_connection(ip));
    }

    #[test]
    fn test_auth_failure_ban() {
        let config = TcpRateLimitConfig {
            max_auth_failures: 3,
            auth_failure_window: Duration::from_secs(1),
            ..Default::default()
        };
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(!limiter.is_banned(ip));

        limiter.record_auth_failure(ip);
        limiter.record_auth_failure(ip);
        limiter.record_auth_failure(ip);

        assert!(!limiter.is_banned(ip)); // 3 failures is exactly the limit, not > limit

        limiter.record_auth_failure(ip);
        assert!(limiter.is_banned(ip)); // 4th failure triggers ban
    }

    #[test]
    fn test_qps_limiting() {
        let config = TcpRateLimitConfig {
            max_qps: Some(10), // 10 requests per second
            ..Default::default()
        };
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 10 requests should be allowed (initial bucket full)
        for _ in 0..10 {
            assert!(
                limiter.allow_request(ip),
                "Initial requests should be allowed"
            );
        }

        // 11th request should be blocked (bucket empty)
        assert!(
            !limiter.allow_request(ip),
            "Request beyond QPS should be blocked"
        );

        // Wait for token refill (100ms = 1 token at 10 QPS)
        std::thread::sleep(Duration::from_millis(110));

        // Should be allowed again after refill
        assert!(
            limiter.allow_request(ip),
            "Request should be allowed after token refill"
        );
    }

    #[test]
    fn test_qps_no_limit() {
        let config = TcpRateLimitConfig {
            max_qps: None, // No QPS limit
            ..Default::default()
        };
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow unlimited requests
        for _ in 0..1000 {
            assert!(limiter.allow_request(ip));
        }
    }
}
