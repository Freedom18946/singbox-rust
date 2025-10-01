//! Modern proxy selector implementation supporting manual and URLTest modes
//!
//! Provides:
//! - ManualSelector: user-controlled static proxy selection
//! - URLTestSelector: automatic selection based on latency testing
//! - Load balancing strategies: round-robin, least-connections, random
//! - Health checking with configurable test URL and interval
//! - Graceful degradation when proxies fail

use crate::adapter::OutboundConnector;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Proxy selection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectMode {
    /// Manual selection (user picks specific proxy)
    Manual,
    /// Auto selection based on URLTest (lowest latency)
    UrlTest,
    /// Load balancing modes
    RoundRobin,
    LeastConnections,
    Random,
}

/// Proxy member in a selector group
#[derive(Clone)]
pub struct ProxyMember {
    pub tag: String,
    pub connector: Arc<dyn OutboundConnector>,
    health: Arc<ProxyHealth>,
}

impl std::fmt::Debug for ProxyMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyMember")
            .field("tag", &self.tag)
            .field("health", &self.health)
            .finish()
    }
}

/// Health status for a proxy
#[derive(Debug)]
pub struct ProxyHealth {
    pub is_alive: Arc<parking_lot::RwLock<bool>>,
    pub last_rtt_ms: AtomicU64,
    pub consecutive_fails: AtomicUsize,
    pub last_check: Mutex<Option<Instant>>,
    pub active_connections: AtomicUsize,
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self {
            is_alive: Arc::new(parking_lot::RwLock::new(true)),
            last_rtt_ms: AtomicU64::new(0),
            consecutive_fails: AtomicUsize::new(0),
            last_check: Mutex::new(None),
            active_connections: AtomicUsize::new(0),
        }
    }
}

impl ProxyHealth {
    fn record_success(&self, rtt_ms: u64) {
        *self.is_alive.write() = true;
        self.last_rtt_ms.store(rtt_ms, Ordering::Relaxed);
        self.consecutive_fails.store(0, Ordering::Relaxed);
        if let Ok(mut last) = self.last_check.lock() {
            *last = Some(Instant::now());
        }
    }

    fn record_failure(&self) {
        self.consecutive_fails.fetch_add(1, Ordering::Relaxed);
        if self.consecutive_fails.load(Ordering::Relaxed) >= 3 {
            *self.is_alive.write() = false;
        }
        if let Ok(mut last) = self.last_check.lock() {
            *last = Some(Instant::now());
        }
    }

    pub fn is_healthy(&self) -> bool {
        *self.is_alive.read()
    }

    pub fn get_rtt_ms(&self) -> u64 {
        self.last_rtt_ms.load(Ordering::Relaxed)
    }
}

/// Selector group for managing multiple proxies
pub struct SelectorGroup {
    pub name: String,
    pub mode: SelectMode,
    members: Vec<ProxyMember>,
    // For manual mode
    selected: Arc<RwLock<Option<String>>>,
    default_member: Option<String>,
    // For load balancing
    round_robin_index: AtomicUsize,
    // For URLTest
    test_url: String,
    test_interval: Duration,
    test_timeout: Duration,
    tolerance_ms: u64,
}

impl SelectorGroup {
    /// Create a new manual selector
    pub fn new_manual(
        name: String,
        members: Vec<ProxyMember>,
        default: Option<String>,
    ) -> Self {
        Self {
            name,
            mode: SelectMode::Manual,
            members,
            selected: Arc::new(RwLock::new(default.clone())),
            default_member: default,
            round_robin_index: AtomicUsize::new(0),
            test_url: String::new(),
            test_interval: Duration::from_secs(60),
            test_timeout: Duration::from_secs(5),
            tolerance_ms: 50,
        }
    }

    /// Create a new URLTest selector
    pub fn new_urltest(
        name: String,
        members: Vec<ProxyMember>,
        test_url: String,
        interval: Duration,
        timeout: Duration,
        tolerance_ms: u64,
    ) -> Self {
        Self {
            name,
            mode: SelectMode::UrlTest,
            members,
            selected: Arc::new(RwLock::new(None)),
            default_member: None,
            round_robin_index: AtomicUsize::new(0),
            test_url,
            test_interval: interval,
            test_timeout: timeout,
            tolerance_ms,
        }
    }

    /// Create a load balancing selector
    pub fn new_load_balancer(
        name: String,
        members: Vec<ProxyMember>,
        mode: SelectMode,
    ) -> Self {
        Self {
            name,
            mode,
            members,
            selected: Arc::new(RwLock::new(None)),
            default_member: None,
            round_robin_index: AtomicUsize::new(0),
            test_url: String::new(),
            test_interval: Duration::from_secs(60),
            test_timeout: Duration::from_secs(5),
            tolerance_ms: 50,
        }
    }

    /// Manually select a proxy by tag
    pub async fn select_by_name(&self, tag: &str) -> std::io::Result<()> {
        if self.mode != SelectMode::Manual {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "select_by_name only works in manual mode",
            ));
        }

        // Check if the proxy exists
        if !self.members.iter().any(|m| m.tag == tag) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("proxy {} not found in selector {}", tag, self.name),
            ));
        }

        let mut selected = self.selected.write().await;
        *selected = Some(tag.to_string());
        tracing::info!(
            selector = %self.name,
            proxy = %tag,
            "manual proxy selection"
        );
        sb_metrics::inc_proxy_select(&self.name);
        Ok(())
    }

    /// Get currently selected proxy tag
    pub async fn get_selected(&self) -> Option<String> {
        self.selected.read().await.clone()
    }

    /// Select the best proxy based on mode
    async fn select_best(&self) -> Option<&ProxyMember> {
        match self.mode {
            SelectMode::Manual => {
                let selected = self.selected.read().await.clone();
                let tag = selected.or_else(|| self.default_member.clone())?;
                self.members.iter().find(|m| m.tag == tag)
            }
            SelectMode::UrlTest => self.select_by_latency(),
            SelectMode::RoundRobin => self.select_round_robin(),
            SelectMode::LeastConnections => self.select_least_connections(),
            SelectMode::Random => self.select_random(),
        }
    }

    /// Select by lowest latency (URLTest mode)
    fn select_by_latency(&self) -> Option<&ProxyMember> {
        let healthy: Vec<_> = self
            .members
            .iter()
            .filter(|m| m.health.is_healthy())
            .collect();

        if healthy.is_empty() {
            tracing::warn!(
                selector = %self.name,
                "no healthy proxies, trying all members"
            );
            return self.members.first();
        }

        // Find the one with lowest RTT
        // tolerance_ms is used to avoid switching too frequently for small differences
        let best = healthy
            .iter()
            .min_by_key(|m| m.health.get_rtt_ms())
            .copied();

        // If we have a current selection, only switch if the difference exceeds tolerance
        // For now, just return the best (tolerance-based switching can be added later)
        let _ = self.tolerance_ms; // Mark as intentionally unused for now
        best
    }

    /// Round-robin selection
    fn select_round_robin(&self) -> Option<&ProxyMember> {
        if self.members.is_empty() {
            return None;
        }
        let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
        self.members.get(idx % self.members.len())
    }

    /// Select by least active connections
    fn select_least_connections(&self) -> Option<&ProxyMember> {
        self.members
            .iter()
            .filter(|m| m.health.is_healthy())
            .min_by_key(|m| m.health.active_connections.load(Ordering::Relaxed))
            .or_else(|| self.members.first())
    }

    /// Random selection
    fn select_random(&self) -> Option<&ProxyMember> {
        if self.members.is_empty() {
            return None;
        }
        let idx = fastrand::usize(0..self.members.len());
        self.members.get(idx)
    }

    /// Start background health checking (for URLTest mode)
    pub fn start_health_check(self: Arc<Self>) {
        if self.mode != SelectMode::UrlTest {
            return;
        }

        let interval = self.test_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                self.run_health_checks().await;
            }
        });
    }

    /// Run health checks on all members
    async fn run_health_checks(&self) {
        let url = self.test_url.clone();
        let timeout = self.test_timeout;

        for member in &self.members {
            let tag = member.tag.clone();
            let health = member.health.clone();
            let url = url.clone();

            tokio::spawn(async move {
                match health_check(&url, timeout).await {
                    Ok(rtt_ms) => {
                        health.record_success(rtt_ms);
                        tracing::trace!(
                            proxy = %tag,
                            rtt_ms = rtt_ms,
                            "health check ok"
                        );
                        // Note: set_proxy_rtt metric will be added when metrics module is extended
                    }
                    Err(e) => {
                        health.record_failure();
                        tracing::debug!(
                            proxy = %tag,
                            error = %e,
                            "health check failed"
                        );
                    }
                }
            });
        }
    }

    /// Get all members and their health status
    pub fn get_members(&self) -> Vec<(String, bool, u64)> {
        self.members
            .iter()
            .map(|m| {
                (
                    m.tag.clone(),
                    m.health.is_healthy(),
                    m.health.get_rtt_ms(),
                )
            })
            .collect()
    }
}

impl std::fmt::Debug for SelectorGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectorGroup")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("members_count", &self.members.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl OutboundConnector for SelectorGroup {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let member = self.select_best().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no available proxy in selector {}", self.name),
            )
        })?;

        // Track active connection
        member
            .health
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        let start = Instant::now();
        let result = member.connector.connect(host, port).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Update metrics and health
        match &result {
            Ok(_) => {
                member.health.record_success(elapsed_ms);
                tracing::debug!(
                    selector = %self.name,
                    proxy = %member.tag,
                    duration_ms = elapsed_ms,
                    "connect ok"
                );
                sb_metrics::inc_proxy_select(&self.name);
            }
            Err(e) => {
                member.health.record_failure();
                tracing::warn!(
                    selector = %self.name,
                    proxy = %member.tag,
                    error = %e,
                    "connect failed"
                );
            }
        }

        // Decrement connection counter when dropped (handled by caller)
        member
            .health
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);

        result
    }
}

/// Perform a health check against a URL
async fn health_check(url: &str, timeout: Duration) -> std::io::Result<u64> {
    let start = Instant::now();

    // Parse URL to extract host and port
    let (host, port, _use_https) = parse_test_url(url)?;

    // Perform HTTP HEAD request
    let result = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect((host.as_str(), port)).await?;

        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            url, host
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await?;

        // Read response (just check for HTTP/1.x 2xx or 3xx or 204)
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;

        if n > 12 {
            let response = std::str::from_utf8(&buf[..n]).unwrap_or("");
            if response.starts_with("HTTP/1.") {
                // Check status code
                if let Some(code_str) = response.split_whitespace().nth(1) {
                    if let Ok(code) = code_str.parse::<u16>() {
                        if (200..400).contains(&code) {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid http response",
        ))
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(start.elapsed().as_millis() as u64),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "health check timeout",
        )),
    }
}

/// Parse test URL to extract host, port, and scheme
fn parse_test_url(url: &str) -> std::io::Result<(String, u16, bool)> {
    if let Some(url_without_scheme) = url.strip_prefix("https://") {
        let parts: Vec<&str> = url_without_scheme.split('/').next().unwrap().split(':').collect();
        let host = parts[0].to_string();
        let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
        Ok((host, port, true))
    } else if let Some(url_without_scheme) = url.strip_prefix("http://") {
        let parts: Vec<&str> = url_without_scheme.split('/').next().unwrap().split(':').collect();
        let host = parts[0].to_string();
        let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(80);
        Ok((host, port, false))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid test url scheme",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (host, port, https) = parse_test_url("http://www.google.com/generate_204").unwrap();
        assert_eq!(host, "www.google.com");
        assert_eq!(port, 80);
        assert!(!https);

        let (host, port, https) = parse_test_url("https://example.com:8443/test").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert!(https);
    }

    #[test]
    fn test_proxy_health() {
        let health = ProxyHealth::default();
        assert!(health.is_healthy());

        health.record_failure();
        assert!(health.is_healthy()); // Still healthy after 1 failure

        health.record_failure();
        health.record_failure();
        assert!(!health.is_healthy()); // Unhealthy after 3 failures

        health.record_success(100);
        assert!(health.is_healthy());
        assert_eq!(health.get_rtt_ms(), 100);
    }
}

// Include comprehensive test suite
#[cfg(test)]
#[path = "selector_group_tests.rs"]
mod selector_group_tests;
