//! Resource pressure detection and fallback handling
//!
//! This module provides low-cost detection of resource exhaustion conditions
//! and implements appropriate fallback behaviors to maintain system stability.
//!
//! ## Resource Types
//! - **File Descriptors (FD)**: Socket/file handle exhaustion
//! - **Memory**: Virtual or physical memory pressure
//!
//! ## Detection Strategy
//! - Monitor specific error patterns in I/O operations
//! - Track pressure metrics for admin visibility
//! - Implement throttling and backoff when pressure detected

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Types of resource pressure that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// File descriptor exhaustion
    FileDescriptors,
    /// Memory pressure
    Memory,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::FileDescriptors => "fd",
            ResourceType::Memory => "mem",
        }
    }
}

/// Resource pressure detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// No pressure detected
    None,
    /// Moderate pressure - apply throttling
    Moderate,
    /// High pressure - aggressive fallback
    High,
}

/// Configuration for resource pressure detection
#[derive(Debug, Clone)]
pub struct ResourcePressureConfig {
    /// How long to remember pressure events
    pub pressure_window: Duration,
    /// FD pressure threshold (events per window)
    pub fd_pressure_threshold: u32,
    /// Memory pressure threshold (events per window)
    pub mem_pressure_threshold: u32,
    /// Throttle delay when moderate pressure detected
    pub moderate_throttle_ms: u64,
    /// Throttle delay when high pressure detected
    pub high_throttle_ms: u64,
}

impl Default for ResourcePressureConfig {
    fn default() -> Self {
        Self {
            pressure_window: Duration::from_secs(60),
            fd_pressure_threshold: 10,
            mem_pressure_threshold: 5,
            moderate_throttle_ms: 100,
            high_throttle_ms: 1000,
        }
    }
}

/// Tracks pressure events for a specific resource type
#[derive(Debug)]
struct PressureTracker {
    events: Vec<Instant>,
    last_cleanup: Instant,
}

impl PressureTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            events: Vec::new(),
            last_cleanup: now,
        }
    }

    /// Record a pressure event
    fn record_event(&mut self) {
        let now = Instant::now();
        self.events.push(now);
        self.cleanup_old_events(now);
    }

    /// Get number of events in the current window
    fn event_count(&mut self, window: Duration) -> u32 {
        let now = Instant::now();
        self.cleanup_old_events(now);
        let cutoff = now.checked_sub(window).unwrap_or(now);
        self.events
            .iter()
            .filter(|&&event_time| event_time >= cutoff)
            .count() as u32
    }

    /// Remove events outside the window
    fn cleanup_old_events(&mut self, now: Instant) {
        // Only cleanup periodically to avoid excessive work
        if now.duration_since(self.last_cleanup) < Duration::from_secs(10) {
            return;
        }

        let cutoff = now.checked_sub(Duration::from_secs(300)).unwrap_or(now); // Keep 5 minutes of history
        self.events.retain(|&event_time| event_time >= cutoff);
        self.last_cleanup = now;
    }
}

/// Global resource pressure monitor
#[derive(Debug)]
pub struct ResourcePressureMonitor {
    config: ResourcePressureConfig,
    fd_tracker: Arc<RwLock<PressureTracker>>,
    mem_tracker: Arc<RwLock<PressureTracker>>,
    fd_pressure_counter: AtomicU64,
    mem_pressure_counter: AtomicU64,
}

impl Default for ResourcePressureMonitor {
    fn default() -> Self {
        Self::new(ResourcePressureConfig::default())
    }
}

impl ResourcePressureMonitor {
    /// Create a new resource pressure monitor
    pub fn new(config: ResourcePressureConfig) -> Self {
        Self {
            config,
            fd_tracker: Arc::new(RwLock::new(PressureTracker::new())),
            mem_tracker: Arc::new(RwLock::new(PressureTracker::new())),
            fd_pressure_counter: AtomicU64::new(0),
            mem_pressure_counter: AtomicU64::new(0),
        }
    }

    /// Record a resource pressure event
    pub async fn record_pressure(&self, resource_type: ResourceType) {
        match resource_type {
            ResourceType::FileDescriptors => {
                let mut tracker = self.fd_tracker.write().await;
                tracker.record_event();
                self.fd_pressure_counter.fetch_add(1, Ordering::Relaxed);
                debug!("Recorded FD pressure event");
            }
            ResourceType::Memory => {
                let mut tracker = self.mem_tracker.write().await;
                tracker.record_event();
                self.mem_pressure_counter.fetch_add(1, Ordering::Relaxed);
                debug!("Recorded memory pressure event");
            }
        }

        // Update metrics
        #[cfg(feature = "metrics")]
        {
            use sb_core::metrics::registry_ext::get_or_register_gauge_vec_f64;
            let gauge = get_or_register_gauge_vec_f64(
                "resource_pressure_level",
                "Resource pressure level",
                &["type"],
            );
            gauge.with_label_values(&[resource_type.as_str()]).set(1.0);
        }
    }

    /// Check current pressure level for a resource type
    pub async fn check_pressure(&self, resource_type: ResourceType) -> PressureLevel {
        let (threshold, tracker) = match resource_type {
            ResourceType::FileDescriptors => {
                (self.config.fd_pressure_threshold, self.fd_tracker.clone())
            }
            ResourceType::Memory => (self.config.mem_pressure_threshold, self.mem_tracker.clone()),
        };

        let mut tracker = tracker.write().await;
        let event_count = tracker.event_count(self.config.pressure_window);

        if event_count >= threshold * 2 {
            PressureLevel::High
        } else if event_count >= threshold {
            PressureLevel::Moderate
        } else {
            PressureLevel::None
        }
    }

    /// Get total pressure event count for a resource type
    pub fn get_pressure_count(&self, resource_type: ResourceType) -> u64 {
        match resource_type {
            ResourceType::FileDescriptors => self.fd_pressure_counter.load(Ordering::Relaxed),
            ResourceType::Memory => self.mem_pressure_counter.load(Ordering::Relaxed),
        }
    }

    /// Apply throttling based on pressure level
    pub async fn throttle_if_needed(&self, resource_type: ResourceType) {
        let pressure = self.check_pressure(resource_type).await;
        match pressure {
            PressureLevel::None => {
                // No throttling needed
            }
            PressureLevel::Moderate => {
                let delay = Duration::from_millis(self.config.moderate_throttle_ms);
                debug!(
                    "Applying moderate throttle for {}: {:?}",
                    resource_type.as_str(),
                    delay
                );
                tokio::time::sleep(delay).await;
            }
            PressureLevel::High => {
                let delay = Duration::from_millis(self.config.high_throttle_ms);
                warn!(
                    "Applying high throttle for {}: {:?}",
                    resource_type.as_str(),
                    delay
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Global instance of the resource pressure monitor
static GLOBAL_MONITOR: once_cell::sync::Lazy<ResourcePressureMonitor> =
    once_cell::sync::Lazy::new(ResourcePressureMonitor::default);

/// Get the global resource pressure monitor instance
pub fn global_monitor() -> &'static ResourcePressureMonitor {
    &GLOBAL_MONITOR
}

/// Error analysis utilities for detecting resource pressure from I/O errors
pub mod error_analysis {
    use super::*;
    use crate::dialer::DialError;
    use std::io::ErrorKind;

    /// Analyze a dial error to detect resource pressure
    pub async fn analyze_dial_error(error: &DialError) -> Option<ResourceType> {
        match error {
            DialError::Io(io_error) => {
                match io_error.kind() {
                    ErrorKind::OutOfMemory => Some(ResourceType::Memory),
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                        // These can indicate FD exhaustion
                        Some(ResourceType::FileDescriptors)
                    }
                    _ => {
                        // Check error message for known patterns
                        let error_msg = io_error.to_string().to_lowercase();
                        if error_msg.contains("too many open files")
                            || error_msg.contains("file descriptor")
                            || error_msg.contains("emfile")
                        {
                            Some(ResourceType::FileDescriptors)
                        } else if error_msg.contains("out of memory")
                            || error_msg.contains("enomem")
                        {
                            Some(ResourceType::Memory)
                        } else {
                            None
                        }
                    }
                }
            }
            DialError::Other(msg) => {
                let msg_lower = msg.to_lowercase();
                if msg_lower.contains("too many open files")
                    || msg_lower.contains("file descriptor")
                {
                    Some(ResourceType::FileDescriptors)
                } else if msg_lower.contains("out of memory") {
                    Some(ResourceType::Memory)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Record resource pressure if detected in an error
    pub async fn record_if_pressure_error(error: &DialError) {
        if let Some(resource_type) = analyze_dial_error(error).await {
            global_monitor().record_pressure(resource_type).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn test_pressure_tracker_basic() {
        let mut tracker = PressureTracker::new();

        // Record some events
        tracker.record_event();
        tracker.record_event();

        let count = tracker.event_count(Duration::from_secs(60));
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_pressure_tracker_window_expiry() {
        let config = ResourcePressureConfig {
            pressure_window: Duration::from_millis(100),
            ..Default::default()
        };

        let monitor = ResourcePressureMonitor::new(config);

        // Record event
        monitor.record_pressure(ResourceType::FileDescriptors).await;

        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_ne!(pressure, PressureLevel::None);

        // Wait for window to expire
        sleep(Duration::from_millis(150)).await;

        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_eq!(pressure, PressureLevel::None);
    }

    #[tokio::test]
    async fn test_pressure_level_thresholds() {
        let config = ResourcePressureConfig {
            fd_pressure_threshold: 2,
            pressure_window: Duration::from_secs(60),
            ..Default::default()
        };

        let monitor = ResourcePressureMonitor::new(config);

        // No events - no pressure
        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_eq!(pressure, PressureLevel::None);

        // One event - still no pressure
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_eq!(pressure, PressureLevel::None);

        // Two events - moderate pressure
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_eq!(pressure, PressureLevel::Moderate);

        // Four events - high pressure
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        let pressure = monitor.check_pressure(ResourceType::FileDescriptors).await;
        assert_eq!(pressure, PressureLevel::High);
    }

    #[tokio::test]
    async fn test_throttling() {
        let config = ResourcePressureConfig {
            fd_pressure_threshold: 1,
            moderate_throttle_ms: 50,
            high_throttle_ms: 100,
            pressure_window: Duration::from_secs(60),
        };

        let monitor = ResourcePressureMonitor::new(config);

        // No throttling when no pressure
        let start = Instant::now();
        monitor
            .throttle_if_needed(ResourceType::FileDescriptors)
            .await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(10));

        // Moderate throttling
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        let start = Instant::now();
        monitor
            .throttle_if_needed(ResourceType::FileDescriptors)
            .await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(45));
        assert!(elapsed < Duration::from_millis(70));

        // High throttling
        monitor.record_pressure(ResourceType::FileDescriptors).await;
        let start = Instant::now();
        monitor
            .throttle_if_needed(ResourceType::FileDescriptors)
            .await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(90));
        assert!(elapsed < Duration::from_millis(120));
    }

    #[tokio::test]
    async fn test_error_analysis() {
        use crate::dialer::DialError;
        use std::io::{Error, ErrorKind};

        // Test FD exhaustion error
        let fd_error = DialError::Io(Error::new(ErrorKind::Other, "too many open files"));
        let resource_type = error_analysis::analyze_dial_error(&fd_error).await;
        assert_eq!(resource_type, Some(ResourceType::FileDescriptors));

        // Test memory error
        let mem_error = DialError::Io(Error::new(ErrorKind::OutOfMemory, "out of memory"));
        let resource_type = error_analysis::analyze_dial_error(&mem_error).await;
        assert_eq!(resource_type, Some(ResourceType::Memory));

        // Test other error
        let other_error = DialError::NotSupported;
        let resource_type = error_analysis::analyze_dial_error(&other_error).await;
        assert_eq!(resource_type, None);

        // Test string-based detection
        let string_error = DialError::Other("EMFILE: too many open files".to_string());
        let resource_type = error_analysis::analyze_dial_error(&string_error).await;
        assert_eq!(resource_type, Some(ResourceType::FileDescriptors));
    }

    #[tokio::test]
    async fn test_pressure_counter() {
        let monitor = ResourcePressureMonitor::new(ResourcePressureConfig::default());

        assert_eq!(monitor.get_pressure_count(ResourceType::FileDescriptors), 0);

        monitor.record_pressure(ResourceType::FileDescriptors).await;
        monitor.record_pressure(ResourceType::FileDescriptors).await;

        assert_eq!(monitor.get_pressure_count(ResourceType::FileDescriptors), 2);
        assert_eq!(monitor.get_pressure_count(ResourceType::Memory), 0);
    }
}
