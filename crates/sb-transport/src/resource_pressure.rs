//! # Resource Pressure Detection and Fallback Handling / 资源压力检测与回退处理
//!
//! This module provides low-cost detection of resource exhaustion conditions
//! and implements appropriate fallback behaviors to maintain system stability.
//! 该模块提供资源耗尽状况的低成本检测，并实现适当的回退行为以保持系统稳定性。
//!
//! ## Resource Types / 资源类型
//! - **File Descriptors (FD)**: Socket/file handle exhaustion
//!   **文件描述符 (FD)**: 套接字/文件句柄耗尽
//! - **Memory**: Virtual or physical memory pressure
//!   **内存**: 虚拟或物理内存压力
//!
//! ## Detection Strategy / 检测策略
//! - Monitor specific error patterns in I/O operations
//!   监控 I/O 操作中的特定错误模式
//! - Track pressure metrics for admin visibility
//!   跟踪压力指标以供管理员查看
//! - Implement throttling and backoff when pressure detected
//!   当检测到压力时实施限流和退避
//!
//! ## Strategic Relevance / 战略关联
//! - **Resilience**: Prevents cascading failures by detecting and mitigating resource exhaustion early.
//!   **弹性**: 通过及早检测和缓解资源耗尽来防止级联故障。
//! - **Self-Protection**: Protects the application from crashing under heavy load.
//!   **自我保护**: 保护应用程序在重负载下不崩溃。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Types of resource pressure that can be detected
/// 可检测到的资源压力类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// File descriptor exhaustion
    /// 文件描述符耗尽
    FileDescriptors,
    /// Memory pressure
    /// 内存压力
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
/// 资源压力检测结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// No pressure detected
    /// 未检测到压力
    None,
    /// Moderate pressure - apply throttling
    /// 中度压力 - 应用限流
    Moderate,
    /// High pressure - aggressive fallback
    /// 高度压力 - 激进回退
    High,
}

/// Configuration for resource pressure detection
/// 资源压力检测配置
#[derive(Debug, Clone)]
pub struct ResourcePressureConfig {
    /// How long to remember pressure events
    /// 记住压力事件的时间长度
    pub pressure_window: Duration,
    /// FD pressure threshold (events per window)
    /// FD 压力阈值（每个窗口的事件数）
    pub fd_pressure_threshold: u32,
    /// Memory pressure threshold (events per window)
    /// 内存压力阈值（每个窗口的事件数）
    pub mem_pressure_threshold: u32,
    /// Throttle delay when moderate pressure detected
    /// 检测到中度压力时的限流延迟
    pub moderate_throttle_ms: u64,
    /// Throttle delay when high pressure detected
    /// 检测到高度压力时的限流延迟
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
/// 全局资源压力监控器
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
    /// 创建一个新的资源压力监控器
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
    /// 记录资源压力事件
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
        // 更新指标
        #[cfg(feature = "metrics")]
        {
            use crate::metrics_ext::get_or_register_gauge_vec_f64;
            let gauge = get_or_register_gauge_vec_f64(
                "resource_pressure_level",
                "Resource pressure level",
                &["type"],
            );
            gauge.with_label_values(&[resource_type.as_str()]).set(1.0);
        }
    }

    /// Check current pressure level for a resource type
    /// 检查资源类型的当前压力水平
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
    /// 获取资源类型的总压力事件计数
    pub fn get_pressure_count(&self, resource_type: ResourceType) -> u64 {
        match resource_type {
            ResourceType::FileDescriptors => self.fd_pressure_counter.load(Ordering::Relaxed),
            ResourceType::Memory => self.mem_pressure_counter.load(Ordering::Relaxed),
        }
    }

    /// Apply throttling based on pressure level
    /// 根据压力水平应用限流
    pub async fn throttle_if_needed(&self, resource_type: ResourceType) {
        let pressure = self.check_pressure(resource_type).await;
        match pressure {
            PressureLevel::None => {
                // No throttling needed
                // 不需要限流
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
/// 全局资源压力监控器实例
static GLOBAL_MONITOR: once_cell::sync::Lazy<ResourcePressureMonitor> =
    once_cell::sync::Lazy::new(ResourcePressureMonitor::default);

/// Get the global resource pressure monitor instance
/// 获取全局资源压力监控器实例
pub fn global_monitor() -> &'static ResourcePressureMonitor {
    &GLOBAL_MONITOR
}

/// Error analysis utilities for detecting resource pressure from I/O errors
/// 用于从 I/O 错误中检测资源压力的错误分析工具
pub mod error_analysis {
    use super::*;
    use crate::dialer::DialError;
    use std::io::ErrorKind;

    /// Analyze a dial error to detect resource pressure
    /// 分析拨号错误以检测资源压力
    pub async fn analyze_dial_error(error: &DialError) -> Option<ResourceType> {
        match error {
            DialError::Io(io_error) => {
                match io_error.kind() {
                    ErrorKind::OutOfMemory => Some(ResourceType::Memory),
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                        // These can indicate FD exhaustion
                        // 这些可能表示 FD 耗尽
                        Some(ResourceType::FileDescriptors)
                    }
                    _ => {
                        // Check error message for known patterns
                        // 检查错误消息中的已知模式
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
    /// 如果在错误中检测到，则记录资源压力
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
    use tokio::time::sleep;

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
            fd_pressure_threshold: 1,
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
            mem_pressure_threshold: 1,
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
        let fd_error = DialError::Io(Error::other("too many open files"));
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
