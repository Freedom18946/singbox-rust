//! Cardinality monitoring for Prometheus metrics
//!
//! This module prevents label explosion by tracking unique label combinations
//! and warning when cardinality exceeds thresholds.
//!
//! ## Problem
//! High cardinality metrics (many unique label combinations) can cause:
//! - Memory exhaustion in Prometheus
//! - Slow query performance
//! - Storage bloat
//!
//! ## Solution
//! Track unique label combinations per metric and warn when threshold exceeded.
//!
//! ## Usage
//! ```
//! use sb_metrics::cardinality::CardinalityMonitor;
//!
//! let monitor = CardinalityMonitor::new(10000); // Warn at 10k time series
//!
//! // Record label usage
//! monitor.record_label_usage("http_requests_total", &["GET".to_string(), "/api".to_string()]);
//! monitor.record_label_usage("http_requests_total", &["POST".to_string(), "/api".to_string()]);
//!
//! // Check cardinality
//! let cardinality = monitor.get_cardinality("http_requests_total");
//! println!("http_requests_total has {} unique time series", cardinality);
//! ```

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use tracing::warn;

/// Monitors label cardinality for Prometheus metrics
///
/// Tracks unique label combinations per metric to detect potential
/// label explosion issues. Uses SHA-256 hashing to store label
/// combinations efficiently.
pub struct CardinalityMonitor {
    /// Map of metric name → set of unique label combination hashes
    metrics: Mutex<HashMap<String, HashSet<[u8; 32]>>>,
    /// Total number of unique time series across all metrics
    total_series: AtomicUsize,
    /// Threshold for warning about high cardinality
    warning_threshold: usize,
    /// Track if we've already warned about a specific metric
    warned_metrics: Mutex<HashSet<String>>,
}

impl CardinalityMonitor {
    /// Create a new cardinality monitor
    ///
    /// # Arguments
    /// * `warning_threshold` - Number of unique time series before warning (e.g., `10_000`)
    ///
    /// # Example
    /// ```
    /// use sb_metrics::cardinality::CardinalityMonitor;
    ///
    /// let monitor = CardinalityMonitor::new(10000);
    /// ```
    #[must_use]
    pub fn new(warning_threshold: usize) -> Self {
        Self {
            metrics: Mutex::new(HashMap::new()),
            total_series: AtomicUsize::new(0),
            warning_threshold,
            warned_metrics: Mutex::new(HashSet::new()),
        }
    }

    /// Record usage of a label combination for a metric
    ///
    /// This should be called whenever a metric is incremented with specific labels.
    ///
    /// # Arguments
    /// * `metric_name` - Name of the metric (e.g., `"http_requests_total"`)
    /// * `labels` - Slice of label values in order (e.g., `&["GET", "/api", "200"]`)
    ///
    /// # Example
    /// ```
    /// # use sb_metrics::cardinality::CardinalityMonitor;
    /// let monitor = CardinalityMonitor::new(1000);
    /// monitor.record_label_usage("http_requests_total", &["GET".to_string(), "/api".to_string()]);
    /// ```
    pub fn record_label_usage(&self, metric_name: &str, labels: &[String]) {
        // Compute hash of label combination for efficient storage
        let label_hash = Self::hash_labels(labels);

        // Acquire lock on metrics map
        let Ok(mut metrics) = self.metrics.lock() else {
            // If mutex is poisoned, skip monitoring (non-critical path)
            return;
        };

        // Get or create the label set for this metric
        let label_set = metrics.entry(metric_name.to_string()).or_default();

        // Try to insert the label combination hash
        if label_set.insert(label_hash) {
            // New unique combination - increment total series count
            let total = self.total_series.fetch_add(1, Ordering::Relaxed) + 1;

            // Check global threshold
            self.check_global_threshold(total);

            // Check per-metric threshold
            let metric_cardinality = label_set.len();
            self.check_metric_threshold(metric_name, metric_cardinality, labels);
        }
    }

    /// Compute SHA-256 hash of label combination
    fn hash_labels(labels: &[String]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for label in labels {
            hasher.update(label.as_bytes());
            hasher.update(b"\0"); // Delimiter to avoid collision
        }
        hasher.finalize().into()
    }

    /// Check if global cardinality threshold is exceeded
    fn check_global_threshold(&self, total: usize) {
        if total > self.warning_threshold && total == self.warning_threshold + 1 {
            // Only warn once globally
            warn!(
                total_series = total,
                threshold = self.warning_threshold,
                "High cardinality detected across all metrics"
            );
        }
    }

    /// Check if per-metric cardinality threshold is exceeded
    fn check_metric_threshold(&self, metric_name: &str, cardinality: usize, labels: &[String]) {
        let per_metric_threshold = self.warning_threshold / 10;
        if cardinality > per_metric_threshold {
            // Warn if single metric has >10% of total threshold
            let Ok(mut warned) = self.warned_metrics.lock() else {
                return;
            };

            if warned.insert(metric_name.to_string()) {
                warn!(
                    metric = metric_name,
                    cardinality,
                    threshold = per_metric_threshold,
                    labels = ?labels,
                    "High cardinality detected for single metric"
                );
            }
        }
    }

    /// Get the cardinality (number of unique time series) for a specific metric
    ///
    /// # Arguments
    /// * `metric_name` - Name of the metric
    ///
    /// # Returns
    /// Number of unique label combinations for this metric
    ///
    /// # Example
    /// ```
    /// # use sb_metrics::cardinality::CardinalityMonitor;
    /// let monitor = CardinalityMonitor::new(1000);
    /// monitor.record_label_usage("http_requests_total", &["GET".to_string()]);
    /// monitor.record_label_usage("http_requests_total", &["POST".to_string()]);
    /// assert_eq!(monitor.get_cardinality("http_requests_total"), 2);
    /// ```
    #[must_use]
    pub fn get_cardinality(&self, metric_name: &str) -> usize {
        self.metrics
            .lock()
            .ok()
            .and_then(|metrics| metrics.get(metric_name).map(HashSet::len))
            .unwrap_or(0)
    }

    /// Get the total number of unique time series across all metrics
    ///
    /// # Example
    /// ```
    /// # use sb_metrics::cardinality::CardinalityMonitor;
    /// let monitor = CardinalityMonitor::new(1000);
    /// monitor.record_label_usage("http_total", &["GET".to_string()]);
    /// monitor.record_label_usage("db_total", &["SELECT".to_string()]);
    /// assert_eq!(monitor.get_total_series(), 2);
    /// ```
    #[must_use]
    pub fn get_total_series(&self) -> usize {
        self.total_series.load(Ordering::Relaxed)
    }

    /// Get a summary of cardinality per metric
    ///
    /// # Returns
    /// `HashMap` of metric name → cardinality
    ///
    /// # Example
    /// ```
    /// # use sb_metrics::cardinality::CardinalityMonitor;
    /// let monitor = CardinalityMonitor::new(1000);
    /// monitor.record_label_usage("http_total", &["GET".to_string()]);
    /// monitor.record_label_usage("http_total", &["POST".to_string()]);
    /// monitor.record_label_usage("db_total", &["SELECT".to_string()]);
    ///
    /// let summary = monitor.get_cardinality_summary();
    /// assert_eq!(summary.get("http_total"), Some(&2));
    /// assert_eq!(summary.get("db_total"), Some(&1));
    /// ```
    #[must_use]
    pub fn get_cardinality_summary(&self) -> HashMap<String, usize> {
        self.metrics
            .lock()
            .ok()
            .map(|metrics| {
                metrics
                    .iter()
                    .map(|(name, set)| (name.clone(), set.len()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reset all cardinality tracking
    ///
    /// This should be called sparingly (e.g., after configuration reload)
    /// as it will clear all tracked label combinations.
    pub fn reset(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.clear();
        }
        self.total_series.store(0, Ordering::Relaxed);
        if let Ok(mut warned) = self.warned_metrics.lock() {
            warned.clear();
        }
    }
}

/// Global cardinality monitor instance
///
/// Default threshold: 10,000 unique time series
pub static CARDINALITY_MONITOR: LazyLock<CardinalityMonitor> =
    LazyLock::new(|| CardinalityMonitor::new(10_000));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cardinality_monitor_creation() {
        let monitor = CardinalityMonitor::new(1000);
        assert_eq!(monitor.get_total_series(), 0);
    }

    #[test]
    fn test_record_label_usage() {
        let monitor = CardinalityMonitor::new(1000);

        monitor.record_label_usage("test_metric", &["value1".to_string()]);
        assert_eq!(monitor.get_cardinality("test_metric"), 1);
        assert_eq!(monitor.get_total_series(), 1);

        // Same labels - should not increase cardinality
        monitor.record_label_usage("test_metric", &["value1".to_string()]);
        assert_eq!(monitor.get_cardinality("test_metric"), 1);
        assert_eq!(monitor.get_total_series(), 1);

        // Different labels - should increase cardinality
        monitor.record_label_usage("test_metric", &["value2".to_string()]);
        assert_eq!(monitor.get_cardinality("test_metric"), 2);
        assert_eq!(monitor.get_total_series(), 2);
    }

    #[test]
    fn test_multiple_metrics() {
        let monitor = CardinalityMonitor::new(1000);

        monitor.record_label_usage("metric1", &["a".to_string()]);
        monitor.record_label_usage("metric1", &["b".to_string()]);
        monitor.record_label_usage("metric2", &["x".to_string()]);

        assert_eq!(monitor.get_cardinality("metric1"), 2);
        assert_eq!(monitor.get_cardinality("metric2"), 1);
        assert_eq!(monitor.get_total_series(), 3);
    }

    #[test]
    fn test_cardinality_summary() {
        let monitor = CardinalityMonitor::new(1000);

        monitor.record_label_usage("metric1", &["a".to_string()]);
        monitor.record_label_usage("metric1", &["b".to_string()]);
        monitor.record_label_usage("metric2", &["x".to_string()]);

        let summary = monitor.get_cardinality_summary();
        assert_eq!(summary.get("metric1"), Some(&2));
        assert_eq!(summary.get("metric2"), Some(&1));
    }

    #[test]
    fn test_reset() {
        let monitor = CardinalityMonitor::new(1000);

        monitor.record_label_usage("test", &["a".to_string()]);
        assert_eq!(monitor.get_total_series(), 1);

        monitor.reset();
        assert_eq!(monitor.get_total_series(), 0);
        assert_eq!(monitor.get_cardinality("test"), 0);
    }

    #[test]
    fn test_warning_threshold() {
        let monitor = CardinalityMonitor::new(5); // Low threshold for testing

        // Add 6 unique combinations (exceeds threshold of 5)
        for i in 0..6 {
            monitor.record_label_usage("test", &[format!("value{i}")]);
        }

        assert_eq!(monitor.get_total_series(), 6);
        // Warning should have been logged (but we can't easily test log output)
    }

    #[test]
    fn test_multiple_label_values() {
        let monitor = CardinalityMonitor::new(1000);

        monitor.record_label_usage(
            "http_requests",
            &["GET".to_string(), "/api".to_string(), "200".to_string()],
        );
        monitor.record_label_usage(
            "http_requests",
            &["GET".to_string(), "/api".to_string(), "404".to_string()],
        );
        monitor.record_label_usage(
            "http_requests",
            &["POST".to_string(), "/api".to_string(), "200".to_string()],
        );

        assert_eq!(monitor.get_cardinality("http_requests"), 3);
    }
}
