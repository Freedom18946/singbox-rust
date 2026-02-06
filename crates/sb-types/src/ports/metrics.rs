//! Metrics abstraction port.

/// Metrics port for observability.
///
/// Core and adapters call this; the actual exporter (prometheus, etc.)
/// is injected by app.
pub trait MetricsPort: Send + Sync + 'static {
    /// Increment a counter.
    fn inc_counter(&self, name: &'static str, labels: &[(&'static str, &str)], value: u64);

    /// Set a gauge value.
    fn set_gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64);

    /// Observe a histogram value.
    fn observe_histogram(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64);
}

/// No-op metrics implementation for when metrics are disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpMetrics;

impl MetricsPort for NoOpMetrics {
    fn inc_counter(&self, _name: &'static str, _labels: &[(&'static str, &str)], _value: u64) {}
    fn set_gauge(&self, _name: &'static str, _labels: &[(&'static str, &str)], _value: f64) {}
    fn observe_histogram(
        &self,
        _name: &'static str,
        _labels: &[(&'static str, &str)],
        _value: f64,
    ) {
    }
}
