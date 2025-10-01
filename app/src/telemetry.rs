#[cfg(feature = "observe")]
mod imp {
    use anyhow::Result;

    #[must_use]
    pub fn next_trace_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, SeqCst);
        format!("{:016x}", n ^ fastrand::u64(..))
    }

    pub fn init_tracing() {
        #[cfg(feature = "dev-cli")]
        crate::tracing_init::init_tracing_once();
    }

    /// Initialize metrics exporter.
    ///
    /// # Errors
    /// Currently never fails, but returns `Result` for future extensibility.
    pub fn init_metrics_exporter() -> Result<()> {
        #[cfg(feature = "dev-cli")]
        crate::tracing_init::init_metrics_exporter_once();
        Ok(())
    }

    pub async fn init_and_listen() {
        // Metrics exporter integration point - admin_debug provides HTTP metrics endpoint
        #[cfg(feature = "admin_debug")]
        crate::admin_debug::init(None).await;
    }
}

#[cfg(not(feature = "observe"))]
mod imp {
    use anyhow::Result;

    #[must_use]
    pub const fn next_trace_id() -> String {
        String::new()
    }

    pub const fn init_tracing() {
        // NOP for minimal
    }

    /// Initialize metrics exporter.
    ///
    /// # Errors
    /// Currently never fails, but returns `Result` for future extensibility.
    pub const fn init_metrics_exporter() -> Result<()> {
        // NOP for minimal
        Ok(())
    }

    #[allow(clippy::unused_async)] // Conditional: async needed for observe feature
    pub async fn init_and_listen() {
        // NOP for minimal
    }
}

pub use imp::*;
