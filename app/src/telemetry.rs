#[cfg(feature = "observe")]
mod imp {
    use anyhow::Result;

    pub fn next_trace_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering::*};
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, SeqCst);
        format!("{:016x}", n ^ fastrand::u64(..))
    }

    pub fn init_tracing() {
        crate::tracing_init::init_tracing_once();
    }

    pub async fn init_metrics_exporter() -> Result<()> {
        crate::tracing_init::init_metrics_exporter_once();
        Ok(())
    }

    pub async fn init_and_listen() {
        // NOTE: metrics exporter entrypoint (stub); admin_debug may expose metrics.
        #[cfg(feature = "admin_debug")]
        crate::admin_debug::init(None).await;
    }
}

#[cfg(not(feature = "observe"))]
mod imp {
    use anyhow::Result;

    pub fn next_trace_id() -> String {
        "00000000000000000".to_string()
    }

    pub fn init_tracing() {
        // NOP for minimal
    }

    pub async fn init_metrics_exporter() -> Result<()> {
        // NOP for minimal
        Ok(())
    }

    pub async fn init_and_listen() {
        // NOP for minimal
    }
}

pub use imp::*;
