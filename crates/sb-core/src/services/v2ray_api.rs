use crate::context::V2RayServer;
use sb_config::ir::V2RayApiIR;
use std::sync::atomic::{AtomicBool, Ordering};

/// Minimal V2Ray API server wrapper (stub).
#[derive(Debug)]
pub struct V2RayApiServer {
    cfg: V2RayApiIR,
    started: AtomicBool,
}

impl V2RayApiServer {
    pub fn new(cfg: V2RayApiIR) -> Self {
        Self {
            cfg,
            started: AtomicBool::new(false),
        }
    }
}

impl V2RayServer for V2RayApiServer {
    fn start(&self) -> anyhow::Result<()> {
        self.started.store(true, Ordering::SeqCst);
        tracing::info!(
            target: "sb_core::services::v2ray",
            listen = ?self.cfg.listen,
            "V2Ray API server start requested (stub)"
        );
        Ok(())
    }

    fn close(&self) -> anyhow::Result<()> {
        self.started.store(false, Ordering::SeqCst);
        tracing::info!(target: "sb_core::services::v2ray", "V2Ray API server stopped (stub)");
        Ok(())
    }
}
