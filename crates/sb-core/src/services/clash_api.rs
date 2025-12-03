use crate::context::ClashServer;
use sb_config::ir::ClashApiIR;
use std::sync::atomic::{AtomicBool, Ordering};

/// Lightweight wrapper around Clash API server config.
#[derive(Debug)]
pub struct ClashApiServer {
    cfg: ClashApiIR,
    started: AtomicBool,
}

impl ClashApiServer {
    pub fn new(cfg: ClashApiIR) -> Self {
        Self {
            cfg,
            started: AtomicBool::new(false),
        }
    }
}

impl ClashServer for ClashApiServer {
    fn start(&self) -> anyhow::Result<()> {
        self.started.store(true, Ordering::SeqCst);
        tracing::info!(
            target: "sb_core::services::clash",
            listen = ?self.cfg.external_controller,
            "Clash API server start requested (stub)"
        );
        Ok(())
    }

    fn close(&self) -> anyhow::Result<()> {
        self.started.store(false, Ordering::SeqCst);
        tracing::info!(target: "sb_core::services::clash", "Clash API server stopped (stub)");
        Ok(())
    }
}
