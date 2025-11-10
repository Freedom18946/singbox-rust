use crate::adapter::InboundService;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::error;

#[derive(Debug, Clone)]
pub struct UnsupportedInbound {
    kind: String,
    reason: String,
    hint: Option<String>,
}

impl UnsupportedInbound {
    pub fn new(kind: impl Into<String>, reason: impl Into<String>, hint: Option<String>) -> Self {
        Self { kind: kind.into(), reason: reason.into(), hint }
    }
}

static ACTIVE: AtomicU64 = AtomicU64::new(0);

impl InboundService for UnsupportedInbound {
    fn serve(&self) -> std::io::Result<()> {
        let plat = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let msg = match &self.hint {
            Some(h) => format!(
                "inbound '{}' is not supported on this platform ({}-{}): {}. Hint: {}",
                self.kind, plat, arch, self.reason, h
            ),
            None => format!(
                "inbound '{}' is not supported on this platform ({}-{}): {}",
                self.kind, plat, arch, self.reason
            ),
        };
        error!(target: "sb_core::inbound", message = %msg);
        Err(io::Error::other(msg))
    }

    fn request_shutdown(&self) {
        // no-op
    }

    fn active_connections(&self) -> Option<u64> {
        Some(ACTIVE.load(Ordering::Relaxed))
    }
}
