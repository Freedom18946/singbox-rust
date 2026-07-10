//! MIG-03 transitional inbound data-plane bridge.
//!
//! Runtime holders consume only `sb_types::Inbound`. Existing blocking protocol
//! loops remain behind this single bridge until WP06 removes scaffold fallbacks
//! and moves lifecycle ownership into concrete inbound implementations. No new
//! protocol may implement this trait.

use super::InboundReadySender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Temporary blocking driver for pre-canonical inbound implementations.
#[doc(hidden)]
pub trait InboundTaskDriver: Send + Sync + std::fmt::Debug + 'static {
    fn serve(&self) -> std::io::Result<()>;

    fn supports_startup_readiness(&self) -> bool {
        false
    }

    fn serve_with_ready(&self, _ready: Option<InboundReadySender>) -> std::io::Result<()> {
        self.serve()
    }

    fn request_shutdown(&self) {}

    fn active_connections(&self) -> Option<u64> {
        None
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        None
    }
}

struct ManagedInbound {
    kind: String,
    tag: sb_types::InboundTag,
    service: Arc<dyn InboundTaskDriver>,
    worker: parking_lot::Mutex<Option<std::thread::JoinHandle<std::io::Result<()>>>>,
    shutdown_requested: Arc<AtomicBool>,
}

impl std::fmt::Debug for ManagedInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedInbound")
            .field("kind", &self.kind)
            .field("tag", &self.tag)
            .field("running", &self.worker.lock().is_some())
            .finish()
    }
}

#[doc(hidden)]
pub fn manage_inbound(
    service: Arc<dyn InboundTaskDriver>,
    kind: impl Into<String>,
    tag: impl Into<String>,
) -> Arc<dyn sb_types::Inbound> {
    Arc::new(ManagedInbound {
        kind: kind.into(),
        tag: sb_types::InboundTag::new(tag),
        service,
        worker: parking_lot::Mutex::new(None),
        shutdown_requested: Arc::new(AtomicBool::new(false)),
    })
}

fn record_transition_exit(
    tag: &sb_types::InboundTag,
    kind: &str,
    shutdown_requested: bool,
    error: Option<&str>,
) {
    let exit_kind = match (shutdown_requested, error.is_some()) {
        (true, _) => "clean_shutdown",
        (false, true) => "serve_error",
        (false, false) => "unexpected_completion",
    };
    if shutdown_requested {
        tracing::debug!(
            target: "sb_core::runtime",
            component = "inbound",
            tag = %tag,
            kind,
            phase = "transition",
            exit_kind,
            "inbound serve task stopped"
        );
    } else {
        tracing::error!(
            target: "sb_core::runtime",
            component = "inbound",
            tag = %tag,
            kind,
            phase = "transition",
            exit_kind,
            error = error.unwrap_or(""),
            "inbound serve task exited abnormally"
        );
    }
}

impl sb_types::Inbound for ManagedInbound {
    fn r#type(&self) -> &str {
        &self.kind
    }

    fn tag(&self) -> sb_types::InboundTag {
        self.tag.clone()
    }

    fn start(&self, stage: sb_types::StartStage) -> Result<(), sb_types::CoreError> {
        if stage != sb_types::StartStage::Start || self.worker.lock().is_some() {
            return Ok(());
        }

        let service = self.service.clone();
        let readiness = service.supports_startup_readiness();
        self.shutdown_requested.store(false, Ordering::SeqCst);
        let shutdown_requested = self.shutdown_requested.clone();
        let tag = self.tag.clone();
        let kind = self.kind.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let worker = std::thread::Builder::new()
            .name(format!("inbound-{}", self.tag.as_str()))
            .spawn(move || {
                let result = if readiness {
                    service.serve_with_ready(Some(ready_tx))
                } else {
                    drop(ready_tx);
                    service.serve()
                };
                record_transition_exit(
                    &tag,
                    &kind,
                    shutdown_requested.load(Ordering::SeqCst),
                    result
                        .as_ref()
                        .err()
                        .map(|error| error.to_string())
                        .as_deref(),
                );
                result
            })
            .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
        *self.worker.lock() = Some(worker);

        if readiness {
            match futures::executor::block_on(ready_rx) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(sb_types::CoreError::io(error.to_string())),
                Err(error) => Err(sb_types::CoreError::io(format!(
                    "inbound readiness channel closed: {error}"
                ))),
            }
        } else {
            Ok(())
        }
    }

    fn close(&self) -> Result<(), sb_types::CoreError> {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.service.request_shutdown();
        if let Some(worker) = self.worker.lock().take() {
            let tag = self.tag.clone();
            std::thread::Builder::new()
                .name(format!("inbound-reaper-{}", tag.as_str()))
                .spawn(move || match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(%error, tag = %tag, "closed inbound worker returned error");
                    }
                    Err(_) => {
                        tracing::error!(tag = %tag, "closed inbound worker panicked");
                    }
                })
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
        }
        Ok(())
    }

    fn supports_startup_readiness(&self) -> bool {
        self.service.supports_startup_readiness()
    }

    fn active_connections(&self) -> Option<u64> {
        self.service.active_connections()
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        self.service.udp_sessions_estimate()
    }
}
