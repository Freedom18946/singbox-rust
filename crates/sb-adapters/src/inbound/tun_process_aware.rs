#![cfg(feature = "tun_macos")]

//! Process-aware TUN ingress for macOS.
//!
//! This module wraps the macOS runtime glue (utun + tun2socks) with
//! awareness of process metadata so routing rules can leverage
//! `process_name` and `process_path` selectors.

use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use sb_core::outbound::OutboundConnector;
use sb_core::router::process_router::ProcessRouter;

use sb_platform::process::ProcessMatcher;
use sb_platform::tun::TunError;

use super::tun_macos::TunMacosRuntime;

/// Process-aware TUN configuration for macOS transparent proxying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAwareTunConfig {
    /// utun interface name (e.g. `utun8`). If left empty, the kernel selects one.
    pub name: String,
    /// MTU configured on the virtual interface.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// IPv4 address to assign to the interface (CIDR /24 by default).
    #[serde(default)]
    pub ipv4: Option<IpAddr>,
    /// IPv6 address to assign to the interface.
    #[serde(default)]
    pub ipv6: Option<IpAddr>,
    /// Whether the runtime should install default routes for the interface.
    #[serde(default)]
    pub auto_route: bool,
}

fn default_mtu() -> u32 {
    1500
}

impl Default for ProcessAwareTunConfig {
    fn default() -> Self {
        Self {
            name: "utun8".to_string(),
            mtu: default_mtu(),
            ipv4: None,
            ipv6: None,
            auto_route: false,
        }
    }
}

/// Runtime statistics that can be queried by management APIs.
#[derive(Default)]
pub struct ProcessAwareTunStatistics {
    tcp_open: AtomicU64,
    tcp_closed: AtomicU64,
    last_tcp_id: AtomicU64,
    udp_packets: AtomicU64,
}

impl ProcessAwareTunStatistics {
    pub(crate) fn next_tcp_id(&self) -> u64 {
        self.last_tcp_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn on_tcp_open(
        &self,
        _target: &sb_core::types::Endpoint,
        _process: Option<&sb_platform::process::ProcessInfo>,
    ) {
        self.tcp_open.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn on_tcp_close(&self) {
        self.tcp_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn on_udp_packet(&self) {
        self.udp_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TunStatsSnapshot {
        TunStatsSnapshot {
            tcp_open: self.tcp_open.load(Ordering::Relaxed),
            tcp_closed: self.tcp_closed.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
        }
    }
}

/// Simple snapshot view for external observers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunStatsSnapshot {
    pub tcp_open: u64,
    pub tcp_closed: u64,
    pub udp_packets: u64,
}

/// macOS implementation of the process-aware inbound.
pub struct ProcessAwareTunInbound {
    config: ProcessAwareTunConfig,
    outbound: Arc<dyn OutboundConnector>,
    process_router: Option<Arc<ProcessRouter>>,
    process_matcher: Option<Arc<ProcessMatcher>>,
    runtime: Mutex<Option<TunMacosRuntime>>,
    stats: Arc<ProcessAwareTunStatistics>,
}

impl ProcessAwareTunInbound {
    pub fn new(
        config: ProcessAwareTunConfig,
        outbound: Arc<dyn OutboundConnector>,
        process_router: Option<ProcessRouter>,
    ) -> Result<Self, TunError> {
        Ok(Self {
            config,
            outbound,
            process_router: process_router.map(Arc::new),
            process_matcher: ProcessMatcher::new().ok().map(Arc::new),
            runtime: Mutex::new(None),
            stats: Arc::new(ProcessAwareTunStatistics::default()),
        })
    }

    pub fn stats(&self) -> Arc<ProcessAwareTunStatistics> {
        self.stats.clone()
    }

    pub async fn start(&self) -> Result<(), TunError> {
        let runtime = TunMacosRuntime::start(
            &self.config,
            self.outbound.clone(),
            self.process_router.clone(),
            self.process_matcher.clone(),
            self.stats.clone(),
        )
        .await?;

        *self.runtime.lock().await = Some(runtime);
        Ok(())
    }

    pub async fn stop(&self) {
        if let Some(runtime) = self.runtime.lock().await.take() {
            runtime.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::outbound::DirectConnector;

    #[tokio::test]
    async fn config_defaults() {
        let cfg = ProcessAwareTunConfig::default();
        assert_eq!(cfg.name, "utun8");
        assert_eq!(cfg.mtu, 1500);
        assert!(!cfg.auto_route);
    }

    #[tokio::test]
    async fn instantiate_tun_inbound() {
        let cfg = ProcessAwareTunConfig::default();
        let outbound = Arc::new(DirectConnector::new());
        let inbound = ProcessAwareTunInbound::new(cfg, outbound, None).unwrap();
        assert!(inbound.runtime.lock().await.is_none());
    }
}
