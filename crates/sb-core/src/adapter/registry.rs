//! Minimal adapter-first registry facade.
//!
//! This provides a lightweight registration mechanism so external crates (or
//! future `sb-adapters`) can register inbound/outbound factories. The bridge
//! consults this registry first and falls back to scaffold implementations.

use super::{
    Bridge, InboundParam, InboundService, OutboundConnector, OutboundParam, UdpOutboundFactory,
};
use crate::context::ContextRegistry;
use crate::dns::dns_router::DnsRouter;
use crate::outbound::OutboundRegistryHandle;
#[cfg(feature = "router")]
use crate::router::RouteConnectionManager;
#[cfg(feature = "router")]
use crate::router::RouterHandle;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Context passed to inbound adapter builders so they can access runtime components.
pub struct AdapterInboundContext {
    #[cfg(feature = "router")]
    pub engine: crate::routing::engine::Engine,
    pub bridge: Arc<Bridge>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    #[cfg(feature = "router")]
    pub router: Arc<RouterHandle>,
    /// DNS router for domain lookup with routing rules.
    /// DNS 路由器，用于带路由规则的域名查找。
    pub dns_router: Option<Arc<dyn DnsRouter>>,
    /// Connection manager for TCP/UDP handling (Go parity: route.ConnectionManager).
    /// TCP/UDP 连接处理管理器（Go 兼容：route.ConnectionManager）。
    #[cfg(feature = "router")]
    pub connection_manager: Option<Arc<RouteConnectionManager>>,
    pub context: ContextRegistry,
}

/// Context passed to outbound adapter builders so they can access the bridge (for Selector/URLTest).
pub struct AdapterOutboundContext {
    pub bridge: Arc<Bridge>,
    pub context: ContextRegistry,
}

pub type InboundBuilder =
    fn(&InboundParam, &AdapterInboundContext) -> Option<Arc<dyn InboundService>>;
pub type OutboundBuilder = fn(
    &OutboundParam,
    &sb_config::ir::OutboundIR,
    &AdapterOutboundContext,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

#[derive(Clone, Default)]
pub struct RegistrySnapshot {
    inbounds: HashMap<&'static str, InboundBuilder>,
    outbounds: HashMap<&'static str, OutboundBuilder>,
}

impl RegistrySnapshot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_inbound(&mut self, kind: &'static str, builder: InboundBuilder) -> bool {
        self.inbounds.insert(kind, builder).is_none()
    }

    pub fn register_outbound(&mut self, kind: &'static str, builder: OutboundBuilder) -> bool {
        self.outbounds.insert(kind, builder).is_none()
    }
}

static INBOUND_REG: Lazy<RwLock<HashMap<&'static str, InboundBuilder>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static OUTBOUND_REG: Lazy<RwLock<HashMap<&'static str, OutboundBuilder>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static RUNTIME_INBOUNDS: Lazy<RwLock<Option<Arc<InboundRegistryHandle>>>> =
    Lazy::new(|| RwLock::new(None));
static RUNTIME_OUTBOUNDS: Lazy<RwLock<Option<Arc<OutboundRegistryHandle>>>> =
    Lazy::new(|| RwLock::new(None));

#[derive(Clone, Debug, Default)]
pub struct InboundRegistryHandle {
    inner: HashMap<String, Arc<dyn InboundService>>,
}

impl InboundRegistryHandle {
    pub fn new(inner: HashMap<String, Arc<dyn InboundService>>) -> Self {
        Self { inner }
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn InboundService>> {
        self.inner.get(tag).cloned()
    }
}

/// Register an inbound builder for a kind key (e.g., "socks", "http", "tun").
/// Returns false if a builder for this kind already exists.
pub fn register_inbound(kind: &'static str, f: InboundBuilder) -> bool {
    let mut g = INBOUND_REG.write().unwrap();
    g.insert(kind, f).is_none()
}

/// Register an outbound builder for a kind key (e.g., "vmess", "vless", "tuic").
/// Returns false if a builder for this kind already exists.
pub fn register_outbound(kind: &'static str, f: OutboundBuilder) -> bool {
    let mut g = OUTBOUND_REG.write().unwrap();
    g.insert(kind, f).is_none()
}

/// Replace the global adapter registry with an explicit snapshot.
pub fn install_snapshot(snapshot: &RegistrySnapshot) {
    let mut inbound = INBOUND_REG.write().unwrap();
    *inbound = snapshot.inbounds.clone();

    let mut outbound = OUTBOUND_REG.write().unwrap();
    *outbound = snapshot.outbounds.clone();
}

/// Look up an inbound builder by kind.
pub fn get_inbound(kind: &str) -> Option<InboundBuilder> {
    let g = INBOUND_REG.read().unwrap();
    g.get(kind).copied()
}

/// Look up an outbound builder by kind.
pub fn get_outbound(kind: &str) -> Option<OutboundBuilder> {
    let g = OUTBOUND_REG.read().unwrap();
    g.get(kind).copied()
}

/// Install the current runtime outbound registry handle for late-bound detours.
pub fn install_runtime_outbounds(handle: Arc<OutboundRegistryHandle>) {
    let mut g = RUNTIME_OUTBOUNDS.write().unwrap();
    *g = Some(handle);
}

/// Install the current runtime inbound registry handle for late-bound detours.
pub fn install_runtime_inbounds(handle: Arc<InboundRegistryHandle>) {
    let mut g = RUNTIME_INBOUNDS.write().unwrap();
    *g = Some(handle);
}

/// Retrieve the current runtime inbound registry handle, if installed.
pub fn runtime_inbounds() -> Option<Arc<InboundRegistryHandle>> {
    let g = RUNTIME_INBOUNDS.read().unwrap();
    g.clone()
}

/// Retrieve the current runtime outbound registry handle, if installed.
pub fn runtime_outbounds() -> Option<Arc<OutboundRegistryHandle>> {
    let g = RUNTIME_OUTBOUNDS.read().unwrap();
    g.clone()
}

/// List all registered outbound kinds (for testing).
pub fn list_registered_outbounds() -> Vec<String> {
    let g = OUTBOUND_REG.read().unwrap();
    g.keys().map(|k| k.to_string()).collect()
}
