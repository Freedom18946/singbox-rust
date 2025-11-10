//! Minimal adapter-first registry facade.
//!
//! This provides a lightweight registration mechanism so external crates (or
//! future `sb-adapters`) can register inbound/outbound factories. The bridge
//! consults this registry first and falls back to scaffold implementations.

use super::{
    Bridge, InboundParam, InboundService, OutboundConnector, OutboundParam, UdpOutboundFactory,
};
use crate::outbound::OutboundRegistryHandle;
#[cfg(feature = "router")]
use crate::router::RouterHandle;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Context passed to inbound adapter builders so they can access runtime components.
#[cfg_attr(not(feature = "router"), allow(unused_lifetimes))]
pub struct AdapterInboundContext<'a> {
    #[cfg(feature = "router")]
    pub engine: crate::routing::engine::Engine<'a>,
    pub bridge: Arc<Bridge>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    #[cfg(feature = "router")]
    pub router: Arc<RouterHandle>,
    #[cfg(not(feature = "router"))]
    pub _phantom: std::marker::PhantomData<&'a ()>,
}

type InboundBuilder =
    fn(&InboundParam, &AdapterInboundContext<'_>) -> Option<Arc<dyn InboundService>>;
type OutboundBuilder = fn(
    &OutboundParam,
    &sb_config::ir::OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

static INBOUND_REG: Lazy<RwLock<HashMap<&'static str, InboundBuilder>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static OUTBOUND_REG: Lazy<RwLock<HashMap<&'static str, OutboundBuilder>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

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
