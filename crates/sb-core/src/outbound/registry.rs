use super::endpoint::ProxyEndpoint;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct Registry {
    pub default: Option<ProxyEndpoint>,
    pub pools: HashMap<String, ProxyPool>,
}

#[derive(Clone)]
pub struct ProxyPool {
    pub name: String,
    pub endpoints: Vec<ProxyEndpoint>,
    pub policy: PoolPolicy,
    pub sticky: StickyCfg,
}

#[derive(Clone, Copy)]
pub enum PoolPolicy {
    WeightedRR,
    WeightedRRWithLatencyBias,
}

#[derive(Clone, Copy)]
pub struct StickyCfg {
    pub ttl_ms: u64,
    pub cap: usize,
}

static GLOBAL: OnceCell<Arc<Registry>> = OnceCell::new();

pub fn install_global(r: Registry) {
    let _ = GLOBAL.set(Arc::new(r));
}

pub fn global() -> Option<Arc<Registry>> {
    GLOBAL.get().cloned()
}
