//! Endpoint-pool selection used by inbound adapters.

use sb_core::outbound::endpoint::ProxyEndpoint;
use std::collections::HashMap;
use std::time::Duration;

/// Health monitoring view for selector endpoints.
#[derive(Debug, Clone)]
pub struct HealthView {
    pub pool_name: String,
    pub endpoints: Vec<EndpointHealth>,
}

#[derive(Debug, Clone)]
pub struct EndpointHealth {
    pub index: usize,
    pub endpoint: ProxyEndpoint,
    pub is_healthy: bool,
    pub avg_rtt_ms: Option<f64>,
    pub success_rate: f64,
    pub last_check: Option<std::time::SystemTime>,
}

impl HealthView {
    pub const fn new(pool_name: String) -> Self {
        Self {
            pool_name,
            endpoints: Vec::new(),
        }
    }

    pub fn add_endpoint(&mut self, proxy_endpoint: ProxyEndpoint) {
        let endpoint = EndpointHealth {
            index: self.endpoints.len(),
            endpoint: proxy_endpoint,
            is_healthy: true,
            avg_rtt_ms: None,
            success_rate: 1.0,
            last_check: None,
        };
        self.endpoints.push(endpoint);
    }

    pub fn add_endpoint_from_string(&mut self, address: String) {
        if let Some(proxy_endpoint) = ProxyEndpoint::parse(&address) {
            self.add_endpoint(proxy_endpoint);
        }
    }

    pub fn update_endpoint_health(&mut self, index: usize, is_healthy: bool, rtt_ms: Option<f64>) {
        if let Some(endpoint) = self.endpoints.get_mut(index) {
            endpoint.is_healthy = is_healthy;
            endpoint.avg_rtt_ms = rtt_ms;
            endpoint.last_check = Some(std::time::SystemTime::now());
        }
    }
}

/// Pool-based selector that manages multiple pools of endpoints.
#[derive(Debug)]
pub struct PoolSelector {
    pub name: String,
    pub pools: HashMap<String, HealthView>,
    pub default_pool: String,
}

impl PoolSelector {
    pub fn new(name: String, default_pool: String) -> Self {
        Self {
            name,
            pools: HashMap::new(),
            default_pool,
        }
    }

    pub fn new_with_capacity(capacity: usize, _ttl: Duration) -> Self {
        Self {
            name: format!("pool_{capacity}"),
            pools: HashMap::with_capacity(capacity),
            default_pool: "default".to_string(),
        }
    }

    pub fn add_pool(&mut self, pool_name: String, endpoints: Vec<String>) {
        let mut health_view = HealthView::new(pool_name.clone());
        for endpoint in endpoints {
            health_view.add_endpoint_from_string(endpoint);
        }
        self.pools.insert(pool_name, health_view);
    }

    pub fn get_pool(&self, pool_name: &str) -> Option<&HealthView> {
        self.pools.get(pool_name)
    }

    pub fn get_pool_mut(&mut self, pool_name: &str) -> Option<&mut HealthView> {
        self.pools.get_mut(pool_name)
    }

    pub fn select_healthy_endpoint(&self, pool_name: &str) -> Option<&EndpointHealth> {
        self.get_pool(pool_name)?
            .endpoints
            .iter()
            .filter(|ep| ep.is_healthy)
            .min_by(|a, b| {
                let a_rtt = a.avg_rtt_ms.unwrap_or(f64::INFINITY);
                let b_rtt = b.avg_rtt_ms.unwrap_or(f64::INFINITY);
                a_rtt
                    .partial_cmp(&b_rtt)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    pub fn record_observation(
        &mut self,
        pool_name: &str,
        endpoint_index: usize,
        dur_ms: u64,
        success: bool,
    ) {
        if let Some(pool) = self.get_pool_mut(pool_name) {
            pool.update_endpoint_health(
                endpoint_index,
                success,
                if success { Some(dur_ms as f64) } else { None },
            );
        }
    }

    pub fn select(
        &self,
        pool_name: &str,
        _peer_addr: std::net::SocketAddr,
        _target: &str,
        _health: &(),
    ) -> Option<&ProxyEndpoint> {
        self.select_healthy_endpoint(pool_name)
            .map(|ep| &ep.endpoint)
    }

    pub fn has_healthy_endpoints(&self, pool_name: &str) -> bool {
        self.get_pool(pool_name)
            .is_some_and(|pool| pool.endpoints.iter().any(|ep| ep.is_healthy))
    }

    pub fn pool_names(&self) -> Vec<&String> {
        self.pools.keys().collect()
    }
}
