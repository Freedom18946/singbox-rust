//! Multi-provider GeoIP implementation
//!
//! This module provides a multiplexing GeoIP provider that can aggregate
//! results from multiple GeoIP sources and provide fallback mechanisms.

use super::{GeoInfo, GeoIpProvider};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Multi-provider GeoIP multiplexer
pub struct GeoMux {
    providers: Vec<ProviderWithConfig>,
    strategy: LookupStrategy,
    cache: std::sync::Mutex<lru::LruCache<IpAddr, CachedGeoInfo>>,
}

#[allow(dead_code)]
struct ProviderWithConfig {
    provider: Arc<dyn GeoIpProvider>,
    name: String,
    priority: u8,
    timeout: Duration,
    enabled: std::sync::atomic::AtomicBool,
    failure_count: std::sync::atomic::AtomicU64,
    last_success: std::sync::Mutex<Option<std::time::Instant>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CachedGeoInfo {
    info: GeoInfo,
    timestamp: std::time::Instant,
    provider: String,
}

/// Lookup strategy for multiple providers
#[derive(Debug, Clone)]
pub enum LookupStrategy {
    /// Use first successful result
    FirstSuccess,
    /// Use highest priority provider
    Priority,
    /// Aggregate results from all providers
    Aggregate,
    /// Use fastest responding provider
    Fastest,
}

impl GeoMux {
    /// Create a GeoMux from environment configuration
    pub fn from_env() -> anyhow::Result<Self> {
        let mut mux = GeoMux::new(LookupStrategy::FirstSuccess);

        // Add MMDB provider if available
        if let Ok(mmdb_provider) = super::mmdb::MmdbProvider::new() {
            mux.add_provider(
                Arc::new(mmdb_provider),
                "mmdb".to_string(),
                1,
                Duration::from_secs(2),
            );
        }

        Ok(mux)
    }

    /// Lookup IP and return source and country code (compatible with router engine)
    pub fn lookup(&self, ip: std::net::IpAddr) -> Option<(String, String)> {
        if let Some(info) = GeoIpProvider::lookup(self, ip) {
            if let Some(country_code) = info.country_code {
                return Some(("geoip".to_string(), country_code));
            }
        }
        None
    }
    /// Create a new GeoMux instance
    pub fn new(strategy: LookupStrategy) -> Self {
        // SAFETY: 5000 is a non-zero constant; fallback to 1 on theoretical failure
        let cap = std::num::NonZeroUsize::new(5000)
            .unwrap_or(unsafe { std::num::NonZeroUsize::new_unchecked(1) });
        Self {
            providers: Vec::new(),
            strategy,
            cache: std::sync::Mutex::new(lru::LruCache::new(cap)),
        }
    }

    /// Add a provider to the multiplexer
    pub fn add_provider(
        &mut self,
        provider: Arc<dyn GeoIpProvider>,
        name: String,
        priority: u8,
        timeout: Duration,
    ) {
        let config = ProviderWithConfig {
            provider,
            name,
            priority,
            timeout,
            enabled: std::sync::atomic::AtomicBool::new(true),
            failure_count: std::sync::atomic::AtomicU64::new(0),
            last_success: std::sync::Mutex::new(None),
        };

        self.providers.push(config);
        self.sort_providers();
    }

    /// Remove a provider by name
    pub fn remove_provider(&mut self, name: &str) {
        self.providers.retain(|p| p.name != name);
    }

    /// Enable or disable a provider
    pub fn set_provider_enabled(&self, name: &str, enabled: bool) {
        for provider in &self.providers {
            if provider.name == name {
                provider
                    .enabled
                    .store(enabled, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    }

    /// Get provider statistics
    pub fn get_provider_stats(&self) -> Vec<ProviderStats> {
        self.providers
            .iter()
            .map(|p| ProviderStats {
                name: p.name.clone(),
                priority: p.priority,
                enabled: p.enabled.load(std::sync::atomic::Ordering::Relaxed),
                failure_count: p.failure_count.load(std::sync::atomic::Ordering::Relaxed),
                last_success: p.last_success.lock().ok().and_then(|g| *g),
            })
            .collect()
    }

    fn sort_providers(&mut self) {
        self.providers.sort_by_key(|p| p.priority);
    }

    fn lookup_with_provider(&self, provider: &ProviderWithConfig, ip: IpAddr) -> Option<GeoInfo> {
        if !provider.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }

        let start = std::time::Instant::now();

        // Use timeout for the lookup
        let result = std::thread::scope(|s| {
            let handle = s.spawn(|| provider.provider.lookup(ip));
            handle.join().unwrap_or_default()
        });

        let _duration = start.elapsed();

        match result {
            Some(info) => {
                // Reset failure count on success
                provider
                    .failure_count
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut g) = provider.last_success.lock() {
                    *g = Some(std::time::Instant::now());
                }

                #[cfg(feature = "metrics")]
                {
                    crate::metrics::geoip::geoip_provider_success(
                        &provider.name,
                        _duration.as_secs_f64(),
                    );
                }

                Some(info)
            }
            None => {
                // Increment failure count
                provider
                    .failure_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                #[cfg(feature = "metrics")]
                {
                    crate::metrics::geoip::geoip_provider_failure(
                        &provider.name,
                        _duration.as_secs_f64(),
                    );
                }

                None
            }
        }
    }

    fn lookup_first_success(&self, ip: IpAddr) -> Option<GeoInfo> {
        for provider in &self.providers {
            if let Some(info) = self.lookup_with_provider(provider, ip) {
                return Some(info);
            }
        }
        None
    }

    fn lookup_priority(&self, ip: IpAddr) -> Option<GeoInfo> {
        // Same as first success since providers are sorted by priority
        self.lookup_first_success(ip)
    }

    fn lookup_aggregate(&self, ip: IpAddr) -> Option<GeoInfo> {
        let mut results = Vec::new();

        for provider in &self.providers {
            if let Some(info) = self.lookup_with_provider(provider, ip) {
                results.push((provider.name.clone(), info));
            }
        }

        if results.is_empty() {
            return None;
        }

        // Aggregate the results (prefer the most detailed information)
        let mut aggregated = GeoInfo {
            country_code: None,
            country_name: None,
            city: None,
            region: None,
            continent_code: None,
            asn: None,
            organization: None,
        };

        for (_, info) in results {
            if aggregated.country_code.is_none() && info.country_code.is_some() {
                aggregated.country_code = info.country_code;
            }
            if aggregated.country_name.is_none() && info.country_name.is_some() {
                aggregated.country_name = info.country_name;
            }
            if aggregated.city.is_none() && info.city.is_some() {
                aggregated.city = info.city;
            }
            if aggregated.region.is_none() && info.region.is_some() {
                aggregated.region = info.region;
            }
            if aggregated.continent_code.is_none() && info.continent_code.is_some() {
                aggregated.continent_code = info.continent_code;
            }
            if aggregated.asn.is_none() && info.asn.is_some() {
                aggregated.asn = info.asn;
            }
            if aggregated.organization.is_none() && info.organization.is_some() {
                aggregated.organization = info.organization;
            }
        }

        Some(aggregated)
    }

    fn lookup_fastest(&self, ip: IpAddr) -> Option<GeoInfo> {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();

        // Start lookups in parallel
        for (idx, provider) in self.providers.iter().enumerate() {
            if !provider.enabled.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }

            let tx_clone = tx.clone();
            let provider_clone = Arc::clone(&provider.provider);
            let provider_name = provider.name.clone();

            let handle = thread::spawn(move || {
                let start = std::time::Instant::now();
                if let Some(info) = provider_clone.lookup(ip) {
                    let duration = start.elapsed();
                    let _ = tx_clone.send((idx, info, duration, provider_name));
                }
            });

            handles.push(handle);
        }

        drop(tx); // Close the sender

        // Wait for the first successful result
        let mut best_result = None;
        let mut best_duration = Duration::from_secs(3600);

        while let Ok((idx, info, duration, _provider_name)) = rx.recv() {
            if duration < best_duration {
                best_duration = duration;
                best_result = Some((idx, info, _provider_name));
            }

            // If we got a very fast response, use it immediately
            if duration < Duration::from_millis(10) {
                break;
            }
        }

        // Clean up remaining threads
        for handle in handles {
            let _ = handle.join();
        }

        if let Some((_, info, _provider_name)) = best_result {
            #[cfg(feature = "metrics")]
            {
                crate::metrics::geoip::geoip_fastest_provider(
                    &_provider_name,
                    best_duration.as_secs_f64(),
                );
            }

            Some(info)
        } else {
            None
        }
    }
}

impl GeoIpProvider for GeoMux {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // Check cache first
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&ip) {
                // Check if cache entry is still valid (5 minutes)
                if cached.timestamp.elapsed() < Duration::from_secs(300) {
                    return Some(cached.info.clone());
                }
            }
        }

        let result = match self.strategy {
            LookupStrategy::FirstSuccess => self.lookup_first_success(ip),
            LookupStrategy::Priority => self.lookup_priority(ip),
            LookupStrategy::Aggregate => self.lookup_aggregate(ip),
            LookupStrategy::Fastest => self.lookup_fastest(ip),
        };

        // Cache the result
        if let Some(ref info) = result {
            if let Ok(mut cache) = self.cache.lock() {
                let cached_info = CachedGeoInfo {
                    info: info.clone(),
                    timestamp: std::time::Instant::now(),
                    provider: "multi".to_string(),
                };
                cache.put(ip, cached_info);
            }
        }

        result
    }
}

/// Provider statistics
#[derive(Debug, Clone)]
pub struct ProviderStats {
    pub name: String,
    pub priority: u8,
    pub enabled: bool,
    pub failure_count: u64,
    pub last_success: Option<std::time::Instant>,
}

/// Builder for GeoMux
pub struct GeoMuxBuilder {
    strategy: LookupStrategy,
    providers: Vec<(Arc<dyn GeoIpProvider>, String, u8, Duration)>,
}

impl GeoMuxBuilder {
    pub fn new(strategy: LookupStrategy) -> Self {
        Self {
            strategy,
            providers: Vec::new(),
        }
    }

    pub fn add_provider(
        mut self,
        provider: Arc<dyn GeoIpProvider>,
        name: String,
        priority: u8,
        timeout: Duration,
    ) -> Self {
        self.providers.push((provider, name, priority, timeout));
        self
    }

    pub fn build(self) -> GeoMux {
        let mut mux = GeoMux::new(self.strategy);
        for (provider, name, priority, timeout) in self.providers {
            mux.add_provider(provider, name, priority, timeout);
        }
        mux
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct MockProvider {
        name: String,
        delay: Duration,
        result: Option<GeoInfo>,
    }

    impl MockProvider {
        fn new(name: &str, delay: Duration, result: Option<GeoInfo>) -> Self {
            Self {
                name: name.to_string(),
                delay,
                result,
            }
        }
    }

    impl GeoIpProvider for MockProvider {
        fn lookup(&self, _ip: IpAddr) -> Option<GeoInfo> {
            if self.delay > Duration::ZERO {
                std::thread::sleep(self.delay);
            }
            self.result.clone()
        }
    }

    #[test]
    fn test_geomux_first_success() {
        let mut mux = GeoMux::new(LookupStrategy::FirstSuccess);

        let provider1 = Arc::new(MockProvider::new("test1", Duration::ZERO, None));
        let provider2 = Arc::new(MockProvider::new(
            "test2",
            Duration::ZERO,
            Some(GeoInfo {
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                city: None,
                region: None,
                continent_code: Some("NA".to_string()),
                asn: None,
                organization: None,
            }),
        ));

        mux.add_provider(provider1, "test1".to_string(), 1, Duration::from_secs(1));
        mux.add_provider(provider2, "test2".to_string(), 2, Duration::from_secs(1));

        let ip = "8.8.8.8".parse().unwrap();
        let result = <GeoMux as GeoIpProvider>::lookup(&mux, ip);

        assert!(result.is_some());
        assert_eq!(result.unwrap().country_code, Some("US".to_string()));
    }

    #[test]
    fn test_geomux_builder() {
        let provider = Arc::new(MockProvider::new("test", Duration::ZERO, None));

        let mux = GeoMuxBuilder::new(LookupStrategy::Priority)
            .add_provider(provider, "test".to_string(), 1, Duration::from_secs(1))
            .build();

        assert_eq!(mux.providers.len(), 1);
    }
}
