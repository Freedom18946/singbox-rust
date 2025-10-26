//! `GeoIP` functionality for IP-based routing rules
//!
//! This module provides comprehensive `GeoIP` functionality for routing decisions,
//! including MMDB database support and multiple provider interfaces.

use std::net::IpAddr;
use std::sync::OnceLock;

pub mod mmdb;
pub mod multi;

/// `GeoIP` lookup result
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub continent_code: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
}

/// Basic `GeoIP` service trait
pub trait GeoIpProvider: Send + Sync {
    /// Lookup geographical information for an IP address
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo>;

    /// Check if an IP belongs to a specific country
    fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {
        self.lookup(ip)
            .and_then(|info| info.country_code)
            .is_some_and(|code| code.eq_ignore_ascii_case(country_code))
    }

    /// Check if an IP belongs to a specific continent
    fn is_continent(&self, ip: IpAddr, continent_code: &str) -> bool {
        self.lookup(ip)
            .and_then(|info| info.continent_code)
            .is_some_and(|code| code.eq_ignore_ascii_case(continent_code))
    }

    /// Get ASN for an IP address
    fn get_asn(&self, ip: IpAddr) -> Option<u32> {
        self.lookup(ip).and_then(|info| info.asn)
    }
}

/// Basic `GeoIP` service implementation
pub struct GeoIpService {
    provider: Box<dyn GeoIpProvider>,
}

impl GeoIpService {
    pub fn new(provider: Box<dyn GeoIpProvider>) -> Self {
        Self { provider }
    }

    /// Lookup geographical information for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        self.provider.lookup(ip)
    }

    /// Check if an IP belongs to a specific country
    pub fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {
        self.provider.is_country(ip, country_code)
    }

    /// Check if an IP belongs to a specific continent
    pub fn is_continent(&self, ip: IpAddr, continent_code: &str) -> bool {
        self.provider.is_continent(ip, continent_code)
    }

    /// Get ASN for an IP address
    pub fn get_asn(&self, ip: IpAddr) -> Option<u32> {
        self.provider.get_asn(ip)
    }
}

/// Global `GeoIP` service instance
static GEOIP_SERVICE: OnceLock<GeoIpService> = OnceLock::new();

/// Initialize the global `GeoIP` service
pub fn init() -> anyhow::Result<()> {
    let provider = mmdb::MmdbProvider::new()?;
    let _ = GEOIP_SERVICE.set(GeoIpService::new(Box::new(provider)));
    Ok(())
}

/// Get a reference to the global `GeoIP` service
pub fn service() -> Option<&'static GeoIpService> {
    GEOIP_SERVICE.get()
}

/// Lookup with metrics
pub fn lookup_with_metrics(ip: IpAddr, country_code: &str) -> bool {
    #[cfg(feature = "metrics")]
    {
        let start = std::time::Instant::now();
        let result = service()
            .map(|s| s.is_country(ip, country_code))
            .unwrap_or(false);
        let duration = start.elapsed();

        // Record metrics
        crate::metrics::geoip::geoip_lookup_duration(duration.as_secs_f64());
        crate::metrics::geoip::geoip_lookup_total(if result { "hit" } else { "miss" });

        result
    }
    #[cfg(not(feature = "metrics"))]
    {
        service()
            .is_some_and(|s| s.is_country(ip, country_code))
    }
}

/// Lookup IP address and return outbound decision
pub fn lookup_with_metrics_decision(ip: IpAddr) -> Option<&'static str> {
    let geo_info = service().and_then(|s| s.lookup(ip))?;

    #[cfg(feature = "metrics")]
    {
        if let Some(country) = &geo_info.country_code {
            crate::metrics::geoip::geoip_country_lookup_total(country);
        }
    }

    // Return outbound based on country
    match geo_info.country_code.as_deref() {
        Some("CN") => Some("direct"),
        Some("US" | "UK" | "CA") => Some("proxy"),
        Some("RU" | "IR" | "KP") => Some("block"),
        _ => Some("auto"),
    }
}
