//! `GeoIP` functionality for IP-based routing rules (weak-owner model).
//!
//! The application layer installs an `Arc<GeoIpService>` via
//! [`install_default_geoip_service`]; sb-core retains only a `Weak` reference so
//! the service is automatically reclaimed when the owning `Arc` is dropped.
//!
//! There is **no** process-wide hard global singleton.  All callers go through
//! the weak-owner lookup in [`lookup_country_code`] or through the router-local
//! GeoIP providers in `RouterHandle::enhanced_geoip_lookup`.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex, Weak};

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

static DEFAULT_GEOIP_SERVICE: LazyLock<Mutex<Option<Weak<GeoIpService>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Install the default `GeoIP` service via a weak compatibility registry.
///
/// The caller keeps the returned `Arc` as the explicit owner while `sb-core`
/// only stores a weak lookup entry for compatibility.
#[must_use]
pub fn install_default_geoip_service(service: Arc<GeoIpService>) -> Arc<GeoIpService> {
    let mut slot = DEFAULT_GEOIP_SERVICE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_ref().and_then(Weak::upgrade) {
        Some(existing) => existing,
        None => {
            *slot = Some(Arc::downgrade(&service));
            service
        }
    }
}

fn current_service() -> Option<Arc<GeoIpService>> {
    DEFAULT_GEOIP_SERVICE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade)
}

/// Look up country code for an IP address via the weak-owner service.
///
/// Returns `None` if no owner is alive.  The caller must ensure
/// [`install_default_geoip_service`] has been called and the owning `Arc` is
/// still held — or use the router-local GeoIP provider path instead.
#[must_use]
pub fn lookup_country_code(ip: IpAddr) -> Option<String> {
    current_service()
        .and_then(|s| s.lookup(ip))
        .and_then(|info| info.country_code)
}

/// Reset the weak-owner slot (test-only).
#[cfg(test)]
pub(crate) fn clear_default_for_test() {
    let mut slot = DEFAULT_GEOIP_SERVICE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = None;
}

/// Lookup with metrics
pub fn lookup_with_metrics(ip: IpAddr, country_code: &str) -> bool {
    #[cfg(feature = "metrics")]
    {
        let start = std::time::Instant::now();
        let result = lookup_country_code(ip)
            .is_some_and(|code| code.eq_ignore_ascii_case(country_code));
        let duration = start.elapsed();

        // Record metrics
        crate::metrics::geoip::geoip_lookup_duration(duration.as_secs_f64());
        crate::metrics::geoip::geoip_lookup_total(if result { "hit" } else { "miss" });

        result
    }
    #[cfg(not(feature = "metrics"))]
    {
        lookup_country_code(ip)
            .is_some_and(|code| code.eq_ignore_ascii_case(country_code))
    }
}

/// Lookup IP address and return outbound decision
pub fn lookup_with_metrics_decision(ip: IpAddr) -> Option<&'static str> {
    let country_code = lookup_country_code(ip)?;

    #[cfg(feature = "metrics")]
    {
        crate::metrics::geoip::geoip_country_lookup_total(&country_code);
    }

    // Return outbound based on country
    match country_code.as_str() {
        "CN" => Some("direct"),
        "US" | "UK" | "CA" => Some("proxy"),
        "RU" | "IR" | "KP" => Some("block"),
        _ => Some("auto"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct TestGeoIpProvider {
        country_code: &'static str,
    }

    impl GeoIpProvider for TestGeoIpProvider {
        fn lookup(&self, _ip: IpAddr) -> Option<GeoInfo> {
            Some(GeoInfo {
                country_code: Some(self.country_code.to_string()),
                country_name: None,
                city: None,
                region: None,
                continent_code: None,
                asn: None,
                organization: None,
            })
        }
    }

    #[test]
    fn weak_default_registry_uses_explicit_owner() {
        clear_default_for_test();

        let service = Arc::new(GeoIpService::new(Box::new(TestGeoIpProvider {
            country_code: "US",
        })));
        let installed = install_default_geoip_service(service);

        assert_eq!(
            lookup_country_code(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            Some("US".to_string())
        );
        assert_eq!(
            lookup_with_metrics_decision(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            Some("proxy")
        );
        assert!(lookup_with_metrics(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            "US"
        ));

        drop(installed);

        // After owner drop, lookup must fail — no hard global fallback.
        assert_eq!(
            lookup_country_code(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            None
        );
        assert_eq!(
            lookup_with_metrics_decision(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            None
        );
        assert!(!lookup_with_metrics(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            "US"
        ));

        // Replacement owner works.
        let replacement = Arc::new(GeoIpService::new(Box::new(TestGeoIpProvider {
            country_code: "CN",
        })));
        let installed = install_default_geoip_service(replacement);
        assert_eq!(
            lookup_country_code(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
            Some("CN".to_string())
        );
        assert_eq!(
            lookup_with_metrics_decision(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
            Some("direct")
        );
        drop(installed);

        clear_default_for_test();
    }
}
