#![cfg(feature = "geoip_mmdb")]

use sb_core::geoip::{
    install_default_geoip_service, lookup_country_code, lookup_with_metrics,
    lookup_with_metrics_decision, GeoInfo, GeoIpProvider, GeoIpService,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

struct StaticGeoIpProvider {
    country_code: &'static str,
}

impl GeoIpProvider for StaticGeoIpProvider {
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
fn default_geoip_service_uses_weak_owner_registry() {
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let service = Arc::new(GeoIpService::new(Box::new(StaticGeoIpProvider {
        country_code: "US",
    })));
    let installed = install_default_geoip_service(service);

    assert_eq!(lookup_country_code(ip), Some("US".to_string()));
    assert!(lookup_with_metrics(ip, "us"));
    assert_eq!(lookup_with_metrics_decision(ip), Some("proxy"));

    drop(installed);

    assert_eq!(lookup_country_code(ip), None);
    assert!(!lookup_with_metrics(ip, "US"));
    assert_eq!(lookup_with_metrics_decision(ip), None);
}
