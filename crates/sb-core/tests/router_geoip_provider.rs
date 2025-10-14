#![cfg(feature = "geoip_provider_DISABLED")]
use sb_core::geoip::{lookup_with_metrics, set_global_provider, Provider};
use std::net::IpAddr;
use std::sync::Arc;

struct DummyGeo;
impl Provider for DummyGeo {
    fn lookup(&self, ip: IpAddr) -> Option<&'static str> {
        match ip {
            IpAddr::V4(v4) if v4.octets()[0] == 11 => Some("proxy"),
            _ => None,
        }
    }
}

#[test]
fn global_provider_is_safe_and_works() {
    set_global_provider(Arc::new(DummyGeo));
    let ip: IpAddr = "11.1.2.3".parse().unwrap();
    assert_eq!(lookup_with_metrics(ip), Some("proxy"));
}
