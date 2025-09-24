#![cfg(feature = "geoip_mmdb")]

use super::mmdb::GeoIp;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct GeoMux {
    pub readers: Vec<(String, Arc<GeoIp>)>,
}

#[cfg(feature = "metrics")]
fn geoip_metric() -> &'static prometheus::IntCounterVec {
    use once_cell::sync::OnceCell;
    use prometheus::{IntCounterVec, Opts};

    static METRIC: OnceCell<IntCounterVec> = OnceCell::new();

    METRIC.get_or_init(|| {
        let vec = IntCounterVec::new(
            Opts::new("geoip_lookup_total", "geoip lookups"),
            &["source", "outcome"],
        )
        .expect("geoip lookup metric");
        if let Err(err) = crate::metrics::registry().register(Box::new(vec.clone())) {
            tracing::warn!(?err, "failed to register geoip_lookup_total metric");
        }
        vec
    })
}

#[cfg(feature = "metrics")]
fn record_geoip_metric(source: &str, outcome: &str) {
    geoip_metric().with_label_values(&[source, outcome]).inc();
}

impl GeoMux {
    pub fn from_env() -> Option<Self> {
        let list = std::env::var("SB_GEOIP_MMDBS").ok()?;
        let list = list.trim();
        if list.is_empty() {
            return None;
        }
        let ttl = std::env::var("SB_GEOIP_TTL")
            .ok()
            .and_then(|v| humantime::parse_duration(&v).ok())
            .unwrap_or(Duration::from_secs(600));
        let cap = std::env::var("SB_GEOIP_CACHE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8192);
        let mut readers = Vec::new();
        for path in list.split(':') {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            match GeoIp::open(path, cap, ttl) {
                Ok(reader) => readers.push((path.to_string(), reader)),
                Err(err) => {
                    tracing::warn!("failed to open mmdb: {:?} at {:?}", err, path);
                }
            }
        }
        if readers.is_empty() {
            None
        } else {
            Some(Self { readers })
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<(String, String)> {
        for (source, reader) in &self.readers {
            if let Some(cc) = reader.lookup(ip) {
                #[cfg(feature = "metrics")]
                record_geoip_metric(source, "hit");
                return Some((source.clone(), cc));
            } else {
                #[cfg(feature = "metrics")]
                record_geoip_metric(source, "miss");
            }
        }
        #[cfg(feature = "metrics")]
        record_geoip_metric("none", "err");
        None
    }
}
