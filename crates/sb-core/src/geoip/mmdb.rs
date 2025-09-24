#![cfg(feature = "geoip_mmdb")]
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]
use hashlink::LruCache;
use maxminddb::Reader;
use parking_lot::Mutex;
use std::{
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct GeoIp {
    reader: Reader<Vec<u8>>,
    cache: Mutex<LruCache<IpAddr, (String, Instant)>>,
    ttl: Duration,
}

impl GeoIp {
    pub fn open<P: AsRef<Path>>(path: P, cap: usize, ttl: Duration) -> anyhow::Result<Arc<Self>> {
        let reader = Reader::open_readfile(path)?;
        Ok(Arc::new(Self {
            reader,
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }))
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        // cache
        if let Some((cc, ts)) = self.cache.lock().get(&ip).cloned() {
            if ts.elapsed() < self.ttl {
                return Some(cc);
            }
        }
        // mmdb
        #[derive(serde::Deserialize)]
        struct Country {
            iso_code: Option<String>,
        }
        #[derive(serde::Deserialize)]
        struct Model {
            country: Option<Country>,
        }
        match self.reader.lookup::<Model>(ip) {
            Ok(model) => {
                let cc = model.country.and_then(|c| c.iso_code).unwrap_or_default();
                if !cc.is_empty() {
                    self.cache.lock().insert(ip, (cc.clone(), Instant::now()));
                    return Some(cc);
                }
                None
            }
            Err(_) => None,
        }
    }
}
