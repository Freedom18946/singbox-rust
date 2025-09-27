//! MaxMind MMDB database implementation for GeoIP lookups
//!
//! This module provides a production-ready implementation using MaxMind's
//! GeoIP2 databases (GeoLite2-City, GeoLite2-Country, etc.)

use super::{GeoInfo, GeoIpProvider};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// MaxMind MMDB reader wrapper
pub struct MmdbReader {
    country_db: Option<maxminddb::Reader<Vec<u8>>>,
    city_db: Option<maxminddb::Reader<Vec<u8>>>,
    asn_db: Option<maxminddb::Reader<Vec<u8>>>,
    db_paths: HashMap<String, PathBuf>,
}

impl MmdbReader {
    /// Create a new MMDB reader from database paths
    pub fn new() -> anyhow::Result<Self> {
        let mut reader = Self {
            country_db: None,
            city_db: None,
            asn_db: None,
            db_paths: HashMap::new(),
        };

        // Try to load databases from standard locations
        reader.try_load_databases()?;
        Ok(reader)
    }

    /// Load databases from file paths
    pub fn from_paths(
        country_path: Option<&Path>,
        city_path: Option<&Path>,
        asn_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let mut reader = Self {
            country_db: None,
            city_db: None,
            asn_db: None,
            db_paths: HashMap::new(),
        };

        if let Some(path) = country_path {
            reader.load_country_db(path)?;
        }

        if let Some(path) = city_path {
            reader.load_city_db(path)?;
        }

        if let Some(path) = asn_path {
            reader.load_asn_db(path)?;
        }

        Ok(reader)
    }

    fn try_load_databases(&mut self) -> anyhow::Result<()> {
        // Common database locations
        let common_paths = [
            "/usr/share/GeoIP",
            "/var/lib/GeoIP",
            "/opt/GeoIP",
            ".",
        ];

        for base_path in &common_paths {
            // Try country database
            let country_path = Path::new(base_path).join("GeoLite2-Country.mmdb");
            if country_path.exists() {
                if let Err(e) = self.load_country_db(&country_path) {
                    tracing::warn!("Failed to load country database from {}: {}", country_path.display(), e);
                }
            }

            // Try city database
            let city_path = Path::new(base_path).join("GeoLite2-City.mmdb");
            if city_path.exists() {
                if let Err(e) = self.load_city_db(&city_path) {
                    tracing::warn!("Failed to load city database from {}: {}", city_path.display(), e);
                }
            }

            // Try ASN database
            let asn_path = Path::new(base_path).join("GeoLite2-ASN.mmdb");
            if asn_path.exists() {
                if let Err(e) = self.load_asn_db(&asn_path) {
                    tracing::warn!("Failed to load ASN database from {}: {}", asn_path.display(), e);
                }
            }
        }

        Ok(())
    }

    fn load_country_db(&mut self, path: &Path) -> anyhow::Result<()> {
        let data = std::fs::read(path)?;
        let reader = maxminddb::Reader::from_source(data)?;
        self.country_db = Some(reader);
        self.db_paths.insert("country".to_string(), path.to_path_buf());
        tracing::info!("Loaded GeoIP country database from {}", path.display());
        Ok(())
    }

    fn load_city_db(&mut self, path: &Path) -> anyhow::Result<()> {
        let data = std::fs::read(path)?;
        let reader = maxminddb::Reader::from_source(data)?;
        self.city_db = Some(reader);
        self.db_paths.insert("city".to_string(), path.to_path_buf());
        tracing::info!("Loaded GeoIP city database from {}", path.display());
        Ok(())
    }

    fn load_asn_db(&mut self, path: &Path) -> anyhow::Result<()> {
        let data = std::fs::read(path)?;
        let reader = maxminddb::Reader::from_source(data)?;
        self.asn_db = Some(reader);
        self.db_paths.insert("asn".to_string(), path.to_path_buf());
        tracing::info!("Loaded GeoIP ASN database from {}", path.display());
        Ok(())
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<CountryRecord> {
        self.country_db.as_ref()?.lookup(ip).ok()
    }

    fn lookup_city(&self, ip: IpAddr) -> Option<CityRecord> {
        self.city_db.as_ref()?.lookup(ip).ok()
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<AsnRecord> {
        self.asn_db.as_ref()?.lookup(ip).ok()
    }
}

/// MMDB provider implementation
pub struct MmdbProvider {
    reader: Arc<MmdbReader>,
    cache: std::sync::Mutex<lru::LruCache<IpAddr, GeoInfo>>,
}

impl MmdbProvider {
    pub fn new() -> anyhow::Result<Self> {
        let reader = Arc::new(MmdbReader::new()?);
        // SAFETY: 10000 is a non-zero constant; unwrap_or fallback uses 1 which is non-zero
        let cap = std::num::NonZeroUsize::new(10000)
            .unwrap_or(unsafe { std::num::NonZeroUsize::new_unchecked(1) });
        let cache = std::sync::Mutex::new(lru::LruCache::new(cap));

        Ok(Self { reader, cache })
    }

    pub fn from_paths(
        country_path: Option<&Path>,
        city_path: Option<&Path>,
        asn_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let reader = Arc::new(MmdbReader::from_paths(country_path, city_path, asn_path)?);
        // SAFETY: 10000 is a non-zero constant; unwrap_or fallback uses 1 which is non-zero
        let cap = std::num::NonZeroUsize::new(10000)
            .unwrap_or(unsafe { std::num::NonZeroUsize::new_unchecked(1) });
        let cache = std::sync::Mutex::new(lru::LruCache::new(cap));

        Ok(Self { reader, cache })
    }
}

impl GeoIpProvider for MmdbProvider {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // Check cache first
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&ip) {
                return Some(cached.clone());
            }
        }

        // Look up in databases
        let country_info = self.reader.lookup_country(ip);
        let city_info = self.reader.lookup_city(ip);
        let asn_info = self.reader.lookup_asn(ip);

        let geo_info = GeoInfo {
            country_code: country_info.as_ref()
                .and_then(|c| c.country.as_ref())
                .and_then(|c| c.iso_code.clone()),
            country_name: country_info.as_ref()
                .and_then(|c| c.country.as_ref())
                .and_then(|c| c.names.as_ref())
                .and_then(|names| names.get("en"))
                .cloned(),
            city: city_info.as_ref()
                .and_then(|c| c.city.as_ref())
                .and_then(|c| c.names.as_ref())
                .and_then(|names| names.get("en"))
                .cloned(),
            region: city_info.as_ref()
                .and_then(|c| c.subdivisions.as_ref())
                .and_then(|subdivisions| subdivisions.first())
                .and_then(|subdivision| subdivision.names.as_ref())
                .and_then(|names| names.get("en"))
                .cloned(),
            continent_code: country_info.as_ref()
                .and_then(|c| c.continent.as_ref())
                .and_then(|c| c.code.clone()),
            asn: asn_info.as_ref().and_then(|a| a.autonomous_system_number),
            organization: asn_info.as_ref()
                .and_then(|a| a.autonomous_system_organization.clone()),
        };

        // Cache the result
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(ip, geo_info.clone());
        }

        Some(geo_info)
    }
}

// MaxMind database record structures
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct CountryRecord {
    continent: Option<ContinentInfo>,
    country: Option<CountryInfo>,
    registered_country: Option<CountryInfo>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct CityRecord {
    continent: Option<ContinentInfo>,
    country: Option<CountryInfo>,
    subdivisions: Option<Vec<SubdivisionInfo>>,
    city: Option<CityInfo>,
    location: Option<LocationInfo>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct ContinentInfo {
    code: Option<String>,
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct CountryInfo {
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct SubdivisionInfo {
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct CityInfo {
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct LocationInfo {
    latitude: Option<f64>,
    longitude: Option<f64>,
    time_zone: Option<String>,
}

/// GeoIP database wrapper (for backward compatibility)
pub struct GeoIp {
    provider: MmdbProvider,
}

impl GeoIp {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            provider: MmdbProvider::new()?,
        })
    }

    /// Open a GeoIP database from file path with cache configuration
    pub fn open(path: &std::path::Path, cache_capacity: usize, _ttl: std::time::Duration) -> anyhow::Result<Self> {
        // Create a custom MMDB reader that loads the specific database file
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read MMDB database at {:?}: {}", path, e))?;

        let reader = maxminddb::Reader::from_source(data)
            .map_err(|e| anyhow::anyhow!("Failed to parse MMDB database at {:?}: {}", path, e))?;

        // Create a custom MmdbReader with the loaded database
        let mut mmdb_reader = MmdbReader {
            country_db: None,
            city_db: None,
            asn_db: None,
            db_paths: HashMap::new(),
        };

        // Determine database type based on filename and load appropriately
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        if filename.contains("country") {
            mmdb_reader.country_db = Some(reader);
            mmdb_reader.db_paths.insert("country".to_string(), path.to_path_buf());
        } else if filename.contains("city") {
            mmdb_reader.city_db = Some(reader);
            mmdb_reader.db_paths.insert("city".to_string(), path.to_path_buf());
        } else if filename.contains("asn") {
            mmdb_reader.asn_db = Some(reader);
            mmdb_reader.db_paths.insert("asn".to_string(), path.to_path_buf());
        } else {
            // Default to country database
            mmdb_reader.country_db = Some(reader);
            mmdb_reader.db_paths.insert("country".to_string(), path.to_path_buf());
        }

        let provider = MmdbProvider {
            reader: Arc::new(mmdb_reader),
            cache: std::sync::Mutex::new(
                // SAFETY: if cache_capacity is zero, fallback to 1024 (>0)
                lru::LruCache::new(
                    std::num::NonZeroUsize::new(cache_capacity).unwrap_or_else(|| {
                        // SAFETY: 1024 is a non-zero constant; NonZeroUsize::new_unchecked(1024) is sound
                        unsafe { std::num::NonZeroUsize::new_unchecked(1024) }
                    })
                )
            ),
        };

        Ok(Self { provider })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        self.provider.lookup(ip)
    }

    pub fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {
        self.provider.is_country(ip, country_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_mmdb_provider_creation() {
        // This test might fail if no databases are available
        let _ = MmdbProvider::new();
    }

    #[test]
    fn test_geoip_creation() {
        let _ = GeoIp::new();
    }

    #[test]
    fn test_fake_lookup() {
        // Test with a known IP (Google DNS)
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        if let Ok(provider) = MmdbProvider::new() {
            let result = provider.lookup(ip);
            // Result may be None if no databases are available
            if let Some(info) = result {
                assert!(info.country_code.is_some() || info.country_name.is_some());
            }
        }
    }
}
