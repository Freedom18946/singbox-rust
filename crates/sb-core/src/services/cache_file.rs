//! Cache file service for storing persistent data.
//! 用于存储持久化数据的缓存文件服务。
//!
//! This module implements persistence for:
//! - FakeIP allocations (domain ↔ IP mappings)
//! - RDRC (Resolver DNS Result Cache) data
//!
//! Reference: Go sing-box `experimental/cachefile/`

use crate::context::CacheFile;
use parking_lot::RwLock;
use sb_config::ir::CacheFileIR;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Cache data format for serialization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheData {
    /// Version for format compatibility
    pub version: u32,
    /// FakeIP domain → IP mappings
    pub fakeip_by_domain: HashMap<String, IpAddr>,
    /// FakeIP IP → domain reverse mappings
    pub fakeip_by_ip: HashMap<String, String>, // IpAddr serialized as string
    /// FakeIP next allocation counters
    pub fakeip_next_v4: u32,
    pub fakeip_next_v6: u128,
    /// RDRC entries: domain → (IPs, TTL expiry timestamp)
    pub rdrc_entries: HashMap<String, RdrcEntry>,
    /// Last save timestamp
    pub last_saved: u64,
}

/// RDRC cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdrcEntry {
    pub ips: Vec<IpAddr>,
    pub expires_at: u64, // Unix timestamp
}

impl CacheData {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            ..Default::default()
        }
    }
}

/// Cache file service for storing persistent data.
#[derive(Debug)]
pub struct CacheFileService {
    enabled: bool,
    path: Option<PathBuf>,
    store_fakeip: bool,
    store_rdrc: bool,
    rdrc_timeout: Duration,
    /// In-memory cache data
    data: Arc<RwLock<CacheData>>,
    /// Dirty flag for lazy saving
    dirty: Arc<RwLock<bool>>,
}

impl Clone for CacheFileService {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            path: self.path.clone(),
            store_fakeip: self.store_fakeip,
            store_rdrc: self.store_rdrc,
            rdrc_timeout: self.rdrc_timeout,
            data: self.data.clone(),
            dirty: self.dirty.clone(),
        }
    }
}

impl CacheFileService {
    /// Create a new cache file service from configuration.
    pub fn new(config: &CacheFileIR) -> Self {
        let path = config.path.as_ref().map(PathBuf::from);
        let rdrc_timeout = config
            .rdrc_timeout
            .as_ref()
            .and_then(|s| parse_duration(s))
            .unwrap_or(Duration::from_secs(7 * 24 * 3600)); // Default: 7 days

        let mut svc = Self {
            enabled: config.enabled,
            path,
            store_fakeip: config.store_fakeip,
            store_rdrc: config.store_rdrc,
            rdrc_timeout,
            data: Arc::new(RwLock::new(CacheData::new())),
            dirty: Arc::new(RwLock::new(false)),
        };

        // Load existing cache if enabled
        if svc.enabled {
            if let Err(e) = svc.load() {
                warn!(error = %e, "Failed to load cache file, starting fresh");
            }
        }

        svc
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn store_fakeip(&self) -> bool {
        self.store_fakeip
    }

    pub fn store_rdrc(&self) -> bool {
        self.store_rdrc
    }

    /// Load cache data from file.
    pub fn load(&mut self) -> anyhow::Result<()> {
        let path = match &self.path {
            Some(p) => p,
            None => {
                debug!("No cache file path configured, skipping load");
                return Ok(());
            }
        };

        if !path.exists() {
            debug!(path = %path.display(), "Cache file does not exist, starting fresh");
            return Ok(());
        }

        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let data: CacheData = serde_json::from_reader(reader)?;

        // Version check
        if data.version != CacheData::CURRENT_VERSION {
            warn!(
                file_version = data.version,
                current_version = CacheData::CURRENT_VERSION,
                "Cache file version mismatch, starting fresh"
            );
            return Ok(());
        }

        // Prune expired RDRC entries
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut loaded_data = data;
        loaded_data
            .rdrc_entries
            .retain(|_, entry| entry.expires_at > now);

        let fakeip_count = loaded_data.fakeip_by_domain.len();
        let rdrc_count = loaded_data.rdrc_entries.len();

        *self.data.write() = loaded_data;
        *self.dirty.write() = false;

        info!(
            path = %path.display(),
            fakeip_entries = fakeip_count,
            rdrc_entries = rdrc_count,
            "Cache file loaded successfully"
        );

        Ok(())
    }

    /// Save cache data to file.
    pub fn save(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let path = match &self.path {
            Some(p) => p,
            None => {
                debug!("No cache file path configured, skipping save");
                return Ok(());
            }
        };

        // Only save if dirty
        if !*self.dirty.read() {
            debug!("Cache not dirty, skipping save");
            return Ok(());
        }

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let mut data = self.data.read().clone();
        data.last_saved = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Write to temp file first, then rename for atomicity
        let temp_path = path.with_extension("tmp");
        let file = fs::File::create(&temp_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &data)?;
        fs::rename(&temp_path, path)?;

        *self.dirty.write() = false;

        debug!(
            path = %path.display(),
            fakeip_entries = data.fakeip_by_domain.len(),
            rdrc_entries = data.rdrc_entries.len(),
            "Cache file saved"
        );

        Ok(())
    }

    /// Store FakeIP mapping
    pub fn store_fakeip_mapping(&self, domain: &str, ip: IpAddr) {
        if !self.store_fakeip {
            return;
        }
        let mut data = self.data.write();
        data.fakeip_by_domain.insert(domain.to_string(), ip);
        data.fakeip_by_ip.insert(ip.to_string(), domain.to_string());
        *self.dirty.write() = true;
    }

    /// Get FakeIP for domain
    pub fn get_fakeip_by_domain(&self, domain: &str) -> Option<IpAddr> {
        if !self.store_fakeip {
            return None;
        }
        self.data.read().fakeip_by_domain.get(domain).copied()
    }

    /// Get domain for FakeIP
    pub fn get_domain_by_fakeip(&self, ip: &IpAddr) -> Option<String> {
        if !self.store_fakeip {
            return None;
        }
        self.data.read().fakeip_by_ip.get(&ip.to_string()).cloned()
    }

    /// Store FakeIP allocation counters
    pub fn store_fakeip_counters(&self, next_v4: u32, next_v6: u128) {
        if !self.store_fakeip {
            return;
        }
        let mut data = self.data.write();
        data.fakeip_next_v4 = next_v4;
        data.fakeip_next_v6 = next_v6;
        *self.dirty.write() = true;
    }

    /// Get FakeIP allocation counters
    pub fn get_fakeip_counters(&self) -> (u32, u128) {
        let data = self.data.read();
        (data.fakeip_next_v4, data.fakeip_next_v6)
    }

    /// Store RDRC entry (put into cache)
    pub fn put_rdrc(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        if !self.store_rdrc {
            return;
        }
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl.as_secs().min(self.rdrc_timeout.as_secs());

        let mut data = self.data.write();
        data.rdrc_entries
            .insert(domain.to_string(), RdrcEntry { ips, expires_at });
        *self.dirty.write() = true;
    }

    /// Get RDRC entry (returns None if expired)
    pub fn get_rdrc(&self, domain: &str) -> Option<Vec<IpAddr>> {
        if !self.store_rdrc {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = self.data.read();
        data.rdrc_entries.get(domain).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.ips.clone())
            } else {
                None
            }
        })
    }

    /// Flush cache to disk (for shutdown)
    pub fn flush(&self) {
        if let Err(e) = self.save() {
            error!(error = %e, "Failed to flush cache file");
        }
    }
}

impl CacheFile for CacheFileService {}

impl Drop for CacheFileService {
    fn drop(&mut self) {
        // Auto-save on drop if dirty
        if self.enabled && *self.dirty.read() {
            if let Err(e) = self.save() {
                error!(error = %e, "Failed to save cache file on drop");
            }
        }
    }
}

/// Parse duration string like "7d", "24h", "30m", "60s"
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, "ms")
    } else {
        let last_char = s.chars().last()?;
        if last_char.is_alphabetic() {
            (&s[..s.len() - 1], &s[s.len() - 1..])
        } else {
            (s, "s") // Default to seconds
        }
    };

    let num: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "ms" => return Some(Duration::from_millis(num)),
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_file_service() {
        let config = CacheFileIR {
            enabled: true,
            path: Some("/tmp/cache.db".into()),
            store_fakeip: true,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        let svc = CacheFileService::new(&config);
        assert!(svc.enabled());
        assert_eq!(svc.path(), Some(&PathBuf::from("/tmp/cache.db")));
        assert!(svc.store_fakeip());
        assert!(!svc.store_rdrc());
    }

    #[test]
    fn test_fakeip_persistence() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache.json");

        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            store_fakeip: true,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        // Store data
        {
            let svc = CacheFileService::new(&config);
            let ip: IpAddr = "198.18.0.1".parse().unwrap();
            svc.store_fakeip_mapping("example.com", ip);
            svc.store_fakeip_counters(100, 200);
            svc.flush();
        }

        // Reload and verify
        {
            let svc = CacheFileService::new(&config);
            let ip = svc.get_fakeip_by_domain("example.com");
            assert_eq!(ip, Some("198.18.0.1".parse().unwrap()));

            let domain = svc.get_domain_by_fakeip(&"198.18.0.1".parse().unwrap());
            assert_eq!(domain, Some("example.com".to_string()));

            let (v4, v6) = svc.get_fakeip_counters();
            assert_eq!(v4, 100);
            assert_eq!(v6, 200);
        }
    }

    #[test]
    fn test_rdrc_persistence() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache.json");

        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            store_fakeip: false,
            store_rdrc: true,
            rdrc_timeout: Some("1h".to_string()),
        };

        // Store data
        {
            let svc = CacheFileService::new(&config);
            let ips: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()];
            svc.put_rdrc("cloudflare.com", ips, Duration::from_secs(3600));
            svc.flush();
        }

        // Reload and verify
        {
            let svc = CacheFileService::new(&config);
            let ips = svc.get_rdrc("cloudflare.com");
            assert!(ips.is_some());
            let ips = ips.unwrap();
            assert_eq!(ips.len(), 2);
        }
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(604800)));
        assert_eq!(parse_duration("100ms"), Some(Duration::from_millis(100)));
        assert_eq!(parse_duration("60"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration(""), None);
    }
}
