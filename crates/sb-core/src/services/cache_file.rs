//! Cache file service for storing persistent data.
//! 用于存储持久化数据的缓存文件服务。
//!
//! This module implements persistence for:
//! - FakeIP allocations (domain ↔ IP mappings)
//! - RDRC (Resolver DNS Result Cache) data
//! - Clash mode / Selection state / RuleSets
//!
//! Reference: Go sing-box `experimental/cachefile/`
//! Note: Uses `sled` for embedded KV storage instead of BoltDB (binary incompatible with Go).

use parking_lot::RwLock;
use sb_config::ir::CacheFileIR;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

#[cfg(not(test))]
const FAKEIP_METADATA_SAVE_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
const FAKEIP_METADATA_SAVE_INTERVAL: Duration = Duration::from_millis(50);

/// RDRC cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdrcEntry {
    pub ips: Vec<IpAddr>,
    pub expires_at: u64, // Unix timestamp
}

#[derive(Debug)]
enum CacheBackend {
    Memory(Box<MemoryBackend>),
    Persistence(sled::Db),
}

#[derive(Debug)]
struct FakeIpMetaDebouncer {
    inner: Arc<FakeIpMetaDebouncerInner>,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Debug)]
struct FakeIpMetaDebouncerInner {
    db: Option<sled::Db>,
    mu: std::sync::Mutex<FakeIpMetaDebouncerState>,
    cv: std::sync::Condvar,
}

#[derive(Debug)]
struct FakeIpMetaDebouncerState {
    stop: bool,
    pending: Option<crate::dns::fakeip::FakeIpMetadata>,
    deadline: Option<Instant>,
}

impl FakeIpMetaDebouncer {
    fn new(db: Option<sled::Db>) -> Arc<Self> {
        let inner = Arc::new(FakeIpMetaDebouncerInner {
            db,
            mu: std::sync::Mutex::new(FakeIpMetaDebouncerState {
                stop: false,
                pending: None,
                deadline: None,
            }),
            cv: std::sync::Condvar::new(),
        });

        let me = Arc::new(Self {
            inner: inner.clone(),
            worker: std::sync::Mutex::new(None),
        });

        let handle = std::thread::spawn(move || worker_loop(inner));
        *me.worker.lock().expect("worker mutex poisoned") = Some(handle);
        me
    }

    fn schedule(&self, metadata: crate::dns::fakeip::FakeIpMetadata) {
        let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");
        if st.stop {
            return;
        }
        st.pending = Some(metadata);
        // Strict debounce: always push deadline forward.
        st.deadline = Some(Instant::now() + FAKEIP_METADATA_SAVE_INTERVAL);
        self.inner.cv.notify_one();
    }

    fn flush_now(&self) {
        let pending = {
            let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");
            st.deadline = None;
            st.pending.take()
        };
        if let Some(meta) = pending {
            persist(&self.inner, meta);
        }
    }

    fn stop_and_join(&self) {
        {
            let mut st = self.inner.mu.lock().expect("debouncer mutex poisoned");
            st.stop = true;
            self.inner.cv.notify_one();
        }
        if let Some(handle) = self.worker.lock().expect("worker mutex poisoned").take() {
            let _ = handle.join();
        }
    }
}

impl Drop for FakeIpMetaDebouncer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn worker_loop(inner: Arc<FakeIpMetaDebouncerInner>) {
    loop {
        let to_write = {
            let mut st = inner.mu.lock().expect("debouncer mutex poisoned");
            while !st.stop && st.pending.is_none() {
                st = inner.cv.wait(st).expect("debouncer condvar poisoned");
            }

            if st.stop && st.pending.is_none() {
                return;
            }

            while !st.stop {
                let Some(deadline) = st.deadline else {
                    break;
                };
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let timeout = deadline.saturating_duration_since(now);
                let (guard, _res) = inner
                    .cv
                    .wait_timeout(st, timeout)
                    .expect("debouncer condvar poisoned");
                st = guard;
            }

            st.deadline = None;
            st.pending.take()
        };

        if let Some(meta) = to_write {
            persist(&inner, meta);
        }

        let st = inner.mu.lock().expect("debouncer mutex poisoned");
        if st.stop && st.pending.is_none() {
            return;
        }
        drop(st);
    }
}

fn persist(inner: &FakeIpMetaDebouncerInner, metadata: crate::dns::fakeip::FakeIpMetadata) {
    let Some(db) = inner.db.as_ref() else {
        return;
    };
    let Ok(tree) = db.open_tree("fakeip_meta") else {
        return;
    };
    let _ = tree.insert("next_v4", &metadata.inet4_current_u32.to_be_bytes());
    let _ = tree.insert("next_v6", &metadata.inet6_current_u128.to_be_bytes());
}

#[derive(Debug, Default)]
struct MemoryBackend {
    fakeip_by_domain: RwLock<HashMap<String, IpAddr>>,
    fakeip_by_ip: RwLock<HashMap<String, String>>,
    fakeip_meta: RwLock<Option<crate::dns::fakeip::FakeIpMetadata>>,
    rdrc: RwLock<HashMap<String, RdrcEntry>>,
    // Namespaced by cache_id ("" means default).
    clash_mode: RwLock<HashMap<String, String>>,
    selected: RwLock<HashMap<String, HashMap<String, String>>>,
    expand: RwLock<HashMap<String, HashMap<String, bool>>>,
    rule_sets: RwLock<HashMap<String, Vec<u8>>>,
}

/// Cache file service for storing persistent data.
#[derive(Debug, Clone)]
pub struct CacheFileService {
    enabled: bool,
    cache_id: Option<String>,
    backend: Arc<CacheBackend>,
    store_fakeip: bool,
    store_rdrc: bool,
    rdrc_timeout: Duration,
    fakeip_meta_debouncer: Option<Arc<FakeIpMetaDebouncer>>,
}

impl CacheFileService {
    /// Create a new cache file service from configuration.
    pub fn new(config: &CacheFileIR) -> Self {
        let cache_id = normalize_cache_id(config.cache_id.as_deref());
        let rdrc_timeout = config
            .rdrc_timeout
            .as_ref()
            .and_then(|s| parse_duration(s))
            .unwrap_or(Duration::from_secs(7 * 24 * 3600)); // Default: 7 days

        let backend = if config.enabled {
            if let Some(path_str) = &config.path {
                let path = PathBuf::from(path_str);
                // Ensure parent directory exists
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                match sled::open(&path) {
                    Ok(db) => {
                        info!("Opened cache file at {}", path.display());
                        Arc::new(CacheBackend::Persistence(db))
                    }
                    Err(e) => {
                        error!(
                            "Failed to open cache file at {}: {}, falling back to memory",
                            path.display(),
                            e
                        );
                        Arc::new(CacheBackend::Memory(Box::default()))
                    }
                }
            } else {
                debug!("Cache enabled but no path provided, using memory backend");
                Arc::new(CacheBackend::Memory(Box::default()))
            }
        } else {
            Arc::new(CacheBackend::Memory(Box::default()))
        };

        let fakeip_meta_debouncer = match &*backend {
            CacheBackend::Persistence(db) if config.store_fakeip => {
                Some(FakeIpMetaDebouncer::new(Some(db.clone())))
            }
            _ => None,
        };

        Self {
            enabled: config.enabled,
            cache_id,
            backend,
            store_fakeip: config.store_fakeip,
            store_rdrc: config.store_rdrc,
            rdrc_timeout,
            fakeip_meta_debouncer,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn store_fakeip(&self) -> bool {
        self.store_fakeip
    }

    pub fn store_rdrc(&self) -> bool {
        self.store_rdrc
    }

    fn ns_key(&self) -> &str {
        self.cache_id.as_deref().unwrap_or("")
    }

    fn open_meta_tree<'a>(&'a self, db: &'a sled::Db) -> Result<sled::Tree, sled::Error> {
        match self.cache_id.as_deref() {
            None => db.open_tree("meta"),
            Some(id) => db.open_tree(format!("cache/{}/meta", escape_cache_id(id))),
        }
    }

    fn open_selected_tree<'a>(&'a self, db: &'a sled::Db) -> Result<sled::Tree, sled::Error> {
        match self.cache_id.as_deref() {
            None => db.open_tree("selected"),
            Some(id) => db.open_tree(format!("cache/{}/selected", escape_cache_id(id))),
        }
    }

    fn open_expand_tree<'a>(&'a self, db: &'a sled::Db) -> Result<sled::Tree, sled::Error> {
        match self.cache_id.as_deref() {
            None => db.open_tree("expand"),
            Some(id) => db.open_tree(format!("cache/{}/expand", escape_cache_id(id))),
        }
    }

    /// Store FakeIP mapping
    pub fn store_fakeip_mapping(&self, domain: &str, ip: IpAddr) {
        if !self.store_fakeip {
            return;
        }

        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.fakeip_by_domain.write().insert(domain.to_string(), ip);
                mem.fakeip_by_ip
                    .write()
                    .insert(ip.to_string(), domain.to_string());
            }
            CacheBackend::Persistence(db) => {
                let _ = db.open_tree("fakeip_domain").and_then(|t| {
                    let val = serde_json::to_vec(&ip).unwrap_or_default();
                    t.insert(domain, val)
                });
                let _ = db.open_tree("fakeip_ip").and_then(|t| {
                    let key = serde_json::to_vec(&ip).unwrap_or_default();
                    t.insert(key, domain.as_bytes())
                });
            }
        }
    }

    /// Get FakeIP for domain
    pub fn get_fakeip_by_domain(&self, domain: &str) -> Option<IpAddr> {
        if !self.store_fakeip {
            return None;
        }

        match &*self.backend {
            CacheBackend::Memory(mem) => mem.fakeip_by_domain.read().get(domain).copied(),
            CacheBackend::Persistence(db) => db
                .open_tree("fakeip_domain")
                .ok()?
                .get(domain)
                .ok()?
                .and_then(|ivar| serde_json::from_slice(&ivar).ok()),
        }
    }

    /// Get domain for FakeIP
    pub fn get_domain_by_fakeip(&self, ip: &IpAddr) -> Option<String> {
        if !self.store_fakeip {
            return None;
        }

        match &*self.backend {
            CacheBackend::Memory(mem) => mem.fakeip_by_ip.read().get(&ip.to_string()).cloned(),
            CacheBackend::Persistence(db) => {
                let key = serde_json::to_vec(ip).ok()?;
                db.open_tree("fakeip_ip")
                    .ok()?
                    .get(&key)
                    .ok()?
                    .and_then(|ivar| String::from_utf8(ivar.to_vec()).ok())
            }
        }
    }

    /// Store FakeIP allocation counters
    pub fn store_fakeip_counters(&self, next_v4: u32, next_v6: u128) {
        if !self.store_fakeip {
            return;
        }

        let meta = crate::dns::fakeip::FakeIpMetadata {
            inet4_current_u32: next_v4,
            inet6_current_u128: next_v6,
        };

        match &*self.backend {
            CacheBackend::Memory(mem) => {
                *mem.fakeip_meta.write() = Some(meta);
            }
            CacheBackend::Persistence(db) => {
                if let Some(d) = &self.fakeip_meta_debouncer {
                    d.schedule(meta);
                } else if let Ok(tree) = db.open_tree("fakeip_meta") {
                    let _ = tree.insert("next_v4", &next_v4.to_be_bytes());
                    let _ = tree.insert("next_v6", &next_v6.to_be_bytes());
                }
            }
        }
    }

    /// Get FakeIP allocation counters
    pub fn get_fakeip_counters(&self) -> (u32, u128) {
        match &*self.backend {
            CacheBackend::Memory(mem) => mem
                .fakeip_meta
                .read()
                .as_ref()
                .map(|m| (m.inet4_current_u32, m.inet6_current_u128))
                .unwrap_or((0, 0)),
            CacheBackend::Persistence(db) => {
                let tree = match db.open_tree("fakeip_meta") {
                    Ok(t) => t,
                    Err(_) => return (0, 0),
                };

                let v4 = tree
                    .get("next_v4")
                    .ok()
                    .flatten()
                    .map(|v| {
                        let mut bytes = [0u8; 4];
                        if v.len() == 4 {
                            bytes.copy_from_slice(&v);
                            u32::from_be_bytes(bytes)
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);

                let v6 = tree
                    .get("next_v6")
                    .ok()
                    .flatten()
                    .map(|v| {
                        let mut bytes = [0u8; 16];
                        if v.len() == 16 {
                            bytes.copy_from_slice(&v);
                            u128::from_be_bytes(bytes)
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);

                (v4, v6)
            }
        }
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

        let entry = RdrcEntry { ips, expires_at };

        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.rdrc.write().insert(domain.to_string(), entry);
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = db.open_tree("rdrc") {
                    if let Ok(val) = serde_json::to_vec(&entry) {
                        let _ = tree.insert(domain, val);
                    }
                }
            }
        }
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

        // Helper to check expiry
        let check = |entry: RdrcEntry| -> Option<Vec<IpAddr>> {
            if entry.expires_at > now {
                Some(entry.ips)
            } else {
                None
            }
        };

        match &*self.backend {
            CacheBackend::Memory(mem) => mem.rdrc.read().get(domain).cloned().and_then(check),
            CacheBackend::Persistence(db) => db
                .open_tree("rdrc")
                .ok()?
                .get(domain)
                .ok()?
                .and_then(|v| serde_json::from_slice::<RdrcEntry>(&v).ok())
                .and_then(check),
        }
    }

    /// Check if a domain was previously rejected by RDRC for a specific transport.
    /// Go parity: adapter.RDRCStore.LoadRDRC(transportName, qName, qType) -> bool
    pub fn check_rdrc_rejection(&self, transport_tag: &str, domain: &str, qtype: u16) -> bool {
        if !self.store_rdrc {
            return false;
        }
        let key = format!("{}\x00{}\x00{}", transport_tag, domain, qtype);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match &*self.backend {
            CacheBackend::Memory(mem) => mem
                .rdrc
                .read()
                .get(&key)
                .is_some_and(|entry| entry.expires_at > now),
            CacheBackend::Persistence(db) => db
                .open_tree("rdrc")
                .ok()
                .and_then(|tree| tree.get(&key).ok().flatten())
                .and_then(|v| serde_json::from_slice::<RdrcEntry>(&v).ok())
                .is_some_and(|entry| entry.expires_at > now),
        }
    }

    /// Save an RDRC rejection for a specific transport + domain + qtype.
    /// Go parity: adapter.RDRCStore.SaveRDRC(transportName, qName, qType)
    pub fn save_rdrc_rejection(&self, transport_tag: &str, domain: &str, qtype: u16) {
        if !self.store_rdrc {
            return;
        }
        let key = format!("{}\x00{}\x00{}", transport_tag, domain, qtype);
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.rdrc_timeout.as_secs();

        let entry = RdrcEntry {
            ips: Vec::new(),
            expires_at,
        };

        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.rdrc.write().insert(key, entry);
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = db.open_tree("rdrc") {
                    if let Ok(val) = serde_json::to_vec(&entry) {
                        let _ = tree.insert(key.as_bytes(), val);
                    }
                }
            }
        }
    }

    pub fn set_clash_mode(&self, mode: String) {
        if !self.enabled {
            return;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.clash_mode
                    .write()
                    .insert(self.ns_key().to_string(), mode);
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = self.open_meta_tree(db) {
                    let _ = tree.insert("clash_mode", mode.as_bytes());
                }
            }
        }
    }

    pub fn get_clash_mode(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => mem.clash_mode.read().get(self.ns_key()).cloned(),
            CacheBackend::Persistence(db) => db
                .open_tree(match self.cache_id.as_deref() {
                    None => "meta".to_string(),
                    Some(id) => format!("cache/{}/meta", escape_cache_id(id)),
                })
                .ok()?
                .get("clash_mode")
                .ok()?
                .and_then(|v| String::from_utf8(v.to_vec()).ok()),
        }
    }

    pub fn set_selected(&self, group: &str, selected: &str) {
        if !self.enabled {
            return;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.selected
                    .write()
                    .entry(self.ns_key().to_string())
                    .or_default()
                    .insert(group.to_string(), selected.to_string());
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = self.open_selected_tree(db) {
                    let _ = tree.insert(group, selected.as_bytes());
                }
            }
        }
    }

    pub fn get_selected(&self, group: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => mem
                .selected
                .read()
                .get(self.ns_key())
                .and_then(|m| m.get(group))
                .cloned(),
            CacheBackend::Persistence(db) => db
                .open_tree(match self.cache_id.as_deref() {
                    None => "selected".to_string(),
                    Some(id) => format!("cache/{}/selected", escape_cache_id(id)),
                })
                .ok()?
                .get(group)
                .ok()?
                .and_then(|v| String::from_utf8(v.to_vec()).ok()),
        }
    }

    pub fn set_expand(&self, group: &str, expand: bool) {
        if !self.enabled {
            return;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.expand
                    .write()
                    .entry(self.ns_key().to_string())
                    .or_default()
                    .insert(group.to_string(), expand);
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = self.open_expand_tree(db) {
                    let _ = tree.insert(group, &[if expand { 1 } else { 0 }]);
                }
            }
        }
    }

    pub fn get_expand(&self, group: &str) -> Option<bool> {
        if !self.enabled {
            return None;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => mem
                .expand
                .read()
                .get(self.ns_key())
                .and_then(|m| m.get(group))
                .copied(),
            CacheBackend::Persistence(db) => db
                .open_tree(match self.cache_id.as_deref() {
                    None => "expand".to_string(),
                    Some(id) => format!("cache/{}/expand", escape_cache_id(id)),
                })
                .ok()?
                .get(group)
                .ok()?
                .map(|v| v.first().copied() == Some(1)),
        }
    }

    pub fn store_rule_set(&self, tag: &str, content: Vec<u8>) {
        if !self.enabled {
            return;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => {
                mem.rule_sets.write().insert(tag.to_string(), content);
            }
            CacheBackend::Persistence(db) => {
                if let Ok(tree) = db.open_tree("rulesets") {
                    let _ = tree.insert(tag, content);
                }
            }
        }
    }

    pub fn get_rule_set(&self, tag: &str) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        match &*self.backend {
            CacheBackend::Memory(mem) => mem.rule_sets.read().get(tag).cloned(),
            CacheBackend::Persistence(db) => db
                .open_tree("rulesets")
                .ok()?
                .get(tag)
                .ok()?
                .map(|v| v.to_vec()),
        }
    }

    /// Flush cache to disk
    pub fn flush(&self) {
        if let Some(d) = &self.fakeip_meta_debouncer {
            d.flush_now();
        }
        if let CacheBackend::Persistence(db) = &*self.backend {
            let _ = db.flush();
        }
    }
}

impl crate::context::CacheFile for CacheFileService {
    fn get_clash_mode(&self) -> Option<String> {
        self.get_clash_mode()
    }

    fn set_clash_mode(&self, mode: String) {
        self.set_clash_mode(mode);
    }

    fn set_selected(&self, group: &str, selected: &str) {
        self.set_selected(group, selected);
    }

    fn get_selected(&self, group: &str) -> Option<String> {
        self.get_selected(group)
    }

    fn get_expand(&self, group: &str) -> Option<bool> {
        self.get_expand(group)
    }

    fn set_expand(&self, group: &str, expand: bool) {
        self.set_expand(group, expand);
    }
}

impl crate::dns::fakeip::FakeIpStorage for CacheFileService {
    fn get_by_domain(&self, domain: &str) -> Option<IpAddr> {
        self.get_fakeip_by_domain(domain)
    }

    fn store(&self, domain: &str, ip: IpAddr) {
        self.store_fakeip_mapping(domain, ip)
    }

    fn load_metadata(&self) -> Option<crate::dns::fakeip::FakeIpMetadata> {
        if !self.store_fakeip {
            return None;
        }

        match &*self.backend {
            CacheBackend::Memory(mem) => mem.fakeip_meta.read().clone(),
            CacheBackend::Persistence(db) => {
                let tree = db.open_tree("fakeip_meta").ok()?;
                let v4 = tree.get("next_v4").ok().flatten()?;
                let v6 = tree.get("next_v6").ok().flatten()?;
                if v4.len() != 4 || v6.len() != 16 {
                    return None;
                }
                let mut b4 = [0u8; 4];
                b4.copy_from_slice(&v4);
                let mut b6 = [0u8; 16];
                b6.copy_from_slice(&v6);
                Some(crate::dns::fakeip::FakeIpMetadata {
                    inet4_current_u32: u32::from_be_bytes(b4),
                    inet6_current_u128: u128::from_be_bytes(b6),
                })
            }
        }
    }

    fn save_metadata_debounced(&self, metadata: crate::dns::fakeip::FakeIpMetadata) {
        if !self.store_fakeip {
            return;
        }

        match &*self.backend {
            CacheBackend::Memory(mem) => {
                *mem.fakeip_meta.write() = Some(metadata);
            }
            CacheBackend::Persistence(db) => {
                if let Some(d) = &self.fakeip_meta_debouncer {
                    d.schedule(metadata);
                } else if let Ok(tree) = db.open_tree("fakeip_meta") {
                    let _ = tree.insert("next_v4", &metadata.inet4_current_u32.to_be_bytes());
                    let _ = tree.insert("next_v6", &metadata.inet6_current_u128.to_be_bytes());
                }
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
        "y" => num * 31536000,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

fn normalize_cache_id(cache_id: Option<&str>) -> Option<String> {
    let id = cache_id?.trim();
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

fn escape_cache_id(cache_id: &str) -> String {
    // Percent-encode unsafe bytes to keep sled tree names stable and hierarchical.
    let mut out = String::with_capacity(cache_id.len());
    for &b in cache_id.as_bytes() {
        let safe = b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-';
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_file_service() {
        // Memory mode check
        let config = CacheFileIR {
            enabled: true,
            path: None, // No path = memory
            cache_id: None,
            store_fakeip: true,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        let svc = CacheFileService::new(&config);
        assert!(svc.enabled());
        assert!(svc.store_fakeip());
        assert!(!svc.store_rdrc());
    }

    #[test]
    fn test_fakeip_persistence_sled() {
        let tmp = TempDir::new().unwrap();
        // Sled uses directory, but typically we pass path to it.
        // If it's a file path in config, sled treats it as DB directory.
        // Let's assume CacheFileIR path is a file path, but for sled we use it as dir.
        let cache_path = tmp.path().join("cache_db");

        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: None,
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
    fn test_rdrc_persistence_sled() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache_rdrc_db");

        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: None,
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
    fn test_rdrc_transport_aware_api() {
        let config = CacheFileIR {
            enabled: true,
            path: None,
            cache_id: None,
            store_fakeip: false,
            store_rdrc: true,
            rdrc_timeout: Some("1h".to_string()),
        };

        let svc = CacheFileService::new(&config);

        // Initially no rejection
        assert!(!svc.check_rdrc_rejection("dns-google", "example.com", 1));

        // Save rejection
        svc.save_rdrc_rejection("dns-google", "example.com", 1);

        // Now it should be rejected
        assert!(svc.check_rdrc_rejection("dns-google", "example.com", 1));

        // Different transport should not be rejected
        assert!(!svc.check_rdrc_rejection("dns-cf", "example.com", 1));

        // Different qtype should not be rejected
        assert!(!svc.check_rdrc_rejection("dns-google", "example.com", 28));

        // Different domain should not be rejected
        assert!(!svc.check_rdrc_rejection("dns-google", "other.com", 1));
    }

    #[test]
    fn test_clash_persistence_sled() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache_clash_db");

        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: None,
            store_fakeip: false,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        // Store data
        {
            let svc = CacheFileService::new(&config);
            svc.set_clash_mode("Global".to_string());
            svc.set_selected("proxy", "us");
            svc.set_expand("group1", true);
            svc.store_rule_set("geoip", vec![1, 2, 3]);
            svc.flush();
        }

        // Reload and verify
        {
            let svc = CacheFileService::new(&config);
            assert_eq!(svc.get_clash_mode(), Some("Global".to_string()));
            assert_eq!(svc.get_selected("proxy"), Some("us".to_string()));
            assert_eq!(svc.get_expand("group1"), Some(true));
            assert_eq!(svc.get_rule_set("geoip"), Some(vec![1, 2, 3]));
        }
    }

    #[test]
    fn test_cache_id_isolates_clash_persistence_sled() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache_clash_cache_id_db");

        let config_a = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: Some("A".to_string()),
            store_fakeip: false,
            store_rdrc: false,
            rdrc_timeout: None,
        };
        let config_b = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: Some("B".to_string()),
            store_fakeip: false,
            store_rdrc: false,
            rdrc_timeout: None,
        };
        let config_default = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: None,
            store_fakeip: false,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        // Write A
        {
            let svc = CacheFileService::new(&config_a);
            svc.set_clash_mode("Rule".to_string());
            svc.set_selected("g", "x");
            svc.set_expand("g", true);
            svc.flush();
        }

        // Read B/default should be empty
        {
            let svc = CacheFileService::new(&config_b);
            assert_eq!(svc.get_clash_mode(), None);
            assert_eq!(svc.get_selected("g"), None);
            assert_eq!(svc.get_expand("g"), None);
        }
        {
            let svc = CacheFileService::new(&config_default);
            assert_eq!(svc.get_clash_mode(), None);
            assert_eq!(svc.get_selected("g"), None);
            assert_eq!(svc.get_expand("g"), None);
        }

        // Read A should restore
        {
            let svc = CacheFileService::new(&config_a);
            assert_eq!(svc.get_clash_mode(), Some("Rule".to_string()));
            assert_eq!(svc.get_selected("g"), Some("x".to_string()));
            assert_eq!(svc.get_expand("g"), Some(true));
        }
    }

    #[test]
    fn test_fakeip_metadata_debounced_persistence() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("cache_fakeip_meta_db");
        let config = CacheFileIR {
            enabled: true,
            path: Some(cache_path.to_string_lossy().to_string()),
            cache_id: None,
            store_fakeip: true,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        {
            let svc = CacheFileService::new(&config);
            <CacheFileService as crate::dns::fakeip::FakeIpStorage>::save_metadata_debounced(
                &svc,
                crate::dns::fakeip::FakeIpMetadata {
                    inet4_current_u32: 1,
                    inet6_current_u128: 2,
                },
            );
            <CacheFileService as crate::dns::fakeip::FakeIpStorage>::save_metadata_debounced(
                &svc,
                crate::dns::fakeip::FakeIpMetadata {
                    inet4_current_u32: 3,
                    inet6_current_u128: 4,
                },
            );
            std::thread::sleep(FAKEIP_METADATA_SAVE_INTERVAL * 4);
            svc.flush();
        }

        let svc = CacheFileService::new(&config);
        let meta = <CacheFileService as crate::dns::fakeip::FakeIpStorage>::load_metadata(&svc)
            .expect("metadata");
        assert_eq!(meta.inet4_current_u32, 3);
        assert_eq!(meta.inet6_current_u128, 4);
    }
}
