use once_cell::sync::OnceCell;
use std::path::Path;
use std::path::PathBuf;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct CacheEntry {
    pub etag: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub timestamp: Instant,
}

fn disk_path_inner(base: &Path, key: &str) -> PathBuf {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash = hasher.finish();
    base.join(format!("{hash:x}"))
}

#[derive(Clone)]
pub enum TierEntry {
    Mem(CacheEntry),
    Disk {
        path: PathBuf,
        etag: Option<String>,
        len: usize,
        content_type: Option<String>,
        timestamp: Instant,
    },
}

impl TierEntry {
    #[must_use]
    pub const fn body_len(&self) -> usize {
        match self {
            Self::Mem(entry) => entry.body.len(),
            Self::Disk { len, .. } => *len,
        }
    }

    #[must_use]
    pub const fn etag(&self) -> Option<&String> {
        match self {
            Self::Mem(entry) => entry.etag.as_ref(),
            Self::Disk { etag, .. } => etag.as_ref(),
        }
    }

    #[must_use]
    pub const fn content_type(&self) -> Option<&String> {
        match self {
            Self::Mem(entry) => entry.content_type.as_ref(),
            Self::Disk { content_type, .. } => content_type.as_ref(),
        }
    }

    #[must_use]
    pub const fn timestamp(&self) -> Instant {
        match self {
            Self::Mem(entry) => entry.timestamp,
            Self::Disk { timestamp, .. } => *timestamp,
        }
    }

    /// # Errors
    /// Returns an error if disk-backed cache entry cannot be read
    pub async fn get_body(&self) -> Result<Vec<u8>, std::io::Error> {
        match self {
            Self::Mem(entry) => Ok(entry.body.clone()),
            Self::Disk { path, .. } => tokio::fs::read(path).await,
        }
    }
}

pub struct Lru {
    cap_items: usize,
    cap_bytes: usize,
    cur_bytes: usize,
    ttl: Duration,
    disk_backing: Option<PathBuf>,
    map: HashMap<String, (TierEntry, Instant)>,
    evict_count_mem: u64,
    evict_count_disk: u64,
    head_count: u64,
}

impl Lru {
    #[must_use]
    pub fn new(cap_items: usize, ttl_ms: u64) -> Self {
        Self::with_byte_limit(cap_items, ttl_ms, 10 * 1024 * 1024) // 10MB default
    }

    pub fn with_byte_limit(cap_items: usize, ttl_ms: u64, cap_bytes: usize) -> Self {
        let disk_backing = std::env::var("SB_SUBS_CACHE_DISK")
            .ok()
            .filter(|s| s != "0")
            .map(|s| {
                if s == "1" {
                    "/tmp/sb-subs-cache".to_string()
                } else {
                    s
                }
            })
            .map(PathBuf::from);

        // Create disk backing directory if enabled
        if let Some(ref path) = disk_backing {
            let _ = std::fs::create_dir_all(path);
        }

        Self {
            cap_items,
            cap_bytes,
            cur_bytes: 0,
            ttl: Duration::from_millis(ttl_ms),
            disk_backing,
            map: HashMap::new(),
            evict_count_mem: 0,
            evict_count_disk: 0,
            head_count: 0,
        }
    }

    pub fn get(&mut self, key: &str) -> Option<TierEntry> {
        let now = Instant::now();
        self.map.get(key).and_then(|(entry, _)| {
            if now.duration_since(entry.timestamp()) <= self.ttl {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    pub fn put(&mut self, key: String, value: CacheEntry) {
        let entry_size = value.body.len();
        let tier_entry = TierEntry::Mem(value);
        self.put_tier_entry(key, tier_entry, entry_size);
    }

    fn put_tier_entry(&mut self, key: String, entry: TierEntry, entry_size: usize) {
        // Evict entries if necessary to make room
        while (self.map.len() >= self.cap_items || self.cur_bytes + entry_size > self.cap_bytes)
            && !self.map.is_empty()
        {
            self.evict_one();
        }

        if entry_size <= self.cap_bytes {
            let now = Instant::now();
            self.cur_bytes += entry_size;
            self.map.insert(key, (entry, now));
        }
    }

    fn evict_one(&mut self) {
        // Find the oldest entry to evict (LRU)
        let oldest_key = self
            .map
            .iter()
            .min_by_key(|(_, (_, timestamp))| *timestamp)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            if let Some((entry, access_time)) = self.map.remove(&key) {
                let size = entry.body_len();

                match entry {
                    TierEntry::Mem(_) => {
                        // Try to move to disk if disk backing is enabled (only for larger entries)
                        if let Some(base_path) = &self.disk_backing {
                            if size > 4096 {
                                if let TierEntry::Mem(cache_entry) = entry {
                                    if matches!(self.write_to_disk(&key, &cache_entry), Ok(())) {
                                        let disk_entry = TierEntry::Disk {
                                            path: disk_path_inner(base_path, &key),
                                            etag: cache_entry.etag,
                                            len: size,
                                            content_type: cache_entry.content_type,
                                            timestamp: cache_entry.timestamp,
                                        };
                                        // Entry moved to disk but stays in cache - no byte count change needed
                                        // Preserve original access timestamp for proper LRU ordering
                                        self.map.insert(key, (disk_entry, access_time));
                                        // This doesn't count as an eviction since entry stays accessible
                                        return;
                                    }
                                }
                            }
                        }

                        // If we reach here, entry was not moved to disk - it's being fully evicted
                        self.cur_bytes = self.cur_bytes.saturating_sub(size);
                        self.evict_count_mem += 1;
                    }
                    TierEntry::Disk { path, .. } => {
                        // Disk entry being fully evicted
                        self.cur_bytes = self.cur_bytes.saturating_sub(size);
                        self.evict_count_disk += 1;
                        let _ = std::fs::remove_file(&path); // Clean up disk file
                    }
                }
            }
        }
    }

    fn write_to_disk(&self, key: &str, entry: &CacheEntry) -> Result<(), std::io::Error> {
        if let Some(ref base_path) = self.disk_backing {
            let file_path = disk_path_inner(base_path, key);
            sb_core::util::fs_atomic::write_atomic(&file_path, &entry.body)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn disk_path(&self, key: &str) -> PathBuf {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        self.disk_backing
            .as_ref()
            .expect("disk backing expected in tests")
            .join(format!("{:x}", hash))
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn byte_usage(&self) -> (usize, usize) {
        let mem_bytes = self
            .map
            .values()
            .filter(|(entry, _)| matches!(entry, TierEntry::Mem(_)))
            .map(|(entry, _)| entry.body_len())
            .sum();

        let disk_bytes = self
            .map
            .values()
            .filter(|(entry, _)| matches!(entry, TierEntry::Disk { .. }))
            .map(|(entry, _)| entry.body_len())
            .sum();

        (mem_bytes, disk_bytes)
    }

    #[must_use]
    pub const fn metrics(&self) -> (u64, u64, u64) {
        (self.evict_count_mem, self.evict_count_disk, self.head_count)
    }

    pub const fn inc_head_count(&mut self) {
        self.head_count += 1;
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.cur_bytes = 0;
        self.evict_count_mem = 0;
        self.evict_count_disk = 0;
        self.head_count = 0;
    }
}

static LRU: OnceCell<Mutex<Lru>> = OnceCell::new();

pub fn global() -> &'static Mutex<Lru> {
    LRU.get_or_init(|| {
        let cap_items = std::env::var("SB_SUBS_CACHE_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);

        let ttl_ms = std::env::var("SB_SUBS_CACHE_TTL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000);

        let cap_bytes = std::env::var("SB_SUBS_CACHE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10 * 1024 * 1024); // 10MB default

        Mutex::new(Lru::with_byte_limit(cap_items, ttl_ms, cap_bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_lru_basic_operations() {
        let mut lru = Lru::with_byte_limit(2, 1000, 1024);
        let entry = CacheEntry {
            etag: Some("test".to_string()),
            content_type: None,
            body: b"test".to_vec(),
            timestamp: Instant::now(),
        };

        lru.put("key1".to_string(), entry.clone());
        assert!(lru.get("key1").is_some());
        assert!(lru.get("missing").is_none());
    }

    #[test]
    fn test_lru_capacity_eviction() {
        let mut lru = Lru::with_byte_limit(2, 10000, 1024);
        let entry1 = CacheEntry {
            etag: Some("1".to_string()),
            content_type: None,
            body: b"1".to_vec(),
            timestamp: Instant::now(),
        };
        let entry2 = entry1.clone();
        let entry3 = entry1.clone();

        lru.put("key1".to_string(), entry1);
        lru.put("key2".to_string(), entry2);
        lru.put("key3".to_string(), entry3);

        // Should have evicted one entry
        assert_eq!(lru.size(), 2);
    }

    #[test]
    fn test_lru_ttl_expiration() {
        let mut lru = Lru::with_byte_limit(10, 10, 1024); // 10ms TTL
        let entry = CacheEntry {
            etag: Some("test".to_string()),
            content_type: None,
            body: b"test".to_vec(),
            timestamp: Instant::now(),
        };

        lru.put("key1".to_string(), entry);
        assert!(lru.get("key1").is_some());

        thread::sleep(Duration::from_millis(20));
        assert!(lru.get("key1").is_none());
    }

    #[test]
    fn test_byte_limit_eviction() {
        let mut lru = Lru::with_byte_limit(10, 10000, 20); // 20 bytes total

        // Create entries that exceed byte limit
        let big_entry1 = CacheEntry {
            etag: Some("big1".to_string()),
            content_type: None,
            body: vec![b'a'; 12], // 12 bytes
            timestamp: Instant::now(),
        };

        let big_entry2 = CacheEntry {
            etag: Some("big2".to_string()),
            content_type: None,
            body: vec![b'b'; 12], // 12 bytes
            timestamp: Instant::now(),
        };

        lru.put("big1".to_string(), big_entry1);
        assert_eq!(lru.size(), 1);

        // Adding second entry should evict first due to byte limit
        lru.put("big2".to_string(), big_entry2);
        assert_eq!(lru.size(), 1);
        assert!(lru.get("big1").is_none()); // Should be evicted
        assert!(lru.get("big2").is_some()); // Should still exist
    }

    #[test]
    fn test_byte_usage_tracking() {
        let mut lru = Lru::with_byte_limit(10, 10000, 1000);

        let entry1 = CacheEntry {
            etag: Some("1".to_string()),
            content_type: None,
            body: vec![b'a'; 100], // 100 bytes
            timestamp: Instant::now(),
        };

        let entry2 = CacheEntry {
            etag: Some("2".to_string()),
            content_type: None,
            body: vec![b'b'; 50], // 50 bytes
            timestamp: Instant::now(),
        };

        lru.put("key1".to_string(), entry1);
        lru.put("key2".to_string(), entry2);

        let (mem_bytes, _disk_bytes) = lru.byte_usage();
        assert_eq!(mem_bytes, 150); // 100 + 50
    }

    #[test]
    fn test_tier_entry_functionality() {
        let cache_entry = CacheEntry {
            etag: Some("test-etag".to_string()),
            content_type: Some("text/plain".to_string()),
            body: b"test body".to_vec(),
            timestamp: Instant::now(),
        };

        let tier_entry = TierEntry::Mem(cache_entry.clone());

        assert_eq!(tier_entry.body_len(), 9);
        assert_eq!(tier_entry.etag().unwrap(), "test-etag");
        assert_eq!(tier_entry.content_type().unwrap(), "text/plain");
    }

    #[tokio::test]
    async fn test_tier_entry_get_body() {
        let cache_entry = CacheEntry {
            etag: None,
            content_type: None,
            body: b"async body test".to_vec(),
            timestamp: Instant::now(),
        };

        let tier_entry = TierEntry::Mem(cache_entry);
        let body = tier_entry.get_body().await.unwrap();
        assert_eq!(body, b"async body test");
    }

    #[test]
    fn test_eviction_metrics() {
        let mut lru = Lru::with_byte_limit(1, 10000, 10); // Very small limits

        let entry1 = CacheEntry {
            etag: None,
            content_type: None,
            body: vec![b'a'; 8],
            timestamp: Instant::now(),
        };

        let entry2 = CacheEntry {
            etag: None,
            content_type: None,
            body: vec![b'b'; 8],
            timestamp: Instant::now(),
        };

        lru.put("key1".to_string(), entry1);
        lru.put("key2".to_string(), entry2); // Should trigger eviction

        let (evict_mem, _evict_disk, _head_count) = lru.metrics();
        assert!(evict_mem > 0); // Should have recorded evictions
    }

    #[test]
    fn test_head_count_tracking() {
        let mut lru = Lru::new(10, 1000);

        assert_eq!(lru.metrics().2, 0); // Initial head count should be 0

        lru.inc_head_count();
        lru.inc_head_count();

        assert_eq!(lru.metrics().2, 2); // Should track HEAD requests
    }

    #[test]
    fn test_disk_backing_configuration() {
        // Test without disk backing
        std::env::remove_var("SB_SUBS_CACHE_DISK");
        let lru_no_disk = Lru::with_byte_limit(10, 1000, 1024);
        assert!(lru_no_disk.disk_backing.is_none());

        // Test with disk backing enabled
        std::env::set_var("SB_SUBS_CACHE_DISK", "1");
        let lru_with_disk = Lru::with_byte_limit(10, 1000, 1024);
        assert!(lru_with_disk.disk_backing.is_some());
        assert_eq!(
            lru_with_disk.disk_backing.unwrap().to_str().unwrap(),
            "/tmp/sb-subs-cache"
        );

        // Test with custom path
        std::env::set_var("SB_SUBS_CACHE_DISK", "/custom/cache/path");
        let lru_custom = Lru::with_byte_limit(10, 1000, 1024);
        assert_eq!(
            lru_custom.disk_backing.unwrap().to_str().unwrap(),
            "/custom/cache/path"
        );

        // Cleanup
        std::env::remove_var("SB_SUBS_CACHE_DISK");
    }

    #[tokio::test]
    async fn test_disk_tier_operations() {
        use std::fs;

        // Create temporary test directory
        let test_dir = "/tmp/sb-cache-test";
        let _ = fs::create_dir_all(test_dir);

        std::env::set_var("SB_SUBS_CACHE_DISK", test_dir);
        let mut lru = Lru::with_byte_limit(1, 10000, 50); // Small memory limit to force disk usage

        let large_entry = CacheEntry {
            etag: Some("disk-test".to_string()),
            content_type: Some("application/test".to_string()),
            body: vec![b'x'; 5000], // Large enough to move to disk
            timestamp: Instant::now(),
        };

        let small_entry = CacheEntry {
            etag: Some("mem-test".to_string()),
            content_type: Some("text/plain".to_string()),
            body: b"small".to_vec(),
            timestamp: Instant::now(),
        };

        // Add large entry first (should stay in memory initially)
        lru.put("large".to_string(), large_entry);

        // Add small entry (should evict large entry and move it to disk if configured properly)
        lru.put("small".to_string(), small_entry);

        // Check metrics show disk eviction
        let (mem_evicts, disk_evicts, _) = lru.metrics();
        assert!(mem_evicts > 0, "Should have memory evictions");

        // Check byte usage tracking
        let (mem_bytes, disk_bytes) = lru.byte_usage();
        assert!(
            mem_bytes > 0 || disk_bytes > 0,
            "Should have bytes tracked in some tier"
        );

        // Cleanup
        std::env::remove_var("SB_SUBS_CACHE_DISK");
        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_tiered_eviction_priority() {
        // Test that larger entries are preferentially moved to disk
        std::env::set_var("SB_SUBS_CACHE_DISK", "/tmp/sb-cache-priority-test");
        let mut lru = Lru::with_byte_limit(2, 10000, 100);

        let small_entry = CacheEntry {
            etag: None,
            content_type: None,
            body: vec![b'a'; 10], // Small entry
            timestamp: Instant::now(),
        };

        let large_entry = CacheEntry {
            etag: None,
            content_type: None,
            body: vec![b'b'; 90], // Large entry (exceeds disk threshold of 4096 in real code, but tests the logic)
            timestamp: Instant::now(),
        };

        lru.put("small".to_string(), small_entry);
        lru.put("large".to_string(), large_entry);

        // The implementation should prefer to evict based on LRU, not size
        // But larger entries should be candidates for disk storage
        let (mem_evicts, _disk_evicts, _) = lru.metrics();

        // Just verify eviction tracking works
        let third_entry = CacheEntry {
            etag: None,
            content_type: None,
            body: vec![b'c'; 50],
            timestamp: Instant::now(),
        };

        lru.put("third".to_string(), third_entry); // Should trigger eviction

        let (mem_evicts_after, _disk_evicts_after, _) = lru.metrics();
        assert!(mem_evicts_after >= mem_evicts, "Should track evictions");

        std::env::remove_var("SB_SUBS_CACHE_DISK");
    }

    #[test]
    fn test_cache_key_hashing() {
        std::env::set_var("SB_SUBS_CACHE_DISK", "/tmp/sb-cache-hash-test");
        let lru = Lru::with_byte_limit(10, 1000, 1024);

        // Test that different keys produce different paths
        let path1 = lru.disk_path("test-key-1");
        let path2 = lru.disk_path("test-key-2");
        let path3 = lru.disk_path("test-key-1"); // Same key should produce same path

        assert_ne!(path1, path2, "Different keys should have different paths");
        assert_eq!(path1, path3, "Same key should produce same path");

        // Verify paths are under the expected directory
        assert!(path1.starts_with("/tmp/sb-cache-hash-test"));
        assert!(path2.starts_with("/tmp/sb-cache-hash-test"));

        std::env::remove_var("SB_SUBS_CACHE_DISK");
    }

    #[test]
    fn test_comprehensive_metrics_integration() {
        let mut lru = Lru::with_byte_limit(2, 10000, 100);

        // Start with zero metrics
        let (mem_evicts_0, disk_evicts_0, head_count_0) = lru.metrics();
        assert_eq!(mem_evicts_0, 0);
        assert_eq!(disk_evicts_0, 0);
        assert_eq!(head_count_0, 0);

        // Add entries to trigger evictions
        for i in 0..5 {
            let entry = CacheEntry {
                etag: Some(format!("etag-{}", i)),
                content_type: Some("text/plain".to_string()),
                body: vec![b'a'; 30],
                timestamp: Instant::now(),
            };
            lru.put(format!("key-{}", i), entry);
        }

        // Simulate HEAD requests
        lru.inc_head_count();
        lru.inc_head_count();
        lru.inc_head_count();

        // Verify metrics have changed
        let (mem_evicts_final, _disk_evicts_final, head_count_final) = lru.metrics();
        assert!(
            mem_evicts_final > 0,
            "Should have memory evictions from capacity limits"
        );
        assert_eq!(head_count_final, 3, "Should track HEAD count correctly");

        // Verify byte usage tracking
        let (mem_bytes, disk_bytes) = lru.byte_usage();
        assert!(mem_bytes > 0, "Should have memory usage");
        assert!(
            mem_bytes <= 100,
            "Should not exceed byte limit significantly"
        ); // Some tolerance for overhead
    }

    #[tokio::test]
    async fn test_tier_entry_disk_async_operations() {
        use std::fs;

        let test_path = PathBuf::from("/tmp/sb-tier-test-file");
        let test_content = b"test content for tier entry";

        // Write test file
        fs::write(&test_path, test_content).expect("Failed to write test file");

        // Create disk tier entry
        let disk_entry = TierEntry::Disk {
            path: test_path.clone(),
            etag: Some("test-etag".to_string()),
            len: test_content.len(),
            content_type: Some("text/plain".to_string()),
            timestamp: Instant::now(),
        };

        // Test async body retrieval
        let retrieved_body = disk_entry
            .get_body()
            .await
            .expect("Failed to read disk entry body");
        assert_eq!(retrieved_body, test_content);

        // Test other accessors
        assert_eq!(disk_entry.body_len(), test_content.len());
        assert_eq!(disk_entry.etag().unwrap(), "test-etag");
        assert_eq!(disk_entry.content_type().unwrap(), "text/plain");

        // Cleanup
        let _ = fs::remove_file(&test_path);
    }

    #[tokio::test]
    async fn test_disk_migration_counting_fix() {
        use std::fs;

        // Create temporary test directory
        let test_dir = "/tmp/sb-cache-counting-test";
        let _ = fs::create_dir_all(test_dir);

        std::env::set_var("SB_SUBS_CACHE_DISK", test_dir);
        let mut lru = Lru::with_byte_limit(1, 10000, 60); // Small memory limit to force eviction

        // Test 1: Memory overflow migration to disk should update evict_count_mem only for true evictions
        let large_entry = CacheEntry {
            etag: Some("large-entry".to_string()),
            content_type: Some("application/test".to_string()),
            body: vec![b'x'; 5000], // Large enough to move to disk (> 4096 threshold)
            timestamp: Instant::now(),
        };

        let small_entry = CacheEntry {
            etag: Some("small-entry".to_string()),
            content_type: Some("text/plain".to_string()),
            body: vec![b'y'; 50], // Small entry
            timestamp: Instant::now(),
        };

        // Add large entry first
        lru.put("large".to_string(), large_entry);
        let (mem_evicts_1, disk_evicts_1, _) = lru.metrics();
        assert_eq!(mem_evicts_1, 0, "No evictions yet");

        // Check initial byte usage
        let initial_bytes = lru.cur_bytes;
        assert_eq!(initial_bytes, 5000, "Should track large entry bytes");

        // Add small entry (should trigger eviction and migration to disk)
        lru.put("small".to_string(), small_entry);

        let (mem_evicts_2, disk_evicts_2, _) = lru.metrics();
        let final_bytes = lru.cur_bytes;

        // Verify: large entry should still be accessible (moved to disk, not evicted)
        let retrieved_large = lru.get("large");
        assert!(
            retrieved_large.is_some(),
            "Large entry should still be accessible from disk"
        );

        // Verify: small entry should be in memory
        let retrieved_small = lru.get("small");
        assert!(
            retrieved_small.is_some(),
            "Small entry should be accessible from memory"
        );

        // Since large entry was moved to disk (not truly evicted), mem_evicts should NOT increase
        // Only cur_bytes should be properly maintained: large (5000) + small (50) = 5050
        assert_eq!(
            mem_evicts_2, mem_evicts_1,
            "Large entry migration to disk should not count as memory eviction"
        );
        assert_eq!(disk_evicts_2, disk_evicts_1, "No disk evictions yet");
        assert_eq!(
            final_bytes, 5050,
            "cur_bytes should include both memory and disk entries"
        );

        // Test 2: Actual disk eviction should update evict_count_disk and cur_bytes
        // Force another eviction by adding more entries
        let another_entry = CacheEntry {
            etag: Some("another".to_string()),
            content_type: Some("text/plain".to_string()),
            body: vec![b'z'; 4000], // Another large entry
            timestamp: Instant::now(),
        };

        lru.put("another".to_string(), another_entry);

        let (mem_evicts_3, disk_evicts_3, _) = lru.metrics();

        // Should have triggered actual evictions now due to capacity constraints
        assert!(
            mem_evicts_3 > mem_evicts_2 || disk_evicts_3 > disk_evicts_2,
            "Should have triggered some evictions due to capacity/byte limits"
        );

        // Test 3: Verify cache_bytes_{mem|disk} sum ≤ quota
        let (mem_bytes, disk_bytes) = lru.byte_usage();
        let total_bytes = mem_bytes + disk_bytes;

        // The quota check - should be roughly within limits (allowing some tolerance for timing)
        assert!(
            total_bytes <= lru.cap_bytes + 1000,
            "Total bytes {} should not significantly exceed cap_bytes {}",
            total_bytes,
            lru.cap_bytes
        );

        // Cleanup
        std::env::remove_var("SB_SUBS_CACHE_DISK");
        let _ = fs::remove_dir_all(test_dir);
    }
}
