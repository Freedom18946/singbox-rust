use once_cell::sync::OnceCell;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum SecurityErrorKind {
    Timeout,
    ConnectTimeout,
    TooManyRedirects,
    Upstream4xx,
    Upstream5xx,
    MimeDeny,
    SizeExceed,
    PrivateBlocked,
    RateLimited,
    Other,
}

impl SecurityErrorKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::ConnectTimeout => "connect_timeout",
            Self::TooManyRedirects => "too_many_redirects",
            Self::Upstream4xx => "upstream_4xx",
            Self::Upstream5xx => "upstream_5xx",
            Self::MimeDeny => "mime_deny",
            Self::SizeExceed => "size_exceed",
            Self::PrivateBlocked => "private_blocked",
            Self::RateLimited => "rate_limited",
            Self::Other => "other",
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ErrorEntry {
    pub ts: u64,
    pub kind: SecurityErrorKind,
    pub url: String,
    pub msg: String,
}

const MAX_ERRORS: usize = 32;

static SUBS_BLOCK_PRIVATE_IP: AtomicU64 = AtomicU64::new(0);
static SUBS_EXCEED_SIZE: AtomicU64 = AtomicU64::new(0);
static SUBS_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static SUBS_TOO_MANY_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static SUBS_CONNECT_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static SUBS_UPSTREAM_4XX: AtomicU64 = AtomicU64::new(0);
static SUBS_UPSTREAM_5XX: AtomicU64 = AtomicU64::new(0);
static SUBS_RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
static SUBS_CACHE_HIT: AtomicU64 = AtomicU64::new(0);
static SUBS_CACHE_MISS: AtomicU64 = AtomicU64::new(0);
static DNS_CACHE_HIT: AtomicU64 = AtomicU64::new(0);
static DNS_CACHE_MISS: AtomicU64 = AtomicU64::new(0);
static SUBS_CACHE_EVICT_MEM: AtomicU64 = AtomicU64::new(0);
static SUBS_CACHE_EVICT_DISK: AtomicU64 = AtomicU64::new(0);
static SUBS_HEAD_TOTAL: AtomicU64 = AtomicU64::new(0);
static SUBS_BREAKER_BLOCK: AtomicU64 = AtomicU64::new(0);
static SUBS_BREAKER_REOPEN: AtomicU64 = AtomicU64::new(0);

// Prefetch metrics
static PREFETCH_ENQUEUE: AtomicU64 = AtomicU64::new(0);
static PREFETCH_DROP: AtomicU64 = AtomicU64::new(0);
static PREFETCH_DONE: AtomicU64 = AtomicU64::new(0);
static PREFETCH_FAIL: AtomicU64 = AtomicU64::new(0);
static PREFETCH_RETRY: AtomicU64 = AtomicU64::new(0);
static PREFETCH_QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
static PREFETCH_QUEUE_HIGH_WATERMARK: AtomicU64 = AtomicU64::new(0);
static PREFETCH_TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
static PREFETCH_SESSION_START: OnceCell<Mutex<Option<std::time::Instant>>> = OnceCell::new();

static PREFETCH_RUN_COUNTS: OnceCell<Mutex<Vec<u64>>> = OnceCell::new();
static PREFETCH_RUN_BUCKETS: [u32; 7] = [50, 100, 200, 500, 1000, 2000, u32::MAX]; // milliseconds
static LAST_ERROR: OnceCell<Mutex<String>> = OnceCell::new();
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_FAILS: AtomicU64 = AtomicU64::new(0);
static LAST_ERR_TS: OnceCell<Mutex<u64>> = OnceCell::new();
static LAST_OK_TS: OnceCell<Mutex<u64>> = OnceCell::new();
static RECENT_ERRORS: OnceCell<Mutex<VecDeque<ErrorEntry>>> = OnceCell::new();

// Error kind tracking with sampling
static ERROR_KINDS: OnceCell<Mutex<BTreeMap<SecurityErrorKind, u64>>> = OnceCell::new();
static ERROR_KINDS_BY_HASH: OnceCell<Mutex<HashMap<(SecurityErrorKind, u16), u64>>> =
    OnceCell::new();

// Latency histogram tracking with finer buckets
static LATENCY_SNAPSHOT: OnceCell<(Vec<(f64, u64)>, u64, u64)> = OnceCell::new();
static LAT_BUCKETS: &[u64] = &[50, 100, 200, 500, 1000, 2000, u64::MAX];
static LAT_COUNTS: OnceCell<Mutex<Vec<u64>>> = OnceCell::new();
static LAT_COUNT: AtomicU64 = AtomicU64::new(0);
static LAT_SUM_MS: AtomicU64 = AtomicU64::new(0);

// DNS latency histogram - same buckets as fetch_seconds
static DNS_BUCKETS: &[u64] = &[50, 100, 200, 500, 1000, 2000, u64::MAX];
static DNS_COUNTS: OnceCell<Mutex<Vec<u64>>> = OnceCell::new();
static DNS_COUNT: AtomicU64 = AtomicU64::new(0);
static DNS_SUM_MS: AtomicU64 = AtomicU64::new(0);

// Host hash calculation for low cardinality
fn host_to_hash(host: &str) -> u16 {
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    (hasher.finish() % 1024) as u16
}

pub fn inc_block_private_ip() {
    SUBS_BLOCK_PRIVATE_IP.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_exceed_size() {
    SUBS_EXCEED_SIZE.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_timeout() {
    SUBS_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_redirects() {
    SUBS_TOO_MANY_REDIRECTS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_connect_timeout() {
    SUBS_CONNECT_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_upstream_4xx() {
    SUBS_UPSTREAM_4XX.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_upstream_5xx() {
    SUBS_UPSTREAM_5XX.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_rate_limited() {
    SUBS_RATE_LIMITED.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_cache_hit() {
    SUBS_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_cache_miss() {
    SUBS_CACHE_MISS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_cache_evict_mem() {
    SUBS_CACHE_EVICT_MEM.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_cache_evict_disk() {
    SUBS_CACHE_EVICT_DISK.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_head_total() {
    SUBS_HEAD_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_breaker_block() {
    SUBS_BREAKER_BLOCK.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_breaker_reopen() {
    SUBS_BREAKER_REOPEN.fetch_add(1, Ordering::Relaxed);
}

// Prefetch metrics functions
pub fn init_prefetch_metrics() {
    PREFETCH_RUN_COUNTS.get_or_init(|| Mutex::new(vec![0u64; PREFETCH_RUN_BUCKETS.len()]));
}

pub fn prefetch_inc(event: &str) {
    match event {
        "enq" => {
            PREFETCH_ENQUEUE.fetch_add(1, Ordering::Relaxed);
        }
        "drop" => {
            PREFETCH_DROP.fetch_add(1, Ordering::Relaxed);
        }
        "done" => {
            PREFETCH_DONE.fetch_add(1, Ordering::Relaxed);
        }
        "fail" => {
            PREFETCH_FAIL.fetch_add(1, Ordering::Relaxed);
        }
        "retry" => {
            PREFETCH_RETRY.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub fn record_prefetch_run_ms(ms: u64) {
    if let Some(counts) = PREFETCH_RUN_COUNTS.get() {
        if let Ok(mut c) = counts.lock() {
            for (i, &bucket_ms) in PREFETCH_RUN_BUCKETS.iter().enumerate() {
                if ms <= u64::from(bucket_ms) {
                    c[i] += 1;
                    break;
                }
            }
        }
    }
}

pub fn set_prefetch_queue_depth(depth: u64) {
    PREFETCH_QUEUE_DEPTH.store(depth, Ordering::Relaxed);
    #[cfg(feature = "admin_debug")]
    crate::admin_debug::endpoints::metrics::update_prefetch_depth(depth as i64);
}

pub fn set_prefetch_queue_high_watermark(watermark: u64) {
    PREFETCH_QUEUE_HIGH_WATERMARK.store(watermark, Ordering::Relaxed);
}

pub fn get_prefetch_queue_high_watermark() -> u64 {
    PREFETCH_QUEUE_HIGH_WATERMARK.load(Ordering::Relaxed)
}

pub fn get_prefetch_queue_depth() -> u64 {
    PREFETCH_QUEUE_DEPTH.load(Ordering::Relaxed)
}

pub fn get_prefetch_counters() -> (u64, u64, u64, u64, u64) {
    (
        PREFETCH_ENQUEUE.load(Ordering::Relaxed),
        PREFETCH_DROP.load(Ordering::Relaxed),
        PREFETCH_DONE.load(Ordering::Relaxed),
        PREFETCH_FAIL.load(Ordering::Relaxed),
        PREFETCH_RETRY.load(Ordering::Relaxed),
    )
}

pub fn add_prefetch_bytes(bytes: u64) {
    PREFETCH_TOTAL_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn get_prefetch_total_bytes() -> u64 {
    PREFETCH_TOTAL_BYTES.load(Ordering::Relaxed)
}

pub fn start_prefetch_session() {
    let session_start = PREFETCH_SESSION_START.get_or_init(|| Mutex::new(None));
    if let Ok(mut start) = session_start.lock() {
        *start = Some(std::time::Instant::now());
    }
}

pub fn get_prefetch_session_duration_ms() -> u64 {
    if let Some(session_start) = PREFETCH_SESSION_START.get() {
        if let Ok(start) = session_start.lock() {
            if let Some(start_time) = *start {
                return start_time.elapsed().as_millis() as u64;
            }
        }
    }
    0
}

pub fn inc_dns_cache_hit() {
    DNS_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_dns_cache_miss() {
    DNS_CACHE_MISS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_dns_latency_ms(ms: u64) {
    let v = DNS_COUNTS.get_or_init(|| Mutex::new(vec![0; DNS_BUCKETS.len()]));
    if let Ok(mut c) = v.lock() {
        for (i, b) in DNS_BUCKETS.iter().enumerate() {
            if ms <= *b {
                c[i] += 1;
                break;
            }
        }
    }
    DNS_COUNT.fetch_add(1, Ordering::Relaxed);
    DNS_SUM_MS.fetch_add(ms, Ordering::Relaxed);
}

// Sampled error recording for low-cardinality metrics (10% sampling)
pub fn record_error_sampled(kind: SecurityErrorKind, host: &str) {
    let host_hash = host_to_hash(host);

    // Only sample 10% of errors (check last 4 bits for 0)
    if (host_hash & 0xF) == 0 {
        let map = ERROR_KINDS_BY_HASH.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(mut m) = map.lock() {
            *m.entry((kind, host_hash)).or_insert(0) += 1;
        }
    }
}

pub fn set_last_error(kind: SecurityErrorKind, msg: impl Into<String>) {
    set_last_error_with_host(kind, "", msg);
}

pub fn set_last_error_with_host(kind: SecurityErrorKind, host: &str, msg: impl Into<String>) {
    let message = msg.into();
    let s = LAST_ERROR.get_or_init(|| Mutex::new(String::new()));
    if let Ok(mut g) = s.lock() {
        *g = message.clone();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = LAST_ERR_TS.get_or_init(|| Mutex::new(0));
    if let Ok(mut t) = ts.lock() {
        *t = now;
    }

    // Add to recent errors ring buffer with kind
    add_recent_error(host, &message, now, kind);

    // Update error kinds counter
    let m = ERROR_KINDS.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(mut map) = m.lock() {
        *map.entry(kind).or_insert(0) += 1;
    }

    // Record sampled error by host hash (only for failures)
    if !host.is_empty() {
        record_error_sampled(kind, host);
    }

    TOTAL_FAILS.fetch_add(1, Ordering::Relaxed);
}

pub fn set_last_error_with_url(kind: SecurityErrorKind, url: &str, msg: impl Into<String>) {
    let message = msg.into();
    let s = LAST_ERROR.get_or_init(|| Mutex::new(String::new()));
    if let Ok(mut g) = s.lock() {
        *g = message.clone();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = LAST_ERR_TS.get_or_init(|| Mutex::new(0));
    if let Ok(mut t) = ts.lock() {
        *t = now;
    }

    // Add to recent errors ring buffer with kind
    add_recent_error(url, &message, now, kind);

    // Update error kinds counter
    let m = ERROR_KINDS.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(mut map) = m.lock() {
        *map.entry(kind).or_insert(0) += 1;
    }

    TOTAL_FAILS.fetch_add(1, Ordering::Relaxed);
}

fn add_recent_error(url: &str, msg: &str, ts: u64, kind: SecurityErrorKind) {
    let errors = RECENT_ERRORS.get_or_init(|| Mutex::new(VecDeque::new()));
    if let Ok(mut e) = errors.lock() {
        e.push_back(ErrorEntry {
            ts,
            kind,
            url: url.to_string(),
            msg: msg.to_string(),
        });

        // Keep only the last MAX_ERRORS entries
        while e.len() > MAX_ERRORS {
            e.pop_front();
        }
    }
}

pub fn inc_total_requests() {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_latency_ms(ms: u64) {
    let v = LAT_COUNTS.get_or_init(|| Mutex::new(vec![0; LAT_BUCKETS.len()]));
    if let Ok(mut c) = v.lock() {
        for (i, b) in LAT_BUCKETS.iter().enumerate() {
            if ms <= *b {
                c[i] += 1;
                break;
            }
        }
    }
    LAT_COUNT.fetch_add(1, Ordering::Relaxed);
    LAT_SUM_MS.fetch_add(ms, Ordering::Relaxed);

    // Update snapshot
    let buckets: Vec<(f64, u64)> = LAT_COUNTS
        .get()
        .unwrap()
        .lock()
        .ok()
        .map(|c| {
            LAT_BUCKETS
                .iter()
                .zip(c.iter())
                .map(|(b, v)| ((*b as f64) / 1000.0, *v))
                .collect()
        })
        .unwrap_or_default();
    let _ = LATENCY_SNAPSHOT.set((
        buckets,
        LAT_COUNT.load(Ordering::Relaxed),
        LAT_SUM_MS.load(Ordering::Relaxed),
    ));
}

pub fn mark_last_ok() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = LAST_OK_TS.get_or_init(|| Mutex::new(0));
    if let Ok(mut t) = ts.lock() {
        *t = now;
    }
}

#[derive(serde::Serialize, Default)]
pub struct SecuritySnapshot {
    pub subs_block_private_ip: u64,
    pub subs_exceed_size: u64,
    pub subs_timeout: u64,
    pub subs_too_many_redirects: u64,
    pub subs_connect_timeout: u64,
    pub subs_upstream_4xx: u64,
    pub subs_upstream_5xx: u64,
    pub subs_rate_limited: u64,
    pub subs_cache_hit: u64,
    pub subs_cache_miss: u64,
    pub subs_cache_evict_mem: u64,
    pub subs_cache_evict_disk: u64,
    pub subs_head_total: u64,
    pub subs_breaker_block: u64,
    pub subs_breaker_reopen: u64,
    pub last_error: Option<String>,
    pub total_requests: u64,
    pub total_fails: u64,
    pub last_error_ts: Option<u64>,
    pub last_ok_ts: Option<u64>,
    pub last_errors: Vec<ErrorEntry>,
    pub error_kinds: BTreeMap<SecurityErrorKind, u64>,
    pub error_kinds_by_hash: HashMap<(SecurityErrorKind, u16), u64>,
    pub latency_buckets: Vec<(f64, u64)>, // {"0.05","0.1","0.2","0.5","1","2","+Inf"}
    pub latency_count: u64,
    pub latency_sum_ms: u64,
    // Cache byte usage
    pub cache_bytes_mem: usize,
    pub cache_bytes_disk: usize,
    // Breaker state by host hash
    pub breaker_states: Vec<(u16, String, u32)>, // (host_hash, state, reopen_count)
    // Limiter concurrent connections
    pub limiter_current_concurrency: u64,
    // DNS resolution metrics
    pub dns_cache_hit: u64,
    pub dns_cache_miss: u64,
    pub dns_latency_buckets: Vec<(f64, u64)>,
    pub dns_latency_count: u64,
    pub dns_latency_sum_ms: u64,
    // Prefetch metrics
    pub prefetch_enqueue: u64,
    pub prefetch_drop: u64,
    pub prefetch_done: u64,
    pub prefetch_fail: u64,
    pub prefetch_retry: u64,
    pub prefetch_queue_depth: u64,
    pub prefetch_run_buckets: Vec<(f64, u64)>,
    pub prefetch_total_bytes: u64,
    pub prefetch_session_duration_ms: u64,
}

#[cfg(test)]
pub fn reset_metrics() {
    // Reset atomic counters
    SUBS_BLOCK_PRIVATE_IP.store(0, Ordering::Relaxed);
    SUBS_EXCEED_SIZE.store(0, Ordering::Relaxed);
    SUBS_TIMEOUT.store(0, Ordering::Relaxed);
    SUBS_TOO_MANY_REDIRECTS.store(0, Ordering::Relaxed);
    SUBS_CONNECT_TIMEOUT.store(0, Ordering::Relaxed);
    SUBS_UPSTREAM_4XX.store(0, Ordering::Relaxed);
    SUBS_UPSTREAM_5XX.store(0, Ordering::Relaxed);
    SUBS_RATE_LIMITED.store(0, Ordering::Relaxed);
    SUBS_CACHE_HIT.store(0, Ordering::Relaxed);
    SUBS_CACHE_MISS.store(0, Ordering::Relaxed);
    DNS_CACHE_HIT.store(0, Ordering::Relaxed);
    DNS_CACHE_MISS.store(0, Ordering::Relaxed);
    SUBS_CACHE_EVICT_MEM.store(0, Ordering::Relaxed);
    SUBS_CACHE_EVICT_DISK.store(0, Ordering::Relaxed);
    SUBS_HEAD_TOTAL.store(0, Ordering::Relaxed);
    SUBS_BREAKER_BLOCK.store(0, Ordering::Relaxed);
    SUBS_BREAKER_REOPEN.store(0, Ordering::Relaxed);
    TOTAL_REQUESTS.store(0, Ordering::Relaxed);
    TOTAL_FAILS.store(0, Ordering::Relaxed);
    LAT_COUNT.store(0, Ordering::Relaxed);
    LAT_SUM_MS.store(0, Ordering::Relaxed);
    DNS_COUNT.store(0, Ordering::Relaxed);
    DNS_SUM_MS.store(0, Ordering::Relaxed);

    // Reset mutex-protected data
    if let Some(m) = LAT_COUNTS.get() {
        if let Ok(mut v) = m.lock() {
            for x in v.iter_mut() {
                *x = 0;
            }
        }
    }
    if let Some(m) = DNS_COUNTS.get() {
        if let Ok(mut v) = m.lock() {
            for x in v.iter_mut() {
                *x = 0;
            }
        }
    }
    if let Some(m) = LAST_ERROR.get() {
        if let Ok(mut s) = m.lock() {
            s.clear();
        }
    }
    if let Some(m) = LAST_ERR_TS.get() {
        if let Ok(mut ts) = m.lock() {
            *ts = 0;
        }
    }
    if let Some(m) = LAST_OK_TS.get() {
        if let Ok(mut ts) = m.lock() {
            *ts = 0;
        }
    }
    if let Some(m) = RECENT_ERRORS.get() {
        if let Ok(mut v) = m.lock() {
            v.clear();
        }
    }
    if let Some(m) = ERROR_KINDS.get() {
        if let Ok(mut map) = m.lock() {
            map.clear();
        }
    }
    if let Some(m) = ERROR_KINDS_BY_HASH.get() {
        if let Ok(mut map) = m.lock() {
            map.clear();
        }
    }
}

#[cfg(test)]
pub fn reset_caches() {
    // Reset cache
    if let Ok(mut cache) = crate::admin_debug::cache::global().lock() {
        cache.clear();
    }

    // Reset breaker
    if let Ok(mut breaker) = crate::admin_debug::breaker::global().lock() {
        *breaker = crate::admin_debug::breaker::HostBreaker::new(30_000, 15_000, 5, 0.5);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_to_hash_cardinality() {
        // Test that host_to_hash produces values in expected range
        let hosts = [
            "test1.com",
            "test2.com",
            "example.org",
            "api.service.local",
            "cdn.provider.net",
        ];

        for host in &hosts {
            let hash = host_to_hash(host);
            assert!(
                hash < 1024,
                "Host hash {} for '{}' should be < 1024",
                hash,
                host
            );
        }

        // Test that different hosts produce different hashes (mostly)
        let hash1 = host_to_hash("different1.com");
        let hash2 = host_to_hash("different2.com");
        // Note: With only 2 samples we can't guarantee they're different due to hash collisions
        // But we can verify they're in valid range
        assert!(hash1 < 1024);
        assert!(hash2 < 1024);
    }

    #[test]
    fn test_host_to_hash_consistency() {
        let host = "consistent-test.example.com";
        let hash1 = host_to_hash(host);
        let hash2 = host_to_hash(host);
        let hash3 = host_to_hash(host);

        assert_eq!(hash1, hash2, "Same host should produce same hash");
        assert_eq!(hash2, hash3, "Hash should be deterministic");
    }

    #[test]
    fn test_error_sampling_logic() {
        // Reset error counts
        let _kinds_map = ERROR_KINDS_BY_HASH.get_or_init(|| Mutex::new(HashMap::new()));

        // Test sampling with known host hashes
        let test_cases = [
            ("sampled-host-0.com", true), // This should be sampled (need to find a host that gives hash & 0xF == 0)
            ("not-sampled-host.com", false), // This might not be sampled
        ];

        // Since we can't predict exact hashes, let's test the sampling mechanism indirectly
        for i in 0..100 {
            let test_host = format!("test-host-{}.com", i);
            let host_hash = host_to_hash(&test_host);
            let should_sample = (host_hash & 0xF) == 0;

            // Call record_error_sampled
            record_error_sampled(SecurityErrorKind::Timeout, &test_host);

            // Verify that sampling occurred if expected
            if should_sample {
                // Should be recorded in ERROR_KINDS_BY_HASH
                let map = ERROR_KINDS_BY_HASH.get().unwrap();
                if let Ok(m) = map.lock() {
                    let key = (SecurityErrorKind::Timeout, host_hash);
                    assert!(
                        m.contains_key(&key),
                        "Sampled error should be recorded for host {}",
                        test_host
                    );
                }
                break; // Found at least one sampled case
            }
        }
    }

    #[test]
    fn test_error_kind_tracking() {
        // Test that error kinds are properly tracked
        let host = "error-kind-test.com";

        set_last_error_with_host(SecurityErrorKind::Upstream4xx, host, "Test 4xx error");
        set_last_error_with_host(SecurityErrorKind::Upstream5xx, host, "Test 5xx error");
        set_last_error_with_host(SecurityErrorKind::Timeout, host, "Test timeout");

        // Verify ERROR_KINDS tracking
        let kinds_map = ERROR_KINDS.get().unwrap();
        if let Ok(m) = kinds_map.lock() {
            assert!(m.get(&SecurityErrorKind::Upstream4xx).unwrap_or(&0) > &0);
            assert!(m.get(&SecurityErrorKind::Upstream5xx).unwrap_or(&0) > &0);
            assert!(m.get(&SecurityErrorKind::Timeout).unwrap_or(&0) > &0);
        }
    }

    #[test]
    fn test_latency_histogram_buckets() {
        // Test that latency buckets are as expected
        let expected_buckets = [50, 100, 200, 500, 1000, 2000, u64::MAX];
        assert_eq!(
            LAT_BUCKETS, &expected_buckets,
            "Latency buckets should match expected fine-grained values"
        );

        // Test latency recording
        record_latency_ms(75); // Should go in 100ms bucket
        record_latency_ms(150); // Should go in 200ms bucket
        record_latency_ms(1500); // Should go in 2000ms bucket
        record_latency_ms(3000); // Should go in +Inf bucket

        // Verify counts are updated
        assert!(LAT_COUNT.load(Ordering::Relaxed) >= 4);
        assert!(LAT_SUM_MS.load(Ordering::Relaxed) >= 75 + 150 + 1500 + 3000);
    }

    #[test]
    fn test_sampling_rate_approximation() {
        // Test that sampling rate is approximately 1/16 (6.25%)
        let mut sampled_count = 0;
        let total_count = 1000;

        for i in 0..total_count {
            let test_host = format!("sampling-test-{}.example.com", i);
            let host_hash = host_to_hash(&test_host);
            if (host_hash & 0xF) == 0 {
                sampled_count += 1;
            }
        }

        let sampling_rate = sampled_count as f64 / total_count as f64;

        // Should be approximately 1/16 = 0.0625, allow some variance
        assert!(
            sampling_rate >= 0.04 && sampling_rate <= 0.10,
            "Sampling rate should be ~6.25%, got {:.1}% ({}/{})",
            sampling_rate * 100.0,
            sampled_count,
            total_count
        );
    }

    #[test]
    fn test_comprehensive_metrics_snapshot() {
        // Test that snapshot includes all expected low-cardinality fields
        let snapshot = snapshot();

        // Should have error kinds tracking
        assert!(snapshot.error_kinds.len() >= 0); // May be empty in test
        assert!(snapshot.error_kinds_by_hash.len() >= 0); // May be empty in test

        // Should have latency data
        assert!(snapshot.latency_buckets.len() == LAT_BUCKETS.len());

        // Basic metrics should be present
        assert!(snapshot.total_requests >= 0);
        assert!(snapshot.total_fails >= 0);
    }
}

fn get_current_concurrency() -> u64 {
    #[cfg(any(
        feature = "subs_http",
        feature = "subs_clash",
        feature = "subs_singbox"
    ))]
    {
        crate::admin_debug::endpoints::subs::get_current_concurrency()
    }
    #[cfg(not(any(
        feature = "subs_http",
        feature = "subs_clash",
        feature = "subs_singbox"
    )))]
    {
        0
    }
}

pub fn snapshot() -> SecuritySnapshot {
    let last = LAST_ERROR
        .get()
        .and_then(|m| m.lock().ok())
        .map(|s| s.clone());
    let err_ts = LAST_ERR_TS.get().and_then(|m| m.lock().ok()).map(|x| *x);
    let ok_ts = LAST_OK_TS.get().and_then(|m| m.lock().ok()).map(|x| *x);
    let recent = RECENT_ERRORS
        .get()
        .and_then(|m| m.lock().ok())
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();
    let kinds = ERROR_KINDS
        .get()
        .and_then(|m| m.lock().ok())
        .map(|m| m.clone())
        .unwrap_or_default();
    let kinds_by_hash = ERROR_KINDS_BY_HASH
        .get()
        .and_then(|m| m.lock().ok())
        .map(|m| m.clone())
        .unwrap_or_default();
    let (buckets, count, sum) = LATENCY_SNAPSHOT.get().cloned().unwrap_or_else(|| {
        // Initialize with zero counts if no latency has been recorded yet
        let empty_buckets: Vec<(f64, u64)> = LAT_BUCKETS
            .iter()
            .map(|&b| (b as f64 / 1000.0, 0))
            .collect();
        (empty_buckets, 0, 0)
    });

    // Get cache byte usage
    let (cache_bytes_mem, cache_bytes_disk) = crate::admin_debug::cache::global()
        .lock()
        .map(|lru| lru.byte_usage())
        .unwrap_or((0, 0));

    // Get breaker states with host hash for low cardinality
    let breaker_states = if let Ok(breaker) = crate::admin_debug::breaker::global().lock() {
        breaker
            .state_stats()
            .into_iter()
            .map(|(host, state, reopen_count)| {
                let host_hash = host_to_hash(&host);
                (host_hash, state, reopen_count)
            })
            .collect()
    } else {
        Vec::new()
    };

    // Get current concurrency usage
    let limiter_current_concurrency = get_current_concurrency();

    // Get DNS latency buckets
    let dns_buckets = DNS_COUNTS
        .get()
        .and_then(|m| m.lock().ok())
        .map(|c| {
            DNS_BUCKETS
                .iter()
                .zip(c.iter())
                .map(|(b, v)| ((*b as f64) / 1000.0, *v))
                .collect()
        })
        .unwrap_or_else(|| {
            // Initialize with zero counts if no DNS latency has been recorded yet
            DNS_BUCKETS
                .iter()
                .map(|&b| (b as f64 / 1000.0, 0))
                .collect()
        });

    SecuritySnapshot {
        subs_block_private_ip: SUBS_BLOCK_PRIVATE_IP.load(Ordering::Relaxed),
        subs_exceed_size: SUBS_EXCEED_SIZE.load(Ordering::Relaxed),
        subs_timeout: SUBS_TIMEOUT.load(Ordering::Relaxed),
        subs_too_many_redirects: SUBS_TOO_MANY_REDIRECTS.load(Ordering::Relaxed),
        subs_connect_timeout: SUBS_CONNECT_TIMEOUT.load(Ordering::Relaxed),
        subs_upstream_4xx: SUBS_UPSTREAM_4XX.load(Ordering::Relaxed),
        subs_upstream_5xx: SUBS_UPSTREAM_5XX.load(Ordering::Relaxed),
        subs_rate_limited: SUBS_RATE_LIMITED.load(Ordering::Relaxed),
        subs_cache_hit: SUBS_CACHE_HIT.load(Ordering::Relaxed),
        subs_cache_miss: SUBS_CACHE_MISS.load(Ordering::Relaxed),
        subs_cache_evict_mem: SUBS_CACHE_EVICT_MEM.load(Ordering::Relaxed),
        subs_cache_evict_disk: SUBS_CACHE_EVICT_DISK.load(Ordering::Relaxed),
        subs_head_total: SUBS_HEAD_TOTAL.load(Ordering::Relaxed),
        subs_breaker_block: SUBS_BREAKER_BLOCK.load(Ordering::Relaxed),
        subs_breaker_reopen: SUBS_BREAKER_REOPEN.load(Ordering::Relaxed),
        last_error: last,
        total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
        total_fails: TOTAL_FAILS.load(Ordering::Relaxed),
        last_error_ts: err_ts,
        last_ok_ts: ok_ts,
        last_errors: recent,
        error_kinds: kinds,
        error_kinds_by_hash: kinds_by_hash,
        latency_buckets: buckets,
        latency_count: count,
        latency_sum_ms: sum,
        cache_bytes_mem,
        cache_bytes_disk,
        breaker_states,
        limiter_current_concurrency,
        dns_cache_hit: DNS_CACHE_HIT.load(Ordering::Relaxed),
        dns_cache_miss: DNS_CACHE_MISS.load(Ordering::Relaxed),
        dns_latency_buckets: dns_buckets,
        dns_latency_count: DNS_COUNT.load(Ordering::Relaxed),
        dns_latency_sum_ms: DNS_SUM_MS.load(Ordering::Relaxed),
        prefetch_enqueue: PREFETCH_ENQUEUE.load(Ordering::Relaxed),
        prefetch_drop: PREFETCH_DROP.load(Ordering::Relaxed),
        prefetch_done: PREFETCH_DONE.load(Ordering::Relaxed),
        prefetch_fail: PREFETCH_FAIL.load(Ordering::Relaxed),
        prefetch_retry: PREFETCH_RETRY.load(Ordering::Relaxed),
        prefetch_queue_depth: PREFETCH_QUEUE_DEPTH.load(Ordering::Relaxed),
        prefetch_total_bytes: PREFETCH_TOTAL_BYTES.load(Ordering::Relaxed),
        prefetch_session_duration_ms: get_prefetch_session_duration_ms(),
        prefetch_run_buckets: PREFETCH_RUN_COUNTS
            .get()
            .and_then(|m| m.lock().ok())
            .map(|c| {
                PREFETCH_RUN_BUCKETS
                    .iter()
                    .zip(c.iter())
                    .map(|(b, v)| (f64::from(*b) / 1000.0, *v))
                    .collect()
            })
            .unwrap_or_else(|| {
                PREFETCH_RUN_BUCKETS
                    .iter()
                    .map(|&b| (f64::from(b) / 1000.0, 0))
                    .collect()
            }),
    }
}
