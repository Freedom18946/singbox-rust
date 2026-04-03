use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::sync::{Arc, LazyLock, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

#[derive(Serialize, Default)]
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
    pub latency_buckets: Vec<(f64, u64)>,
    pub latency_count: u64,
    pub latency_sum_ms: u64,
    pub cache_bytes_mem: usize,
    pub cache_bytes_disk: usize,
    pub breaker_states: Vec<(u16, String, u32)>,
    pub limiter_current_concurrency: u64,
    pub dns_cache_hit: u64,
    pub dns_cache_miss: u64,
    pub dns_latency_buckets: Vec<(f64, u64)>,
    pub dns_latency_count: u64,
    pub dns_latency_sum_ms: u64,
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

const MAX_ERRORS: usize = 32;
const PREFETCH_RUN_BUCKETS: [u32; 7] = [50, 100, 200, 500, 1000, 2000, u32::MAX];
const LAT_BUCKETS: &[u64] = &[50, 100, 200, 500, 1000, 2000, u64::MAX];
const DNS_BUCKETS: &[u64] = &[50, 100, 200, 500, 1000, 2000, u64::MAX];

static DEFAULT_STATE: LazyLock<StdMutex<Weak<SecurityMetricsState>>> =
    LazyLock::new(|| StdMutex::new(Weak::new()));

#[derive(Default)]
pub struct SecurityMetricsState {
    subs_block_private_ip: AtomicU64,
    subs_exceed_size: AtomicU64,
    subs_timeout: AtomicU64,
    subs_too_many_redirects: AtomicU64,
    subs_connect_timeout: AtomicU64,
    subs_upstream_4xx: AtomicU64,
    subs_upstream_5xx: AtomicU64,
    subs_rate_limited: AtomicU64,
    subs_cache_hit: AtomicU64,
    subs_cache_miss: AtomicU64,
    dns_cache_hit: AtomicU64,
    dns_cache_miss: AtomicU64,
    subs_cache_evict_mem: AtomicU64,
    subs_cache_evict_disk: AtomicU64,
    subs_head_total: AtomicU64,
    subs_breaker_block: AtomicU64,
    subs_breaker_reopen: AtomicU64,
    prefetch_enqueue: AtomicU64,
    prefetch_drop: AtomicU64,
    prefetch_done: AtomicU64,
    prefetch_fail: AtomicU64,
    prefetch_retry: AtomicU64,
    prefetch_queue_depth: AtomicU64,
    prefetch_queue_high_watermark: AtomicU64,
    prefetch_total_bytes: AtomicU64,
    total_requests: AtomicU64,
    total_fails: AtomicU64,
    lat_count: AtomicU64,
    lat_sum_ms: AtomicU64,
    dns_count: AtomicU64,
    dns_sum_ms: AtomicU64,
    prefetch_session_start: Mutex<Option<Instant>>,
    prefetch_run_counts: Mutex<Vec<u64>>,
    last_error: Mutex<Option<String>>,
    last_err_ts: Mutex<Option<u64>>,
    last_ok_ts: Mutex<Option<u64>>,
    recent_errors: Mutex<VecDeque<ErrorEntry>>,
    error_kinds: Mutex<BTreeMap<SecurityErrorKind, u64>>,
    error_kinds_by_hash: Mutex<HashMap<(SecurityErrorKind, u16), u64>>,
    lat_counts: Mutex<Vec<u64>>,
    dns_counts: Mutex<Vec<u64>>,
}

impl SecurityMetricsState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefetch_run_counts: Mutex::new(vec![0; PREFETCH_RUN_BUCKETS.len()]),
            lat_counts: Mutex::new(vec![0; LAT_BUCKETS.len()]),
            dns_counts: Mutex::new(vec![0; DNS_BUCKETS.len()]),
            ..Self::default()
        }
    }

    pub fn inc_block_private_ip(&self) {
        self.subs_block_private_ip.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_exceed_size(&self) {
        self.subs_exceed_size.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_timeout(&self) {
        self.subs_timeout.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_redirects(&self) {
        self.subs_too_many_redirects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_connect_timeout(&self) {
        self.subs_connect_timeout.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_upstream_4xx(&self) {
        self.subs_upstream_4xx.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_upstream_5xx(&self) {
        self.subs_upstream_5xx.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rate_limited(&self) {
        self.subs_rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_hit(&self) {
        self.subs_cache_hit.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_miss(&self) {
        self.subs_cache_miss.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_evict_mem(&self) {
        self.subs_cache_evict_mem.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cache_evict_disk(&self) {
        self.subs_cache_evict_disk.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_head_total(&self) {
        self.subs_head_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_breaker_block(&self) {
        self.subs_breaker_block.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_breaker_reopen(&self) {
        self.subs_breaker_reopen.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_total_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dns_cache_hit(&self) {
        self.dns_cache_hit.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dns_cache_miss(&self) {
        self.dns_cache_miss.fetch_add(1, Ordering::Relaxed);
    }

    pub const fn init_prefetch_metrics(&self) {
        let _ = &self.prefetch_run_counts;
    }

    pub fn prefetch_inc(&self, event: &str) {
        match event {
            "enq" => {
                self.prefetch_enqueue.fetch_add(1, Ordering::Relaxed);
            }
            "drop" => {
                self.prefetch_drop.fetch_add(1, Ordering::Relaxed);
            }
            "done" => {
                self.prefetch_done.fetch_add(1, Ordering::Relaxed);
            }
            "fail" => {
                self.prefetch_fail.fetch_add(1, Ordering::Relaxed);
            }
            "retry" => {
                self.prefetch_retry.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_prefetch_run_ms(&self, ms: u64) {
        let mut counts = self.prefetch_run_counts.lock();
        for (idx, bucket_ms) in PREFETCH_RUN_BUCKETS.iter().enumerate() {
            if ms <= u64::from(*bucket_ms) {
                counts[idx] += 1;
                break;
            }
        }
    }

    pub fn set_prefetch_queue_depth(&self, depth: u64) {
        self.prefetch_queue_depth.store(depth, Ordering::Relaxed);
    }

    #[must_use]
    pub fn get_prefetch_queue_depth(&self) -> u64 {
        self.prefetch_queue_depth.load(Ordering::Relaxed)
    }

    pub fn set_prefetch_queue_high_watermark(&self, watermark: u64) {
        self.prefetch_queue_high_watermark
            .store(watermark, Ordering::Relaxed);
    }

    #[must_use]
    pub fn get_prefetch_queue_high_watermark(&self) -> u64 {
        self.prefetch_queue_high_watermark.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn get_prefetch_counters(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.prefetch_enqueue.load(Ordering::Relaxed),
            self.prefetch_drop.load(Ordering::Relaxed),
            self.prefetch_done.load(Ordering::Relaxed),
            self.prefetch_fail.load(Ordering::Relaxed),
            self.prefetch_retry.load(Ordering::Relaxed),
        )
    }

    pub fn add_prefetch_bytes(&self, bytes: u64) {
        self.prefetch_total_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    #[must_use]
    pub fn get_prefetch_total_bytes(&self) -> u64 {
        self.prefetch_total_bytes.load(Ordering::Relaxed)
    }

    pub fn start_prefetch_session(&self) {
        *self.prefetch_session_start.lock() = Some(Instant::now());
    }

    #[must_use]
    pub fn get_prefetch_session_duration_ms(&self) -> u64 {
        self.prefetch_session_start
            .lock()
            .as_ref()
            .map_or(0, |started| started.elapsed().as_millis() as u64)
    }

    pub fn record_dns_latency_ms(&self, ms: u64) {
        let mut counts = self.dns_counts.lock();
        for (idx, bucket) in DNS_BUCKETS.iter().enumerate() {
            if ms <= *bucket {
                counts[idx] += 1;
                break;
            }
        }
        self.dns_count.fetch_add(1, Ordering::Relaxed);
        self.dns_sum_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn set_last_error(&self, kind: SecurityErrorKind, msg: impl Into<String>) {
        self.set_last_error_with_host(kind, "", msg);
    }

    pub fn set_last_error_with_host(
        &self,
        kind: SecurityErrorKind,
        host: &str,
        msg: impl Into<String>,
    ) {
        let message = msg.into();
        *self.last_error.lock() = Some(message.clone());
        let now = current_ts();
        *self.last_err_ts.lock() = Some(now);

        self.add_recent_error(host, &message, now, kind);
        *self.error_kinds.lock().entry(kind).or_insert(0) += 1;
        if !host.is_empty() {
            self.record_error_sampled(kind, host);
        }
        self.total_fails.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_last_error_with_url(
        &self,
        kind: SecurityErrorKind,
        url: &str,
        msg: impl Into<String>,
    ) {
        self.set_last_error_with_host(kind, url, msg);
    }

    pub fn mark_last_ok(&self) {
        *self.last_ok_ts.lock() = Some(current_ts());
    }

    pub fn record_latency_ms(&self, ms: u64) {
        let mut counts = self.lat_counts.lock();
        for (idx, bucket) in LAT_BUCKETS.iter().enumerate() {
            if ms <= *bucket {
                counts[idx] += 1;
                break;
            }
        }
        self.lat_count.fetch_add(1, Ordering::Relaxed);
        self.lat_sum_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// # Errors
    /// Returns an error when dependent admin subsystems cannot be inspected.
    pub fn snapshot(&self) -> Result<SecuritySnapshot> {
        self.snapshot_with_query(SecuritySnapshotQuery::compat())
    }

    /// # Errors
    /// Returns an error when the supplied control-plane owners cannot be
    /// inspected while building the snapshot.
    pub fn snapshot_with_control_plane(
        &self,
        cache: &crate::admin_debug::cache::CacheStore,
        breaker: &crate::admin_debug::breaker::BreakerStore,
        current_concurrency: u64,
    ) -> Result<SecuritySnapshot> {
        self.snapshot_with_query(SecuritySnapshotQuery::new(
            cache,
            breaker,
            current_concurrency,
        ))
    }

    /// # Errors
    /// Returns an error when dependent admin subsystems cannot be inspected.
    pub fn snapshot_with_query(
        &self,
        query: SecuritySnapshotQuery<'_>,
    ) -> Result<SecuritySnapshot> {
        let last_error = self.last_error.lock().clone();
        let last_error_ts = *self.last_err_ts.lock();
        let last_ok_ts = *self.last_ok_ts.lock();
        let last_errors = self.recent_errors.lock().iter().cloned().collect();
        let error_kinds = self.error_kinds.lock().clone();
        let error_kinds_by_hash = self.error_kinds_by_hash.lock().clone();
        let latency_buckets = self.histogram_pairs(LAT_BUCKETS, &self.lat_counts.lock());
        let dns_latency_buckets = self.histogram_pairs(DNS_BUCKETS, &self.dns_counts.lock());
        let prefetch_run_buckets =
            self.histogram_pairs_u32(&PREFETCH_RUN_BUCKETS, &self.prefetch_run_counts.lock());

        let (cache_bytes_mem, cache_bytes_disk) = query.cache.byte_usage_snapshot()?;

        let breaker_states = query
            .breaker
            .state_stats_snapshot()?
            .into_iter()
            .map(|(host, state, reopen_count)| (host_to_hash(&host), state, reopen_count))
            .collect();

        Ok(SecuritySnapshot {
            subs_block_private_ip: self.subs_block_private_ip.load(Ordering::Relaxed),
            subs_exceed_size: self.subs_exceed_size.load(Ordering::Relaxed),
            subs_timeout: self.subs_timeout.load(Ordering::Relaxed),
            subs_too_many_redirects: self.subs_too_many_redirects.load(Ordering::Relaxed),
            subs_connect_timeout: self.subs_connect_timeout.load(Ordering::Relaxed),
            subs_upstream_4xx: self.subs_upstream_4xx.load(Ordering::Relaxed),
            subs_upstream_5xx: self.subs_upstream_5xx.load(Ordering::Relaxed),
            subs_rate_limited: self.subs_rate_limited.load(Ordering::Relaxed),
            subs_cache_hit: self.subs_cache_hit.load(Ordering::Relaxed),
            subs_cache_miss: self.subs_cache_miss.load(Ordering::Relaxed),
            subs_cache_evict_mem: self.subs_cache_evict_mem.load(Ordering::Relaxed),
            subs_cache_evict_disk: self.subs_cache_evict_disk.load(Ordering::Relaxed),
            subs_head_total: self.subs_head_total.load(Ordering::Relaxed),
            subs_breaker_block: self.subs_breaker_block.load(Ordering::Relaxed),
            subs_breaker_reopen: self.subs_breaker_reopen.load(Ordering::Relaxed),
            last_error,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_fails: self.total_fails.load(Ordering::Relaxed),
            last_error_ts,
            last_ok_ts,
            last_errors,
            error_kinds,
            error_kinds_by_hash,
            latency_buckets,
            latency_count: self.lat_count.load(Ordering::Relaxed),
            latency_sum_ms: self.lat_sum_ms.load(Ordering::Relaxed),
            cache_bytes_mem,
            cache_bytes_disk,
            breaker_states,
            limiter_current_concurrency: query.current_concurrency,
            dns_cache_hit: self.dns_cache_hit.load(Ordering::Relaxed),
            dns_cache_miss: self.dns_cache_miss.load(Ordering::Relaxed),
            dns_latency_buckets,
            dns_latency_count: self.dns_count.load(Ordering::Relaxed),
            dns_latency_sum_ms: self.dns_sum_ms.load(Ordering::Relaxed),
            prefetch_enqueue: self.prefetch_enqueue.load(Ordering::Relaxed),
            prefetch_drop: self.prefetch_drop.load(Ordering::Relaxed),
            prefetch_done: self.prefetch_done.load(Ordering::Relaxed),
            prefetch_fail: self.prefetch_fail.load(Ordering::Relaxed),
            prefetch_retry: self.prefetch_retry.load(Ordering::Relaxed),
            prefetch_queue_depth: self.prefetch_queue_depth.load(Ordering::Relaxed),
            prefetch_run_buckets,
            prefetch_total_bytes: self.prefetch_total_bytes.load(Ordering::Relaxed),
            prefetch_session_duration_ms: self.get_prefetch_session_duration_ms(),
        })
    }

    #[cfg(test)]
    pub fn reset_metrics(&self) {
        for counter in [
            &self.subs_block_private_ip,
            &self.subs_exceed_size,
            &self.subs_timeout,
            &self.subs_too_many_redirects,
            &self.subs_connect_timeout,
            &self.subs_upstream_4xx,
            &self.subs_upstream_5xx,
            &self.subs_rate_limited,
            &self.subs_cache_hit,
            &self.subs_cache_miss,
            &self.dns_cache_hit,
            &self.dns_cache_miss,
            &self.subs_cache_evict_mem,
            &self.subs_cache_evict_disk,
            &self.subs_head_total,
            &self.subs_breaker_block,
            &self.subs_breaker_reopen,
            &self.prefetch_enqueue,
            &self.prefetch_drop,
            &self.prefetch_done,
            &self.prefetch_fail,
            &self.prefetch_retry,
            &self.prefetch_queue_depth,
            &self.prefetch_queue_high_watermark,
            &self.prefetch_total_bytes,
            &self.total_requests,
            &self.total_fails,
            &self.lat_count,
            &self.lat_sum_ms,
            &self.dns_count,
            &self.dns_sum_ms,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        *self.prefetch_session_start.lock() = None;
        self.prefetch_run_counts.lock().fill(0);
        *self.last_error.lock() = None;
        *self.last_err_ts.lock() = None;
        *self.last_ok_ts.lock() = None;
        self.recent_errors.lock().clear();
        self.error_kinds.lock().clear();
        self.error_kinds_by_hash.lock().clear();
        self.lat_counts.lock().fill(0);
        self.dns_counts.lock().fill(0);
    }

    fn add_recent_error(&self, url: &str, msg: &str, ts: u64, kind: SecurityErrorKind) {
        let mut errors = self.recent_errors.lock();
        errors.push_back(ErrorEntry {
            ts,
            kind,
            url: url.to_string(),
            msg: msg.to_string(),
        });
        while errors.len() > MAX_ERRORS {
            errors.pop_front();
        }
    }

    fn record_error_sampled(&self, kind: SecurityErrorKind, host: &str) {
        let host_hash = host_to_hash(host);
        if (host_hash & 0xF) == 0 {
            *self
                .error_kinds_by_hash
                .lock()
                .entry((kind, host_hash))
                .or_insert(0) += 1;
        }
    }

    fn histogram_pairs(&self, buckets: &[u64], counts: &[u64]) -> Vec<(f64, u64)> {
        buckets
            .iter()
            .zip(counts.iter())
            .map(|(bucket, value)| ((*bucket as f64) / 1000.0, *value))
            .collect()
    }

    fn histogram_pairs_u32(&self, buckets: &[u32], counts: &[u64]) -> Vec<(f64, u64)> {
        buckets
            .iter()
            .zip(counts.iter())
            .map(|(bucket, value)| (f64::from(*bucket) / 1000.0, *value))
            .collect()
    }
}

pub struct SecuritySnapshotQuery<'a> {
    cache: &'a crate::admin_debug::cache::CacheStore,
    breaker: &'a crate::admin_debug::breaker::BreakerStore,
    current_concurrency: u64,
}

impl<'a> SecuritySnapshotQuery<'a> {
    #[must_use]
    pub const fn new(
        cache: &'a crate::admin_debug::cache::CacheStore,
        breaker: &'a crate::admin_debug::breaker::BreakerStore,
        current_concurrency: u64,
    ) -> Self {
        Self {
            cache,
            breaker,
            current_concurrency,
        }
    }
}

impl SecuritySnapshotQuery<'static> {
    #[must_use]
    fn compat() -> Self {
        Self {
            cache: crate::admin_debug::cache::default_owner_ref(),
            breaker: crate::admin_debug::breaker::default_owner_ref(),
            current_concurrency: current_concurrency(),
        }
    }
}

#[must_use]
pub fn install_default(state: Arc<SecurityMetricsState>) -> Arc<SecurityMetricsState> {
    let mut slot = DEFAULT_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.upgrade() {
        Some(existing) => existing,
        None => {
            *slot = Arc::downgrade(&state);
            state
        }
    }
}

fn current() -> Result<Arc<SecurityMetricsState>> {
    DEFAULT_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .upgrade()
        .context("security metrics state has not been installed")
}

#[must_use]
pub(crate) fn current_owner() -> Option<Arc<SecurityMetricsState>> {
    DEFAULT_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .upgrade()
}

#[must_use]
fn host_to_hash(host: &str) -> u16 {
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    (hasher.finish() % 1024) as u16
}

fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

#[must_use]
pub(crate) fn current_concurrency() -> u64 {
    get_current_concurrency()
}

fn with_current(f: impl FnOnce(&SecurityMetricsState)) {
    if let Some(state) = current_owner() {
        f(&state);
    }
}

fn map_current<T>(f: impl FnOnce(&SecurityMetricsState) -> T, default: T) -> T {
    current_owner().map_or(default, |state| f(&state))
}

pub fn inc_block_private_ip() {
    with_current(SecurityMetricsState::inc_block_private_ip);
}
pub fn inc_exceed_size() {
    with_current(SecurityMetricsState::inc_exceed_size);
}
pub fn inc_timeout() {
    with_current(SecurityMetricsState::inc_timeout);
}
pub fn inc_redirects() {
    with_current(SecurityMetricsState::inc_redirects);
}
pub fn inc_connect_timeout() {
    with_current(SecurityMetricsState::inc_connect_timeout);
}
pub fn inc_upstream_4xx() {
    with_current(SecurityMetricsState::inc_upstream_4xx);
}
pub fn inc_upstream_5xx() {
    with_current(SecurityMetricsState::inc_upstream_5xx);
}
pub fn inc_rate_limited() {
    with_current(SecurityMetricsState::inc_rate_limited);
}
pub fn inc_cache_hit() {
    with_current(SecurityMetricsState::inc_cache_hit);
}
pub fn inc_cache_miss() {
    with_current(SecurityMetricsState::inc_cache_miss);
}
pub fn inc_cache_evict_mem() {
    with_current(SecurityMetricsState::inc_cache_evict_mem);
}
pub fn inc_cache_evict_disk() {
    with_current(SecurityMetricsState::inc_cache_evict_disk);
}
pub fn inc_head_total() {
    with_current(SecurityMetricsState::inc_head_total);
}
pub fn inc_breaker_block() {
    with_current(SecurityMetricsState::inc_breaker_block);
}
pub fn inc_breaker_reopen() {
    with_current(SecurityMetricsState::inc_breaker_reopen);
}
pub fn init_prefetch_metrics() {
    with_current(SecurityMetricsState::init_prefetch_metrics);
}
pub fn prefetch_inc(event: &str) {
    with_current(|s| s.prefetch_inc(event));
}
pub fn record_prefetch_run_ms(ms: u64) {
    with_current(|s| s.record_prefetch_run_ms(ms));
}
pub fn set_prefetch_queue_depth(depth: u64) {
    with_current(|s| s.set_prefetch_queue_depth(depth));
}
#[must_use]
pub fn get_prefetch_queue_depth() -> u64 {
    map_current(SecurityMetricsState::get_prefetch_queue_depth, 0)
}
pub fn set_prefetch_queue_high_watermark(watermark: u64) {
    with_current(|s| s.set_prefetch_queue_high_watermark(watermark));
}
#[must_use]
pub fn get_prefetch_queue_high_watermark() -> u64 {
    map_current(SecurityMetricsState::get_prefetch_queue_high_watermark, 0)
}
#[must_use]
pub fn get_prefetch_counters() -> (u64, u64, u64, u64, u64) {
    map_current(SecurityMetricsState::get_prefetch_counters, (0, 0, 0, 0, 0))
}
pub fn add_prefetch_bytes(bytes: u64) {
    with_current(|s| s.add_prefetch_bytes(bytes));
}
#[must_use]
pub fn get_prefetch_session_duration_ms() -> u64 {
    map_current(SecurityMetricsState::get_prefetch_session_duration_ms, 0)
}
#[must_use]
pub fn get_prefetch_total_bytes() -> u64 {
    map_current(SecurityMetricsState::get_prefetch_total_bytes, 0)
}
pub fn start_prefetch_session() {
    with_current(SecurityMetricsState::start_prefetch_session);
}
pub fn inc_dns_cache_hit() {
    with_current(SecurityMetricsState::inc_dns_cache_hit);
}
pub fn inc_dns_cache_miss() {
    with_current(SecurityMetricsState::inc_dns_cache_miss);
}
pub fn record_dns_latency_ms(ms: u64) {
    with_current(|s| s.record_dns_latency_ms(ms));
}
pub fn set_last_error(kind: SecurityErrorKind, msg: impl Into<String>) {
    with_current(|s| s.set_last_error(kind, msg));
}
pub fn set_last_error_with_host(kind: SecurityErrorKind, host: &str, msg: impl Into<String>) {
    with_current(|s| s.set_last_error_with_host(kind, host, msg));
}
pub fn set_last_error_with_url(kind: SecurityErrorKind, url: &str, msg: impl Into<String>) {
    with_current(|s| s.set_last_error_with_url(kind, url, msg));
}
pub fn inc_total_requests() {
    with_current(SecurityMetricsState::inc_total_requests);
}
pub fn record_latency_ms(ms: u64) {
    with_current(|s| s.record_latency_ms(ms));
}
pub fn mark_last_ok() {
    with_current(SecurityMetricsState::mark_last_ok);
}
pub fn snapshot() -> Result<SecuritySnapshot> {
    compat_snapshot()
}

/// # Errors
/// Returns an error when the current default security metrics owner has not
/// been installed or its compat control-plane query cannot be built.
pub fn compat_snapshot() -> Result<SecuritySnapshot> {
    current()?.snapshot()
}

#[cfg(test)]
pub fn reset_metrics() {
    if let Ok(state) = current() {
        state.reset_metrics();
    }
}

#[cfg(test)]
pub fn reset_caches() {
    crate::admin_debug::cache::default_owner_ref().reset();
    crate::admin_debug::breaker::default_owner_ref().reset();
}

#[cfg(test)]
pub(crate) fn clear_default_for_test() {
    let mut slot = DEFAULT_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Weak::new();
}

#[cfg(test)]
#[cfg(feature = "admin_tests")]
mod tests {
    use super::*;
    use std::time::Instant;

    fn install_test_state() -> Arc<SecurityMetricsState> {
        let state = Arc::new(SecurityMetricsState::new());
        let _ = install_default(Arc::clone(&state));
        state.reset_metrics();
        state
    }

    #[test]
    fn test_host_to_hash_cardinality() {
        for host in [
            "test1.com",
            "test2.com",
            "example.org",
            "api.service.local",
            "cdn.provider.net",
        ] {
            assert!(host_to_hash(host) < 1024);
        }
    }

    #[test]
    fn test_error_kind_tracking() {
        let state = install_test_state();
        state.set_last_error_with_host(SecurityErrorKind::Upstream4xx, "a", "4xx");
        state.set_last_error_with_host(SecurityErrorKind::Upstream5xx, "a", "5xx");
        state.set_last_error_with_host(SecurityErrorKind::Timeout, "a", "timeout");
        let kinds = state.error_kinds.lock().clone();
        assert!(kinds.get(&SecurityErrorKind::Upstream4xx).unwrap_or(&0) > &0);
        assert!(kinds.get(&SecurityErrorKind::Upstream5xx).unwrap_or(&0) > &0);
        assert!(kinds.get(&SecurityErrorKind::Timeout).unwrap_or(&0) > &0);
    }

    #[test]
    fn test_latency_histogram_buckets() {
        let state = install_test_state();
        state.record_latency_ms(75);
        state.record_latency_ms(150);
        state.record_latency_ms(1500);
        state.record_latency_ms(3000);
        assert!(state.lat_count.load(Ordering::Relaxed) >= 4);
        assert!(state.lat_sum_ms.load(Ordering::Relaxed) >= 75 + 150 + 1500 + 3000);
    }

    #[test]
    fn explicit_snapshot_with_control_plane_uses_supplied_owner_state() {
        let state = SecurityMetricsState::new();
        state.inc_total_requests();
        state.record_latency_ms(25);

        let cache = crate::admin_debug::cache::CacheStore::from_env();
        {
            let mut cache_guard = cache.lock().expect("cache lock should succeed");
            cache_guard.put(
                "query-owner".to_string(),
                crate::admin_debug::cache::CacheEntry {
                    etag: None,
                    content_type: Some("text/plain".to_string()),
                    body: vec![1, 2, 3, 4],
                    timestamp: Instant::now(),
                },
            );
        }

        let breaker = crate::admin_debug::breaker::BreakerStore::from_env();
        {
            let mut breaker_guard = breaker.lock().expect("breaker lock should succeed");
            for _ in 0..3 {
                assert!(breaker_guard.check("query-owner.test"));
                breaker_guard.mark_failure("query-owner.test");
            }
        }

        let snapshot = state
            .snapshot_with_control_plane(&cache, &breaker, 9)
            .expect("explicit owner snapshot should succeed");
        assert_eq!(snapshot.total_requests, 1);
        assert_eq!(snapshot.cache_bytes_mem, 4);
        assert_eq!(snapshot.limiter_current_concurrency, 9);
        assert!(
            !snapshot.breaker_states.is_empty(),
            "explicit breaker store should contribute breaker state"
        );
    }
}
