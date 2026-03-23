// app/src/admin_debug/prefetch.rs
use anyhow::Result;
use once_cell::sync::OnceCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::{LazyLock, Weak};
use std::time::Duration;
use tokio::sync::{
    mpsc,
    mpsc::{Receiver, Sender},
};
use url::Url;

type SecurityMetricsState = crate::admin_debug::security_metrics::SecurityMetricsState;

#[derive(Clone)]
pub struct PrefetchJob {
    pub url: String,
    pub etag: Option<String>,
    pub deadline_ms: u64,
    pub tries: u8,
    metrics: Option<Arc<SecurityMetricsState>>,
}

pub struct Prefetcher {
    tx: Sender<PrefetchJob>,
}

static GLOBAL: OnceCell<Prefetcher> = OnceCell::new();
static DEFAULT_PREFETCHER: LazyLock<StdMutex<Option<Weak<Prefetcher>>>> =
    LazyLock::new(|| StdMutex::new(None));
static QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static HIGH_WATERMARK: AtomicU64 = AtomicU64::new(0);
static LAST_PREFETCH_SIZE: AtomicU64 = AtomicU64::new(0);

fn observe_depth(depth: u64, metrics: Option<&SecurityMetricsState>) {
    let mut cur = HIGH_WATERMARK.load(Ordering::Relaxed);
    while depth > cur
        && HIGH_WATERMARK
            .compare_exchange(cur, depth, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        cur = HIGH_WATERMARK.load(Ordering::Relaxed);
    }
    set_prefetch_queue_depth(depth, metrics);
    set_prefetch_queue_high_watermark(HIGH_WATERMARK.load(Ordering::Relaxed), metrics);
}

const fn init_prefetch_metrics(metrics: Option<&SecurityMetricsState>) {
    if let Some(metrics) = metrics {
        metrics.init_prefetch_metrics();
    }
}

fn prefetch_inc(event: &str, metrics: Option<&SecurityMetricsState>) {
    if let Some(metrics) = metrics {
        metrics.prefetch_inc(event);
    }
}

fn record_prefetch_run_ms(ms: u64, metrics: Option<&SecurityMetricsState>) {
    if let Some(metrics) = metrics {
        metrics.record_prefetch_run_ms(ms);
    }
}

fn set_prefetch_queue_depth(depth: u64, metrics: Option<&SecurityMetricsState>) {
    if let Some(metrics) = metrics {
        metrics.set_prefetch_queue_depth(depth);
    }
}

fn set_prefetch_queue_high_watermark(watermark: u64, metrics: Option<&SecurityMetricsState>) {
    if let Some(metrics) = metrics {
        metrics.set_prefetch_queue_high_watermark(watermark);
    }
}

impl Prefetcher {
    #[must_use]
    pub fn from_env() -> Self {
        let cap = parse_prefetch_env_usize("SB_PREFETCH_CAP", 128);
        let (tx, rx) = mpsc::channel::<PrefetchJob>(cap);
        let n = parse_prefetch_env_usize("SB_PREFETCH_WORKERS", 2);

        // Create shared receiver using Arc
        let rx = std::sync::Arc::new(tokio::sync::Mutex::new(rx));

        for id in 0..n {
            let rx_clone = rx.clone();
            // If we are inside a Tokio runtime, use tokio::spawn. Otherwise, spawn a thread
            // and create a small runtime to drive the worker. This prevents tests without
            // a runtime from panicking.
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(worker_loop(id, rx_clone));
            } else {
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build tokio runtime");
                    rt.block_on(worker_loop(id, rx_clone));
                });
            }
        }

        Self { tx }
    }

    pub fn global() -> &'static Self {
        GLOBAL.get_or_init(Self::from_env)
    }

    pub fn enqueue(&self, job: PrefetchJob) -> bool {
        let metrics = job.metrics.clone();
        init_prefetch_metrics(metrics.as_deref());
        // 队列满即丢弃 + 计数
        match self.tx.try_send(job) {
            Ok(()) => {
                prefetch_inc("enq", metrics.as_deref());
                // Update queue depth after successful enqueue with high watermark tracking
                let new_depth = QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
                observe_depth(new_depth as u64, metrics.as_deref());
                true
            }
            Err(_e) => {
                prefetch_inc("drop", metrics.as_deref());
                false
            }
        }
    }

    pub fn shutdown(self) {
        // Placeholder for graceful shutdown - simplified version for compatibility
        drop(self.tx);
    }
}

/// Install the default prefetcher via a weak compatibility registry.
///
/// The caller keeps the returned `Arc` as the explicit owner while admin-debug
/// lookup paths only store a weak compatibility handle.
#[must_use]
pub fn install_default_prefetcher(prefetcher: Arc<Prefetcher>) -> Arc<Prefetcher> {
    let mut slot = DEFAULT_PREFETCHER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_ref().and_then(Weak::upgrade) {
        Some(existing) => existing,
        None => {
            *slot = Some(Arc::downgrade(&prefetcher));
            prefetcher
        }
    }
}

fn current_prefetcher() -> Option<Arc<Prefetcher>> {
    DEFAULT_PREFETCHER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade)
}

async fn worker_loop(id: usize, rx: std::sync::Arc<tokio::sync::Mutex<Receiver<PrefetchJob>>>) {
    loop {
        let job = {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(job) => job,
                None => break, // Channel closed
            }
        };

        let start = std::time::Instant::now();
        let mut ok = false;
        let mut left = parse_prefetch_env_usize("SB_PREFETCH_RETRIES", 2);
        loop {
            match do_prefetch(&job.url, job.etag.clone(), job.metrics.clone()).await {
                Ok(()) => {
                    ok = true;
                    prefetch_inc("done", job.metrics.as_deref());
                    break;
                }
                Err(_e) => {
                    prefetch_inc("fail", job.metrics.as_deref());
                    if left == 0 {
                        break;
                    }
                    left -= 1;
                    prefetch_inc("retry", job.metrics.as_deref());
                    // 简单指数退避（避免与 breaker backoff 相互放大）
                    let backoff_ms =
                        50u64.saturating_mul(1 << u32::from(job.tries.saturating_sub(left as u8)));
                    tokio::time::sleep(Duration::from_millis(backoff_ms.min(1000))).await;
                }
            }
        }

        // Update queue depth after job completion (success or failure)
        let prev = QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed) - 1;
        set_prefetch_queue_depth(prev as u64, job.metrics.as_deref());

        let dur_ms = start.elapsed().as_millis() as u64;
        record_prefetch_run_ms(dur_ms, job.metrics.as_deref());
        tracing::debug!(id, ok, "prefetch worker finished");
    }
}

async fn do_prefetch(
    url: &str,
    etag: Option<String>,
    metrics: Option<Arc<SecurityMetricsState>>,
) -> Result<()> {
    // 1) 走已有安全路径：限流/熔断/DNS 私网拦截/ETag 条件请求
    // 可直接复用 subs 的 fetch 函数（建议抽出 fetch_with_limits(&url, etag) -> Result<CacheEntry>）
    let cache_entry = prefetch_once(url, etag, metrics).await?;

    // Update size tracking
    let size = cache_entry.body.len() as u64;
    LAST_PREFETCH_SIZE.store(size, Ordering::Relaxed);

    Ok(())
}

/// For shutdown support - can be called once to take ownership for graceful shutdown
#[must_use]
pub const fn global_take() -> Option<Prefetcher> {
    // Note: This is a simplified version - in production you'd want proper synchronization
    None // Current structure doesn't easily support taking ownership, placeholder for interface
}

/// Get high watermark metric for export
pub fn get_high_watermark() -> u64 {
    HIGH_WATERMARK.load(Ordering::Relaxed)
}

/// Get the size of the last completed prefetch operation
pub fn get_last_prefetch_size() -> u64 {
    LAST_PREFETCH_SIZE.load(Ordering::Relaxed)
}

#[must_use]
pub fn enqueue_prefetch(url: &str, etag: Option<String>) -> bool {
    if std::env::var("SB_PREFETCH_ENABLE").ok().as_deref() != Some("1") {
        return false;
    }
    let job = PrefetchJob {
        url: url.to_string(),
        etag,
        deadline_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + 60_000,
        tries: parse_prefetch_env_u8("SB_PREFETCH_RETRIES", 3),
        metrics: crate::admin_debug::security_metrics::current_owner(),
    };
    if let Some(prefetcher) = current_prefetcher() {
        prefetcher.enqueue(job)
    } else {
        Prefetcher::global().enqueue(job)
    }
}

#[must_use]
pub fn enqueue_prefetch_with_metrics(
    url: &str,
    etag: Option<String>,
    metrics: Arc<SecurityMetricsState>,
) -> bool {
    if std::env::var("SB_PREFETCH_ENABLE").ok().as_deref() != Some("1") {
        return false;
    }
    let job = PrefetchJob {
        url: url.to_string(),
        etag,
        deadline_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + 60_000,
        tries: parse_prefetch_env_u8("SB_PREFETCH_RETRIES", 3),
        metrics: Some(metrics),
    };
    if let Some(prefetcher) = current_prefetcher() {
        prefetcher.enqueue(job)
    } else {
        Prefetcher::global().enqueue(job)
    }
}

async fn prefetch_once(
    url: &str,
    etag: Option<String>,
    metrics: Option<Arc<SecurityMetricsState>>,
) -> Result<crate::admin_debug::cache::CacheEntry> {
    // 快速校验
    if url.len() > 2048 {
        anyhow::bail!("url too long");
    }
    let parsed = Url::parse(url)?;
    crate::admin_debug::security::forbid_private_host_or_resolved_with_allowlist(&parsed)?;

    // 真实抓取（含限流/熔断/缓存/ETag）
    #[cfg(feature = "subs_http")]
    {
        return if let Some(metrics) = metrics.as_ref() {
            crate::admin_debug::endpoints::subs::fetch_with_limits_to_cache_with_metrics(
                url,
                etag,
                true,
                Arc::clone(metrics),
            )
            .await
        } else {
            crate::admin_debug::endpoints::subs::fetch_with_limits_to_cache(url, etag, true).await
        };
    }
    #[cfg(not(feature = "subs_http"))]
    {
        anyhow::bail!("subs_http feature disabled");
    }
}

fn parse_prefetch_env_usize(key: &str, default: usize) -> usize {
    let raw = match std::env::var(key) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let trimmed = raw.trim();
    match trimmed.parse::<usize>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("env '{key}' value '{trimmed}' is not a valid usize; silent parse fallback is disabled; using default {default}: {err}");
            default
        }
    }
}

fn parse_prefetch_env_u8(key: &str, default: u8) -> u8 {
    let raw = match std::env::var(key) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let trimmed = raw.trim();
    match trimmed.parse::<u8>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("env '{key}' value '{trimmed}' is not a valid u8; silent parse fallback is disabled; using default {default}: {err}");
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        match ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        }
    }

    fn clear_default_prefetcher_for_test() {
        let mut slot = DEFAULT_PREFETCHER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = None;
    }

    #[test]
    fn test_prefetch_job_creation() {
        let job = PrefetchJob {
            url: "https://example.com/config".to_string(),
            etag: Some("\"abc123\"".to_string()),
            deadline_ms: 5000,
            tries: 0,
            metrics: None,
        };

        assert_eq!(job.url, "https://example.com/config");
        assert_eq!(job.etag, Some("\"abc123\"".to_string()));
        assert_eq!(job.deadline_ms, 5000);
        assert_eq!(job.tries, 0);
    }

    #[test]
    fn test_enqueue_when_disabled() {
        let _guard = env_lock();
        let prev = std::env::var("SB_PREFETCH_ENABLE").ok();
        std::env::set_var("SB_PREFETCH_ENABLE", "0");
        let result = enqueue_prefetch("https://example.com", None);
        assert!(!result);
        match prev {
            Some(value) => std::env::set_var("SB_PREFETCH_ENABLE", value),
            None => std::env::remove_var("SB_PREFETCH_ENABLE"),
        }
    }

    #[test]
    fn test_enqueue_when_enabled() {
        let _guard = env_lock();
        let prev = std::env::var("SB_PREFETCH_ENABLE").ok();
        std::env::set_var("SB_PREFETCH_ENABLE", "1");
        // Note: This test might succeed or fail depending on queue capacity
        // In a real test, we'd want to mock the underlying components
        let _result = enqueue_prefetch("https://example.com", None);
        match prev {
            Some(value) => std::env::set_var("SB_PREFETCH_ENABLE", value),
            None => std::env::remove_var("SB_PREFETCH_ENABLE"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_explicit_metrics_owner_tracks_prefetch_depth() {
        HIGH_WATERMARK.store(0, Ordering::Relaxed);
        let metrics = crate::admin_debug::security_metrics::SecurityMetricsState::new();
        observe_depth(3, Some(&metrics));

        let snapshot = metrics
            .snapshot()
            .expect("explicit metrics snapshot should succeed");
        assert_eq!(snapshot.prefetch_queue_depth, 3);
        assert_eq!(metrics.get_prefetch_queue_high_watermark(), 3);
    }

    #[test]
    #[serial_test::serial]
    fn weak_default_prefetcher_routes_enqueue_through_explicit_owner() {
        let _guard = env_lock();
        let prev = std::env::var("SB_PREFETCH_ENABLE").ok();
        std::env::set_var("SB_PREFETCH_ENABLE", "1");
        clear_default_prefetcher_for_test();

        let (tx_one, mut rx_one) = mpsc::channel::<PrefetchJob>(1);
        let owner_one = install_default_prefetcher(Arc::new(Prefetcher { tx: tx_one }));
        assert!(enqueue_prefetch("https://example.com/one", None));
        let first = rx_one
            .try_recv()
            .expect("explicit owner should receive first job");
        assert_eq!(first.url, "https://example.com/one");
        drop(owner_one);

        let (tx_two, mut rx_two) = mpsc::channel::<PrefetchJob>(1);
        let owner_two = install_default_prefetcher(Arc::new(Prefetcher { tx: tx_two }));
        assert!(enqueue_prefetch("https://example.com/two", None));
        let second = rx_two
            .try_recv()
            .expect("replacement explicit owner should receive second job");
        assert_eq!(second.url, "https://example.com/two");
        drop(owner_two);

        clear_default_prefetcher_for_test();
        match prev {
            Some(value) => std::env::set_var("SB_PREFETCH_ENABLE", value),
            None => std::env::remove_var("SB_PREFETCH_ENABLE"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn enqueue_prefetch_attaches_current_default_metrics_owner() {
        let _guard = env_lock();
        let prev = std::env::var("SB_PREFETCH_ENABLE").ok();
        std::env::set_var("SB_PREFETCH_ENABLE", "1");
        clear_default_prefetcher_for_test();
        crate::admin_debug::security_metrics::clear_default_for_test();

        let _metrics = crate::admin_debug::security_metrics::install_default(Arc::new(
            crate::admin_debug::security_metrics::SecurityMetricsState::new(),
        ));
        let (tx, mut rx) = mpsc::channel::<PrefetchJob>(1);
        let owner = install_default_prefetcher(Arc::new(Prefetcher { tx }));

        assert!(enqueue_prefetch("https://example.com/metrics", None));
        let job = rx
            .try_recv()
            .expect("prefetch job should be enqueued through explicit owner");
        assert!(
            job.metrics.is_some(),
            "legacy enqueue should capture current metrics owner"
        );

        drop(owner);
        crate::admin_debug::security_metrics::clear_default_for_test();
        clear_default_prefetcher_for_test();
        match prev {
            Some(value) => std::env::set_var("SB_PREFETCH_ENABLE", value),
            None => std::env::remove_var("SB_PREFETCH_ENABLE"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn owner_aware_helpers_record_without_default_state() {
        crate::admin_debug::security_metrics::clear_default_for_test();
        HIGH_WATERMARK.store(0, Ordering::Relaxed);

        let metrics = crate::admin_debug::security_metrics::SecurityMetricsState::new();

        // Helpers should work via explicit owner, not compat wrappers
        prefetch_inc("enq", Some(&metrics));
        prefetch_inc("done", Some(&metrics));
        observe_depth(5, Some(&metrics));
        record_prefetch_run_ms(42, Some(&metrics));

        assert_eq!(metrics.get_prefetch_queue_depth(), 5);
        assert_eq!(metrics.get_prefetch_queue_high_watermark(), 5);
        let (enq, _, done, _, _) = metrics.get_prefetch_counters();
        assert_eq!(enq, 1);
        assert_eq!(done, 1);

        // None metrics should silently no-op, not panic
        prefetch_inc("enq", None);
        observe_depth(10, None);
    }

    #[tokio::test]
    async fn queue_depth_drops_when_full() {
        // 构造容量=1的 prefetcher
        let (tx, _rx) = mpsc::channel::<PrefetchJob>(1);
        let pf = Prefetcher { tx };

        assert!(pf.enqueue(PrefetchJob {
            url: "http://a".into(),
            etag: None,
            deadline_ms: 0,
            tries: 1,
            metrics: None,
        }));
        // 第二次应丢弃
        assert!(!pf.enqueue(PrefetchJob {
            url: "http://b".into(),
            etag: None,
            deadline_ms: 0,
            tries: 1,
            metrics: None,
        }));
    }
}
