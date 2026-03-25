// app/src/admin_debug/prefetch.rs
//
// Prefetch subsystem with explicit owner model.
//
// The `Prefetcher` is always created and installed via an explicit owner
// (`install_default_prefetcher`). There is no process-wide global singleton.
// Legacy entry points (`enqueue_prefetch`, `enqueue_prefetch_with_metrics`)
// look up the current owner through a weak-owner compatibility registry
// (`DEFAULT_PREFETCHER`). If no owner is installed, enqueue silently returns
// `false`.
//
// Worker lifecycle is fully managed: a single dispatcher task owns the
// `Receiver` directly (no `Arc<Mutex<Receiver>>`), spawns bounded concurrent
// workers via `JoinSet`, and responds to a `CancellationToken` for graceful
// shutdown. The owner (`Arc<Prefetcher>`) cancels the token on drop, causing
// the dispatcher to drain and exit.

use anyhow::Result;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::{LazyLock, Weak};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
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
    cancel: CancellationToken,
    /// The dispatcher task handle, taken on shutdown for awaiting.
    dispatcher_handle: StdMutex<Option<JoinHandle<()>>>,
}

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
    /// Create a new prefetcher reading configuration from environment variables.
    ///
    /// If called inside a Tokio runtime, the dispatcher task is spawned via
    /// `tokio::spawn` and tracked. If no runtime is available (e.g. sync test
    /// context), the dispatcher is not started — enqueue still works but jobs
    /// won't be consumed until a runtime-aware owner is installed.
    #[must_use]
    pub fn from_env() -> Self {
        let cap = parse_prefetch_env_usize("SB_PREFETCH_CAP", 128);
        let (tx, rx) = tokio::sync::mpsc::channel::<PrefetchJob>(cap);
        let workers = parse_prefetch_env_usize("SB_PREFETCH_WORKERS", 2);
        let cancel = CancellationToken::new();

        let handle = if tokio::runtime::Handle::try_current().is_ok() {
            Some(tokio::spawn(dispatcher_loop(rx, workers, cancel.clone())))
        } else {
            // No Tokio runtime — skip dispatcher. The receiver is dropped,
            // so `try_send` will return `Err` once the channel buffer fills.
            // This is acceptable: the only sync callers are test setups that
            // verify the owner plumbing, not actual prefetch processing.
            drop(rx);
            None
        };

        Self {
            tx,
            cancel,
            dispatcher_handle: StdMutex::new(handle),
        }
    }

    pub fn enqueue(&self, job: PrefetchJob) -> bool {
        let metrics = job.metrics.clone();
        init_prefetch_metrics(metrics.as_deref());
        match self.tx.try_send(job) {
            Ok(()) => {
                prefetch_inc("enq", metrics.as_deref());
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

    /// Graceful shutdown: cancel the dispatcher, drop the sender, and await
    /// the dispatcher task to finish processing in-flight jobs.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        // Close the sender side so the dispatcher sees channel closed.
        // (The `tx` clone inside `self` is the only sender; dropping it
        // signals the dispatcher. But we can't drop `self.tx` through &self,
        // so we rely on cancellation token + channel close on Drop.)
        let handle = self
            .dispatcher_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

impl Drop for Prefetcher {
    fn drop(&mut self) {
        // Signal the dispatcher to stop. The JoinHandle is not awaited here
        // (we are in sync Drop), but the dispatcher will observe cancellation
        // and exit promptly once the channel sender is also dropped.
        self.cancel.cancel();
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

/// The single dispatcher task that owns the `Receiver` and fans out work to a
/// bounded set of concurrent worker futures via `JoinSet`.
async fn dispatcher_loop(
    mut rx: Receiver<PrefetchJob>,
    max_workers: usize,
    cancel: CancellationToken,
) {
    use tokio::task::JoinSet;

    let mut workers = JoinSet::new();

    loop {
        // If we are at max concurrency, wait for a slot to free up.
        while workers.len() >= max_workers {
            tokio::select! {
                () = cancel.cancelled() => {
                    // Drain remaining workers on cancellation.
                    while workers.join_next().await.is_some() {}
                    return;
                }
                result = workers.join_next() => {
                    if result.is_none() {
                        break; // No more workers, proceed to recv.
                    }
                }
            }
        }

        // Receive next job or exit.
        let job = tokio::select! {
            () = cancel.cancelled() => {
                // Drain remaining workers on cancellation.
                while workers.join_next().await.is_some() {}
                return;
            }
            maybe_job = rx.recv() => {
                match maybe_job {
                    Some(job) => job,
                    None => {
                        // Channel closed — owner dropped. Drain workers.
                        while workers.join_next().await.is_some() {}
                        return;
                    }
                }
            }
        };

        workers.spawn(run_job(job));
    }
}

/// Execute a single prefetch job with retries.
async fn run_job(job: PrefetchJob) {
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
                let backoff_ms =
                    50u64.saturating_mul(1 << u32::from(job.tries.saturating_sub(left as u8)));
                tokio::time::sleep(Duration::from_millis(backoff_ms.min(1000))).await;
            }
        }
    }

    let prev = QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed) - 1;
    set_prefetch_queue_depth(prev as u64, job.metrics.as_deref());

    let dur_ms = start.elapsed().as_millis() as u64;
    record_prefetch_run_ms(dur_ms, job.metrics.as_deref());
    tracing::debug!(ok, "prefetch worker finished");
}

async fn do_prefetch(
    url: &str,
    etag: Option<String>,
    metrics: Option<Arc<SecurityMetricsState>>,
) -> Result<()> {
    let cache_entry = prefetch_once(url, etag, metrics).await?;
    let size = cache_entry.body.len() as u64;
    LAST_PREFETCH_SIZE.store(size, Ordering::Relaxed);
    Ok(())
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
        // No owner installed — silently fail.
        false
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
        // No owner installed — silently fail.
        false
    }
}

async fn prefetch_once(
    url: &str,
    etag: Option<String>,
    metrics: Option<Arc<SecurityMetricsState>>,
) -> Result<crate::admin_debug::cache::CacheEntry> {
    if url.len() > 2048 {
        anyhow::bail!("url too long");
    }
    let parsed = Url::parse(url)?;
    crate::admin_debug::security::forbid_private_host_or_resolved_with_allowlist(&parsed)?;

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
    use tokio::sync::mpsc;

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
    fn test_enqueue_when_enabled_but_no_owner() {
        let _guard = env_lock();
        let prev = std::env::var("SB_PREFETCH_ENABLE").ok();
        std::env::set_var("SB_PREFETCH_ENABLE", "1");
        clear_default_prefetcher_for_test();
        // With no owner installed, enqueue should return false (no global fallback).
        let result = enqueue_prefetch("https://example.com", None);
        assert!(!result, "enqueue should fail when no owner is installed");
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

        // Install first owner via a manually-constructed Prefetcher (no dispatcher needed).
        let (tx_one, mut rx_one) = mpsc::channel::<PrefetchJob>(1);
        let owner_one = install_default_prefetcher(Arc::new(Prefetcher {
            tx: tx_one,
            cancel: CancellationToken::new(),
            dispatcher_handle: StdMutex::new(None),
        }));
        assert!(enqueue_prefetch("https://example.com/one", None));
        let first = rx_one
            .try_recv()
            .expect("explicit owner should receive first job");
        assert_eq!(first.url, "https://example.com/one");
        drop(owner_one);

        // After owner_one is dropped, enqueue should fail (no global fallback).
        clear_default_prefetcher_for_test();
        assert!(
            !enqueue_prefetch("https://example.com/orphan", None),
            "enqueue must fail after owner drop without global fallback"
        );

        // Install replacement owner.
        let (tx_two, mut rx_two) = mpsc::channel::<PrefetchJob>(1);
        let owner_two = install_default_prefetcher(Arc::new(Prefetcher {
            tx: tx_two,
            cancel: CancellationToken::new(),
            dispatcher_handle: StdMutex::new(None),
        }));
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
        let owner = install_default_prefetcher(Arc::new(Prefetcher {
            tx,
            cancel: CancellationToken::new(),
            dispatcher_handle: StdMutex::new(None),
        }));

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
        let (tx, _rx) = mpsc::channel::<PrefetchJob>(1);
        let pf = Prefetcher {
            tx,
            cancel: CancellationToken::new(),
            dispatcher_handle: StdMutex::new(None),
        };

        assert!(pf.enqueue(PrefetchJob {
            url: "http://a".into(),
            etag: None,
            deadline_ms: 0,
            tries: 1,
            metrics: None,
        }));
        assert!(!pf.enqueue(PrefetchJob {
            url: "http://b".into(),
            etag: None,
            deadline_ms: 0,
            tries: 1,
            metrics: None,
        }));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn dispatcher_exits_on_owner_drop() {
        // Verify that the tracked dispatcher task exits when the owner is dropped.
        let (tx, rx) = mpsc::channel::<PrefetchJob>(4);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(dispatcher_loop(rx, 2, cancel.clone()));

        // Give the dispatcher a moment to enter its recv loop.
        tokio::task::yield_now().await;

        // Drop sender + cancel to simulate owner drop.
        drop(tx);
        cancel.cancel();

        // The dispatcher handle must resolve promptly.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "dispatcher should exit within 2s of owner drop"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn shutdown_awaits_dispatcher() {
        clear_default_prefetcher_for_test();

        let (tx, rx) = mpsc::channel::<PrefetchJob>(4);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(dispatcher_loop(rx, 2, cancel.clone()));

        let pf = Prefetcher {
            tx,
            cancel,
            dispatcher_handle: StdMutex::new(Some(handle)),
        };

        // Shutdown should complete without hanging.
        let result = tokio::time::timeout(Duration::from_secs(2), pf.shutdown()).await;
        assert!(result.is_ok(), "shutdown should complete within 2s");
    }
}
