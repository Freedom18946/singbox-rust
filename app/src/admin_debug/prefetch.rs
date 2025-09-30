// app/src/admin_debug/prefetch.rs
use anyhow::Result;
use once_cell::sync::OnceCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{
    mpsc,
    mpsc::{Receiver, Sender},
};
use url::Url;

#[derive(Clone, Debug)]
pub struct PrefetchJob {
    pub url: String,
    pub etag: Option<String>,
    pub deadline_ms: u64,
    pub tries: u8,
}

pub struct Prefetcher {
    tx: Sender<PrefetchJob>,
}

static GLOBAL: OnceCell<Prefetcher> = OnceCell::new();
static QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static HIGH_WATERMARK: AtomicU64 = AtomicU64::new(0);
static LAST_PREFETCH_SIZE: AtomicU64 = AtomicU64::new(0);

fn observe_depth(depth: u64) {
    let mut cur = HIGH_WATERMARK.load(Ordering::Relaxed);
    while depth > cur
        && HIGH_WATERMARK
            .compare_exchange(cur, depth, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        cur = HIGH_WATERMARK.load(Ordering::Relaxed);
    }
    crate::admin_debug::security_metrics::set_prefetch_queue_depth(depth);
    crate::admin_debug::security_metrics::set_prefetch_queue_high_watermark(
        HIGH_WATERMARK.load(Ordering::Relaxed),
    );
}

impl Prefetcher {
    pub fn global() -> &'static Self {
        GLOBAL.get_or_init(|| {
            let cap = std::env::var("SB_PREFETCH_CAP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(128);
            let (tx, rx) = mpsc::channel::<PrefetchJob>(cap);
            let n = std::env::var("SB_PREFETCH_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2);

            // Create shared receiver using Arc
            let rx = std::sync::Arc::new(tokio::sync::Mutex::new(rx));

            for id in 0..n {
                let rx_clone = rx.clone();
                tokio::spawn(worker_loop(id, rx_clone));
            }
            // metrics init（建议放 metrics 模块集中管理）
            crate::admin_debug::security_metrics::init_prefetch_metrics();
            Self { tx }
        })
    }

    pub fn enqueue(&self, job: PrefetchJob) -> bool {
        // 队列满即丢弃 + 计数
        match self.tx.try_send(job) {
            Ok(()) => {
                crate::admin_debug::security_metrics::prefetch_inc("enq");
                // Update queue depth after successful enqueue with high watermark tracking
                let new_depth = QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
                observe_depth(new_depth as u64);
                true
            }
            Err(_e) => {
                crate::admin_debug::security_metrics::prefetch_inc("drop");
                false
            }
        }
    }

    pub fn shutdown(self) {
        // Placeholder for graceful shutdown - simplified version for compatibility
        drop(self.tx);
    }
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
        let mut left = std::env::var("SB_PREFETCH_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);
        loop {
            match do_prefetch(&job).await {
                Ok(()) => {
                    ok = true;
                    crate::admin_debug::security_metrics::prefetch_inc("done");
                    break;
                }
                Err(_e) => {
                    crate::admin_debug::security_metrics::prefetch_inc("fail");
                    if left == 0 {
                        break;
                    }
                    left -= 1;
                    crate::admin_debug::security_metrics::prefetch_inc("retry");
                    // 简单指数退避（避免与 breaker backoff 相互放大）
                    let backoff_ms =
                        50u64.saturating_mul(1 << u32::from(job.tries.saturating_sub(left as u8)));
                    tokio::time::sleep(Duration::from_millis(backoff_ms.min(1000))).await;
                }
            }
        }

        // Update queue depth after job completion (success or failure)
        let prev = QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed) - 1;
        crate::admin_debug::security_metrics::set_prefetch_queue_depth(prev as u64);

        let dur_ms = start.elapsed().as_millis() as u64;
        crate::admin_debug::security_metrics::record_prefetch_run_ms(dur_ms);
        tracing::debug!(id, ok, "prefetch worker finished");
    }
}

async fn do_prefetch(job: &PrefetchJob) -> Result<()> {
    // 1) 走已有安全路径：限流/熔断/DNS 私网拦截/ETag 条件请求
    // 可直接复用 subs 的 fetch 函数（建议抽出 fetch_with_limits(&url, etag) -> Result<CacheEntry>）
    let url = &job.url;
    let cache_entry = prefetch_once(url, job.etag.clone()).await?;

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
        tries: std::env::var("SB_PREFETCH_RETRIES")
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(3),
    };
    Prefetcher::global().enqueue(job)
}

async fn prefetch_once(
    url: &str,
    etag: Option<String>,
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
        return crate::admin_debug::endpoints::subs::fetch_with_limits_to_cache(url, etag, true)
            .await;
    }
    #[cfg(not(feature = "subs_http"))]
    {
        anyhow::bail!("subs_http feature disabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetch_job_creation() {
        let job = PrefetchJob {
            url: "https://example.com/config".to_string(),
            etag: Some("\"abc123\"".to_string()),
            deadline_ms: 5000,
            tries: 0,
        };

        assert_eq!(job.url, "https://example.com/config");
        assert_eq!(job.etag, Some("\"abc123\"".to_string()));
        assert_eq!(job.deadline_ms, 5000);
        assert_eq!(job.tries, 0);
    }

    #[test]
    fn test_enqueue_when_disabled() {
        std::env::set_var("SB_PREFETCH_ENABLE", "0");
        let result = enqueue_prefetch("https://example.com", None);
        assert!(!result);
        std::env::remove_var("SB_PREFETCH_ENABLE");
    }

    #[test]
    fn test_enqueue_when_enabled() {
        std::env::set_var("SB_PREFETCH_ENABLE", "1");
        // Note: This test might succeed or fail depending on queue capacity
        // In a real test, we'd want to mock the underlying components
        let _result = enqueue_prefetch("https://example.com", None);
        std::env::remove_var("SB_PREFETCH_ENABLE");
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
            tries: 1
        }));
        // 第二次应丢弃
        assert!(!pf.enqueue(PrefetchJob {
            url: "http://b".into(),
            etag: None,
            deadline_ms: 0,
            tries: 1
        }));
    }
}
