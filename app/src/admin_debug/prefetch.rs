// app/src/admin_debug/prefetch.rs
use std::time::Duration;
use once_cell::sync::OnceCell;
use tokio::sync::{mpsc, mpsc::{Sender, Receiver}};
use anyhow::Result;

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

impl Prefetcher {
    pub fn global() -> &'static Prefetcher {
        GLOBAL.get_or_init(|| {
            let cap = std::env::var("SB_PREFETCH_CAP").ok().and_then(|s| s.parse().ok()).unwrap_or(128);
            let (tx, rx) = mpsc::channel::<PrefetchJob>(cap);
            let n = std::env::var("SB_PREFETCH_WORKERS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);

            // Create shared receiver using Arc
            let rx = std::sync::Arc::new(tokio::sync::Mutex::new(rx));

            for id in 0..n {
                let rx_clone = rx.clone();
                tokio::spawn(worker_loop(id, rx_clone));
            }
            // metrics init（建议放 metrics 模块集中管理）
            crate::admin_debug::security_metrics::init_prefetch_metrics();
            Prefetcher { tx }
        })
    }

    pub fn enqueue(&self, job: PrefetchJob) -> bool {
        // 队列满即丢弃 + 计数
        match self.tx.try_send(job) {
            Ok(_) => {
                crate::admin_debug::security_metrics::prefetch_inc("enq");
                true
            }
            Err(_e) => {
                crate::admin_debug::security_metrics::prefetch_inc("drop");
                false
            }
        }
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
        let mut left = std::env::var("SB_PREFETCH_RETRIES").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
        loop {
            match do_prefetch(&job).await {
                Ok(_) => {
                    ok = true;
                    crate::admin_debug::security_metrics::prefetch_inc("done");
                    break;
                }
                Err(_e) => {
                    crate::admin_debug::security_metrics::prefetch_inc("fail");
                    if left == 0 { break; }
                    left -= 1;
                    crate::admin_debug::security_metrics::prefetch_inc("retry");
                    // 简单指数退避（避免与 breaker backoff 相互放大）
                    let backoff_ms = 50u64.saturating_mul(1 << (job.tries.saturating_sub(left as u8) as u32));
                    tokio::time::sleep(Duration::from_millis(backoff_ms.min(1000))).await;
                }
            }
        }
        let dur_ms = start.elapsed().as_millis() as u64;
        crate::admin_debug::security_metrics::record_prefetch_run_ms(dur_ms);
        tracing::debug!(id, ok, "prefetch worker finished");
    }
}

async fn do_prefetch(job: &PrefetchJob) -> Result<()> {
    // 1) 走已有安全路径：限流/熔断/DNS 私网拦截/ETag 条件请求
    // 可直接复用 subs 的 fetch 函数（建议抽出 fetch_with_limits(&url, etag) -> Result<CacheEntry>）
    let url = &job.url;
    let _ = prefetch_once(url, job.etag.clone()).await?;
    Ok(())
}

// 简化版本的预取实现，复用现有安全检查
async fn prefetch_once(url: &str, _etag: Option<String>) -> Result<()> {
    // 检查是否启用预取
    if std::env::var("SB_PREFETCH_ENABLE").ok().as_deref() != Some("1") {
        return Err(anyhow::anyhow!("prefetch disabled"));
    }

    // 基本 URL 验证和安全检查
    if url.len() > 2048 {
        return Err(anyhow::anyhow!("URL too long"));
    }

    // 解析 URL 以便使用现有安全检查
    let parsed_url = reqwest::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))?;

    // 使用现有的安全检查
    crate::admin_debug::security::forbid_private_host_or_resolved_with_allowlist(&parsed_url)?;

    // 这里应该调用实际的 HTTP fetch 逻辑
    // 暂时返回成功以完成骨架
    tracing::debug!("Prefetch attempted for: {}", url);
    Ok(())
}

// 对外 API
pub fn enqueue_prefetch(url: &str, etag: Option<String>) -> bool {
    if std::env::var("SB_PREFETCH_ENABLE").ok().as_deref() != Some("1") {
        return false;
    }

    let job = PrefetchJob {
        url: url.to_string(),
        etag,
        deadline_ms: 0, // TODO: 实际计算
        tries: 0,
    };

    Prefetcher::global().enqueue(job)
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
}