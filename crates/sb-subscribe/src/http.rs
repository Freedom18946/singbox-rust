//! HTTP fetching utilities for subscription/provider content.
//! HTTP 获取工具，用于订阅/提供者内容下载。

use crate::model::SubsError;
use std::time::Duration;

/// Default request timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retry attempts for transient failures.
const MAX_RETRIES: u32 = 3;

/// Cached conditional-GET metadata returned alongside content.
/// 条件 GET 缓存元数据，随内容一并返回。
#[derive(Debug, Clone, Default)]
pub struct FetchMeta {
    /// `ETag` header from the server response.
    pub etag: Option<String>,
    /// `Last-Modified` header from the server response.
    pub last_modified: Option<String>,
}

/// Result of a conditional fetch.
/// 条件 GET 的结果。
#[derive(Debug)]
pub enum FetchResult {
    /// New or updated content with its cache metadata.
    /// 新内容或已更新的内容，附带缓存元数据。
    Ok(String, FetchMeta),
    /// Server returned 304 Not Modified — caller should keep old content.
    /// 服务器返回 304 Not Modified — 调用方应保留旧内容。
    NotModified,
}

/// Simple (no conditional GET) text fetch with timeout and retry.
/// 简单文本获取（无条件 GET），带超时和重试。
pub async fn fetch_text(url: &str) -> Result<String, SubsError> {
    match fetch_with_retry(url, None).await? {
        FetchResult::Ok(body, _) => Ok(body),
        FetchResult::NotModified => {
            // Shouldn't happen without cache headers, but handle gracefully
            Err(SubsError::Fetch(
                "unexpected 304 without cache headers".into(),
            ))
        }
    }
}

/// Fetch URL content with timeout, retry, and optional conditional GET.
/// 带超时、重试和可选条件 GET 的 URL 内容获取。
///
/// If `cache_meta` is provided, sends `If-None-Match` / `If-Modified-Since`
/// headers. Returns `FetchResult::NotModified` on HTTP 304.
///
/// Retries up to `MAX_RETRIES` times with exponential backoff for transient
/// errors (connection, timeout, 5xx).
pub async fn fetch_with_retry(
    url: &str,
    cache_meta: Option<&FetchMeta>,
) -> Result<FetchResult, SubsError> {
    let client = reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| SubsError::Fetch(format!("failed to build HTTP client: {e}")))?;

    let mut last_err = String::new();

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            // Exponential backoff: 1s, 2s, 4s ...
            let delay = Duration::from_secs(1 << (attempt - 1));
            tokio::time::sleep(delay).await;
        }

        let mut req = client.get(url);

        // Conditional GET headers
        if let Some(meta) = cache_meta {
            if let Some(ref etag) = meta.etag {
                req = req.header("If-None-Match", etag.as_str());
            }
            if let Some(ref lm) = meta.last_modified {
                req = req.header("If-Modified-Since", lm.as_str());
            }
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();

                // 304 Not Modified
                if status == reqwest::StatusCode::NOT_MODIFIED {
                    return Ok(FetchResult::NotModified);
                }

                // Retry on server errors (5xx)
                if status.is_server_error() {
                    last_err = format!("server error: HTTP {status}");
                    continue;
                }

                // Non-success, non-retryable
                if !status.is_success() {
                    return Err(SubsError::Fetch(format!("HTTP {status} for {url}")));
                }

                // Extract cache metadata from response headers
                let meta = FetchMeta {
                    etag: resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string()),
                    last_modified: resp
                        .headers()
                        .get("last-modified")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string()),
                };

                let body = resp
                    .text()
                    .await
                    .map_err(|e| SubsError::Fetch(format!("failed to read body: {e}")))?;

                return Ok(FetchResult::Ok(body, meta));
            }
            Err(e) => {
                // Retry on timeout / connection errors
                if e.is_timeout() || e.is_connect() {
                    last_err = format!("transient error: {e}");
                    continue;
                }
                // Non-transient error — fail immediately
                return Err(SubsError::Fetch(e.to_string()));
            }
        }
    }

    Err(SubsError::Fetch(format!(
        "all {MAX_RETRIES} attempts failed for {url}: {last_err}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_meta_default() {
        let meta = FetchMeta::default();
        assert!(meta.etag.is_none());
        assert!(meta.last_modified.is_none());
    }

    #[test]
    fn test_fetch_result_variants() {
        // Ensure the enum variants compile and can be matched
        let ok = FetchResult::Ok("body".into(), FetchMeta::default());
        assert!(matches!(ok, FetchResult::Ok(_, _)));

        let nm = FetchResult::NotModified;
        assert!(matches!(nm, FetchResult::NotModified));
    }
}
