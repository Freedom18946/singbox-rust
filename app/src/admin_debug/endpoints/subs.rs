use crate::admin_debug::breaker;
use crate::admin_debug::cache;
use crate::admin_debug::http_util::{
    is_networking_allowed, parse_query, respond, respond_json_error, validate_decoded_size,
    validate_format, validate_inline_size_estimate, validate_kinds, validate_url_scheme,
};
use crate::admin_debug::reloadable;
use crate::admin_debug::security::forbid_private_host_or_resolved_with_allowlist;
use crate::admin_debug::security_async::forbid_private_host_or_resolved_async;
use crate::admin_debug::security_metrics::{
    inc_block_private_ip, inc_breaker_block, inc_cache_hit, inc_cache_miss, inc_connect_timeout,
    inc_exceed_size, inc_redirects, inc_timeout, inc_total_requests, inc_upstream_4xx,
    inc_upstream_5xx, mark_last_ok, record_latency_ms, set_last_error, set_last_error_with_host,
    SecurityErrorKind,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

#[cfg(feature = "subs_http")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(feature = "subs_http")]
use std::sync::Arc;
#[cfg(feature = "subs_http")]
use std::time::{Duration, Instant};
#[cfg(feature = "subs_http")]
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

#[cfg(feature = "subs_http")]
use reqwest::{redirect::Policy, Client};
#[cfg(feature = "subs_http")]
use std::net::IpAddr;
#[cfg(feature = "subs_http")]
use tokio::time::timeout;

// Rate limiting globals - updated for hot reloading
#[cfg(feature = "subs_http")]
static MAX_CONC: OnceCell<RwLock<Arc<Semaphore>>> = OnceCell::new();
#[cfg(feature = "subs_http")]
static RPS_TOKENS: OnceCell<(AtomicU64, AtomicU64, AtomicU64)> = OnceCell::new(); // (current, capacity, last_tick)
#[cfg(feature = "subs_http")]
static DESIRED_CONCURRENCY: AtomicUsize = AtomicUsize::new(8);
#[cfg(feature = "subs_http")]
static CONCURRENCY_CAP: AtomicUsize = AtomicUsize::new(8);

// Improved RPS with tick-based resetting
#[cfg(feature = "subs_http")]
static RPS_CAP: AtomicU64 = AtomicU64::new(4);
#[cfg(feature = "subs_http")]
static RPS_CURRENT: AtomicU64 = AtomicU64::new(4);
#[cfg(feature = "subs_http")]
static RPS_LAST_TICK: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "subs_http")]
fn parse_env_usize(key: &str, def: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

#[cfg(feature = "subs_http")]
fn parse_env_u64(key: &str, def: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

#[cfg(feature = "subs_http")]
fn parse_env_bool(key: &str, def: bool) -> bool {
    std::env::var(key)
        .ok()
        .map_or(def, |v| v != "0" && v.to_lowercase() != "false")
}

#[cfg(feature = "subs_http")]
fn limiter_init() {
    let config = reloadable::get();

    MAX_CONC.get_or_init(|| {
        DESIRED_CONCURRENCY.store(config.max_concurrency, Ordering::Relaxed);
        CONCURRENCY_CAP.store(config.max_concurrency, Ordering::Relaxed);
        RwLock::new(Arc::new(Semaphore::new(config.max_concurrency)))
    });

    RPS_TOKENS.get_or_init(|| {
        let cap = config.rps;
        (AtomicU64::new(cap), AtomicU64::new(cap), AtomicU64::new(0))
    });
}

#[cfg(feature = "subs_http")]
pub fn resize_limiters(new_conc: usize, new_rps: u64) {
    // Update desired concurrency
    DESIRED_CONCURRENCY.store(new_conc, Ordering::Relaxed);
    CONCURRENCY_CAP.store(new_conc, Ordering::Relaxed);

    // Hot-swap semaphore
    if let Some(sem_lock) = MAX_CONC.get() {
        if let Ok(mut sem) = sem_lock.try_write() {
            *sem = Arc::new(Semaphore::new(new_conc));
        }
    }

    // Update RPS capacity with tick-based approach
    RPS_CAP.store(new_rps, Ordering::Relaxed);
    RPS_CURRENT.store(new_rps, Ordering::Relaxed); // Reset current tokens to new cap

    // Legacy RPS_TOKENS support for compatibility
    if let Some((_, capacity, _)) = RPS_TOKENS.get() {
        capacity.store(new_rps, Ordering::Relaxed);
    }
}

#[cfg(feature = "subs_http")]
pub fn resize_rps(cap: u64) {
    RPS_CAP.store(cap, Ordering::Relaxed);
    RPS_CURRENT.store(cap, Ordering::Relaxed);
}

#[cfg(feature = "subs_http")]
pub fn get_current_concurrency() -> u64 {
    if let Some(sem_lock) = MAX_CONC.get() {
        if let Ok(sem_guard) = sem_lock.try_read() {
            let total_permits = CONCURRENCY_CAP.load(Ordering::Relaxed) as u64;
            let available_permits = sem_guard.available_permits() as u64;
            return total_permits.saturating_sub(available_permits);
        }
    }
    0
}

#[cfg(not(feature = "subs_http"))]
pub fn get_current_concurrency() -> u64 {
    0
}

#[cfg(feature = "subs_http")]
async fn acquire_permits() -> anyhow::Result<OwnedSemaphorePermit> {
    limiter_init();
    #[allow(clippy::expect_used)] // Safe: limiter_init() just called above
    let sem: Arc<Semaphore> = {
        let sem_lock = MAX_CONC.get().expect("limiter initialized");
        let sem_guard = sem_lock.read().await;
        Arc::clone(&*sem_guard)
    };

    // Tick-based RPS token bucket: refill tokens every second
    let refill_tokens = || {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let prev_tick = RPS_LAST_TICK.swap(now_secs, Ordering::Relaxed);
        if prev_tick != now_secs {
            let cap = RPS_CAP.load(Ordering::Relaxed);
            RPS_CURRENT.store(cap, Ordering::Relaxed);
        }
    };
    refill_tokens();

    // Try to acquire a token with timeout
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 100; // ~1 second timeout with 10ms intervals

    loop {
        refill_tokens();
        let bal = RPS_CURRENT.load(Ordering::Relaxed);
        if bal > 0
            && RPS_CURRENT
                .compare_exchange(bal, bal - 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            break;
        }

        attempts += 1;
        if attempts >= MAX_ATTEMPTS {
            // Rate limited - add this to metrics
            anyhow::bail!("rate limited: too many requests");
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Semi-hot limiter fallback: dynamic capacity adjustment
    let desired = DESIRED_CONCURRENCY.load(Ordering::Relaxed);
    let current_cap = CONCURRENCY_CAP.load(Ordering::Relaxed);
    if desired > current_cap {
        let to_add = desired.saturating_sub(current_cap);
        if to_add > 0 && to_add <= 32 {
            sem.add_permits(to_add);
            CONCURRENCY_CAP.store(desired, Ordering::Relaxed);
            tracing::debug!(
                desired = %desired,
                current_cap = %current_cap,
                added = %to_add,
                "Expanded semaphore capacity"
            );
        }
    }

    // For shrinking: rely on natural permit exhaustion + front gate limiting
    // This provides zero-risk shrinking as old permits expire naturally

    // Acquire concurrency semaphore (permit must live for the request duration)
    let permit = sem.acquire_owned().await?;
    Ok(permit)
}

#[cfg(feature = "subs_http")]
fn parse_allow_hosts() -> Vec<String> {
    std::env::var("SB_ADMIN_URL_ALLOW_HOSTS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(feature = "subs_http")]
const fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.octets()[0] == 169 && v4.octets()[1] == 254
            // link-local 169.254/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

#[cfg(feature = "subs_http")]
// DNS 解析+私网拒绝；同时应用 host allowlist
async fn resolve_and_check_host(host: &str) -> Result<(), &'static str> {
    let allow_hosts = parse_allow_hosts();
    if !allow_hosts.is_empty() && !allow_hosts.iter().any(|h| h == &host.to_lowercase()) {
        return Err("host not in allowlist");
    }
    if parse_env_bool("SB_ADMIN_URL_DENY_PRIVATE", true) {
        // 简化：仅解析 A/AAAA 第一条记录进行判定（已足够提升安全基线）
        let addrs = tokio::net::lookup_host((host, 80))
            .await
            .map_err(|_| "dns resolve failed")?;
        for addr in addrs {
            if is_private_ip(addr.ip()) {
                return Err("target resolves to private/loopback address");
            }
        }
    }
    Ok(())
}

/// # Errors
/// Returns an error if fetching fails due to rate limiting, circuit breaker, network issues, or response processing errors
#[cfg(feature = "subs_http")]
pub async fn fetch_with_limits(url: &str) -> anyhow::Result<String> {
    inc_total_requests();

    let t0 = Instant::now();

    // Rate limiting - acquire permits for both concurrency and RPS
    let permit = acquire_permits().await.map_err(|e| {
        crate::admin_debug::security_metrics::inc_rate_limited();
        set_last_error(SecurityErrorKind::RateLimited, format!("rate limit: {e}"));
        e
    })?;
    let result = async {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("").to_string();

    // Circuit breaker check
    if let Ok(mut br) = breaker::global().lock() {
        if !br.check(&host) {
            inc_breaker_block();
            set_last_error_with_host(SecurityErrorKind::Other, &host, "circuit breaker open");
            anyhow::bail!("circuit breaker open for host: {host}");
        }
    }
    // 同步 allowlist 快速放行/拒绝 + 异步 DNS 私网校验
    if let Err(e) = forbid_private_host_or_resolved_with_allowlist(&parsed) {
        inc_block_private_ip();
        set_last_error_with_host(
            SecurityErrorKind::PrivateBlocked,
            &host,
            format!("private/loopback: {e}"),
        );
        return Err(e);
    }
    if let Err(e) = forbid_private_host_or_resolved_async(&parsed).await {
        inc_block_private_ip();
        set_last_error_with_host(
            SecurityErrorKind::PrivateBlocked,
            &host,
            format!("dns-private: {e}"),
        );
        return Err(e);
    }

    // Get current configuration
    let config = reloadable::get();
    let _max_redirects = config.max_redirects;
    let timeout_ms = config.timeout_ms;
    let size_limit = config.max_bytes;

    // Build HTTP client with SafeRedirect policy
    use crate::admin_debug::http::redirect::SafeRedirect;
    let redirect =
        SafeRedirect::new(vec!["example.com".into(), "githubusercontent.com".into()]).policy();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(redirect))
        .connect_timeout(std::time::Duration::from_millis(timeout_ms.min(1500)))
        .user_agent(format!("sb-subs/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Try cache first and prepare conditional request
    let mut if_none_match = None;
    let mut has_cached_entry = false;
    if let Ok(mut lru) = cache::global().lock() {
        if let Some(cached_tier_entry) = lru.get(url) {
            inc_cache_hit();
            if_none_match = cached_tier_entry.etag().cloned();
            has_cached_entry = true;
        } else {
            inc_cache_miss();
        }
    }

    // HEAD pre-exploration if no cached ETag available
    let mut head_etag = None;
    if !has_cached_entry && std::env::var("SB_SUBS_HEAD_PRECHECK").ok().as_deref() == Some("1") {
        if let Ok(mut lru) = cache::global().lock() {
            lru.inc_head_count();
        }
        crate::admin_debug::security_metrics::inc_head_total();

        let _head_resp = match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms / 2), // Shorter timeout for HEAD
            client.head(parsed.clone()).send(),
        )
        .await
        {
            Ok(Ok(r)) if r.status().is_success() => {
                head_etag = r
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(std::string::ToString::to_string);
                Some(r)
            }
            _ => None, // HEAD failed or timed out, proceed with GET
        };

        if head_etag.is_some() {
            if_none_match = head_etag.clone();
        }
    }

    // Build request with conditional headers if we have an ETag
    let mut request_builder = client.get(parsed.clone());
    if let Some(etag) = &if_none_match {
        request_builder = request_builder.header(reqwest::header::IF_NONE_MATCH, etag);
    }

    let resp = match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        request_builder.send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            // 识别 TooManyRedirects (更稳定的类型检查)
            let mut is_tmr = false;
            let mut cur: &(dyn std::error::Error + 'static) = &e;
            while let Some(src) = cur.source() {
                if src.is::<reqwest::Error>() {
                    // 检查 reqwest error 是否为 redirect 类型
                    if src.to_string().contains("too many redirects")
                        || src.to_string().contains("redirect")
                    {
                        is_tmr = true;
                        break;
                    }
                }
                cur = src;
            }
            if is_tmr {
                inc_redirects();
                set_last_error_with_host(
                    SecurityErrorKind::TooManyRedirects,
                    &host,
                    "too many redirects",
                );
            }
            if e.is_connect() {
                inc_connect_timeout();
                set_last_error_with_host(
                    SecurityErrorKind::ConnectTimeout,
                    &host,
                    "connect timeout",
                );
            }
            // Mark circuit breaker failure
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
            return Err(e.into());
        }
        Err(_) => {
            inc_timeout();
            set_last_error_with_host(SecurityErrorKind::Timeout, &host, "overall timeout");
            // Mark circuit breaker failure
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
            return Err(anyhow::anyhow!("timeout"));
        }
    };

    // Handle 304 Not Modified - return cached content
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        if let Ok(mut lru) = cache::global().lock() {
            if let Some(cached_tier_entry) = lru.get(resp.url().as_str()) {
                // Handle both memory and disk cached entries
                let cached_body = cached_tier_entry
                    .get_body()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to read cached body: {e}"))?;
                let cached_string = String::from_utf8_lossy(&cached_body).to_string();
                record_latency_ms(t0.elapsed().as_millis() as u64);
                mark_last_ok();
                // Trigger prefetch for successful 304 response
                let et_local: Option<String> = cached_tier_entry.etag().cloned();
                maybe_enqueue_prefetch(&resp, et_local.as_ref());
                return Ok(cached_string);
            }
        }
        anyhow::bail!("cache miss on 304 response");
    }

    // 若发生重定向，检查最终 URL
    if resp.url() != &parsed {
        let redirect_host = resp.url().host_str().unwrap_or("").to_string();
        if let Err(e) = forbid_private_host_or_resolved_with_allowlist(resp.url()) {
            inc_block_private_ip();
            set_last_error_with_host(
                SecurityErrorKind::PrivateBlocked,
                &redirect_host,
                format!("redirect->private: {e}"),
            );
            return Err(e);
        }
        if let Err(e) = forbid_private_host_or_resolved_async(resp.url()).await {
            inc_block_private_ip();
            set_last_error_with_host(
                SecurityErrorKind::PrivateBlocked,
                &redirect_host,
                format!("redirect->dns-private: {e}"),
            );
            return Err(e);
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let code = resp.status().as_u16();
        if (400..500).contains(&code) {
            inc_upstream_4xx();
            set_last_error_with_host(
                SecurityErrorKind::Upstream4xx,
                &host,
                format!("upstream {status}"),
            );
        }
        if (500..600).contains(&code) {
            inc_upstream_5xx();
            set_last_error_with_host(
                SecurityErrorKind::Upstream5xx,
                &host,
                format!("upstream {status}"),
            );
        }
        // Mark circuit breaker failure for server errors
        if (500..600).contains(&code) {
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
        }
        anyhow::bail!("upstream status {status}");
    }

    // Check MIME allow list using reloadable config
    if let Some(allow_list) = &config.mime_allow {
        if let Some(ct) = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            let allowed = allow_list.iter().any(|pat| ct.starts_with(pat));
            if !allowed {
                set_last_error_with_host(
                    SecurityErrorKind::MimeDeny,
                    &host,
                    format!("mime not allowed: {ct}"),
                );
                anyhow::bail!("content-type not allowed: {ct}");
            }
        }
    }

    // Check MIME deny list using reloadable config
    if let Some(deny_list) = &config.mime_deny {
        if let Some(ct) = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            let denied = deny_list.iter().any(|pat| ct.starts_with(pat));
            if denied {
                set_last_error_with_host(
                    SecurityErrorKind::MimeDeny,
                    &host,
                    format!("mime denied: {ct}"),
                );
                anyhow::bail!("content-type denied: {ct}");
            }
        }
    }
    if let Some(cl) = resp.content_length() {
        if cl as usize > size_limit {
            inc_exceed_size();
            set_last_error_with_host(SecurityErrorKind::SizeExceed, &host, "cl exceed");
            anyhow::bail!("exceed size limit: {size_limit} bytes");
        }
    }
    // Extract all data before consuming response
    let response_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let response_content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let response_url = resp.url().clone();
    let response_headers = resp.headers().clone();

    let read_body = async {
        let mut body = bytes::BytesMut::with_capacity(std::cmp::min(size_limit, 8192));
        let mut stream = resp.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len() + chunk.len() > size_limit {
                inc_exceed_size();
                set_last_error_with_host(SecurityErrorKind::SizeExceed, &host, "stream exceed");
                anyhow::bail!("exceed size limit: {size_limit} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        Ok::<bytes::BytesMut, anyhow::Error>(body)
    };

    let body = match timeout(std::time::Duration::from_millis(timeout_ms), read_body).await {
        Ok(Ok(body)) => body,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            inc_timeout();
            set_last_error_with_host(SecurityErrorKind::Timeout, &host, "read timeout");
            return Err(anyhow::anyhow!("timeout"));
        }
    };

    // Record latency and mark success
    let dt = t0.elapsed().as_millis() as u64;
    record_latency_ms(dt);

    let out = String::from_utf8_lossy(&body).to_string();

    // Store in cache with ETag and Content-Type if available
    if let Ok(mut lru) = cache::global().lock() {
        let cache_entry = cache::CacheEntry {
            etag: response_etag.clone(),
            content_type: response_content_type,
            body: body.to_vec(),
            timestamp: std::time::Instant::now(),
        };

        lru.put(url.to_string(), cache_entry);
    }

    // Mark circuit breaker success
    if let Ok(mut br) = breaker::global().lock() {
        br.mark_success(&host);
    }

    mark_last_ok();
    // Trigger prefetch for successful 200 response
    let et_local: Option<String> = response_etag.clone();
    if let Some(ma) = cache_control_max_age(&response_headers) {
        if ma >= 60 {
            let _ = crate::admin_debug::prefetch::enqueue_prefetch(response_url.as_str(), et_local);
        }
    }
        Ok(out)
    }
    .await;
    drop(permit);
    result
}

#[cfg(feature = "subs_http")]
pub async fn fetch_with_limits_to_cache(
    url: &str,
    etag: Option<String>,
    is_prefetch: bool,
) -> anyhow::Result<crate::admin_debug::cache::CacheEntry> {
    inc_total_requests();

    let t0 = Instant::now();

    // Rate limiting - acquire permits for both concurrency and RPS
    let _permit = acquire_permits().await.map_err(|e| {
        crate::admin_debug::security_metrics::inc_rate_limited();
        set_last_error(SecurityErrorKind::RateLimited, format!("rate limit: {e}"));
        e
    })?;
    let parsed = url::Url::parse(url)?;
    let host = parsed.host_str().unwrap_or("").to_string();

    // Circuit breaker check
    if let Ok(mut br) = breaker::global().lock() {
        if !br.check(&host) {
            inc_breaker_block();
            set_last_error_with_host(SecurityErrorKind::Other, &host, "circuit breaker open");
            anyhow::bail!("circuit breaker open for host: {host}");
        }
    }

    // Async security checks
    if let Err(e) = forbid_private_host_or_resolved_with_allowlist(&parsed) {
        inc_block_private_ip();
        set_last_error_with_host(
            SecurityErrorKind::PrivateBlocked,
            &host,
            format!("private/loopback: {e}"),
        );
        return Err(e);
    }
    if let Err(e) = forbid_private_host_or_resolved_async(&parsed).await {
        inc_block_private_ip();
        set_last_error_with_host(
            SecurityErrorKind::PrivateBlocked,
            &host,
            format!("dns-private: {e}"),
        );
        return Err(e);
    }

    // Get current configuration
    let config = reloadable::get();
    let _max_redirects = config.max_redirects;
    let timeout_ms = config.timeout_ms;
    let size_limit = config.max_bytes;

    // Build HTTP client with SafeRedirect policy
    use crate::admin_debug::http::redirect::SafeRedirect;
    let redirect =
        SafeRedirect::new(vec!["example.com".into(), "githubusercontent.com".into()]).policy();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(redirect))
        .connect_timeout(std::time::Duration::from_millis(timeout_ms.min(1500)))
        .user_agent(format!("sb-subs/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Check cache first
    let mut if_none_match = etag;
    if let Ok(mut lru) = cache::global().lock() {
        if let Some(cached_tier_entry) = lru.get(url) {
            inc_cache_hit();
            if if_none_match.is_none() {
                if_none_match = cached_tier_entry.etag().cloned();
            }
        } else {
            inc_cache_miss();
        }
    }

    // Build request with conditional headers if we have an ETag
    let mut request_builder = client.get(parsed.clone());
    if let Some(etag_val) = &if_none_match {
        request_builder = request_builder.header(reqwest::header::IF_NONE_MATCH, etag_val);
    }

    let resp = match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        request_builder.send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            // Handle various error types
            if e.is_connect() {
                inc_connect_timeout();
                set_last_error_with_host(
                    SecurityErrorKind::ConnectTimeout,
                    &host,
                    "connect timeout",
                );
            }
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
            return Err(e.into());
        }
        Err(_) => {
            inc_timeout();
            set_last_error_with_host(SecurityErrorKind::Timeout, &host, "overall timeout");
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
            return Err(anyhow::anyhow!("timeout"));
        }
    };

    // Handle 304 Not Modified
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        let cached_entry = {
            if let Ok(mut lru) = cache::global().lock() {
                lru.get(resp.url().as_str())
            } else {
                None
            }
        };

        if let Some(cached_tier_entry) = cached_entry {
            let cached_body = cached_tier_entry
                .get_body()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read cached body: {e}"))?;
            record_latency_ms(t0.elapsed().as_millis() as u64);
            mark_last_ok();
            // Trigger prefetch for successful 304 response
            let et_local: Option<String> = cached_tier_entry.etag().cloned();
            maybe_enqueue_prefetch(&resp, et_local.as_ref());

            return Ok(crate::admin_debug::cache::CacheEntry {
                etag: cached_tier_entry.etag().cloned(),
                content_type: cached_tier_entry.content_type().cloned(),
                body: cached_body,
                timestamp: std::time::Instant::now(),
            });
        }
        if is_prefetch {
            anyhow::bail!("cache miss on 304 (prefetch)");
        }
        // Fallback: make a fresh request without If-None-Match for main path
        let fresh_resp = match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            client.get(parsed.clone()).send(),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                if e.is_connect() {
                    inc_connect_timeout();
                    set_last_error_with_host(
                        SecurityErrorKind::ConnectTimeout,
                        &host,
                        "connect timeout on fallback",
                    );
                }
                if let Ok(mut br) = breaker::global().lock() {
                    br.mark_failure(&host);
                }
                return Err(e.into());
            }
            Err(_) => {
                inc_timeout();
                set_last_error_with_host(SecurityErrorKind::Timeout, &host, "timeout on fallback");
                if let Ok(mut br) = breaker::global().lock() {
                    br.mark_failure(&host);
                }
                return Err(anyhow::anyhow!("timeout on fallback"));
            }
        };

        if !fresh_resp.status().is_success() {
            let status = fresh_resp.status();
            let code = fresh_resp.status().as_u16();
            if (400..500).contains(&code) {
                inc_upstream_4xx();
                set_last_error_with_host(
                    SecurityErrorKind::Upstream4xx,
                    &host,
                    format!("upstream {status} on fallback"),
                );
            }
            if (500..600).contains(&code) {
                inc_upstream_5xx();
                set_last_error_with_host(
                    SecurityErrorKind::Upstream5xx,
                    &host,
                    format!("upstream {status} on fallback"),
                );
            }
            if (500..600).contains(&code) {
                if let Ok(mut br) = breaker::global().lock() {
                    br.mark_failure(&host);
                }
            }
            anyhow::bail!("upstream status {status} on fallback");
        }

        // Process the fresh response like a normal success response
        let response_etag = fresh_resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(std::string::ToString::to_string);

        let response_content_type = fresh_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(std::string::ToString::to_string);

        let fresh_resp_url = fresh_resp.url().clone();
        let fresh_resp_headers = fresh_resp.headers().clone();

        // Check content length
        if let Some(cl) = fresh_resp.content_length() {
            if cl as usize > size_limit {
                inc_exceed_size();
                set_last_error_with_host(
                    SecurityErrorKind::SizeExceed,
                    &host,
                    "cl exceed on fallback",
                );
                anyhow::bail!("exceed size limit: {size_limit} bytes on fallback");
            }
        }

        let mut body = bytes::BytesMut::with_capacity(std::cmp::min(size_limit, 8192));
        let mut stream = fresh_resp.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len() + chunk.len() > size_limit {
                inc_exceed_size();
                set_last_error_with_host(
                    SecurityErrorKind::SizeExceed,
                    &host,
                    "stream exceed on fallback",
                );
                anyhow::bail!("exceed size limit: {size_limit} bytes on fallback");
            }
            body.extend_from_slice(&chunk);
        }

        // Record latency and mark success
        let dt = t0.elapsed().as_millis() as u64;
        record_latency_ms(dt);

        // Create cache entry
        let fresh_cache_entry = crate::admin_debug::cache::CacheEntry {
            etag: response_etag.clone(),
            content_type: response_content_type,
            body: body.to_vec(),
            timestamp: std::time::Instant::now(),
        };

        // Store in cache
        if let Ok(mut lru) = cache::global().lock() {
            lru.put(url.to_string(), fresh_cache_entry.clone());
        }

        // Mark circuit breaker success
        if let Ok(mut br) = breaker::global().lock() {
            br.mark_success(&host);
        }

        mark_last_ok();
        // Trigger prefetch for successful fallback 200 response
        let et_local: Option<String> = response_etag.clone();
        if let Some(ma) = cache_control_max_age(&fresh_resp_headers) {
            if ma >= 60 {
                let _ = crate::admin_debug::prefetch::enqueue_prefetch(
                    fresh_resp_url.as_str(),
                    et_local,
                );
            }
        }
        return Ok(fresh_cache_entry);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let code = resp.status().as_u16();
        if (400..500).contains(&code) {
            inc_upstream_4xx();
            set_last_error_with_host(
                SecurityErrorKind::Upstream4xx,
                &host,
                format!("upstream {status}"),
            );
        }
        if (500..600).contains(&code) {
            inc_upstream_5xx();
            set_last_error_with_host(
                SecurityErrorKind::Upstream5xx,
                &host,
                format!("upstream {status}"),
            );
        }
        if (500..600).contains(&code) {
            if let Ok(mut br) = breaker::global().lock() {
                br.mark_failure(&host);
            }
        }
        anyhow::bail!("upstream status {status}");
    }

    // Extract all data before consuming response
    let response_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let response_content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let resp_url = resp.url().clone();
    let resp_headers = resp.headers().clone();

    // Check content length
    if let Some(cl) = resp.content_length() {
        if cl as usize > size_limit {
            inc_exceed_size();
            set_last_error_with_host(SecurityErrorKind::SizeExceed, &host, "cl exceed");
            anyhow::bail!("exceed size limit: {size_limit} bytes");
        }
    }

    let mut body = bytes::BytesMut::with_capacity(std::cmp::min(size_limit, 8192));
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > size_limit {
            inc_exceed_size();
            set_last_error_with_host(SecurityErrorKind::SizeExceed, &host, "stream exceed");
            anyhow::bail!("exceed size limit: {size_limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }

    // Record latency and mark success
    let dt = t0.elapsed().as_millis() as u64;
    record_latency_ms(dt);

    // Create cache entry
    let cache_entry = crate::admin_debug::cache::CacheEntry {
        etag: response_etag.clone(),
        content_type: response_content_type,
        body: body.to_vec(),
        timestamp: std::time::Instant::now(),
    };

    // Store in cache
    if let Ok(mut lru) = cache::global().lock() {
        lru.put(url.to_string(), cache_entry.clone());
    }

    // Mark circuit breaker success
    if let Ok(mut br) = breaker::global().lock() {
        br.mark_success(&host);
    }

    mark_last_ok();
    // Trigger prefetch for successful 200 response
    let et_local: Option<String> = response_etag.clone();
    if let Some(ma) = cache_control_max_age(&resp_headers) {
        if ma >= 60 {
            let _ = crate::admin_debug::prefetch::enqueue_prefetch(resp_url.as_str(), et_local);
        }
    }
    Ok(cache_entry)
}

pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/subs/") {
        return Ok(());
    }

    let q = path_q.split_once('?').map_or("", |x| x.1);
    let _params = parse_query(q);

    // Check which sub-endpoint is being requested
    if path_q.starts_with("/subs/fetch") {
        // Check if networking is allowed
        if !is_networking_allowed() {
            return respond_json_error(
                sock,
                501,
                "networking disabled",
                Some("set SB_ADMIN_ALLOW_NET=1 to enable networking"),
            )
            .await;
        }

        #[cfg(feature = "subs_http")]
        {
            let params = parse_query(q);
            let url = params.get("url").cloned().unwrap_or_default();
            if url.is_empty() {
                return respond_json_error(
                    sock,
                    400,
                    "missing url parameter",
                    Some("provide url in ?url parameter"),
                )
                .await;
            }

            // Validate URL scheme for security
            if validate_url_scheme(&url).is_err() {
                return respond_json_error(
                    sock,
                    400,
                    "invalid URL scheme",
                    Some("only http:// and https:// schemes are allowed"),
                )
                .await;
            }

            // 解析主机并安全检查
            let host = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(std::string::ToString::to_string))
                .ok_or_else(|| std::io::Error::other("invalid url"))?;
            if let Err(e) = resolve_and_check_host(&host).await {
                return respond_json_error(sock, 400, "unsafe target", Some(e)).await;
            }

            // 限制
            let timeout_ms = parse_env_u64("SB_ADMIN_FETCH_TIMEOUT_MS", 8000);
            let max_redirects = parse_env_usize("SB_ADMIN_FETCH_MAX_REDIRECTS", 5);
            let max_bytes = parse_env_usize("SB_ADMIN_FETCH_MAX_BYTES", 1_048_576);

            // 构建 client with custom redirect policy for hop-by-hop validation
            let allow_hosts_clone = parse_allow_hosts();
            let deny_private = parse_env_bool("SB_ADMIN_URL_DENY_PRIVATE", true);

            let client = Client::builder()
                .redirect(Policy::custom(move |attempt| {
                    if attempt.previous().len() >= max_redirects {
                        return attempt.stop();
                    }

                    let url = attempt.url();
                    if let Some(host) = url.host_str() {
                        // Host allowlist check
                        if !allow_hosts_clone.is_empty()
                            && !allow_hosts_clone.iter().any(|h| h == &host.to_lowercase())
                        {
                            return attempt.error("redirect host not in allowlist");
                        }

                        // Private/loopback address check (DNS resolution)
                        if deny_private {
                            // Note: this is a sync operation in async context,
                            // but reqwest redirect policy requires sync
                            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host, 80))
                            {
                                for addr in addrs {
                                    if is_private_ip(addr.ip()) {
                                        return attempt
                                            .error("redirect to private/loopback address");
                                    }
                                }
                            }
                        }
                    }

                    attempt.follow()
                }))
                .build()
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            // 请求 + 总体超时
            let fut = client.get(&url).send();
            let resp = match timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    return respond_json_error(sock, 502, "fetch failed", Some(&e.to_string()))
                        .await
                }
                Err(_) => {
                    return respond_json_error(
                        sock,
                        504,
                        "fetch timeout",
                        Some("increase SB_ADMIN_FETCH_TIMEOUT_MS"),
                    )
                    .await
                }
            };

            if !resp.status().is_success() {
                return respond_json_error(
                    sock,
                    resp.status().as_u16(),
                    "upstream error",
                    Some("non-2xx status"),
                )
                .await;
            }

            // 体积限制读取
            let mut stream_body = resp.bytes_stream();
            use futures_util::StreamExt;
            let mut buf = bytes::BytesMut::with_capacity(std::cmp::min(64 * 1024, max_bytes));
            let mut total = 0usize;
            while let Some(chunk) = stream_body.next().await {
                let chunk = chunk.map_err(|e| std::io::Error::other(e.to_string()))?;
                total += chunk.len();
                if total > max_bytes {
                    return respond_json_error(
                        sock,
                        413,
                        "fetched content too large",
                        Some("increase SB_ADMIN_FETCH_MAX_BYTES"),
                    )
                    .await;
                }
                buf.extend_from_slice(&chunk);
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            respond(sock, 200, "text/plain; charset=utf-8", &text).await
        }
        #[cfg(not(feature = "subs_http"))]
        {
            respond_json_error(
                sock,
                501,
                "subs_http feature not enabled",
                Some("enable subs_http feature"),
            )
            .await
        }
    } else if path_q.starts_with("/subs/convert") {
        let params = parse_query(q);
        let format = params.get("format").cloned().unwrap_or_default();
        let mode = params
            .get("mode")
            .cloned()
            .unwrap_or_else(|| "suffix".to_string());
        let b64_content = params.get("inline").cloned().unwrap_or_default();

        // Validate format
        if validate_format(&format).is_err() {
            return respond_json_error(
                sock,
                400,
                "invalid format",
                Some("format must be 'clash' or 'singbox'"),
            )
            .await;
        }

        if b64_content.is_empty() {
            return respond_json_error(
                sock,
                400,
                "missing inline parameter",
                Some("provide base64 content in ?inline parameter"),
            )
            .await;
        }

        // Validate size estimate before decoding
        if validate_inline_size_estimate(&b64_content).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        let bytes: Vec<u8> = match STANDARD.decode(b64_content.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                return respond_json_error(
                    sock,
                    400,
                    "invalid base64 encoding",
                    Some("provide valid base64 in ?inline parameter"),
                )
                .await
            }
        };

        // Validate actual decoded size
        if validate_decoded_size(&bytes).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        let text = String::from_utf8_lossy(&bytes).to_string();

        let profile: Result<_, sb_subscribe::model::SubsError> = match format.as_str() {
            "clash" => {
                #[cfg(feature = "subs_clash")]
                {
                    sb_subscribe::parse_clash::parse_with_mode(&text, &mode == "keyword")
                }
                #[cfg(not(feature = "subs_clash"))]
                {
                    Err::<sb_subscribe::model::Profile, _>(
                        sb_subscribe::model::SubsError::Unsupported,
                    )
                }
            }
            "singbox" => {
                #[cfg(feature = "subs_singbox")]
                {
                    sb_subscribe::parse_singbox::parse_with_mode(&text, &mode == "keyword")
                }
                #[cfg(not(feature = "subs_singbox"))]
                {
                    Err::<sb_subscribe::model::Profile, _>(
                        sb_subscribe::model::SubsError::Unsupported,
                    )
                }
            }
            _ => Err(sb_subscribe::model::SubsError::Unsupported),
        };

        match profile {
            Ok(pf) => {
                let joined = pf
                    .rules
                    .iter()
                    .map(|r| r.line.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let norm = sb_core::router::normalize::normalize(&joined);
                respond(sock, 200, "text/plain", &norm).await
            }
            Err(_) => {
                respond_json_error(
                    sock,
                    400,
                    "unsupported format or parse error",
                    Some("check format parameter and content"),
                )
                .await
            }
        }
    } else if path_q.starts_with("/subs/parse") {
        let params = parse_query(q);
        let format = params.get("format").cloned().unwrap_or_default();
        let mode = params
            .get("mode")
            .cloned()
            .unwrap_or_else(|| "suffix".to_string());
        let b64_content = params.get("inline").cloned().unwrap_or_default();

        if b64_content.is_empty() {
            return respond_json_error(
                sock,
                400,
                "missing inline parameter",
                Some("provide base64 content in ?inline parameter"),
            )
            .await;
        }

        // Validate size estimate before decoding
        if validate_inline_size_estimate(&b64_content).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        let bytes: Vec<u8> = match STANDARD.decode(b64_content.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                return respond_json_error(
                    sock,
                    400,
                    "invalid base64 encoding",
                    Some("provide valid base64 in ?inline parameter"),
                )
                .await
            }
        };

        // Validate actual decoded size
        if validate_decoded_size(&bytes).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        let text = String::from_utf8_lossy(&bytes).to_string();

        let profile: Result<_, sb_subscribe::model::SubsError> = match format.as_str() {
            "clash" => {
                #[cfg(feature = "subs_clash")]
                {
                    sb_subscribe::parse_clash::parse_with_mode(&text, &mode == "keyword")
                }
                #[cfg(not(feature = "subs_clash"))]
                {
                    Err::<sb_subscribe::model::Profile, _>(
                        sb_subscribe::model::SubsError::Unsupported,
                    )
                }
            }
            "singbox" => {
                #[cfg(feature = "subs_singbox")]
                {
                    sb_subscribe::parse_singbox::parse_with_mode(&text, &mode == "keyword")
                }
                #[cfg(not(feature = "subs_singbox"))]
                {
                    Err::<sb_subscribe::model::Profile, _>(
                        sb_subscribe::model::SubsError::Unsupported,
                    )
                }
            }
            _ => Err(sb_subscribe::model::SubsError::Unsupported),
        };

        match profile {
            Ok(pf) => {
                #[derive(Serialize)]
                struct ProfileSummary {
                    rules: usize,
                    outbounds: usize,
                }

                let summary = ProfileSummary {
                    rules: pf.rules.len(),
                    outbounds: pf.outbounds.len(),
                };
                let body = serde_json::to_string(&summary)
                    .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_string());
                respond(sock, 200, "application/json", &body).await
            }
            Err(_) => {
                respond_json_error(
                    sock,
                    400,
                    "unsupported format or parse error",
                    Some("check format parameter and content"),
                )
                .await
            }
        }
    } else if path_q.starts_with("/subs/plan") {
        #[cfg(feature = "sbcore_rules_tool")]
        {
            let params = parse_query(q);
            let b64_content = params.get("inline").cloned().unwrap_or_default();
            let format = params.get("format").cloned().unwrap_or_default();
            let kinds = params.get("kinds").cloned().unwrap_or_default();

            // Validate format
            if validate_format(&format).is_err() {
                return respond_json_error(
                    sock,
                    400,
                    "invalid format",
                    Some("format must be 'clash' or 'singbox'"),
                )
                .await;
            }

            // Validate kinds
            if let Err(ref err_msg) = validate_kinds(&kinds) {
                return respond_json_error(sock, 400, "invalid kinds parameter", Some(err_msg))
                    .await;
            }

            if b64_content.is_empty() {
                return respond_json_error(
                    sock,
                    400,
                    "missing inline parameter",
                    Some("provide base64 content in ?inline parameter"),
                )
                .await;
            }

            // Validate size estimate before decoding
            if validate_inline_size_estimate(&b64_content).is_err() {
                return respond_json_error(
                    sock,
                    413,
                    "inline content too large",
                    Some("maximum size is 512KB"),
                )
                .await;
            }

            let bytes: Vec<u8> = match STANDARD.decode(b64_content.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    return respond_json_error(
                        sock,
                        400,
                        "invalid base64 encoding",
                        Some("provide valid base64 in ?inline parameter"),
                    )
                    .await
                }
            };

            // Validate actual decoded size
            if validate_decoded_size(&bytes).is_err() {
                return respond_json_error(
                    sock,
                    413,
                    "inline content too large",
                    Some("maximum size is 512KB"),
                )
                .await;
            }

            let text = String::from_utf8_lossy(&bytes).to_string();

            let profile: Result<_, sb_subscribe::model::SubsError> = match format.as_str() {
                "clash" => {
                    #[cfg(feature = "subs_clash")]
                    {
                        sb_subscribe::parse_clash::parse_with_mode(&text, false)
                    }
                    #[cfg(not(feature = "subs_clash"))]
                    {
                        Err::<sb_subscribe::model::Profile, _>(
                            sb_subscribe::model::SubsError::Unsupported,
                        )
                    }
                }
                "singbox" => {
                    #[cfg(feature = "subs_singbox")]
                    {
                        sb_subscribe::parse_singbox::parse_with_mode(&text, false)
                    }
                    #[cfg(not(feature = "subs_singbox"))]
                    {
                        Err::<sb_subscribe::model::Profile, _>(
                            sb_subscribe::model::SubsError::Unsupported,
                        )
                    }
                }
                _ => Err(sb_subscribe::model::SubsError::Unsupported),
            };

            match profile {
                Ok(pf) => {
                    let rules_text = pf
                        .rules
                        .iter()
                        .map(|r| r.line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let norm = sb_core::router::rules_normalize(&rules_text);
                    let kinds_v = validate_kinds(&kinds).unwrap_or_default();
                    let kinds_str_refs: Vec<&str> =
                        kinds_v.iter().map(std::string::String::as_str).collect();
                    let plan = sb_core::router::patch_plan::build_plan(
                        &norm,
                        &kinds_str_refs,
                        Some("rules.conf"),
                    );
                    use sb_core::router::minijson::{self, Val};
                    let body = minijson::obj([
                        ("summary", Val::Raw(&plan.summary.to_json())),
                        ("patch", Val::Str(&plan.patch_text)),
                    ]);
                    respond(sock, 200, "application/json", &body).await
                }
                Err(_) => {
                    respond_json_error(
                        sock,
                        400,
                        "unsupported format or parse error",
                        Some("check format parameter and content"),
                    )
                    .await
                }
            }
        }
        #[cfg(not(feature = "sbcore_rules_tool"))]
        {
            respond_json_error(
                sock,
                501,
                "sbcore_rules_tool feature not enabled",
                Some("enable sbcore_rules_tool feature"),
            )
            .await
        }
    } else {
        respond_json_error(sock, 404, "unknown subs endpoint", None).await
    }
}

/// 解析 Cache-Control: max-age
#[cfg(feature = "subs_http")]
pub fn cache_control_max_age(h: &reqwest::header::HeaderMap) -> Option<u64> {
    use reqwest::header::CACHE_CONTROL;
    let s = h.get(CACHE_CONTROL)?.to_str().ok()?;
    for d in s.split(',') {
        let d = d.trim();
        if let Some(v) = d.strip_prefix("max-age=") {
            if let Ok(n) = v.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

/// 在主路径成功后触发预取（200/304 且 max-age>=60）
#[cfg(feature = "subs_http")]
pub(crate) fn maybe_enqueue_prefetch(resp: &reqwest::Response, response_etag: Option<&String>) {
    if let Some(ma) = cache_control_max_age(resp.headers()) {
        if ma >= 60 {
            let _ = crate::admin_debug::prefetch::enqueue_prefetch(
                resp.url().as_str(),
                response_etag.cloned(),
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "admin_tests")]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_limiter_resize_concurrency() {
        // Test concurrency resize from 2 -> 8 -> 3
        resize_limiters(2, 10);

        // Try to acquire more permits than initial limit
        let mut tasks = Vec::new();

        // Should be able to get 2 permits
        for _ in 0..2 {
            let task = tokio::spawn(async { acquire_permits().await.is_ok() });
            tasks.push(task);
        }

        // Give some time for tasks to complete
        sleep(Duration::from_millis(100)).await;

        // Increase to 8
        resize_limiters(8, 10);

        // Now should be able to get more permits
        for _ in 0..6 {
            let task = tokio::spawn(async { acquire_permits().await.is_ok() });
            tasks.push(task);
        }

        // Wait for all tasks
        let results: Vec<_> = futures_util::future::join_all(tasks).await;
        let success_count = results
            .iter()
            .filter(|r| *r.as_ref().unwrap_or(&false))
            .count();

        // Should have at least some successful acquisitions
        assert!(
            success_count >= 2,
            "Expected at least 2 successful permit acquisitions"
        );
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_rps_resize() {
        // Test RPS resize functionality
        resize_rps(2);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), 2);
        assert_eq!(RPS_CURRENT.load(Ordering::Relaxed), 2);

        resize_rps(10);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), 10);
        assert_eq!(RPS_CURRENT.load(Ordering::Relaxed), 10);
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_tick_based_rps_refill() {
        // Set low RPS for testing
        resize_rps(1);

        // Consume the single token
        let result1 = acquire_permits().await;
        assert!(result1.is_ok(), "First request should succeed");

        // Immediate second request should fail (rate limited)
        let start = Instant::now();
        let result2 = acquire_permits().await;
        let duration = start.elapsed();

        // Should either succeed after waiting or fail quickly
        if result2.is_err() {
            assert!(
                duration.as_millis() > 500,
                "Should have waited at least 500ms before failing"
            );
        }

        // Wait for next second and try again - should work
        sleep(Duration::from_secs(2)).await;
        let result3 = acquire_permits().await;
        assert!(result3.is_ok(), "Request after tick reset should succeed");
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_concurrent_resize_operations() {
        // Test thread safety of resize operations
        let handles: Vec<_> = (0..10)
            .map(|i| {
                tokio::spawn(async move {
                    resize_limiters(i + 1, (i + 1) as u64);
                    sleep(Duration::from_millis(10)).await;
                    resize_rps((i + 5) as u64);
                })
            })
            .collect();

        futures_util::future::join_all(handles).await;

        // Final state should be consistent (no panics/races)
        let cap = RPS_CAP.load(Ordering::Relaxed);
        let current = RPS_CURRENT.load(Ordering::Relaxed);
        assert!(cap > 0, "RPS capacity should be positive");
        assert!(current <= cap, "Current tokens should not exceed capacity");
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_semi_hot_expansion_logic() {
        // Test the semi-hot expansion logic that dynamically adds permits
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        // Create a test scenario where desired concurrency increases
        resize_limiters(2, 10);

        // Set desired concurrency higher than current
        DESIRED_CONCURRENCY.store(8, Ordering::Relaxed);

        // Start with multiple tasks that should trigger expansion
        let tasks: Vec<_> = (0..6)
            .map(|i| {
                tokio::spawn(async move {
                    // Each acquire_permits call should potentially trigger expansion
                    let result = acquire_permits().await;
                    sleep(Duration::from_millis(50 * (i + 1) as u64)).await; // Stagger releases
                    result
                })
            })
            .collect();

        let results = futures_util::future::join_all(tasks).await;
        let success_count = results.iter().filter(|r| matches!(r, Ok(Ok(_)))).count();

        // Should have successful acquisitions due to semi-hot expansion
        assert!(
            success_count >= 2,
            "Semi-hot expansion should allow at least 2 acquisitions, got {}",
            success_count
        );
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_expansion_limit() {
        // Test that expansion is limited to prevent abuse
        resize_limiters(1, 10);

        // Set an extremely high desired concurrency (should be capped)
        DESIRED_CONCURRENCY.store(100, Ordering::Relaxed);

        // Try to trigger expansion
        let result = acquire_permits().await;

        // Should still work but not add 100 permits at once
        assert!(
            result.is_ok(),
            "Acquisition should succeed even with high desired concurrency"
        );

        // Reset to reasonable value
        DESIRED_CONCURRENCY.store(4, Ordering::Relaxed);
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_end_to_end_hot_reload() {
        // Simulate a complete hot-reload scenario
        let initial_conc = 3;
        let initial_rps = 5;
        let new_conc = 12;
        let new_rps = 20;

        // Start with initial configuration
        resize_limiters(initial_conc, initial_rps);
        assert_eq!(DESIRED_CONCURRENCY.load(Ordering::Relaxed), initial_conc);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), initial_rps);

        // Verify initial capacity works
        let initial_tasks: Vec<_> = (0..2)
            .map(|_| tokio::spawn(async { acquire_permits().await.is_ok() }))
            .collect();

        sleep(Duration::from_millis(50)).await;

        // Now simulate hot reload with higher capacity
        resize_limiters(new_conc, new_rps);

        // Verify new configuration is active
        assert_eq!(DESIRED_CONCURRENCY.load(Ordering::Relaxed), new_conc);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), new_rps);

        // Should now support higher concurrency
        let expanded_tasks: Vec<_> = (0..8)
            .map(|_| tokio::spawn(async { acquire_permits().await.is_ok() }))
            .collect();

        // Wait for all tasks and count successes
        let initial_results = futures_util::future::join_all(initial_tasks).await;
        let expanded_results = futures_util::future::join_all(expanded_tasks).await;

        let initial_success = initial_results
            .iter()
            .filter(|r| *r.as_ref().unwrap_or(&false))
            .count();
        let expanded_success = expanded_results
            .iter()
            .filter(|r| *r.as_ref().unwrap_or(&false))
            .count();

        assert!(initial_success >= 1, "Initial tasks should succeed");
        assert!(
            expanded_success >= 4,
            "Expanded capacity should support more concurrent tasks"
        );
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_rps_hot_reload_with_token_reset() {
        // Test that RPS changes immediately reset token count
        resize_rps(3);
        assert_eq!(RPS_CURRENT.load(Ordering::Relaxed), 3);

        // Consume all tokens
        for _ in 0..3 {
            let result = acquire_permits().await;
            if result.is_err() {
                break; // Rate limited, which is expected
            }
        }

        // Hot-reload with higher RPS
        resize_rps(10);

        // Should immediately have new token capacity
        assert_eq!(RPS_CURRENT.load(Ordering::Relaxed), 10);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), 10);

        // Should be able to make requests again immediately
        let result = acquire_permits().await;
        assert!(
            result.is_ok() || matches!(result, Err(e) if e.to_string().contains("rate limited")),
            "Should either succeed or be rate limited, not other errors"
        );
    }

    #[cfg(feature = "subs_http")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_resize_limiters_atomicity() {
        // Test that resize_limiters updates both concurrency and RPS atomically
        let original_conc = DESIRED_CONCURRENCY.load(Ordering::Relaxed);
        let original_rps = RPS_CAP.load(Ordering::Relaxed);

        let new_conc = 7;
        let new_rps = 15;

        // Perform atomic resize
        resize_limiters(new_conc, new_rps);

        // Both should be updated
        assert_eq!(DESIRED_CONCURRENCY.load(Ordering::Relaxed), new_conc);
        assert_eq!(RPS_CAP.load(Ordering::Relaxed), new_rps);
        assert_eq!(RPS_CURRENT.load(Ordering::Relaxed), new_rps); // Should reset current tokens

        // Semaphore should be hot-swapped
        if let Some(sem_lock) = MAX_CONC.get() {
            let sem_guard = sem_lock.read().await;
            // We can't directly check the semaphore capacity, but it should be functioning
            let available = sem_guard.available_permits();
            assert!(
                available <= new_conc,
                "Available permits should not exceed new concurrency limit"
            );
        }
    }
}
