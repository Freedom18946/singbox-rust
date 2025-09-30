use crate::admin_debug::security_metrics as sm;
use tokio::io::AsyncWriteExt;
use std::fmt::Write as _;

use prometheus::{register_int_gauge, IntGauge};

static PREFETCH_QUEUE_DEPTH: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("sb_prefetch_queue_depth", "Prefetch queue depth")
        .expect("Failed to register PREFETCH_QUEUE_DEPTH metric")
});

/// 供 `security_metrics` 调用，更新 Prom Gauge
pub fn update_prefetch_depth(v: i64) {
    PREFETCH_QUEUE_DEPTH.set(v);
}

fn line(k: &str, v: u64) -> String {
    format!("{k} {v}\n")
}

/// # Errors
/// Returns an IO error if metrics cannot be written to the socket
pub async fn handle(sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    let h = sm::snapshot();
    let mut buf = String::new();
    buf.push_str("# HELP sb_subs_requests_total total subs fetch requests\n# TYPE sb_subs_requests_total counter\n");
    buf.push_str(&line("sb_subs_requests_total", h.total_requests));
    buf.push_str("# HELP sb_subs_failures_total total failed subs fetch\n# TYPE sb_subs_failures_total counter\n");
    buf.push_str(&line("sb_subs_failures_total", h.total_fails));
    buf.push_str("# HELP sb_subs_timeout_total total overall timeouts\n# TYPE sb_subs_timeout_total counter\n");
    buf.push_str(&line("sb_subs_timeout_total", h.subs_timeout));
    buf.push_str("# HELP sb_subs_connect_timeout_total connect timeout\n# TYPE sb_subs_connect_timeout_total counter\n");
    buf.push_str(&line(
        "sb_subs_connect_timeout_total",
        h.subs_connect_timeout,
    ));
    buf.push_str("# HELP sb_subs_redirects_total too many redirects\n# TYPE sb_subs_redirects_total counter\n");
    buf.push_str(&line("sb_subs_redirects_total", h.subs_too_many_redirects));
    buf.push_str("# HELP sb_subs_exceed_bytes_total exceed size limit\n# TYPE sb_subs_exceed_bytes_total counter\n");
    buf.push_str(&line("sb_subs_exceed_bytes_total", h.subs_exceed_size));
    buf.push_str("# HELP sb_subs_block_private_total private/loopback blocked\n# TYPE sb_subs_block_private_total counter\n");
    buf.push_str(&line(
        "sb_subs_block_private_total",
        h.subs_block_private_ip,
    ));
    buf.push_str("# HELP sb_subs_upstream_4xx_total upstream 4xx\n# TYPE sb_subs_upstream_4xx_total counter\n");
    buf.push_str(&line("sb_subs_upstream_4xx_total", h.subs_upstream_4xx));
    buf.push_str("# HELP sb_subs_upstream_5xx_total upstream 5xx\n# TYPE sb_subs_upstream_5xx_total counter\n");
    buf.push_str(&line("sb_subs_upstream_5xx_total", h.subs_upstream_5xx));
    buf.push_str("# HELP sb_subs_rate_limited_total rate limited requests\n# TYPE sb_subs_rate_limited_total counter\n");
    buf.push_str(&line("sb_subs_rate_limited_total", h.subs_rate_limited));
    buf.push_str(
        "# HELP sb_subs_cache_hit_total cache hits\n# TYPE sb_subs_cache_hit_total counter\n",
    );
    buf.push_str(&line("sb_subs_cache_hit_total", h.subs_cache_hit));
    buf.push_str(
        "# HELP sb_subs_cache_miss_total cache misses\n# TYPE sb_subs_cache_miss_total counter\n",
    );
    buf.push_str(&line("sb_subs_cache_miss_total", h.subs_cache_miss));
    buf.push_str("# HELP sb_subs_cache_evict_total cache evictions by tier\n# TYPE sb_subs_cache_evict_total counter\n");
    let _ = writeln!(buf, "sb_subs_cache_evict_total{{tier=\"mem\"}} {}", h.subs_cache_evict_mem);
    let _ = writeln!(buf, "sb_subs_cache_evict_total{{tier=\"disk\"}} {}", h.subs_cache_evict_disk);
    buf.push_str(
        "# HELP sb_subs_cache_bytes cache byte usage by tier\n# TYPE sb_subs_cache_bytes gauge\n",
    );
    let _ = writeln!(buf, "sb_subs_cache_bytes{{tier=\"mem\"}} {}", h.cache_bytes_mem);
    let _ = writeln!(buf, "sb_subs_cache_bytes{{tier=\"disk\"}} {}", h.cache_bytes_disk);
    buf.push_str(
        "# HELP sb_subs_head_total HEAD request total\n# TYPE sb_subs_head_total counter\n",
    );
    buf.push_str(&line("sb_subs_head_total", h.subs_head_total));
    buf.push_str("# HELP sb_subs_breaker_block_total circuit breaker blocks\n# TYPE sb_subs_breaker_block_total counter\n");
    buf.push_str(&line("sb_subs_breaker_block_total", h.subs_breaker_block));
    buf.push_str("# HELP sb_subs_breaker_reopen_total circuit breaker reopen events\n# TYPE sb_subs_breaker_reopen_total counter\n");
    buf.push_str(&line("sb_subs_breaker_reopen_total", h.subs_breaker_reopen));

    // Breaker state by host hash for low cardinality monitoring
    buf.push_str("# HELP sb_subs_breaker_state circuit breaker state by host hash\n# TYPE sb_subs_breaker_state gauge\n");
    for (host_hash, state, _reopen_count) in &h.breaker_states {
        // Export each state as 0/1 gauge for this host
        for possible_state in &["closed", "open", "half_open"] {
            let value = i32::from(state == possible_state);
            let _ = writeln!(buf, "sb_subs_breaker_state{{host_hash=\"{host_hash}\",state=\"{possible_state}\"}} {value}");
        }
    }

    // Current concurrency usage
    buf.push_str("# HELP sb_subs_limiter_concurrency current concurrent connections\n# TYPE sb_subs_limiter_concurrency gauge\n");
    let _ = writeln!(buf, "sb_subs_limiter_concurrency {}", h.limiter_current_concurrency);

    // DNS resolution metrics
    buf.push_str("# HELP sb_subs_dns_cache_hit_total DNS cache hits\n# TYPE sb_subs_dns_cache_hit_total counter\n");
    buf.push_str(&line("sb_subs_dns_cache_hit_total", h.dns_cache_hit));
    buf.push_str("# HELP sb_subs_dns_cache_miss_total DNS cache misses\n# TYPE sb_subs_dns_cache_miss_total counter\n");
    buf.push_str(&line("sb_subs_dns_cache_miss_total", h.dns_cache_miss));

    // DNS latency histogram
    buf.push_str("# HELP sb_subs_dns_resolve_seconds DNS resolve latency\n# TYPE sb_subs_dns_resolve_seconds histogram\n");
    for (le, c) in &h.dns_latency_buckets {
        let bucket = if *le >= 999_999.0 {
            "+Inf".to_string()
        } else {
            le.to_string()
        };
        let _ = writeln!(buf, "sb_subs_dns_resolve_seconds_bucket{{le=\"{bucket}\"}} {c}");
    }
    let _ = writeln!(buf, "sb_subs_dns_resolve_seconds_count {}", h.dns_latency_count);
    #[allow(clippy::cast_precision_loss)]
    let _ = writeln!(buf, "sb_subs_dns_resolve_seconds_sum {}", h.dns_latency_sum_ms as f64 / 1000.0);

    // Error kind enumeration counts
    buf.push_str("# HELP sb_subs_error_kind_total error counts by kind\n# TYPE sb_subs_error_kind_total counter\n");
    for (k, v) in &h.error_kinds {
        let _ = writeln!(buf, "sb_subs_error_kind_total{{kind=\"{}\"}} {}", k.as_str(), v);
    }

    // Low-cardinality error counts by host hash (sampled)
    buf.push_str("# HELP sb_subs_error_kind_by_hash_total sampled error counts by kind and host hash\n# TYPE sb_subs_error_kind_by_hash_total counter\n");
    for ((kind, host_hash), count) in &h.error_kinds_by_hash {
        let _ = writeln!(buf, "sb_subs_error_kind_by_hash_total{{kind=\"{}\",host_hash=\"{}\"}} {}", kind.as_str(), host_hash, count);
    }

    // Request latency histogram with finer buckets
    buf.push_str(
        "# HELP sb_subs_fetch_seconds request latency\n# TYPE sb_subs_fetch_seconds histogram\n",
    );
    for (le, c) in &h.latency_buckets {
        let bucket = if *le >= 999_999.0 {
            "+Inf".to_string()
        } else {
            format!("{le:.3}")
        };
        let _ = writeln!(buf, "sb_subs_fetch_seconds_bucket{{le=\"{bucket}\"}} {c}");
    }
    let _ = writeln!(buf, "sb_subs_fetch_seconds_count {}", h.latency_count);
    #[allow(clippy::cast_precision_loss)]
    let _ = writeln!(buf, "sb_subs_fetch_seconds_sum {}", h.latency_sum_ms as f64 / 1000.0);

    // Prefetch metrics
    buf.push_str("# HELP sb_prefetch_queue_depth Prefetch queue depth\n# TYPE sb_prefetch_queue_depth gauge\n");
    let _ = writeln!(buf, "sb_prefetch_queue_depth {}", h.prefetch_queue_depth);

    buf.push_str("# HELP sb_prefetch_queue_high_watermark Prefetch queue high watermark\n# TYPE sb_prefetch_queue_high_watermark gauge\n");
    let _ = writeln!(buf, "sb_prefetch_queue_high_watermark {}", crate::admin_debug::security_metrics::get_prefetch_queue_high_watermark());

    buf.push_str("# HELP sb_prefetch_jobs_total Prefetch job events\n# TYPE sb_prefetch_jobs_total counter\n");
    let _ = writeln!(buf, "sb_prefetch_jobs_total{{event=\"enq\"}} {}", h.prefetch_enqueue);
    let _ = writeln!(buf, "sb_prefetch_jobs_total{{event=\"drop\"}} {}", h.prefetch_drop);
    let _ = writeln!(buf, "sb_prefetch_jobs_total{{event=\"done\"}} {}", h.prefetch_done);
    let _ = writeln!(buf, "sb_prefetch_jobs_total{{event=\"fail\"}} {}", h.prefetch_fail);
    let _ = writeln!(buf, "sb_prefetch_jobs_total{{event=\"retry\"}} {}", h.prefetch_retry);

    // Prefetch run time histogram
    buf.push_str("# HELP sb_prefetch_run_seconds Prefetch worker execution time\n# TYPE sb_prefetch_run_seconds histogram\n");
    for (le, c) in &h.prefetch_run_buckets {
        let bucket = if *le >= 999_999.0 {
            "+Inf".to_string()
        } else {
            format!("{le:.3}")
        };
        let _ = writeln!(buf, "sb_prefetch_run_seconds_bucket{{le=\"{bucket}\"}} {c}");
    }

    crate::admin_debug::http_util::respond(sock, 200, "text/plain; version=0.0.4", &buf).await
}
