// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::undocumented_unsafe_blocks
    )
)]
use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use parking_lot::Mutex;
#[cfg(feature = "reqwest")]
use reqwest::Method;
use serde::Serialize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

#[derive(ClapArgs, Debug)]
pub struct BenchArgs {
    #[command(subcommand)]
    pub cmd: BenchCmd,
}

#[derive(Subcommand, Debug)]
pub enum BenchCmd {
    /// 简易 HTTP I/O 基准
    Io {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 100)]
        requests: u32,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        #[arg(long)]
        json: bool,
        /// HTTP 方法
        #[arg(long, value_parser=["GET","POST","PUT","DELETE","HEAD","PATCH"], default_value="GET")]
        method: String,
        /// 请求体（@file 或 字面值）
        #[arg(long)]
        body: Option<String>,
        /// 追加头（可多次）K:V
        #[arg(long = "hdr")]
        hdrs: Vec<String>,
        /// 允许 HTTP/2
        #[arg(long)]
        h2: bool,
        /// 不验证 TLS
        #[arg(long)]
        insecure: bool,
        /// 保持连接
        #[arg(long)]
        keepalive: bool,
        /// 客户端超时（毫秒）
        #[arg(long, default_value_t = 10000)]
        timeout_ms: u64,
        /// 输出延迟直方图：以毫秒为单位的边界，逗号分隔（例：1,5,10,20,50,100,200）
        #[arg(long = "hist-buckets")]
        hist_buckets: Option<String>,
        /// 将结果保存为 JSON
        #[arg(long = "save")]
        save_path: Option<std::path::PathBuf>,
        /// Preferred output path (alias of --save)
        #[arg(long = "out")]
        out_path: Option<std::path::PathBuf>,
    },
}

pub async fn main(a: BenchArgs) -> Result<()> {
    match a.cmd {
        #[cfg(feature = "reqwest")]
        BenchCmd::Io {
            url,
            requests,
            concurrency,
            json,
            method,
            body,
            hdrs,
            h2,
            insecure,
            keepalive,
            timeout_ms,
            hist_buckets,
            save_path,
            out_path,
        } => {
            bench_io(
                url,
                requests,
                concurrency,
                json,
                method,
                body,
                hdrs,
                h2,
                insecure,
                keepalive,
                timeout_ms,
                hist_buckets,
                save_path,
                out_path,
            )
            .await
        }

        #[cfg(not(feature = "reqwest"))]
        BenchCmd::Io { json, .. } => {
            // Great UX when feature is missing: actionable hint + exit code 2
            let hint = "Enable 'reqwest' feature. Example: cargo run -p app --features reqwest -- bench io --h2 --url https://example.com";
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": "feature_required",
                        "feature": "reqwest"
                    })
                );
            } else {
                eprintln!("bench io requires feature 'reqwest'\nHint: {}", hint);
            }
            std::process::exit(2);
        }
    }
}

#[derive(Default, Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Hist {
    /// 边界（毫秒）
    buckets: Vec<f64>,
    /// 每个桶的计数
    counts: Vec<u64>,
    /// 累计百分比（0~1）
    cdf: Vec<f64>,
}

#[derive(Default, Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
struct IoStats {
    total: u32,
    ok_2xx: u32,
    other: u32,
    elapsed_ms: u128,
    bytes: u64,
    p50_ms: u64,
    p90_ms: u64,
    p99_ms: u64,
    max_ms: u64,
    min_ms: u64,
    rps: f64,
    thrpt_mib_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    hist: Option<Hist>,
}

#[must_use]
pub(crate) fn parse_buckets(s: &str) -> Result<Vec<f64>> {
    let mut v = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let x = f64::from_str(part)?;
        v.push(x);
    }
    v.sort_by(f64::total_cmp);
    v.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
    Ok(v)
}

/// testhooks: 根据采样延迟与边界，计算直方图（counts/cdf）
#[must_use]
#[allow(dead_code)]
pub(crate) fn compute_hist(lat_ms: &[u64], buckets: &[f64]) -> Hist {
    let mut counts = vec![0u64; buckets.len()];
    for &lat in lat_ms {
        let mut idx = buckets.len().saturating_sub(1);
        for (i, &b) in buckets.iter().enumerate() {
            if (lat as f64) <= b {
                idx = i;
                break;
            }
        }
        if idx < counts.len() {
            counts[idx] += 1;
        }
    }
    let total = lat_ms.len() as f64;
    let mut acc = 0u64;
    let mut cdf = Vec::with_capacity(counts.len());
    for &c in &counts {
        acc += c;
        cdf.push(if total == 0.0 {
            0.0
        } else {
            (acc as f64 / total).min(1.0)
        });
    }
    Hist {
        buckets: buckets.to_vec(),
        counts,
        cdf,
    }
}

/// 从 `--body` 参数加载正文；支持 `@file`，失败将带上下文返回错误
#[must_use]
fn load_body(arg: &str) -> Result<String> {
    if let Some(path) = arg.strip_prefix('@') {
        Ok(std::fs::read_to_string(path)
            .with_context(|| format!("read body from file {path:?}"))?)
    } else {
        Ok(arg.to_string())
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
struct BenchJsonOut {
    // fixed schema keys
    p50: u64,
    p90: u64,
    p99: u64,
    rps: f64,
    throughput_bps: f64,
    elapsed_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    histogram: Option<Hist>,
}

#[cfg(feature = "reqwest")]
fn to_fixed_schema(s: &IoStats) -> BenchJsonOut {
    let secs = (s.elapsed_ms as f64) / 1000.0;
    let bps = if secs <= 0.0 {
        0.0
    } else {
        (s.bytes as f64) / secs
    };
    BenchJsonOut {
        p50: s.p50_ms,
        p90: s.p90_ms,
        p99: s.p99_ms,
        rps: s.rps,
        throughput_bps: bps,
        elapsed_ms: s.elapsed_ms,
        histogram: s.hist.clone(),
    }
}

#[cfg(feature = "reqwest")]
// 实现：支持 --h2。按请求级别强制 HTTP/2（不依赖 builder 全局开关）
async fn bench_io(
    url: String,
    requests: u32,
    concurrency: usize,
    json: bool,
    method: String,
    body: Option<String>,
    hdrs: Vec<String>,
    h2: bool,
    insecure: bool,
    keepalive: bool,
    timeout_ms: u64,
    hist_buckets: Option<String>,
    save_path: Option<std::path::PathBuf>,
    out_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let mut cb = reqwest::Client::builder().timeout(Duration::from_millis(timeout_ms));
    if insecure {
        cb = cb.danger_accept_invalid_certs(true);
    }
    // Note: http2_prior_knowledge() not available in reqwest 0.12 with current features
    // if h2 { cb = cb.http2_prior_knowledge(); }
    if !keepalive {
        cb = cb.pool_idle_timeout(Duration::from_millis(0));
    }
    let client = cb.build()?;
    let t0 = Instant::now();
    let stats = Arc::new(Mutex::new(IoStats::default()));
    let lat = Arc::new(Mutex::new(Vec::<u64>::with_capacity(requests as usize)));
    let mut joins = Vec::with_capacity(concurrency);
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    // 将 Option<Result<String>> 转换为 Result<Option<String>>
    let body_text = body.map(|b| load_body(&b)).transpose()?;
    for _ in 0..concurrency {
        let client = client.clone();
        let stats = stats.clone();
        let lat = lat.clone();
        let url = url.clone();
        let hdrs = hdrs.clone();
        let method = method.clone();
        let body_text = body_text.clone();
        joins.push(tokio::spawn(async move {
            let mut done = 0u32;
            while stats.lock().total + done < requests {
                let t = Instant::now();
                let mut req = client.request(method.clone(), &url);
                if h2 {
                    // reqwest 0.12 支持 per-request 指定协议版本
                    req = req.version(reqwest::Version::HTTP_2);
                }
                if let Some(ref b) = body_text {
                    req = req.body(b.clone());
                }
                for h in &hdrs {
                    if let Some((k, v)) = h.split_once(':') {
                        req = req.header(k.trim(), v.trim());
                    }
                }
                let response = req.send().await;
                if let Ok(r) = response {
                    let sc = r.status().as_u16();
                    let bytes = match r.bytes().await {
                        Ok(b) => b.len() as u64,
                        Err(_) => 0,
                    };
                    let mut g = stats.lock();
                    if (200..300).contains(&sc) {
                        g.ok_2xx += 1;
                    } else {
                        g.other += 1;
                    }
                    g.bytes += bytes;
                    lat.lock()
                        .push(Instant::now().duration_since(t).as_millis() as u64);
                    done += 1;
                } else {
                    let mut g = stats.lock();
                    g.other += 1;
                    lat.lock()
                        .push(Instant::now().duration_since(t).as_millis() as u64);
                    done += 1;
                }
            }
            let mut g = stats.lock();
            g.total += done;
        }));
    }
    for j in joins {
        let _ = j.await;
    }
    let mut out = stats.lock().clone();
    out.elapsed_ms = t0.elapsed().as_millis();
    // 计算分位
    let mut v = lat.lock().clone();
    v.sort_unstable();
    let q = |p: f64| -> u64 {
        if v.is_empty() {
            return 0;
        }
        let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[idx]
    };
    out.min_ms = *v.first().unwrap_or(&0);
    out.max_ms = *v.last().unwrap_or(&0);
    out.p50_ms = q(0.50);
    out.p90_ms = q(0.90);
    out.p99_ms = q(0.99);
    // 计算 RPS 和吞吐量
    let secs = (out.elapsed_ms as f64) / 1000.0;
    out.rps = f64::from(out.total) / secs.max(1e-6);
    out.thrpt_mib_s = (out.bytes as f64) / 1_048_576.0 / secs.max(1e-6);
    // 可选直方图
    out.hist = if let Some(spec) = hist_buckets {
        let buckets = parse_buckets(&spec)?;
        let mut counts = vec![0u64; buckets.len()];
        for &lat_ms in &v {
            let mut idx = buckets.len().saturating_sub(1);
            for (i, &b) in buckets.iter().enumerate() {
                if (lat_ms as f64) <= b {
                    idx = i;
                    break;
                }
            }
            if idx < counts.len() {
                counts[idx] += 1;
            }
        }
        let total = v.len() as f64;
        let mut acc = 0u64;
        let mut cdf = Vec::with_capacity(counts.len());
        for &c in &counts {
            acc += c;
            cdf.push((acc as f64 / total).min(1.0));
        }
        Some(Hist {
            buckets,
            counts,
            cdf,
        })
    } else {
        None
    };
    if json {
        let fixed = to_fixed_schema(&out);
        println!("{}", serde_json::to_string(&fixed)?);
    } else {
        println!("total={} ok_2xx={} other={} time_ms={} rps={:.1} thrpt_MiBps={:.2} p50={} p90={} p99={} max={} min={}",
            out.total, out.ok_2xx, out.other, out.elapsed_ms, out.rps, out.thrpt_mib_s,
            out.p50_ms, out.p90_ms, out.p99_ms, out.max_ms, out.min_ms);
        if let Some(h) = &out.hist {
            eprintln!(
                "# hist buckets(ms)={:?} counts={:?} cdf={:?}",
                h.buckets, h.counts, h.cdf
            );
        }
    }
    let final_path = out_path.or(save_path);
    if let Some(path) = final_path {
        let data = serde_json::to_string_pretty(&to_fixed_schema(&out))?;
        app::util::write_atomic(&path, data.as_bytes())
            .with_context(|| format!("write histogram json atomically to {path:?}"))?;
    }
    Ok(())
}

#[cfg(not(feature = "reqwest"))]
async fn bench_io(
    _url: String,
    _requests: u32,
    _concurrency: usize,
    _json: bool,
    _method: String,
    _body: Option<String>,
    _hdrs: Vec<String>,
    _h2: bool,
    _insecure: bool,
    _keepalive: bool,
    _timeout_ms: u64,
    _hist_buckets: Option<String>,
    _save_path: Option<std::path::PathBuf>,
) -> Result<()> {
    // Should be handled in main() guard; keep as a fallback.
    anyhow::bail!("feature 'reqwest' is required for `bench io`")
}

// -----------------------------
// Tests (pure; no network)
// -----------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_buckets_ok() {
        let v = parse_buckets(" 10, 5, 5 , 20 , 1 ").unwrap();
        assert_eq!(v, vec![1.0, 5.0, 10.0, 20.0]);
    }

    #[test]
    fn test_parse_buckets_err() {
        assert!(parse_buckets("a,1").is_err());
        assert!(parse_buckets("").unwrap().is_empty());
    }

    #[test]
    fn test_compute_hist_counts_cdf() {
        // 样本：5 个延迟（ms）
        let lat = vec![1, 2, 3, 3, 9];
        let buckets = vec![1.0, 3.0, 10.0];
        let h = compute_hist(&lat, &buckets);
        // ≤1:1 个； ≤3:3 个（不包括已在bucket0的）； ≤10:1 个（不包括已在前面bucket的）
        assert_eq!(h.counts, vec![1, 3, 1]);
        assert_eq!(h.cdf.len(), 3);
        assert!((h.cdf[0] - 1.0 / 5.0).abs() < 1e-9); // 1/5 = 0.2
        assert!((h.cdf[1] - 4.0 / 5.0).abs() < 1e-9); // (1+3)/5 = 0.8
        assert!((h.cdf[2] - 1.0).abs() < 1e-9); // (1+3+1)/5 = 1.0
    }

    #[test]
    fn test_json_roundtrip_with_hist() {
        let h = Hist {
            buckets: vec![1.0, 2.0, 3.0],
            counts: vec![2, 3, 4],
            cdf: vec![0.2, 0.5, 1.0],
        };
        let s = IoStats {
            total: 9,
            ok_2xx: 8,
            other: 1,
            elapsed_ms: 1234,
            bytes: 4096,
            p50_ms: 10,
            p90_ms: 50,
            p99_ms: 90,
            max_ms: 100,
            min_ms: 1,
            rps: 100.0,
            thrpt_mib_s: 1.23,
            hist: Some(h.clone()),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: IoStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hist.unwrap(), h);
    }
}
