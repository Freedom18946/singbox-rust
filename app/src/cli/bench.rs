// SPDX-License-Identifier: Apache-2.0
use clap::{Args as ClapArgs, Subcommand};
use anyhow::Result;
use tokio::time::{Instant, Duration};
use std::sync::Arc;
use parking_lot::Mutex;
use serde::Serialize;
use reqwest::Method;
use std::fs;

#[derive(ClapArgs, Debug)]
pub struct BenchArgs {
    #[command(subcommand)]
    pub cmd: BenchCmd,
}

#[derive(Subcommand, Debug)]
pub enum BenchCmd {
    /// 简易 HTTP I/O 基准
    Io {
        #[arg(long)] url: String,
        #[arg(long, default_value_t=100)] requests: u32,
        #[arg(long, default_value_t=8)] concurrency: usize,
        #[arg(long)] json: bool,
        /// HTTP 方法
        #[arg(long, value_parser=["GET","POST","PUT","DELETE","HEAD","PATCH"], default_value="GET")]
        method: String,
        /// 请求体（@file 或 字面值）
        #[arg(long)] body: Option<String>,
        /// 追加头（可多次）K:V
        #[arg(long="hdr")] hdrs: Vec<String>,
        /// 允许 HTTP/2
        #[arg(long)] h2: bool,
        /// 不验证 TLS
        #[arg(long)] insecure: bool,
        /// 保持连接
        #[arg(long)] keepalive: bool,
        /// 客户端超时（毫秒）
        #[arg(long, default_value_t=10000)] timeout_ms: u64,
        /// 将结果保存为 JSON
        #[arg(long="save")] save_path: Option<std::path::PathBuf>,
    },
}

pub async fn main(a: BenchArgs) -> Result<()> {
    match a.cmd {
        BenchCmd::Io { url, requests, concurrency, json, method, body, hdrs, h2, insecure, keepalive, timeout_ms, save_path } =>
            bench_io(url, requests, concurrency, json, method, body, hdrs, h2, insecure, keepalive, timeout_ms, save_path).await,
    }
}

#[derive(Default, Serialize, Clone)]
struct IoStats {
    total: u32, ok_2xx: u32, other: u32,
    elapsed_ms: u128, bytes: u64,
    p50_ms: u64, p90_ms: u64, p99_ms: u64, max_ms: u64, min_ms: u64,
}

fn load_body(arg: &str) -> String {
    if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).unwrap_or_default()
    } else { arg.to_string() }
}

async fn bench_io(url: String, requests: u32, concurrency: usize, json: bool,
                  method: String, body: Option<String>, hdrs: Vec<String>, _h2: bool,
                  insecure: bool, keepalive: bool, timeout_ms: u64, save_path: Option<std::path::PathBuf>) -> Result<()> {
    #[cfg(feature = "reqwest")]
    {
        let mut cb = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms));
        if insecure { cb = cb.danger_accept_invalid_certs(true); }
        // Note: http2_prior_knowledge() not available in reqwest 0.12 with current features
        // if h2 { cb = cb.http2_prior_knowledge(); }
        if !keepalive { cb = cb.pool_idle_timeout(Duration::from_millis(0)); }
        let client = cb.build()?;
        let t0 = Instant::now();
        let stats = Arc::new(Mutex::new(IoStats::default()));
        let lat = Arc::new(Mutex::new(Vec::<u64>::with_capacity(requests as usize)));
        let mut joins = Vec::with_capacity(concurrency);
        let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
        let body_text = body.map(|b| load_body(&b));
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
                    if let Some(ref b) = body_text { req = req.body(b.clone()); }
                    for h in hdrs.iter() {
                        if let Some((k,v)) = h.split_once(':') { req = req.header(k.trim(), v.trim()); }
                    }
                    let res = req.send().await;
                    match res {
                        Ok(r) => {
                            let sc = r.status().as_u16();
                            let bytes = r.bytes().await.map(|b| b.len() as u64).unwrap_or(0);
                            let mut g = stats.lock();
                            if (200..300).contains(&sc) { g.ok_2xx += 1; } else { g.other += 1; }
                            g.bytes += bytes;
                            lat.lock().push(Instant::now().duration_since(t).as_millis() as u64);
                            done += 1;
                        }
                        Err(_) => {
                            let mut g = stats.lock();
                            g.other += 1;
                            lat.lock().push(Instant::now().duration_since(t).as_millis() as u64);
                            done += 1;
                        }
                    }
                }
                let mut g = stats.lock();
                g.total += done;
            }));
        }
        for j in joins { let _ = j.await; }
        let mut out = stats.lock().clone();
        out.elapsed_ms = t0.elapsed().as_millis();
        // 计算分位
        let mut v = lat.lock().clone();
        v.sort_unstable();
        let q = |p: f64| -> u64 {
            if v.is_empty() { return 0; }
            let idx = ((v.len() as f64 - 1.0) * p).round() as usize; v[idx]
        };
        out.min_ms = *v.first().unwrap_or(&0);
        out.max_ms = *v.last().unwrap_or(&0);
        out.p50_ms = q(0.50); out.p90_ms = q(0.90); out.p99_ms = q(0.99);
        if json {
            println!("{}", serde_json::to_string(&out)?);
        } else {
            let secs = (out.elapsed_ms as f64)/1000.0;
            let rps = (out.total as f64)/secs.max(1e-6);
            let mbps = (out.bytes as f64)/1_048_576.0/secs.max(1e-6);
            println!("total={} ok_2xx={} other={} time_ms={} rps={:.1} thrpt_MiBps={:.2} p50={} p90={} p99={} max={} min={}",
                out.total, out.ok_2xx, out.other, out.elapsed_ms, rps, mbps,
                out.p50_ms, out.p90_ms, out.p99_ms, out.max_ms, out.min_ms);
        }
        if let Some(path) = save_path {
            let data = serde_json::to_string_pretty(&out)?;
            let _ = fs::write(path, data);
        }
        Ok(())
    }
    #[cfg(not(feature = "reqwest"))]
    {
        anyhow::bail!("该命令需要启用编译特性：reqwest")
    }
}