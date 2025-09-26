// SPDX-License-Identifier: Apache-2.0
use clap::{Args as ClapArgs, Subcommand};
#[cfg(feature="dev-cli")]
use serde::Serialize;

#[derive(ClapArgs, Debug)]
pub struct PrefetchArgs {
    #[command(subcommand)]
    pub cmd: PrefetchCmd,
}

#[derive(Subcommand, Debug)]
pub enum PrefetchCmd {
    /// 打印预取指标（队列深度/高水位/事件计数）
    Stats {
        /// 输出 JSON 格式而不是文本
        #[arg(long)]
        json: bool,
    },
    /// 入队一个预取任务
    Enqueue {
        /// 目标 URL
        #[arg(long)]
        url: String,
        /// 可选 ETag
        #[arg(long)]
        etag: Option<String>,
    },
    /// 压测入队
    Heat {
        /// 目标 URL
        #[arg(long)]
        url: String,
        /// 并发度
        #[arg(long, default_value_t=8)]
        concurrency: usize,
        /// 压测时长（秒）
        #[arg(long, default_value_t=20)]
        duration: u64,
        /// 每秒入队速率（0 表示尽力）
        #[arg(long, default_value_t=0)]
        rps: u64,
        /// 可选 ETag
        #[arg(long)]
        etag: Option<String>,
    },
    /// 实时观测（刷新曲线/文本/JSON/NDJSON）
    Watch {
        /// 刷新间隔秒
        #[arg(long, default_value_t=1)]
        interval: u64,
        /// 总时长秒（0 表示无限）
        #[arg(long, default_value_t=0)]
        duration: u64,
        /// 纯文本输出（非 TTY 友好）
        #[arg(long)]
        plain: bool,
        /// JSON 单行输出（每次刷新打印一行）
        #[arg(long)]
        json: bool,
        /// NDJSON 持续输出
        #[arg(long)]
        ndjson: bool,
    },
    /// 等待队列排空（或超时）
    Drain {
        /// 超时时间（秒）
        #[arg(long, default_value_t=30)]
        timeout: u64,
        /// 轮询间隔（毫秒）
        #[arg(long, default_value_t=200)]
        every: u64,
        /// 静默模式（仅用退出码表示结果）
        #[arg(long)]
        quiet: bool,
    },
    /// 对单 URL 做一次触发→观测→汇报
    Sample {
        /// 目标 URL
        #[arg(long)]
        url: String,
        /// 可选 ETag
        #[arg(long)]
        etag: Option<String>,
        /// 观测窗口（秒）
        #[arg(long, default_value_t=3)]
        window: u64,
        /// 等待深度回落到初值 ±Δ（Δ=1）
        #[arg(long)]
        wait_done: bool,
        /// JSON 输出
        #[arg(long)]
        json: bool,
    },
}

pub fn main(a: PrefetchArgs) -> anyhow::Result<()> {
    match a.cmd {
        PrefetchCmd::Stats { json } => stats(json),
        PrefetchCmd::Enqueue { url, etag } => enqueue(url, etag),
        PrefetchCmd::Heat { url, concurrency, duration, rps, etag } => {
            heat(url, concurrency, duration, rps, etag)
        }
        PrefetchCmd::Watch { interval, duration, plain, json, ndjson } =>
            watch(interval, duration, plain, json, ndjson),
        PrefetchCmd::Drain { timeout, every, quiet } => drain(timeout, every, quiet),
        PrefetchCmd::Sample { url, etag, window, wait_done, json } =>
            sample(url, etag, window, wait_done, json),
    }
}

fn feature_guard(feature: &str) -> anyhow::Result<()> {
    anyhow::bail!("该命令需要启用编译特性：{}", feature)
}

fn stats(_json: bool) -> anyhow::Result<()> {
    // admin_debug 下导出指标；否则提示开启特性
    #[cfg(feature = "admin_debug")]
    {
        use crate::admin_debug::security_metrics as m;
        let depth = m::get_prefetch_queue_depth();
        let high = m::get_prefetch_queue_high_watermark();
        let (enq, drop, done, fail, retry) = m::get_prefetch_counters();

        if _json {
            // 输出 JSON 格式
            let json_obj = serde_json::json!({
                "depth": depth,
                "high_watermark": high,
                "enq": enq,
                "drop": drop,
                "done": done,
                "fail": fail,
                "retry": retry
            });
            println!("{}", json_obj);
        } else {
            // 输出文本格式
            println!("sb_prefetch_queue_depth             {}", depth);
            println!("sb_prefetch_queue_high_watermark    {}", high);
            println!("sb_prefetch_jobs_total{{event=enq}} {}", enq);
            println!("sb_prefetch_jobs_total{{event=drop}} {}", drop);
            println!("sb_prefetch_jobs_total{{event=done}} {}", done);
            println!("sb_prefetch_jobs_total{{event=fail}} {}", fail);
            println!("sb_prefetch_jobs_total{{event=retry}} {}", retry);
        }
        return Ok(());
    }
    #[cfg(not(feature = "admin_debug"))]
    {
        return feature_guard("admin_debug");
    }
}

fn enqueue(_url: String, _etag: Option<String>) -> anyhow::Result<()> {
    #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
    {
        // 检查是否启用
        let prefetch_enabled = std::env::var("SB_PREFETCH_ENABLE").ok().as_deref() == Some("1");
        if !prefetch_enabled {
            anyhow::bail!("预取功能未启用。请设置环境变量：export SB_PREFETCH_ENABLE=1");
        }

        // 检查队列容量配置
        let queue_cap = std::env::var("SB_PREFETCH_CAP").ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(128);

        // 仅入队，不抓取
        let ok = crate::admin_debug::prefetch::enqueue_prefetch(&_url, _etag);
        if ok {
            println!("enqueued: {}", _url);
            Ok(())
        } else {
            anyhow::bail!(
                "入队失败，可能原因：队列已满（容量{}）。尝试：export SB_PREFETCH_CAP=256",
                queue_cap
            );
        }
    }
    #[cfg(not(all(feature = "admin_debug", feature = "subs_http")))]
    {
        feature_guard("admin_debug + subs_http")
    }
}

fn heat(_url: String, _concurrency: usize, _duration: u64, _rps: u64, _etag: Option<String>) -> anyhow::Result<()> {
    #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
    {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(_duration));
            stop2.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        let mut handles = Vec::with_capacity(_concurrency);
        for _ in 0.._concurrency {
            let stop = stop.clone();
            let url = _url.clone();
            let etag = _etag.clone();
            handles.push(std::thread::spawn(move || {
                let mut enq = 0u64;
                let mut drop = 0u64;
                let mut last = std::time::Instant::now();
                let interval = if _rps == 0 { std::time::Duration::from_millis(0) } else { std::time::Duration::from_secs_f64(1.0 / (_rps as f64).max(1.0)) };
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let ok = crate::admin_debug::prefetch::enqueue_prefetch(&url, etag.clone());
                    if ok { enq += 1; } else { drop += 1; }
                    if _rps > 0 {
                        let target = interval;
                        let spent = last.elapsed();
                        if spent < target {
                            std::thread::sleep(target - spent);
                        }
                        last = std::time::Instant::now();
                    } else {
                        // 当 rps=0 时避免 CPU 100% 占用
                        std::thread::yield_now();
                    }
                }
                (enq, drop)
            }));
        }

        let mut total_enq = 0u64;
        let mut total_drop = 0u64;
        for jh in handles {
            let (e, d) = jh.join().unwrap_or((0, 0));
            total_enq += e;
            total_drop += d;
        }
        println!("heat finished: enq={} drop={}", total_enq, total_drop);
        Ok(())
    }
    #[cfg(not(all(feature = "admin_debug", feature = "subs_http")))]
    {
        feature_guard("admin_debug + subs_http")
    }
}

#[cfg(feature="dev-cli")]
#[derive(Clone, Copy, Default, Serialize)]
struct PrefStats {
    depth: u64,
    high: u64,
    enq: u64,
    drop: u64,
    done: u64,
    fail: u64,
    retry: u64,
}

#[cfg(feature = "admin_debug")]
fn read_stats() -> PrefStats {
    use crate::admin_debug::security_metrics as m;
    let (enq, drop, done, fail, retry) = m::get_prefetch_counters();
    PrefStats {
        depth: m::get_prefetch_queue_depth(),
        high: m::get_prefetch_queue_high_watermark(),
        enq, drop, done, fail, retry,
    }
}

fn watch(_interval: u64, _duration: u64, _plain: bool, _json: bool, _ndjson: bool) -> anyhow::Result<()> {
    #[cfg(feature = "admin_debug")]
    {
        let iv = std::time::Duration::from_secs(_interval.max(1));
        let deadline = if _duration == 0 { None } else { Some(std::time::Instant::now() + std::time::Duration::from_secs(_duration)) };
        let mut series: Vec<u64> = Vec::with_capacity(1200);
        let is_tty = atty::is(atty::Stream::Stdout) && !_plain && !_json && !_ndjson;
        loop {
            let s = read_stats();
            series.push(s.depth);
            while series.len() > 60 { series.remove(0); }
            if _json || _ndjson {
                let line = serde_json::json!({
                    "depth": s.depth, "high": s.high, "enq": s.enq, "drop": s.drop,
                    "done": s.done, "fail": s.fail, "retry": s.retry,
                    "ts_ms": (std::time::Instant::now().elapsed().as_millis() as u64)
                });
                println!("{}", line);
            } else if is_tty {
                print!("\r\x1b[2K"); // clear line
                let spark = sparkline(&series);
                print!("depth {:>5}  high {:>5}  enq {:>8}  drop {:>6}  done {:>8}  fail {:>6} | {}",
                    s.depth, s.high, s.enq, s.drop, s.done, s.fail, spark);
                std::io::Write::flush(&mut std::io::stdout())?;
            } else {
                println!("depth={} high={} enq={} drop={} done={} fail={} retry={}",
                    s.depth, s.high, s.enq, s.drop, s.done, s.fail, s.retry);
            }
            if let Some(t) = deadline { if std::time::Instant::now() >= t { break; } }
            std::thread::sleep(iv);
        }
        if is_tty { println!(); }
        Ok(())
    }
    #[cfg(not(feature = "admin_debug"))]
    {
        feature_guard("admin_debug")
    }
}

fn sparkline(data: &[u64]) -> String {
    // unicode blocks ▁▂▃▄▅▆▇█
    const GLYPHS: &[char] = &['▁','▂','▃','▄','▅','▆','▇','█'];
    if data.is_empty() { return "".into(); }
    let min = *data.iter().min().unwrap_or(&0);
    let max = *data.iter().max().unwrap_or(&0);
    if max == min { return std::iter::repeat('▁').take(data.len()).collect(); }
    data.iter().map(|v| {
        let n = (((*v - min) as f64) / ((max - min) as f64) * (GLYPHS.len() as f64 - 1.0)).round() as usize;
        GLYPHS[n]
    }).collect()
}

fn drain(_timeout: u64, _every_ms: u64, _quiet: bool) -> anyhow::Result<()> {
    #[cfg(feature = "admin_debug")]
    {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(_timeout);
        loop {
            let d = read_stats().depth;
            if d == 0 {
                if !_quiet { println!("queue drained"); }
                return Ok(());
            }
            if std::time::Instant::now() >= until {
                if !_quiet { eprintln!("timeout waiting for drain; depth={}", d); }
                std::process::exit(2);
            }
            std::thread::sleep(std::time::Duration::from_millis(_every_ms.max(50)));
        }
    }
    #[cfg(not(feature = "admin_debug"))]
    {
        feature_guard("admin_debug")
    }
}

#[cfg(feature="dev-cli")]
#[derive(Serialize)]
struct SampleOut {
    trigger: &'static str,
    before: u64,
    peak: u64,
    after: u64,
    enqueue_cost_ms: u128,
}

fn sample(_url: String, _etag: Option<String>, _window: u64, _wait_done: bool, _json: bool) -> anyhow::Result<()> {
    #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
    {
        let before = read_stats().depth;
        let t0 = std::time::Instant::now();
        let ok = crate::admin_debug::prefetch::enqueue_prefetch(&_url, _etag);
        let t1 = t0.elapsed();
        let mut peak = before;
        let until = std::time::Instant::now() + std::time::Duration::from_secs(_window);
        while std::time::Instant::now() < until {
            let cur = read_stats();
            peak = peak.max(cur.depth);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let mut after = read_stats().depth;
        if _wait_done {
            let target = before.saturating_add(1); // 允许微小波动
            let end2 = std::time::Instant::now() + std::time::Duration::from_secs(_window);
            while std::time::Instant::now() < end2 {
                after = read_stats().depth;
                if after <= target { break; }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        if _json {
            let out = SampleOut {
                trigger: if ok { "enqueued" } else { "drop" },
                before, peak, after,
                enqueue_cost_ms: t1.as_millis(),
            };
            println!("{}", serde_json::to_string(&out)?);
        } else {
            println!("trigger: {}", if ok { "enqueued" } else { "drop" });
            println!("queue: before={} peak={} after={}", before, peak, after);
            println!("enqueue_cost_ms={}", t1.as_millis());
        }
        Ok(())
    }
    #[cfg(not(all(feature = "admin_debug", feature = "subs_http")))]
    {
        feature_guard("admin_debug + subs_http")
    }
}
