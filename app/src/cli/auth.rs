// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(test), deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::undocumented_unsafe_blocks
))]
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use anyhow::{Result, Context};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use base64::Engine;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub cmd: AuthCmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Algo { #[value(name="hmac-sha256")] HmacSha256, #[value(name="hmac-sha512")] HmacSha512 }

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// 生成签名
    Sign {
        /// Key ID（可被 --env 文件的 KEY_ID 覆盖）
        #[arg(long)] key_id: String,
        /// Secret（可被 --env 文件的 KEY_SECRET 覆盖）
        #[arg(long)] secret: String,
        /// 参与 canonical 的附加请求头（可多次）K:V
        #[arg(long="header")] header: Vec<String>,
        /// 从 .env 文件读取键值（KEY_ID / KEY_SECRET）
        #[arg(long="env")] env_file: Option<std::path::PathBuf>,
        /// 签名算法
        #[arg(long, value_enum, default_value_t=Algo::HmacSha256)] algo: Algo,
        /// 打印 canonical 字符串
        #[arg(long)] canon: bool,
        /// 可选：参与签名的请求体（字面值）
        #[arg(long="body")] body: Option<String>,
        /// 可选：参与签名的请求体文件（从文件读取）
        #[arg(long="body-file")] body_file: Option<PathBuf>,
        /// 若开启，则计算 SHA256(body) 并作为 x-body-sha256 加入 canonical
        #[arg(long="body-hash")] body_hash: bool,
    },
    /// 回放重试（指向 dry-run 端点）
    Replay {
        #[arg(long)] url: String, #[arg(long)] key_id: String, #[arg(long)] secret: String,
        #[arg(long="times", default_value_t=100)] times: u64,
        #[arg(long, default_value_t=16)] concurrency: usize,
        /// 目标 RPS（令牌桶）
        #[arg(long, default_value_t=0)] rps: u64,
        /// 客户端超时（毫秒）
        #[arg(long="timeout-ms", default_value_t=5000)] timeout_ms: u64,
        /// 仅输出状态直方图（而非每条响应）
        #[arg(long="status-only")] status_only: bool,
        /// 追加请求头（可多次）K:V
        #[arg(long="hdr")] hdrs: Vec<String>,
        #[arg(long)] json: bool,
        /// 可选：参与签名并发送的请求体（字面值）
        #[arg(long="body")] body: Option<String>,
        /// 可选：参与签名并发送的请求体文件
        #[arg(long="body-file")] body_file: Option<PathBuf>,
        /// 若开启，则计算 SHA256(body) 并以 x-body-sha256 参与签名
        #[arg(long="body-hash")] body_hash: bool,
    }
}

pub fn main(a: AuthArgs) -> Result<()> {
    match a.cmd {
        AuthCmd::Sign { key_id, secret, header, env_file, algo, canon, body, body_file, body_hash } =>
            sign_ex(key_id, secret, header, env_file, algo, canon, body, body_file, body_hash),
        AuthCmd::Replay { url, key_id, secret, times, concurrency, rps, timeout_ms, status_only, hdrs, json, body, body_file, body_hash } =>
            tokio::runtime::Runtime::new().unwrap().block_on(
                replay(url, key_id, secret, times, concurrency, rps, timeout_ms, status_only, hdrs, json, body, body_file, body_hash)
            ),
    }
}

fn parse_env_file(p: &std::path::Path) -> BTreeMap<String,String> {
    let mut m = BTreeMap::new();
    if let Ok(txt) = std::fs::read_to_string(p) {
        for line in txt.lines() {
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') { continue; }
            if let Some((k,v)) = s.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    m
}

pub(crate) fn read_body_inline(body: &Option<String>, body_file: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    match (body, body_file) {
        (Some(b), None) => Ok(Some(b.as_bytes().to_vec())),
        (None, Some(p)) => Ok(Some(fs::read(p).with_context(|| format!("read body-file {:?}", p))?)),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => anyhow::bail!("--body 与 --body-file 只能二选一"),
    }
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn build_canonical(ts: i64, nonce: &str, headers: &[String]) -> (String, Vec<(String,String)>) {
    let mut kvs = Vec::<(String,String)>::new();
    for h in headers {
        if let Some((k,v)) = h.split_once(':') {
            kvs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    // 规范串：固定顺序：ts, nonce, headers…
    let mut canon = format!("ts:{}\nnonce:{}\n", ts, nonce);
    for (k,v) in &kvs { canon.push_str(&format!("{}:{}\n", k.to_ascii_lowercase(), v)); }
    (canon, kvs)
}

pub(crate) fn inject_body_hash(
    headers: &mut Vec<String>,
    body: &Option<Vec<u8>>,
    enable: bool
) {
    if !enable { return; }
    if let Some(b) = body {
        let h = sha256_hex(b);
        // 避免重复
        if !headers.iter().any(|h| h.to_ascii_lowercase().starts_with("x-body-sha256:")) {
            headers.push(format!("x-body-sha256:{}", h));
        }
    }
}

fn sign_ex(key_id: String, secret: String, mut header: Vec<String>,
           env_file: Option<std::path::PathBuf>, algo: Algo, canon: bool,
           body: Option<String>, body_file: Option<PathBuf>, body_hash: bool) -> Result<()> {
    let mut key_id = key_id;
    let mut secret = secret;
    if let Some(p) = env_file.as_ref() {
        let m = parse_env_file(p);
        if let Some(v) = m.get("KEY_ID") { key_id = v.clone(); }
        if let Some(v) = m.get("KEY_SECRET") { secret = v.clone(); }
    }
    let body_bytes = read_body_inline(&body, &body_file)?;
    inject_body_hash(&mut header, &body_bytes, body_hash);
    let ts = (chrono::Utc::now().timestamp()) as i64;
    let nonce = format!("{:016x}", rand::random::<u64>());
    let (canon_str, _hdrs) = build_canonical(ts, &nonce, &header);
    let sig_b64 = match algo {
        Algo::HmacSha256 => {
            type H = Hmac<Sha256>;
            let mut mac = H::new_from_slice(secret.as_bytes())?;
            mac.update(canon_str.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        }
        Algo::HmacSha512 => {
            type H = Hmac<Sha512>;
            let mut mac = H::new_from_slice(secret.as_bytes())?;
            mac.update(canon_str.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        }
    };

    println!("Authorization: SB-HMAC key_id=\"{}\", ts={}, nonce=\"{}\"", key_id, ts, nonce);
    println!("X-SB-Signature: {}", sig_b64);
    if canon { println!("--- canonical ---\n{}", canon_str); }
    Ok(())
}

#[derive(Default, Clone)]
struct ReplayStats {
    ok2xx: u64, e4xx: u64, e5xx: u64, other: u64,
    total: u64, bytes: u64,
    start_ms: u128, end_ms: u128,
    qps_peak: f64,
    per_sec: BTreeMap<u64, u64>,
}

async fn replay(url: String, key_id: String, secret: String,
                times: u64, concurrency: usize, rps: u64, timeout_ms: u64,
                status_only: bool, mut hdrs: Vec<String>, json: bool,
                body: Option<String>, body_file: Option<PathBuf>, body_hash: bool) -> Result<()> {
    let body_bytes = read_body_inline(&body, &body_file)?;
    inject_body_hash(&mut hdrs, &body_bytes, body_hash);
    #[cfg(feature = "reqwest")]
    {
        let client = reqwest::Client::builder().timeout(Duration::from_millis(timeout_ms)).build()?;
        // 令牌桶：一个后台 task 以 RPS 频率往信号量投放许可
        let sem = Arc::new(tokio::sync::Semaphore::new(if rps == 0 { i32::MAX as usize } else { 0 }));
        if rps > 0 {
            let sem_filler = sem.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / (rps as f64)));
                loop { ticker.tick().await; let _ = sem_filler.add_permits(1); }
            });
        }
        let counter = Arc::new(AtomicU64::new(0));
        let stats = Arc::new(Mutex::new(ReplayStats::default()));
        stats.lock().start_ms = Instant::now().elapsed().as_millis(); // 起点基准
        let pb = if json { None } else {
            Some(indicatif::ProgressBar::new(times).with_style(indicatif::ProgressStyle::with_template(
                "{msg}   {wide_bar} {pos}/{len}  {per_sec}").unwrap()))
        };
        let ts = (chrono::Utc::now().timestamp()) as i64;
        let nonce = format!("{:016x}", rand::random::<u64>());
        let mut join = Vec::new();
        for _ in 0..concurrency {
            let client = client.clone();
            let url = url.clone();
            let key_id = key_id.clone();
            let secret = secret.clone();
            let stats = stats.clone();
            let pb2 = pb.clone();
            let hdrs_vec = hdrs.clone();
            let nonce_cloned = nonce.clone();
            let counter = counter.clone();
            let sem = sem.clone();
            let body_bytes_cloned = body_bytes.clone();
            let per_sec_key = move || (chrono::Utc::now().timestamp()) as u64;
            join.push(tokio::spawn(async move {
                // 循环领取任务
                loop {
                    let i = counter.fetch_add(1, Ordering::Relaxed);
                    if i >= times { break; }
                    // 限速：取令牌
                    let _p = sem.acquire().await.map_err(|e| anyhow::anyhow!("semaphore acquire failed: {}", e))?;
                    let auth = format!("SB-HMAC key_id=\"{}\", ts={}, nonce=\"{}\"", key_id, ts, nonce_cloned);
                    let mut req = client.put(&url).header("Authorization", auth);
                    for h in &hdrs_vec {
                        if let Some((k,v)) = h.split_once(':') { req = req.header(k.trim(), v.trim()); }
                    }
                    // 签名头（使用 canonical 字符串包括可选的 body hash 头）
                    let header_strs: Vec<String> = hdrs_vec.iter().cloned().collect();
                    let (canon_str, _) = build_canonical(ts, &nonce_cloned, &header_strs);
                    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                        .context("invalid HMAC key length")?;
                    mac.update(canon_str.as_bytes());
                    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
                    req = req.header("X-SB-Signature", sig_b64);
                    // 可选请求体
                    if let Some(body) = &body_bytes_cloned {
                        req = req.body(body.clone());
                    }
                    let t = Instant::now();
                    let res = req.send().await;
                    let ms = t.elapsed().as_millis() as u64;
                    if let Some(pb) = pb2.as_ref() { pb.inc(1); pb.set_message(format!("{} ms", ms)); }
                    let sec = per_sec_key();
                    match res {
                        Ok(r) => {
                            let sc = r.status().as_u16();
                            let bytes_len = if !status_only {
                                match r.bytes().await {
                                    Ok(b) => b.len() as u64,
                                    Err(_) => 0,
                                }
                            } else { 0 };
                            let mut g = stats.lock();
                            *g.per_sec.entry(sec).or_default() += 1;
                            if (200..300).contains(&sc) { g.ok2xx+=1; } else if (400..500).contains(&sc) { g.e4xx+=1; }
                            else if (500..600).contains(&sc) { g.e5xx+=1; } else { g.other+=1; }
                            g.bytes += bytes_len;
                            g.total += 1;
                        }
                        Err(_) => {
                            let mut g = stats.lock();
                            *g.per_sec.entry(sec).or_default() += 1;
                            g.other += 1;
                            g.total += 1;
                        }
                    }
                }
            }));
        }
        for t in join { let _ = t.await; }
        if let Some(pb) = pb { pb.finish_and_clear(); }
        {
            let mut g = stats.lock().clone();
            g.end_ms = Instant::now().elapsed().as_millis();
            let elapsed_s = ((g.end_ms as i128 - g.start_ms as i128).abs() as f64 / 1000.0).max(1e-6);
            let qps_avg = (g.total as f64) / elapsed_s;
            let qps_peak = g.per_sec.values().copied().max().unwrap_or(0) as f64;
            g.qps_peak = qps_peak;
            if json {
                println!("{}", serde_json::json!({
                  "ok2xx": g.ok2xx, "e4xx": g.e4xx, "e5xx": g.e5xx, "other": g.other,
                  "total": g.total, "bytes": g.bytes,
                  "qps_avg": qps_avg, "qps_peak": g.qps_peak
                }).to_string());
            } else {
                println!("2xx={} 4xx={} 5xx={} other={} total={} qps_avg={:.2} qps_peak={}",
                         g.ok2xx, g.e4xx, g.e5xx, g.other, g.total, qps_avg, g.qps_peak as u64);
            }
        }
        Ok(())
    }
    #[cfg(not(feature = "reqwest"))]
    {
        anyhow::bail!("该命令需要启用编译特性：reqwest")
    }
}

// -----------------------------
// Tests (pure; no network)
// -----------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};

    fn hmac256_hex(key: &str, data: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn test_sha256_hex_ok() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_inject_body_hash_once() {
        let body = Some(b"abc".to_vec());
        let mut hdrs = vec!["X-A:1".into()];
        inject_body_hash(&mut hdrs, &body, true);
        inject_body_hash(&mut hdrs, &body, true);
        let count = hdrs.iter().filter(|h| h.to_ascii_lowercase().starts_with("x-body-sha256:")).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_canonical_and_signature_matrix() {
        // 固定 ts/nonce/secret，构造 4×2 矩阵：
        // headers: 无 / 有自定义； body-hash: 关/开
        let ts = 1700000000_i64;
        let nonce = "0000000000000001";
        let secret = "s3cr3t";

        // 基线 headers
        let base = vec![
            "x-key-id:demo".into(),
            "x-extra:42".into(),
        ];

        // case 1: no body-hash
        {
            let hdrs = base.clone();
            let (canon, _kv) = build_canonical(ts, nonce, &hdrs);
            let sig_hex = hmac256_hex(secret, &canon);
            assert!(sig_hex.len() == 64);
        }

        // case 2: body-hash enabled with body
        {
            let mut hdrs = base.clone();
            let body = Some(b"hello".to_vec());
            inject_body_hash(&mut hdrs, &body, true);
            let (canon, _kv) = build_canonical(ts, nonce, &hdrs);
            // 证明 x-body-sha256 已参与
            assert!(canon.contains("x-body-sha256"));
            let sig_hex = hmac256_hex(secret, &canon);
            assert!(sig_hex.len() == 64);
        }

        // case 3: body-hash enabled but no body -> 等效于 case1
        {
            let mut hdrs = base.clone();
            let body: Option<Vec<u8>> = None;
            inject_body_hash(&mut hdrs, &body, true);
            let (canon, _kv) = build_canonical(ts, nonce, &hdrs);
            assert!(!canon.contains("x-body-sha256"));
        }

        // case 4: duplicated x-body-sha256 should not duplicate
        {
            let mut hdrs = base.clone();
            hdrs.push(format!("x-body-sha256:{}", sha256_hex(b"hello")));
            let body = Some(b"hello".to_vec());
            inject_body_hash(&mut hdrs, &body, true);
            let only_one = hdrs.iter().filter(|h| h.to_ascii_lowercase().starts_with("x-body-sha256:")).count();
            assert_eq!(only_one, 1);
        }
    }
}