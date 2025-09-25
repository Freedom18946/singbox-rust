// SPDX-License-Identifier: Apache-2.0
use clap::{Args as ClapArgs, Subcommand};
use regex::Regex;
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(ClapArgs, Debug)]
pub struct PromArgs { #[command(subcommand)] pub cmd: PromCmd }

#[derive(Subcommand, Debug)]
pub enum PromCmd {
    /// 抓取并筛选样本
    Scrape { #[arg(long)] url: String, #[arg(long)] filter: Option<String>, #[arg(long)] select: Option<String>,
             /// 标签选择器（key=val，可多次）
             #[arg(long="label")] labels: Vec<String>, #[arg(long)] jsonl: bool, #[arg(long)] json: bool },
    /// 直方图转分位（支持多 metric）
    Hist { #[arg(long="metric")] metrics: Vec<String>, #[arg(long)] url: String, #[arg(long="label")] labels: Vec<String> },
}

pub async fn main(a: PromArgs) -> Result<()> {
    match a.cmd {
        PromCmd::Scrape { url, filter, select, labels, jsonl, json } => scrape(url, filter, select, labels, jsonl, json).await,
        PromCmd::Hist { url, metrics, labels } => hist(metrics, url, labels).await,
    }
}

#[derive(Debug, Serialize, Clone)]
struct Sample { name: String, labels: BTreeMap<String,String>, value: f64 }

async fn scrape(url: String, filter: Option<String>, select: Option<String>, labels: Vec<String>, jsonl: bool, _json: bool) -> Result<()> {
    let txt = http_get_text(&url).await?;
    let re = Regex::new(r#"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+]?\d+(\.\d+)?|NaN|\+?Inf)$"#).unwrap();
    let mut out: Vec<Sample> = Vec::new();
    let filter_re = filter.and_then(|f| Regex::new(&f).ok());
    let sel: Option<Vec<String>> = select.map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    for line in txt.lines() {
        if line.starts_with('#') { continue; }
        if let Some(cap) = re.captures(line) {
            let name = &cap[1];
            let label_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let value_str = &cap[3];
            let value: f64 = match value_str {
                "NaN" => f64::NAN,
                "Inf" | "+Inf" => f64::INFINITY,
                _ => value_str.parse().unwrap_or(f64::NAN),
            };
            if let Some(re) = &filter_re { if !re.is_match(name) { continue; } }
            let mut lbl = BTreeMap::new();
            for kv in label_str.trim_matches(|c| c=='{'||c=='}').split(',') {
                if kv.trim().is_empty() { continue; }
                let (k,v) = kv.split_once('=').unwrap_or((kv,""));
                lbl.insert(k.trim().to_string(), v.trim_matches('"').to_string());
            }
            // label selector 过滤
            let mut ok = true;
            for sel in &labels { if let Some((k,v)) = sel.split_once('=') { if lbl.get(k.trim()) != Some(&v.trim().to_string()) { ok=false; break; } } }
            if !ok { continue; }
            out.push(Sample{ name: name.to_string(), labels: lbl, value });
            if jsonl { println!("{}", serde_json::to_string(out.last().unwrap())?); }
        }
    }
    if !jsonl {
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

async fn hist(metrics: Vec<String>, url: String, labels: Vec<String>) -> Result<()> {
    let txt = http_get_text(&url).await?;
    for metric in metrics {
        let (mut buckets, mut sum, mut count) = (Vec::<(f64,f64)>::new(), 0.0_f64, 0.0_f64);
        let re_b = Regex::new(&format!(r#"^{}(_bucket)\{{.*le="([^"]+)"[^}}]*\}}\s+([-+]?\d+(\.\d+)?)"#, regex::escape(&metric))).unwrap();
        let re_s = Regex::new(&format!(r#"^{}(_sum)\s+([-+]?\d+(\.\d+)?)"#, regex::escape(&metric))).unwrap();
        let re_c = Regex::new(&format!(r#"^{}(_count)\s+([-+]?\d+(\.\d+)?)"#, regex::escape(&metric))).unwrap();
        for line in txt.lines() {
            if let Some(cap) = re_b.captures(line) {
                let le = cap[2].parse::<f64>().unwrap_or(f64::INFINITY);
                let v = cap[3].parse::<f64>().unwrap_or(0.0);
                buckets.push((le, v));
            } else if let Some(cap) = re_s.captures(line) {
                sum = cap[2].parse::<f64>().unwrap_or(0.0);
            } else if let Some(cap) = re_c.captures(line) {
                count = cap[2].parse::<f64>().unwrap_or(0.0);
            }
        }
        buckets.sort_by(|a,b| a.0.total_cmp(&b.0));
        // 非累积桶
        let mut prev = 0.0;
        let mut noncum = Vec::<(f64,f64)>::new();
        for (le,v) in &buckets { noncum.push((*le, (*v - prev).max(0.0))); prev = *v; }
        let p = |q: f64| -> f64 {
            if count<=0.0 || buckets.is_empty() { return 0.0; }
            let target = q * count;
            let mut acc = 0.0;
            for (le, v) in &buckets {
                acc += *v;
                if acc >= target { return *le; }
            }
            f64::INFINITY
        };
        let p50 = p(0.50); let p90 = p(0.90); let p99 = p(0.99);
        // 标签选择提示（若指定了 label 但未过滤，打印说明）
        if !labels.is_empty() { eprintln!("# note: label selectors provided but not used in hist text path"); }
        println!("metric={} p50={} p90={} p99={} sum={} count={}", metric, p50, p90, p99, sum, count);
    }
    Ok(())
}

async fn http_get_text(url: &str) -> Result<String> {
    #[cfg(feature = "reqwest")]
    {
        let txt = reqwest::Client::new().get(url).send().await?.text().await?;
        Ok(txt)
    }
    #[cfg(not(feature = "reqwest"))]
    {
        anyhow::bail!("该命令需要启用编译特性：reqwest")
    }
}