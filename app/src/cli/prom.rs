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
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

#[derive(ClapArgs, Debug)]
pub struct PromArgs {
    #[command(subcommand)]
    pub cmd: PromCmd,
}

#[derive(Subcommand, Debug)]
pub enum PromCmd {
    /// 抓取并筛选样本
    Scrape {
        #[arg(long)]
        url: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        select: Option<String>,
        /// 标签选择器（key=val，可多次）
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        jsonl: bool,
        #[arg(long)]
        json: bool,
    },
    /// 直方图转分位（支持多 metric）
    ///
    /// 支持：
    /// - --label key=val（可多次）：对 bucket/sum/count 三类样本统一标签过滤
    /// - --group-by <label>：按某个 label 分组输出每组的 p50/p90/p99/sum/count
    ///   若分组 label 缺失则归为组名 "_"
    Hist {
        #[arg(long = "metric")]
        metrics: Vec<String>,
        #[arg(long)]
        url: String,
        #[arg(long = "label")]
        labels: Vec<String>,
        /// 对直方图进行分组聚合的标签键
        #[arg(long = "group-by")]
        group_by: Option<String>,
        /// 输出格式（默认 text）
        #[arg(long, value_enum, default_value_t=HistFormat::Text)]
        format: HistFormat,
    },
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
pub enum HistFormat {
    Text,
    Json,
}
impl fmt::Display for HistFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::Json => f.write_str("json"),
        }
    }
}

pub fn main(a: PromArgs) -> Result<()> {
    match a.cmd {
        PromCmd::Scrape {
            url,
            filter,
            select,
            labels,
            jsonl,
            json,
        } => {
            // We are already in a Tokio runtime (app main), so we can block_on safely.
            tokio::runtime::Handle::current().block_on(scrape(url, filter, select, labels, jsonl, json))
        }
        PromCmd::Hist {
            url,
            metrics,
            labels,
            group_by,
            format,
        } => tokio::runtime::Handle::current().block_on(hist(metrics, url, labels, group_by, format)),
    }
}

#[derive(Debug, Serialize, Clone)]
struct Sample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

/// testhooks: 供单测使用，保持 crate 可见
#[must_use]
pub(crate) fn parse_label_kvs(xs: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for s in xs {
        if let Some((k, v)) = s.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// 将 `{k="v",x="y"}` 文本解析为 map（宽松容错）
#[must_use]
pub(crate) fn parse_labels_text(label_text: &str) -> BTreeMap<String, String> {
    let mut lbl = BTreeMap::new();
    let inner = label_text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}');
    for kv in inner.split(',') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        lbl.insert(k.trim().to_string(), v.trim_matches('"').to_string());
    }
    lbl
}

/// 所有选择器均需命中
#[must_use]
pub(crate) fn labels_match(all: &BTreeMap<String, String>, sel: &BTreeMap<String, String>) -> bool {
    sel.iter()
        .all(|(k, want)| all.get(k).is_some_and(|v| v == want))
}

#[allow(clippy::unused_async)]
async fn scrape(
    url: String,
    filter: Option<String>,
    select: Option<String>,
    labels: Vec<String>,
    jsonl: bool,
    _json: bool,
) -> Result<()> {
    let txt = http_get_text(&url).await?;
    let re =
        Regex::new(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+]?\d+(\.\d+)?|NaN|\+?Inf)$")
            .context("invalid regex pattern for metrics parsing")?;
    let mut out: Vec<Sample> = Vec::new();
    let filter_re = filter.and_then(|f| Regex::new(&f).ok());
    let sel: Option<Vec<String>> =
        select.map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let label_sel = parse_label_kvs(&labels);
    for line in txt.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(cap) = re.captures(line) {
            let name = &cap[1];
            let label_str = cap.get(2).map_or("", |m| m.as_str());
            let value_str = &cap[3];
            let value: f64 = match value_str {
                "NaN" => f64::NAN,
                "Inf" | "+Inf" => f64::INFINITY,
                _ => value_str.parse().unwrap_or(f64::NAN),
            };
            if let Some(re) = &filter_re {
                if !re.is_match(name) {
                    continue;
                }
            }
            let lbl = parse_labels_text(label_str);
            if !label_sel.is_empty() && !labels_match(&lbl, &label_sel) {
                continue;
            }
            out.push(Sample {
                name: name.to_string(),
                labels: lbl,
                value,
            });
            if jsonl {
                if let Some(last) = out.last() {
                    println!("{}", serde_json::to_string(last)?);
                }
            }
        }
    }
    if !jsonl {
        if let Some(sel) = sel {
            // 简易 select：输出指定字段
            for s in &out {
                let mut xs = Vec::new();
                for k in &sel {
                    match k.as_str() {
                        "name" => xs.push(s.name.clone()),
                        "value" => xs.push(format!("{}", s.value)),
                        other => xs.push(s.labels.get(other).cloned().unwrap_or_default()),
                    }
                }
                println!("{}", xs.join("\t"));
            }
        } else {
            for s in &out {
                println!(
                    "{}\t{}\t{}",
                    s.name,
                    serde_json::to_string(&s.labels)?,
                    s.value
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::unused_async)]
async fn hist(
    metrics: Vec<String>,
    url: String,
    labels: Vec<String>,
    group_by: Option<String>,
    format: HistFormat,
) -> Result<()> {
    let txt = http_get_text(&url).await?;
    let label_sel = parse_label_kvs(&labels);
    #[derive(Default)]
    struct Agg {
        buckets: Vec<(f64, f64)>,
        sum: f64,
        count: f64,
    }
    #[derive(Serialize)]
    struct GroupOut<'a> {
        metric: &'a str,
        group: String,
        p50: f64,
        p90: f64,
        p99: f64,
        sum: f64,
        count: f64,
    }

    // 按 metric → (group_key → 聚合)
    let mut store: HashMap<String, HashMap<String, Agg>> = HashMap::new();

    // 为每个 metric 构建三类正则
    let rx_for = |m: &str| -> Result<(Regex, Regex, Regex)> {
        Ok((
            Regex::new(&format!(
                r"^{}_bucket\{{([^}}]*)\}}\s+([-\+]?\d+(\.\d+)?)$",
                regex::escape(m)
            ))?,
            Regex::new(&format!(
                r"^{}_sum\{{([^}}]*)\}}\s+([-\+]?\d+(\.\d+)?)$",
                regex::escape(m)
            ))?,
            Regex::new(&format!(
                r"^{}_count\{{([^}}]*)\}}\s+([-\+]?\d+(\.\d+)?)$",
                regex::escape(m)
            ))?,
        ))
    };
    let mut rx: HashMap<String, (Regex, Regex, Regex)> = HashMap::new();
    for m in &metrics {
        rx.insert(m.clone(), rx_for(m)?);
    }

    for line in txt.lines() {
        if line.starts_with('#') {
            continue;
        }
        for m in &metrics {
            let Some((re_b, re_s, re_c)) = rx.get(m) else {
                continue;
            };
            if let Some(cap) = re_b.captures(line) {
                let lbl = parse_labels_text(cap.get(1).map_or("", |m| m.as_str()));
                if !label_sel.is_empty() && !labels_match(&lbl, &label_sel) {
                    continue;
                }
                let group_key = group_by
                    .as_ref()
                    .and_then(|k| lbl.get(k).cloned())
                    .unwrap_or_else(|| "_".into());
                let mut le = f64::INFINITY;
                if let Some(v) = lbl.get("le") {
                    le = v.parse::<f64>().unwrap_or(f64::INFINITY);
                }
                let v = cap[2].parse::<f64>().unwrap_or(0.0);
                let entry = store
                    .entry(m.clone())
                    .or_default()
                    .entry(group_key)
                    .or_default();
                entry.buckets.push((le, v));
                break;
            }
            if let Some(cap) = re_s.captures(line) {
                let lbl = parse_labels_text(cap.get(1).map_or("", |m| m.as_str()));
                if !label_sel.is_empty() && !labels_match(&lbl, &label_sel) {
                    continue;
                }
                let group_key = group_by
                    .as_ref()
                    .and_then(|k| lbl.get(k).cloned())
                    .unwrap_or_else(|| "_".into());
                let v = cap[2].parse::<f64>().unwrap_or(0.0);
                let entry = store
                    .entry(m.clone())
                    .or_default()
                    .entry(group_key)
                    .or_default();
                entry.sum = v;
                break;
            }
            if let Some(cap) = re_c.captures(line) {
                let lbl = parse_labels_text(cap.get(1).map_or("", |m| m.as_str()));
                if !label_sel.is_empty() && !labels_match(&lbl, &label_sel) {
                    continue;
                }
                let group_key = group_by
                    .as_ref()
                    .and_then(|k| lbl.get(k).cloned())
                    .unwrap_or_else(|| "_".into());
                let v = cap[2].parse::<f64>().unwrap_or(0.0);
                let entry = store
                    .entry(m.clone())
                    .or_default()
                    .entry(group_key)
                    .or_default();
                entry.count = v;
                break;
            }
        }
    }

    let mut outs = Vec::<GroupOut>::new();
    for (metric, groups) in &mut store {
        for (gk, agg) in groups {
            let mut buckets = agg.buckets.clone();
            buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut prev = 0.0;
            let mut _noncum = Vec::<(f64, f64)>::new();
            for (le, v) in &buckets {
                _noncum.push((*le, (*v - prev).max(0.0)));
                prev = *v;
            }
            let p = |q: f64, count: f64, buckets: &Vec<(f64, f64)>| -> f64 {
                if count <= 0.0 || buckets.is_empty() {
                    return 0.0;
                }
                let target = q * count;
                let mut acc = 0.0;
                for (le, v) in buckets {
                    acc += *v;
                    if acc >= target {
                        return *le;
                    }
                }
                f64::INFINITY
            };
            let p50 = p(0.50, agg.count, &buckets);
            let p90 = p(0.90, agg.count, &buckets);
            let p99 = p(0.99, agg.count, &buckets);
            outs.push(GroupOut {
                metric,
                group: gk.clone(),
                p50,
                p90,
                p99,
                sum: agg.sum,
                count: agg.count,
            });
        }
    }
    match format {
        HistFormat::Text => {
            for o in outs {
                if group_by.is_some() {
                    println!(
                        "metric={} group={} p50={} p90={} p99={} sum={} count={}",
                        o.metric, o.group, o.p50, o.p90, o.p99, o.sum, o.count
                    );
                } else {
                    println!(
                        "metric={} p50={} p90={} p99={} sum={} count={}",
                        o.metric, o.p50, o.p90, o.p99, o.sum, o.count
                    );
                }
            }
        }
        HistFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&outs)?);
        }
    }
    Ok(())
}

#[allow(clippy::unused_async)]
async fn http_get_text(_url: &str) -> Result<String> {
    #[cfg(feature = "reqwest")]
    {
        let txt = reqwest::Client::new()
            .get(_url)
            .send()
            .await
            .with_context(|| format!("GET {_url}"))?
            .text()
            .await?;
        Ok(txt)
    }
    #[cfg(not(feature = "reqwest"))]
    {
        anyhow::bail!("该命令需要启用编译特性：reqwest")
    }
}

// -----------------------------
// Tests (no network)
// -----------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_labels_text_basic() {
        let m = parse_labels_text(r#"{instance="a:9100",job="node"}"#);
        assert_eq!(m.get("instance").unwrap(), "a:9100");
        assert_eq!(m.get("job").unwrap(), "node");
    }

    #[test]
    fn test_parse_labels_text_tolerant() {
        let m = parse_labels_text(r#"  instance="b" , le="0.5"  "#); // 无花括号也可
        assert_eq!(m.get("instance").unwrap(), "b");
        assert_eq!(m.get("le").unwrap(), "0.5");
    }

    #[test]
    fn test_label_selector_match() {
        let all = BTreeMap::from([
            ("job".into(), "api".into()),
            ("instance".into(), "x:123".into()),
        ]);
        let sel_none = BTreeMap::<String, String>::new();
        let sel_hit = BTreeMap::from([("job".into(), "api".into())]);
        let sel_miss = BTreeMap::from([("job".into(), "ingest".into())]);
        assert!(labels_match(&all, &sel_none));
        assert!(labels_match(&all, &sel_hit));
        assert!(!labels_match(&all, &sel_miss));
    }

    #[test]
    fn test_group_quantiles_simple() {
        // 模拟已聚合的累积桶数据（两个组）
        // 这里不直接调用 hist()（其依赖 HTTP），而是复刻关键分位逻辑的小片段
        fn q(p: f64, count: f64, buckets: &[(f64, f64)]) -> f64 {
            if count <= 0.0 || buckets.is_empty() {
                return 0.0;
            }
            let target = p * count;
            let mut acc = 0.0;
            for (le, v) in buckets {
                acc += *v;
                if acc >= target {
                    return *le;
                }
            }
            f64::INFINITY
        }

        // 组 A：count=100，桶边界 0.1/0.2/0.5/1.0，增量值转换为累积需要的格式
        let ba = vec![(0.1, 10.0), (0.2, 40.0), (0.5, 40.0), (1.0, 10.0)];
        // 组 B：count=5，桶边界 1/2/3/4/5，每桶增量值 1/1/1/1/1
        let bb = vec![(1.0, 1.0), (2.0, 1.0), (3.0, 1.0), (4.0, 1.0), (5.0, 1.0)];

        assert_eq!(q(0.50, 100.0, &ba), 0.2); // 50th percentile: target=50, acc at 0.2 bucket = 10+40=50
        assert_eq!(q(0.90, 100.0, &ba), 0.5); // 90th percentile: target=90, acc at 0.5 bucket = 10+40+40=90
        assert_eq!(q(0.99, 100.0, &ba), 1.0); // 99th percentile: target=99, acc at 1.0 bucket = 10+40+40+10=100

        assert_eq!(q(0.50, 5.0, &bb), 3.0); // 50th percentile: target=2.5, acc at 3.0 bucket = 1+1+1=3
        assert_eq!(q(0.90, 5.0, &bb), 5.0); // 90th percentile: target=4.5, acc at 5.0 bucket = 1+1+1+1+1=5
        assert_eq!(q(0.99, 5.0, &bb), 5.0); // 99th percentile: target=4.95, acc at 5.0 bucket = 1+1+1+1+1=5
    }
}
