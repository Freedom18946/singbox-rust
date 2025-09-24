#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! sb-route：批量预演与规则诊断（离线）
//! 依赖：features = ["preview_route","dsl_analyze"]；如需 DSL+，请先用 sb-dsl expand 或 SB_DSL_PLUS=1+feature=dsl_plus 搭配 sb-preview
// Warnings Wave 2（局部）：无用导入/变量清理（保持 CLI 层，不触核心）
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value as Jv;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::PathBuf,
    time::Instant,
};

#[derive(ValueEnum, Clone, Debug)]
enum Proto {
    Tcp,
    Udp,
}
#[derive(ValueEnum, Clone, Debug)]
enum OutFmt {
    Min,
    Json,
    Pretty,
}
#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "snake_case")]
enum EEmit {
    Full,
    SummaryOnly,
}
#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "snake_case")]
enum Emit {
    Full,
    MatrixOnly,
    SamplesOnly,
}
#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "snake_case")]
enum AEmit {
    Full,
    StatsOnly,
    ShadowOnly,
    KeysOnly,
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "snake_case")]
enum SampleMode {
    Head,
    Random,
}
#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "snake_case")]
enum ClusterBy {
    None,
    Decision,
    ReasonKind,
    Rule,
    RuleId,
}

#[derive(Parser, Debug)]
#[command(
    name = "sb-route",
    version,
    about = "Batch preview & DSL analyzer (offline)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 批量预演：对一批目标（host[:port]）执行 explain，并可输出汇总
    ExplainBatch {
        /// DSL 文件（标准 DSL；若已提前 expand，可直接传展开后的）
        #[arg(short = 'f', long = "dsl")]
        dsl_file: PathBuf,
        /// 目标列表文件；省略或 "-" 则读 stdin
        #[arg(short = 'i', long = "input")]
        input: Option<PathBuf>,
        /// tcp|udp（默认 tcp）
        #[arg(long="proto", value_enum, default_value_t=Proto::Tcp)]
        proto: Proto,
        /// 输出格式：min|json|pretty（min=仅 decision）
        #[arg(long="fmt", value_enum, default_value_t=OutFmt::Json)]
        fmt: OutFmt,
        /// 输出末尾追加汇总（counts），JSON 对象
        #[arg(long, default_value_t = true)]
        summary: bool,
        /// 输出选择：full|summary_only（summary_only 不打印逐行结果，仅打印聚合）
        #[arg(long = "emit", value_enum, default_value_t = EEmit::Full)]
        emit: EEmit,
        /// 可选：将 summary 以 pretty JSON 落地
        #[arg(long = "out-summary")]
        out_summary: Option<PathBuf>,
    },
    /// 分析 DSL：输出 duplicates/conflicts/shadowed 与分类计数
    Analyze {
        /// DSL 文件（标准 DSL；如需 DSL+，请先 sb-dsl expand）
        #[arg(short = 'f', long = "dsl")]
        dsl_file: PathBuf,
        /// 输出格式：json|pretty
        #[arg(long="fmt", value_enum, default_value_t=OutFmt::Json)]
        fmt: OutFmt,
        /// 输出选择：full|stats_only|shadow_only|keys_only
        #[arg(long = "emit", value_enum, default_value_t = AEmit::Full)]
        emit: AEmit,
        /// JSON Pointer（RFC6901）抽取子树，例如：/rules/0 或 /analysis/reasons
        #[arg(long = "pointer")]
        pointer: Option<String>,
        /// Top-N（计数字段与数组规模聚合的截断；0 表示全量）
        #[arg(long = "top", default_value_t = 20)]
        top: usize,
        /// 将最终输出写入文件（pretty JSON）
        #[arg(long = "out-analyze")]
        out_analyze: Option<PathBuf>,
        /// 当 emit=shadow_only 时，将影子报告单独落地
        #[arg(long = "out-shadow")]
        out_shadow: Option<PathBuf>,
        /// 当 emit=keys_only 时，将键频与深度分布单独落地
        #[arg(long = "out-keys")]
        out_keys: Option<PathBuf>,
    },
    /// 对比两份 DSL 的决策一致性（可自动生成目标集）
    Compare {
        /// DSL 文件 A（标准 DSL；若是 DSL+，请先 sb-dsl expand）
        #[arg(long = "dsl-a")]
        dsl_a: PathBuf,
        /// DSL 文件 B
        #[arg(long = "dsl-b")]
        dsl_b: PathBuf,
        /// 目标列表文件；省略或 "-" 则自动派生（见 --auto-limit）
        #[arg(short = 'i', long = "input")]
        input: Option<PathBuf>,
        /// 自动派生目标集上限（默认 2000）
        #[arg(long = "auto-limit", default_value_t = 2000)]
        auto_limit: usize,
        /// 协议：tcp|udp
        #[arg(long="proto", value_enum, default_value_t=Proto::Tcp)]
        proto: Proto,
        /// 输出格式：json|pretty
        #[arg(long="fmt", value_enum, default_value_t=OutFmt::Json)]
        fmt: OutFmt,
        /// 是否输出差异样本（最大数量）
        #[arg(long = "diff-sample", default_value_t = 50)]
        diff_sample: usize,
        /// 差异样本的采样策略：head|random（random 可配 seed 保证可复现）
        #[arg(long = "diff-sample-mode", value_enum, default_value_t = SampleMode::Head)]
        sample_mode: SampleMode,
        /// 随机采样的种子（0 也有效）
        #[arg(long = "seed", default_value_t = 0)]
        seed: u64,
        /// 样本聚类维度：none|decision|reason_kind|rule|rule_id
        #[arg(long = "cluster-by", value_enum, default_value_t = ClusterBy::None)]
        cluster_by: ClusterBy,
        /// 每个簇的样本上限（0 表示平均分配 diff-sample；>0 则每簇上限为该值）
        #[arg(long = "max-per-cluster", default_value_t = 0)]
        max_per_cluster: usize,
        /// 选择输出内容：full|matrix_only|samples_only（默认 full）
        #[arg(long = "emit", value_enum, default_value_t = Emit::Full)]
        emit: Emit,
        /// 可选：将 matrix 结构单独写入文件（pretty JSON）
        #[arg(long = "out-matrix")]
        out_matrix: Option<PathBuf>,
        /// 可选：将 samples 列表单独写入文件（pretty JSON）
        #[arg(long = "out-samples")]
        out_samples: Option<PathBuf>,
        /// 可选：将 sample_meta 写入文件（pretty JSON）
        #[arg(long = "out-sample-meta")]
        out_sample_meta: Option<PathBuf>,
    },
    /// 从 DSL 自动派生覆盖性目标集（写文件或打印）
    Cover {
        /// DSL 文件（标准 DSL；若是 DSL+ 先 expand）
        #[arg(short = 'f', long = "dsl")]
        dsl_file: PathBuf,
        /// 输出目标文件路径；省略则打印到 stdout
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// 数量上限（默认 2000）
        #[arg(long = "limit", default_value_t = 2000)]
        limit: usize,
    },
}

fn read_all(p: Option<PathBuf>) -> Result<String> {
    match p {
        Some(path) if path.as_os_str() != "-" => {
            Ok(fs::read_to_string(&path)
                .map_err(|e| anyhow!("无法读取 {}: {e}", path.display()))?)
        }
        _ => {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
    }
}

fn print_json_str(s: &str, fmt: &OutFmt) {
    match fmt {
        OutFmt::Pretty => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| s.to_string())
                );
            } else {
                println!("{s}");
            }
        }
        _ => println!("{s}"),
    }
}

struct JStats {
    total_keys: usize,
    arrays_by_key: BTreeMap<String, usize>,
    reason_kind: BTreeMap<String, usize>,
    decisions: BTreeMap<String, usize>,
    rules_len: usize,
    shadowed_len: usize,
}

impl JStats {
    fn new() -> Self {
        Self {
            total_keys: 0,
            arrays_by_key: BTreeMap::new(),
            reason_kind: BTreeMap::new(),
            decisions: BTreeMap::new(),
            rules_len: 0,
            shadowed_len: 0,
        }
    }
}

fn collect_stats(node: &Jv, parent_key: Option<&str>, stats: &mut JStats) {
    match node {
        Jv::Object(map) => {
            stats.total_keys = stats.total_keys.saturating_add(map.len());
            for (k, v) in map {
                if k == "rules" {
                    if let Some(arr) = v.as_array() {
                        stats.rules_len = arr.len();
                    }
                }
                if k.contains("shadow") {
                    if let Some(arr) = v.as_array() {
                        stats.shadowed_len = stats.shadowed_len.saturating_add(arr.len());
                    }
                }
                if k == "reason_kind" {
                    if let Some(label) = v.as_str() {
                        *stats.reason_kind.entry(label.to_string()).or_insert(0) += 1;
                    }
                }
                if k == "decision" {
                    if let Some(label) = v.as_str() {
                        *stats.decisions.entry(label.to_string()).or_insert(0) += 1;
                    }
                }
                collect_stats(v, Some(k.as_str()), stats);
            }
        }
        Jv::Array(arr) => {
            if let Some(parent) = parent_key {
                let counter = stats.arrays_by_key.entry(parent.to_string()).or_insert(0);
                *counter = counter.saturating_add(arr.len());
            }
            for item in arr {
                collect_stats(item, parent_key, stats);
            }
        }
        _ => {}
    }
}

fn sort_top(map: &BTreeMap<String, usize>, top: usize) -> Vec<(String, usize)> {
    let mut items: Vec<(String, usize)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if top == 0 {
        items
    } else {
        items.into_iter().take(top).collect()
    }
}

fn stats_to_json(stats: &JStats, top: usize) -> Jv {
    let reason = sort_top(&stats.reason_kind, top);
    let decisions = sort_top(&stats.decisions, top);
    let arrays = sort_top(&stats.arrays_by_key, top);
    serde_json::json!({
        "summary": {
            "total_keys": stats.total_keys,
            "rules_len": stats.rules_len,
            "shadowed_len": stats.shadowed_len,
        },
        "top": {
            "reason_kind": reason,
            "decisions": decisions,
            "arrays_by_key": arrays,
        }
    })
}

// ===== Analyze 键频与深度分布（结构无关） =====
#[derive(Default)]
struct KeysAgg {
    key_freq: BTreeMap<String, usize>,
    depth_obj: BTreeMap<usize, usize>,
    depth_arr: BTreeMap<usize, usize>,
    depth_val: BTreeMap<usize, usize>,
    max_depth: usize,
}

fn walk_keys(v: &Jv, depth: usize, agg: &mut KeysAgg) {
    agg.max_depth = agg.max_depth.max(depth);
    match v {
        Jv::Object(map) => {
            *agg.depth_obj.entry(depth).or_insert(0) += 1;
            for (k, vv) in map {
                *agg.key_freq.entry(k.clone()).or_insert(0) += 1;
                walk_keys(vv, depth + 1, agg);
            }
        }
        Jv::Array(arr) => {
            *agg.depth_arr.entry(depth).or_insert(0) += 1;
            for it in arr {
                walk_keys(it, depth + 1, agg);
            }
        }
        _ => {
            *agg.depth_val.entry(depth).or_insert(0) += 1;
        }
    }
}

fn to_sorted_vec(map: &BTreeMap<String, usize>, top: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = map.iter().map(|(k, &c)| (k.clone(), c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if top > 0 {
        v.truncate(top);
    }
    v
}

fn keys_report(root: &Jv, top: usize) -> Jv {
    let mut agg = KeysAgg::default();
    walk_keys(root, 0, &mut agg);
    serde_json::json!({
        "keys_top": to_sorted_vec(&agg.key_freq, top),
        "depth": {
            "max": agg.max_depth,
            "objects": agg.depth_obj.iter().map(|(d,c)| serde_json::json!([d,c])).collect::<Vec<_>>(),
            "arrays":  agg.depth_arr.iter().map(|(d,c)| serde_json::json!([d,c])).collect::<Vec<_>>(),
            "values":  agg.depth_val.iter().map(|(d,c)| serde_json::json!([d,c])).collect::<Vec<_>>()
        }
    })
}

// ===== Analyze 影子/遮蔽提取器（结构无关） =====
#[derive(Default)]
struct ShadowAgg {
    arrays: usize,
    items: usize,
    by_key: BTreeMap<String, usize>,
    samples: Vec<Jv>,
}

fn sanitize_shadow_item(item: &Jv) -> Jv {
    // 尝试提取常见字段；否则原样输出（可能是字符串/数字）
    if let Some(o) = item.as_object() {
        let mut m = serde_json::Map::new();
        for k in [
            "rule",
            "rule_id",
            "index",
            "decision",
            "reason_kind",
            "reason",
            "target",
            "outbound",
            "name",
            "tag",
        ] {
            if let Some(v) = o.get(k) {
                m.insert(k.to_string(), v.clone());
            }
        }
        if !m.is_empty() {
            return Jv::Object(m);
        }
    }
    item.clone()
}

fn walk_shadow(v: &Jv, key_path: &str, agg: &mut ShadowAgg, top: usize) {
    match v {
        Jv::Object(map) => {
            for (k, vv) in map {
                let next = if key_path.is_empty() {
                    k.clone()
                } else {
                    format!("{key_path}.{k}")
                };
                // 命中规则：键名包含 "shadow"
                if k.contains("shadow") {
                    if let Some(arr) = vv.as_array() {
                        agg.arrays += 1;
                        *agg.by_key.entry(k.clone()).or_insert(0) += arr.len();
                        agg.items += arr.len();
                        for it in arr {
                            if agg.samples.len() < top.max(5) {
                                agg.samples.push(sanitize_shadow_item(it));
                            }
                        }
                    }
                }
                walk_shadow(vv, &next, agg, top);
            }
        }
        Jv::Array(arr) => {
            for it in arr {
                walk_shadow(it, key_path, agg, top);
            }
        }
        _ => {}
    }
}

fn shadow_report(root: &Jv, top: usize) -> Jv {
    let mut agg = ShadowAgg::default();
    walk_shadow(root, "", &mut agg, top);
    let mut by_key: Vec<(String, usize)> = agg.by_key.into_iter().collect();
    by_key.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if top > 0 {
        by_key.truncate(top);
    }
    serde_json::json!({
        "summary": { "shadow_arrays": agg.arrays, "shadow_items": agg.items },
        "top_arrays": by_key,
        "samples": agg.samples
    })
}

// ===== Compare: 可复现随机 + 聚类抽样 =====
struct Rng64(u64);
impl Rng64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn urange(&mut self, m: usize) -> usize {
        if m == 0 {
            0
        } else {
            (self.next() as usize) % m
        }
    }
}
fn sample_head(v: &[Jv], k: usize) -> Vec<Jv> {
    v.iter().take(k).cloned().collect()
}
fn sample_random(v: &[Jv], k: usize, seed: u64) -> Vec<Jv> {
    if k == 0 || v.is_empty() {
        return vec![];
    }
    if v.len() <= k {
        return v.to_vec();
    }
    let mut rng = Rng64::new(seed);
    let mut out: Vec<Jv> = Vec::with_capacity(k);
    for (i, it) in v.iter().cloned().enumerate() {
        if i < k {
            out.push(it);
        } else {
            let j = rng.urange(i + 1);
            if j < k {
                out[j] = it;
            }
        }
    }
    out
}
fn extract_cluster_key(x: &Jv, by: &ClusterBy) -> String {
    let o = x.as_object();
    match by {
        ClusterBy::None => "all".into(),
        ClusterBy::Decision => o
            .and_then(|m| m.get("decision"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        ClusterBy::ReasonKind => o
            .and_then(|m| m.get("reason_kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        ClusterBy::Rule => o
            .and_then(|m| m.get("rule"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        ClusterBy::RuleId => o
            .and_then(|m| m.get("rule_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
    }
}
fn cluster_and_sample(
    samples: &[Jv],
    total_k: usize,
    mode: &SampleMode,
    seed: u64,
    by: &ClusterBy,
    max_per_cluster: usize,
) -> (Vec<Jv>, Jv) {
    use std::collections::BTreeMap;
    if matches!(by, ClusterBy::None) {
        let picked = match mode {
            SampleMode::Head => sample_head(samples, total_k),
            SampleMode::Random => sample_random(samples, total_k, seed),
        };
        let meta = serde_json::json!({"clusters": [{"key":"all","size":samples.len(),"picked":picked.len()}]});
        return (picked, meta);
    }
    let mut buckets: BTreeMap<String, Vec<Jv>> = BTreeMap::new();
    for s in samples.iter().cloned() {
        let key = extract_cluster_key(&s, by);
        buckets.entry(key).or_default().push(s);
    }
    let c = buckets.len().max(1);
    let per = if max_per_cluster > 0 {
        max_per_cluster
    } else {
        (total_k / c).max(1)
    };
    let mut picked: Vec<Jv> = Vec::with_capacity(c * per);
    let mut rng = Rng64::new(seed);
    let mut clusters_meta = Vec::new();
    for (k, v) in buckets.iter() {
        let take = per.min(v.len());
        let take_vec = match mode {
            SampleMode::Head => sample_head(v, take),
            SampleMode::Random => sample_random(v, take, rng.next()),
        };
        clusters_meta.push(serde_json::json!({"key":k, "size": v.len(), "picked": take_vec.len()}));
        picked.extend(take_vec);
    }
    // 如果还有预算（diff_sample 未分完），做一轮补齐（round-robin）
    let mut budget = total_k.saturating_sub(picked.len());
    if budget > 0 {
        'outer: loop {
            for (_k, v) in buckets.iter() {
                if budget == 0 {
                    break 'outer;
                }
                let idx = rng.urange(v.len());
                picked.push(v[idx].clone());
                budget -= 1;
                if picked.len() >= total_k {
                    break 'outer;
                }
            }
        }
    }
    (picked, serde_json::json!({"clusters": clusters_meta}))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ExplainBatch {
            dsl_file,
            input,
            proto,
            fmt,
            summary,
            emit,
            out_summary,
        } => {
            let dsl = fs::read_to_string(&dsl_file)
                .map_err(|e| anyhow!("无法读取 DSL：{}: {e}", dsl_file.display()))?;
            // 若用户设置了 SB_DSL_PLUS=1 且二进制编译入了 dsl_plus，可在用 sb-preview 路径；本工具仅吃标准 DSL
            let idx = sb_core::router::preview::build_index_from_rules(&dsl)
                .map_err(|e| anyhow!("构建路由索引失败：{e}"))?;
            let targets = read_all(input)?;
            let mut total = 0usize;
            let mut reason_cnt: BTreeMap<String, usize> = BTreeMap::new();
            let mut decision_cnt: BTreeMap<String, usize> = BTreeMap::new();
            let t0 = Instant::now();
            for line in targets.lines() {
                let tgt = line.trim();
                if tgt.is_empty() || tgt.starts_with('#') {
                    continue;
                }
                let ex = match proto {
                    Proto::Tcp => sb_core::router::preview::preview_decide_http(&idx, tgt),
                    Proto::Udp => sb_core::router::preview::preview_decide_udp(&idx, tgt),
                };
                total += 1;
                *reason_cnt.entry(ex.reason_kind.to_string()).or_insert(0) += 1;
                *decision_cnt.entry(ex.decision.to_string()).or_insert(0) += 1;
                if matches!(emit, EEmit::Full) {
                    match fmt {
                        OutFmt::Min => println!("{}", ex.decision),
                        OutFmt::Json => {
                            let j = sb_core::router::minijson::obj([
                                ("target", sb_core::router::minijson::Val::Str(tgt)),
                                (
                                    "decision",
                                    sb_core::router::minijson::Val::Str(&ex.decision),
                                ),
                                ("reason", sb_core::router::minijson::Val::Str(&ex.reason)),
                                (
                                    "reason_kind",
                                    sb_core::router::minijson::Val::Str(&ex.reason_kind),
                                ),
                            ]);
                            println!("{}", j.to_string());
                        }
                        OutFmt::Pretty => {
                            let j = sb_core::router::minijson::obj([
                                ("target", sb_core::router::minijson::Val::Str(tgt)),
                                (
                                    "decision",
                                    sb_core::router::minijson::Val::Str(&ex.decision),
                                ),
                                ("reason", sb_core::router::minijson::Val::Str(&ex.reason)),
                                (
                                    "reason_kind",
                                    sb_core::router::minijson::Val::Str(&ex.reason_kind),
                                ),
                            ]);
                            let s = j.to_string();
                            print_json_str(&s, &OutFmt::Pretty);
                        }
                    }
                }
            }
            if summary {
                let elapsed_ms = t0.elapsed().as_millis();
                // 构造 summary JSON
                let mut obj = serde_json::json!({
                    "total": total,
                    "elapsed_ms": elapsed_ms,
                    "per_sec": if elapsed_ms>0 { (total as u128 * 1000 / elapsed_ms) as u64 } else { 0 },
                    "reason_kind": serde_json::Value::Object(serde_json::Map::new()),
                    "decisions": serde_json::Value::Object(serde_json::Map::new()),
                });
                if let Some(m) = obj.get_mut("reason_kind").and_then(|v| v.as_object_mut()) {
                    for (k, v) in reason_cnt {
                        m.insert(k, serde_json::json!(v));
                    }
                }
                if let Some(m) = obj.get_mut("decisions").and_then(|v| v.as_object_mut()) {
                    for (k, v) in decision_cnt {
                        m.insert(k, serde_json::json!(v));
                    }
                }
                print_json_str(&obj.to_string(), &fmt);
                if let Some(p) = out_summary {
                    let s = serde_json::to_string_pretty(&obj)
                        .map_err(|e| anyhow!("summary 序列化失败：{e}"))?;
                    fs::write(&p, s)
                        .map_err(|e| anyhow!("写入 summary 到 {} 失败：{e}", p.display()))?;
                    let reason_cnt = obj
                        .get("reason_kind")
                        .and_then(|v| v.as_object())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let decision_cnt = obj
                        .get("decisions")
                        .and_then(|v| v.as_object())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    println!(
                        "EXPLAIN_SUMMARY_OUT: path='{}' total={} per_sec={} reason_kinds={} decisions={}",
                        p.display(),
                        obj.get("total").and_then(|v| v.as_u64()).unwrap_or(0),
                        obj.get("per_sec").and_then(|v| v.as_u64()).unwrap_or(0),
                        reason_cnt,
                        decision_cnt
                    );
                }
            }
        }
        Cmd::Analyze {
            dsl_file,
            fmt,
            emit,
            pointer,
            top,
            out_analyze,
            out_shadow,
            out_keys,
        } => {
            let dsl = fs::read_to_string(&dsl_file)
                .map_err(|e| anyhow!("无法读取 DSL：{}: {e}", dsl_file.display()))?;
            // 如果用户要分析 DSL+，请先 sb-dsl expand；本分析器仅吃标准 DSL
            let a = sb_core::router::preview::analyze_dsl(&dsl);
            let raw_json = sb_core::router::preview::analysis_to_json(&a);
            let mut material = raw_json.clone();
            if let Some(ptr_raw) = pointer.as_deref() {
                // pointer() 要求以 '/' 开头
                let pointer_path = if ptr_raw.starts_with('/') {
                    ptr_raw.to_string()
                } else {
                    format!("/{}", ptr_raw)
                };
                match serde_json::from_str::<Jv>(&raw_json) {
                    Ok(tree) => match tree.pointer(&pointer_path) {
                        Some(sub) => {
                            material =
                                serde_json::to_string(sub).unwrap_or_else(|_| raw_json.clone());
                        }
                        None => {
                            eprintln!(
                                "[warn] JSON Pointer 未命中：{pointer_path}；回退输出完整 JSON"
                            );
                        }
                    },
                    Err(e) => {
                        eprintln!("[warn] 分析结果解析失败：{e}; 回退输出完整 JSON");
                    }
                }
            }

            let finalized = match emit {
                AEmit::Full => material,
                AEmit::StatsOnly => {
                    let value: Jv = serde_json::from_str(&material)
                        .map_err(|e| anyhow!("分析结果不是合法 JSON：{e}"))?;
                    let mut stats = JStats::new();
                    collect_stats(&value, None, &mut stats);
                    stats_to_json(&stats, top).to_string()
                }
                AEmit::ShadowOnly => {
                    let value: Jv = serde_json::from_str(&material)
                        .map_err(|e| anyhow!("分析结果不是合法 JSON：{e}"))?;
                    shadow_report(&value, top).to_string()
                }
                AEmit::KeysOnly => {
                    let value: Jv = serde_json::from_str(&material)
                        .map_err(|e| anyhow!("分析结果不是合法 JSON：{e}"))?;
                    keys_report(&value, top).to_string()
                }
            };

            match fmt {
                OutFmt::Pretty => print_json_str(&finalized, &OutFmt::Pretty),
                _ => println!("{finalized}"),
            }

            if let Some(path) = out_analyze {
                let pretty = match serde_json::from_str::<Jv>(&finalized) {
                    Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| finalized.clone()),
                    Err(_) => finalized.clone(),
                };
                fs::write(&path, pretty)
                    .map_err(|e| anyhow!("写入 analyze 到 {} 失败：{e}", path.display()))?;
                println!(
                    "ANALYZE_OUT: path='{}' emit={:?} pointer={} top={}",
                    path.display(),
                    emit,
                    pointer.as_deref().unwrap_or(""),
                    top
                );
            }
            if matches!(emit, AEmit::ShadowOnly) {
                if let Some(p) = out_shadow {
                    let v: Jv = serde_json::from_str(&finalized).unwrap_or(serde_json::json!({}));
                    let s = serde_json::to_string_pretty(&v).unwrap_or(finalized.clone());
                    fs::write(&p, s)
                        .map_err(|e| anyhow!("写入 shadow 到 {} 失败：{e}", p.display()))?;
                    let arrays = v
                        .get("summary")
                        .and_then(|x| x.get("shadow_arrays"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                    let items = v
                        .get("summary")
                        .and_then(|x| x.get("shadow_items"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                    println!(
                        "ANALYZE_SHADOW_OUT: path='{}' arrays={} items={}",
                        p.display(),
                        arrays,
                        items
                    );
                }
            }
            if matches!(emit, AEmit::KeysOnly) {
                if let Some(p) = out_keys {
                    let v: Jv = serde_json::from_str(&finalized).unwrap_or(serde_json::json!({}));
                    let s = serde_json::to_string_pretty(&v).unwrap_or(finalized.clone());
                    fs::write(&p, s)
                        .map_err(|e| anyhow!("写入 keys 到 {} 失败：{e}", p.display()))?;
                    let topk = v
                        .get("keys_top")
                        .and_then(|x| x.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    println!("ANALYZE_KEYS_OUT: path='{}' keys_top={}", p.display(), topk);
                }
            }
        }
        Cmd::Compare {
            dsl_a,
            dsl_b,
            input,
            auto_limit,
            proto,
            fmt,
            diff_sample,
            sample_mode,
            seed,
            cluster_by,
            max_per_cluster,
            emit,
            out_matrix,
            out_samples,
            out_sample_meta,
        } => {
            let a_txt = fs::read_to_string(&dsl_a)
                .map_err(|e| anyhow!("无法读取 DSL-A：{}: {e}", dsl_a.display()))?;
            let b_txt = fs::read_to_string(&dsl_b)
                .map_err(|e| anyhow!("无法读取 DSL-B：{}: {e}", dsl_b.display()))?;
            // 目标集：优先 input，否则自动派生（A+B 的合并派生）
            let input_s = match &input {
                Some(p) if p.as_os_str() != "-" => Some(
                    fs::read_to_string(p)
                        .map_err(|e| anyhow!("无法读取 targets：{}: {e}", p.display()))?,
                ),
                _ => None,
            };
            let targets = sb_core::router::preview::derive_compare_targets(
                &a_txt,
                &b_txt,
                input_s.as_deref(),
                Some(auto_limit),
            );
            // 构建索引
            let idx_a = sb_core::router::preview::build_index_from_rules(&a_txt)
                .map_err(|e| anyhow!("DSL-A 索引构建失败：{e}"))?;
            let idx_b = sb_core::router::preview::build_index_from_rules(&b_txt)
                .map_err(|e| anyhow!("DSL-B 索引构建失败：{e}"))?;
            // 对比
            let t0 = Instant::now();
            let mut total = 0usize;
            let mut equal = 0usize;
            let mut diff = 0usize;
            let mut matrix: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
            let mut all_samples: Vec<serde_json::Value> = Vec::new();
            for tgt in targets {
                let ex_a = match proto {
                    Proto::Tcp => sb_core::router::preview::preview_decide_http(&idx_a, &tgt),
                    Proto::Udp => sb_core::router::preview::preview_decide_udp(&idx_a, &tgt),
                };
                let ex_b = match proto {
                    Proto::Tcp => sb_core::router::preview::preview_decide_http(&idx_b, &tgt),
                    Proto::Udp => sb_core::router::preview::preview_decide_udp(&idx_b, &tgt),
                };
                total += 1;
                let a = ex_a.decision.to_string();
                let b = ex_b.decision.to_string();
                if a == b {
                    equal += 1;
                } else {
                    diff += 1;
                    all_samples.push(serde_json::json!({
                        "target": tgt,
                        "a": { "decision": ex_a.decision, "reason_kind": ex_a.reason_kind, "reason": ex_a.reason },
                        "b": { "decision": ex_b.decision, "reason_kind": ex_b.reason_kind, "reason": ex_b.reason },
                    }));
                }
                *matrix.entry(a).or_default().entry(b).or_insert(0) += 1;
            }

            let elapsed_ms = t0.elapsed().as_millis();
            let out_full: Jv = serde_json::json!({
                "total": total,
                "equal": equal,
                "diff": diff,
                "elapsed_ms": elapsed_ms,
                "per_sec": if elapsed_ms>0 { (total as u128 * 1000 / elapsed_ms) as u64 } else { 0 },
                "matrix": matrix,
                "samples": Vec::<Jv>::new(), // Will be filled by sampling logic above
            });
            let mut out_final = out_full.clone();

            // Apply the sampling logic to the final output
            if diff_sample == 0 {
                println!(
                    "COMPARE_SAMPLE: mode={:?} cluster_by={:?} count=0 seed={}",
                    sample_mode, cluster_by, seed
                );
            } else {
                let (picked, sample_meta) = {
                    if matches!(cluster_by, ClusterBy::None) {
                        let base = match sample_mode {
                            SampleMode::Head => sample_head(&all_samples, diff_sample),
                            SampleMode::Random => sample_random(&all_samples, diff_sample, seed),
                        };
                        let picked_len = base.len();
                        (
                            base,
                            serde_json::json!({"clusters":[{"key":"all","size":all_samples.len(),"picked":picked_len}]}),
                        )
                    } else {
                        cluster_and_sample(
                            &all_samples,
                            diff_sample,
                            &sample_mode,
                            seed,
                            &cluster_by,
                            max_per_cluster,
                        )
                    }
                };

                // Write sample_meta to file if requested
                if let Some(p) = &out_sample_meta {
                    let s = serde_json::to_string_pretty(&sample_meta)
                        .map_err(|e| anyhow!("sample_meta 序列化失败：{e}"))?;
                    fs::write(p, s)
                        .map_err(|e| anyhow!("写入 sample_meta 到 {} 失败：{e}", p.display()))?;
                    let clusters_count = sample_meta
                        .get("clusters")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(1);
                    println!(
                        "COMPARE_OUT_META: path='{}' clusters={}",
                        p.display(),
                        clusters_count
                    );
                }

                if let Some(obj) = out_final.as_object_mut() {
                    obj.insert("samples".into(), Jv::Array(picked));
                    obj.insert("sample_meta".into(), sample_meta);
                }
                println!(
                    "COMPARE_SAMPLE: mode={:?} cluster_by={:?} count={} seed={} max_per_cluster={}",
                    sample_mode, cluster_by, diff_sample, seed, max_per_cluster
                );
            }
            match emit {
                Emit::Full => {
                    print_json_str(&out_final.to_string(), &fmt);
                }
                Emit::MatrixOnly => {
                    let matrix_obj = out_final
                        .get("matrix")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let obj = serde_json::json!({ "matrix": matrix_obj });
                    print_json_str(&obj.to_string(), &fmt);
                }
                Emit::SamplesOnly => {
                    let samples_arr = out_final
                        .get("samples")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([]));
                    // Output pure array format for userspace compatibility
                    print_json_str(&samples_arr.to_string(), &fmt);
                }
            }
            if let Some(p) = out_matrix {
                let matrix_obj = out_final
                    .get("matrix")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let s = serde_json::to_string_pretty(&matrix_obj)
                    .map_err(|e| anyhow!("matrix 序列化失败：{e}"))?;
                fs::write(&p, s)
                    .map_err(|e| anyhow!("写入 matrix 到 {} 失败：{e}", p.display()))?;
                let mut kinds = 0usize;
                let mut sum = 0usize;
                if let Some(m) = matrix_obj.as_object() {
                    kinds = m.len();
                    for sub in m.values() {
                        if let Some(subm) = sub.as_object() {
                            for vv in subm.values() {
                                if let Some(n) = vv.as_u64() {
                                    sum = sum.saturating_add(n as usize);
                                }
                            }
                        }
                    }
                }
                println!(
                    "COMPARE_OUT: matrix='{}' kinds={} total_counts={}",
                    p.display(),
                    kinds,
                    sum
                );
            }
            if let Some(p) = out_samples {
                let s = serde_json::to_string_pretty(
                    out_final.get("samples").unwrap_or(&serde_json::json!([])),
                )
                .map_err(|e| anyhow!("samples 序列化失败：{e}"))?;
                fs::write(&p, s)
                    .map_err(|e| anyhow!("写入 samples 到 {} 失败：{e}", p.display()))?;
                let n = out_final
                    .get("samples")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                println!("COMPARE_OUT: samples='{}' count={}", p.display(), n);
            }
        }
        Cmd::Cover {
            dsl_file,
            output,
            limit,
        } => {
            let dsl = fs::read_to_string(&dsl_file)
                .map_err(|e| anyhow!("无法读取 DSL：{}: {e}", dsl_file.display()))?;
            let targets = sb_core::router::preview::derive_targets(&dsl, Some(limit));
            if let Some(p) = output {
                fs::write(&p, targets.join("\n"))
                    .map_err(|e| anyhow!("写入 {} 失败：{e}", p.display()))?;
                println!("COVER_OK: {} ({} targets)", p.display(), targets.len());
            } else {
                for t in targets {
                    println!("{t}");
                }
            }
        }
    }
    Ok(())
}
