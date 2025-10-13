use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,  // 出站标识
    pub weight: u32, // 预留：静态权重
}

#[derive(Clone, Debug)]
pub struct Stats {
    pub rtt_ema: f64,
    pub err_ema: f64,
    pub open_fail_ema: f64,
    pub samples: u64,
    pub last_switch: Option<Instant>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            rtt_ema: 0.0,
            err_ema: 0.0,
            open_fail_ema: 0.0,
            samples: 0,
            last_switch: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExploreMode {
    Off,
    Epsilon(f64),
    Softmax(f64),
} // tau for softmax

/// Configuration parameters for ScoreSelector
#[derive(Clone, Debug)]
pub struct SelectorConfig {
    pub alpha: f64,               // EMA 衰减系数
    pub eps: f64,                 // 抖动阈
    pub cooldown: Duration,       // 切换冷却窗
    pub bias_cold: f64,           // 冷启动偏置
    pub weights: (f64, f64, f64), // (w_rtt, w_err, w_open)
    pub explore: ExploreMode,
    pub min_dwell: Duration,    // 最小驻留时间
    pub min_samples: u64,       // 最小样本数
    pub ema_halflife: Duration, // EMA halflife for future smoothing
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self {
            alpha: 0.3,
            eps: 0.05,
            cooldown: Duration::from_secs(5),
            bias_cold: 10.0,
            weights: (1.0, 2.0, 3.0),
            explore: ExploreMode::Off,
            min_dwell: Duration::from_secs(2),
            min_samples: 5,
            ema_halflife: Duration::from_secs(30),
        }
    }
}

pub struct ScoreSelector {
    alpha: f64,               // EMA 衰减系数
    eps: f64,                 // 抖动阈
    cooldown: Duration,       // 切换冷却窗
    bias_cold: f64,           // 冷启动偏置
    weights: (f64, f64, f64), // (w_rtt, w_err, w_open)
    min_dwell: Duration,      // 最小驻留时间
    min_samples: u64,         // 最小样本数
    /// EMA halflife for future smoothing algorithms
    #[allow(dead_code)]
    ema_halflife: Duration,
    stats: HashMap<String, Stats>,
    current: Option<String>,
    #[cfg(feature = "metrics")]
    metrics: crate::metrics::outbound::SelectorMetrics,
    explore: ExploreMode,
}

impl ScoreSelector {
    pub fn new(config: SelectorConfig) -> Self {
        Self {
            alpha: config.alpha,
            eps: config.eps,
            cooldown: config.cooldown,
            bias_cold: config.bias_cold,
            weights: config.weights,
            min_dwell: config.min_dwell,
            min_samples: config.min_samples,
            ema_halflife: config.ema_halflife,
            stats: HashMap::new(),
            current: None,
            #[cfg(feature = "metrics")]
            metrics: crate::metrics::outbound::register_selector_metrics(),
            explore: config.explore,
        }
    }

    fn norm_rtt(ms: f64) -> f64 {
        // 简易归一：100ms 视为基线
        (ms / 100.0).min(10.0)
    }

    fn score(&self, id: &str) -> f64 {
        let s = self.stats.get(id).cloned().unwrap_or_default();
        let cold = if s.samples < self.min_samples {
            self.bias_cold
        } else {
            0.0
        };
        let (wr, we, wo) = self.weights;
        wr * Self::norm_rtt(s.rtt_ema) + we * s.err_ema + wo * s.open_fail_ema + cold
    }

    pub fn choose(&mut self, cs: &[Candidate], now: Instant) -> String {
        // 初始化不存在的统计
        for c in cs {
            self.stats.entry(c.id.clone()).or_default();
        }
        // 计算得分
        let mut best_id = None;
        let mut best = f64::INFINITY;
        let mut scores = Vec::with_capacity(cs.len());
        for c in cs {
            let sc = self.score(&c.id);
            #[cfg(feature = "metrics")]
            {
                self.metrics.score.with_label_values(&[&c.id]).set(sc);
                // Also export via metrics crate for /metrics endpoint
                metrics::gauge!("proxy_select_score", "outbound" => c.id.clone()).set(sc);
            }
            if sc < best {
                best = sc;
                best_id = Some(c.id.clone());
            }
            scores.push((c.id.clone(), sc));
        }
        // 探索：仅在允许切换场景下参与最终选择
        let mut pick = best_id
            .clone()
            .unwrap_or_else(|| cs.first().map(|c| c.id.clone()).unwrap_or_default());
        match self.explore {
            ExploreMode::Off => {}
            ExploreMode::Epsilon(p) => {
                let r: f64 = rand::random::<f64>();
                if r < p && !cs.is_empty() {
                    let idx = rand::random::<usize>() % cs.len();
                    pick = cs[idx].id.clone();
                    #[cfg(feature = "metrics")]
                    self.metrics
                        .explore_total
                        .with_label_values(&["epsilon"])
                        .inc();
                }
            }
            ExploreMode::Softmax(tau) => {
                if cs.len() > 1 {
                    let denom: f64 = scores.iter().map(|(_, s)| (-(*s) / tau).exp()).sum();
                    let mut r = rand::random::<f64>() * denom;
                    for (id, s) in scores {
                        let w = (-s / tau).exp();
                        if r <= w {
                            pick = id;
                            break;
                        }
                        r -= w;
                    }
                    #[cfg(feature = "metrics")]
                    self.metrics
                        .explore_total
                        .with_label_values(&["softmax"])
                        .inc();
                }
            }
        }
        // 抖动阈与冷却窗
        if let Some(cur) = &self.current {
            if let Some(bid) = &best_id {
                if bid != cur {
                    let cur_sc = self.score(cur);
                    if (cur_sc - best) < self.eps {
                        #[cfg(feature = "metrics")]
                        {
                            self.metrics
                                .switch_total
                                .with_label_values(&["jitter"])
                                .inc();
                            metrics::counter!("proxy_select_switch_total", "reason" => "jitter")
                                .increment(1);
                        }
                        return cur.clone();
                    }
                    if let Some(last) = self.stats.get(cur).and_then(|s| s.last_switch) {
                        if now.duration_since(last) < self.cooldown {
                            #[cfg(feature = "metrics")]
                            {
                                self.metrics
                                    .switch_total
                                    .with_label_values(&["cooldown"])
                                    .inc();
                                metrics::counter!("proxy_select_switch_total", "reason" => "cooldown").increment(1);
                            }
                            return cur.clone();
                        }
                        // 最小驻留
                        if now.duration_since(last) < self.min_dwell {
                            #[cfg(feature = "metrics")]
                            {
                                self.metrics
                                    .switch_total
                                    .with_label_values(&["min_dwell"])
                                    .inc();
                                metrics::counter!("proxy_select_switch_total", "reason" => "min_dwell").increment(1);
                            }
                            return cur.clone();
                        }
                    }
                    // 低样本保护
                    if let Some(s) = self.stats.get(bid) {
                        if s.samples < self.min_samples {
                            #[cfg(feature = "metrics")]
                            {
                                self.metrics
                                    .switch_total
                                    .with_label_values(&["low_samples"])
                                    .inc();
                                metrics::counter!("proxy_select_switch_total", "reason" => "low_samples").increment(1);
                            }
                            return cur.clone();
                        }
                    }
                    // 允许切换
                    #[cfg(feature = "metrics")]
                    {
                        self.metrics
                            .switch_total
                            .with_label_values(&["score"])
                            .inc();
                        metrics::counter!("proxy_select_switch_total", "reason" => "score")
                            .increment(1);
                    }
                }
            }
        }
        self.current = Some(pick.clone());
        if let Some(s) = self.stats.get_mut(&pick) {
            s.last_switch = Some(now);
        }
        pick
    }

    pub fn record_success(&mut self, id: &str, rtt_ms: u64) {
        let s = self.stats.entry(id.into()).or_default();
        let a = self.alpha;
        let r = rtt_ms as f64;
        s.rtt_ema = if s.samples == 0 {
            r
        } else {
            a * r + (1.0 - a) * s.rtt_ema
        };
        s.err_ema *= 1.0 - a;
        s.open_fail_ema *= 1.0 - a;
        s.samples += 1;
    }

    pub fn record_error(&mut self, id: &str) {
        let s = self.stats.entry(id.into()).or_default();
        let a = self.alpha;
        // 半衰：把错误短期放大到 EMA，再按 halflife 逐步回落（近似：提高权重）
        s.err_ema = a * 1.0 + (1.0 - a) * s.err_ema;
    }

    pub fn record_open_fail(&mut self, id: &str) {
        let s = self.stats.entry(id.into()).or_default();
        let a = self.alpha;
        s.open_fail_ema = a * 1.0 + (1.0 - a) * s.open_fail_ema;
    }

    pub fn get_current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    pub fn get_stats(&self) -> &HashMap<String, Stats> {
        &self.stats
    }
}

#[cfg(feature = "selector_p3")]
impl crate::outbound::feedback::SelectorFeedback for ScoreSelector {
    fn record_success(&mut self, id: &str, rtt_ms: u64) {
        #[cfg(feature = "chaos")]
        crate::util::failpoint::hit("p3::feedback");
        self.record_success(id, rtt_ms);
    }
    fn record_error(&mut self, id: &str) {
        #[cfg(feature = "chaos")]
        crate::util::failpoint::hit("p3::feedback");
        self.record_error(id);
    }
    fn record_open_fail(&mut self, id: &str) {
        #[cfg(feature = "chaos")]
        crate::util::failpoint::hit("p3::feedback");
        self.record_open_fail(id);
    }
}
