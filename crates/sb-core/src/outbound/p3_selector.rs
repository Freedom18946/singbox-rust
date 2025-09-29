//! P3 selector with cold-start protection & jitter threshold (behind env/feature).
//! score = w_rtt * rtt_ema + w_err * err_rate + w_fuse * fuse_penalty
//! - rtt_ema：指数滑动平均
//! - err_rate：近窗口失败率
//! - fuse：熔断开关（触发后短时降权）
use sb_metrics::constants::*;
use sb_metrics::registry::global as M;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PickerConfig {
    pub alpha_rtt: f64,          // EMA 平滑
    pub window_err: usize,       // 错误统计窗口
    pub jitter_threshold: f64,   // 抖动阈：低于阈值不切换
    pub fuse_penalty: f64,       // 熔断惩罚项
    pub cold_start_bias_ms: u64, // 冷启动 bias（避免刚上线被冷落）
}

impl Default for PickerConfig {
    fn default() -> Self {
        Self {
            alpha_rtt: 0.2,
            window_err: 64,
            jitter_threshold: 0.05,
            fuse_penalty: 100.0,
            cold_start_bias_ms: 50,
        }
    }
}

#[derive(Clone, Debug)]
struct Stat {
    rtt_ema: f64,
    err_ring: Vec<bool>,
    err_idx: usize,
    last_seen: Instant,
    fused_until: Option<Instant>,
}

impl Stat {
    fn new(now: Instant, cfg: &PickerConfig) -> Self {
        Self {
            rtt_ema: cfg.cold_start_bias_ms as f64,
            err_ring: vec![false; cfg.window_err.max(1)],
            err_idx: 0,
            last_seen: now,
            fused_until: None,
        }
    }
    fn feed_rtt(&mut self, ms: f64, cfg: &PickerConfig) {
        self.rtt_ema = if self.rtt_ema == 0.0 {
            ms
        } else {
            cfg.alpha_rtt * ms + (1.0 - cfg.alpha_rtt) * self.rtt_ema
        };
        self.last_seen = Instant::now();
    }
    fn feed_result(&mut self, ok: bool) {
        let len = self.err_ring.len();
        self.err_ring[self.err_idx % len] = !ok;
        self.err_idx += 1;
    }
    fn err_rate(&self) -> f64 {
        let tot = self.err_ring.len() as f64;
        let bad = self.err_ring.iter().filter(|b| **b).count() as f64;
        if tot == 0.0 {
            0.0
        } else {
            bad / tot
        }
    }
    fn fuse(&mut self, dur: Duration) {
        self.fused_until = Some(Instant::now() + dur);
    }
    fn fuse_penalty(&self, cfg: &PickerConfig) -> f64 {
        match self.fused_until {
            Some(t) if Instant::now() < t => cfg.fuse_penalty,
            _ => 0.0,
        }
    }
}

pub struct P3Selector {
    cfg: PickerConfig,
    outbounds: Vec<String>,
    stats: HashMap<String, Stat>,
    last_pick: Option<String>,
}

impl P3Selector {
    pub fn new(outbounds: Vec<String>, cfg: PickerConfig) -> Self {
        let now = Instant::now();
        let mut stats = HashMap::new();
        for ob in &outbounds {
            stats.insert(ob.clone(), Stat::new(now, &cfg));
        }
        Self {
            cfg,
            outbounds,
            stats,
            last_pick: None,
        }
    }
    pub fn record_rtt(&mut self, ob: &str, ms: f64) {
        if let Some(s) = self.stats.get_mut(ob) {
            s.feed_rtt(ms, &self.cfg);
        }
    }
    pub fn record_result(&mut self, ob: &str, ok: bool) {
        if let Some(s) = self.stats.get_mut(ob) {
            s.feed_result(ok);
        }
        if !ok {
            if let Some(s) = self.stats.get_mut(ob) {
                s.fuse(Duration::from_millis(300));
            }
        }
    }
    fn score_of(&self, ob: &str) -> f64 {
        let s = match self.stats.get(ob) {
            Some(x) => x,
            None => return f64::MAX,
        };
        s.rtt_ema + 1000.0 * s.err_rate() + s.fuse_penalty(&self.cfg)
    }
    /// Pick a member outbound by score with jitter threshold.
    ///
    /// Example
    /// ```
    /// use sb_core::outbound::p3_selector::{P3Selector, PickerConfig};
    /// let mut s = P3Selector::new(vec!["a".into(), "b".into()], PickerConfig::default());
    /// for _ in 0..10 { s.record_rtt("a", 20.0); s.record_rtt("b", 50.0); }
    /// let pick = s.pick();
    /// assert!(pick == "a" || pick == "b");
    /// ```
    pub fn pick(&mut self) -> String {
        // 计算得分
        let mut best = None::<(String, f64)>;
        for ob in &self.outbounds {
            let sc = self.score_of(ob);
            // 记录分数到 metrics
            M().proxy_select_score.set(&[(LABEL_OUTBOUND, ob)], sc);
            match &mut best {
                None => best = Some((ob.clone(), sc)),
                Some((_p, b)) if sc < *b => best = Some((ob.clone(), sc)),
                _ => {}
            }
        }
        let (pick, pick_sc) = match best {
            Some(v) => v,
            None => {
                let fallback = self
                    .last_pick
                    .clone()
                    .or_else(|| self.outbounds.first().cloned())
                    .unwrap_or_default();
                M().proxy_select_total
                    .inc(&[(LABEL_OUTBOUND, fallback.as_str())]);
                return fallback;
            }
        };
        // 抖动阈：若新旧差距不足阈值比率，保持原选择
        if let Some(prev) = self.last_pick.clone() {
            let prev_sc = self.score_of(&prev);
            if (prev_sc - pick_sc).abs() / prev_sc.max(1.0) < self.cfg.jitter_threshold {
                M().proxy_select_total
                    .inc(&[(LABEL_OUTBOUND, prev.as_str())]);
                return prev;
            }
        }
        self.last_pick = Some(pick.clone());
        M().proxy_select_total
            .inc(&[(LABEL_OUTBOUND, pick.as_str())]);
        pick
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trending_selection() {
        let mut s = P3Selector::new(vec!["a".into(), "b".into()], PickerConfig::default());
        // 初期 a/b 分不相上下，给 a 更好的 rtt
        for _ in 0..10 {
            s.record_rtt("a", 20.0);
            s.record_rtt("b", 60.0);
        }
        let p = s.pick();
        assert_eq!(p, "a");
        // 模拟 b 逐步变好
        for i in 0..50 {
            s.record_rtt("b", 25.0 - (i as f64 * 0.2).max(0.0));
            s.record_rtt("a", 22.0 + (i as f64 * 0.1));
        }
        let _p2 = s.pick();
        // 可能仍为 a（抖动阈），再喂几轮
        for _ in 0..20 {
            s.record_rtt("b", 10.0);
        }
        let p3 = s.pick();
        assert_eq!(p3, "b");
    }
}
