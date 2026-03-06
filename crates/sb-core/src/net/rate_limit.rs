use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn parse_env_u64_default(key: &str, default: u64) -> u64 {
    match std::env::var(key).ok() {
        Some(raw) => match raw.parse::<u64>() {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "rate-limit env '{key}' value '{raw}' is invalid; silent parse fallback is disabled; fix the config explicitly: {err}; using default {default}"
                );
                default
            }
        },
        None => default,
    }
}

pub struct RateLimiter {
    tick_ms: u64,       // 时间片（ms）
    bps_tick: u64,      // 每片最大字节
    pps_tick: u64,      // 每片最大包数
    tick: AtomicU64,    // 当前片序号
    bytes: AtomicU64,   // 片内累计字节
    packets: AtomicU64, // 片内累计包
}

impl RateLimiter {
    pub fn from_env_udp() -> Option<Self> {
        let bps = parse_env_u64_default("SB_UDP_OUTBOUND_BPS_MAX", 0);
        let pps = parse_env_u64_default("SB_UDP_OUTBOUND_PPS_MAX", 0);
        if bps == 0 && pps == 0 {
            return None;
        }
        let tick_ms = 100;
        let bps_tick = if bps == 0 {
            0
        } else {
            (bps.saturating_mul(tick_ms)) / 1000
        };
        let pps_tick = if pps == 0 {
            0
        } else {
            (pps.saturating_mul(tick_ms)) / 1000
        };
        Some(Self {
            tick_ms,
            bps_tick,
            pps_tick,
            tick: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            packets: AtomicU64::new(0),
        })
    }

    #[inline]
    fn now_tick(&self) -> u64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now_ms / self.tick_ms
    }

    /// 返回 Ok(()) 允许；Err("bps"|"pps") 拒绝
    pub fn allow(&self, sz: usize) -> Result<(), &'static str> {
        let t = self.now_tick();
        let prev = self.tick.load(Ordering::Relaxed);
        if t != prev {
            // 简化：跨片直接重置（竞争时容忍轻微偏差）
            self.tick.store(t, Ordering::Relaxed);
            self.bytes.store(0, Ordering::Relaxed);
            self.packets.store(0, Ordering::Relaxed);
        }
        if self.pps_tick > 0 {
            let p = self.packets.fetch_add(1, Ordering::Relaxed) + 1;
            if p > self.pps_tick {
                return Err("pps");
            }
        }
        if self.bps_tick > 0 {
            let b = self.bytes.fetch_add(sz as u64, Ordering::Relaxed) + (sz as u64);
            if b > self.bps_tick {
                return Err("bps");
            }
        }
        Ok(())
    }
}
