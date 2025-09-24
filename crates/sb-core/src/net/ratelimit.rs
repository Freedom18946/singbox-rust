use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

/// 100ms 计时片；简单无锁漏桶：原子计数 + 原子时间片翻转。
struct Bucket {
    epoch_tick: AtomicU64,
    bytes_used: AtomicU64,
    pkts_used: AtomicU64,
    bytes_q: u64,
    pkts_q: u64,
}

impl Bucket {
    fn new(bytes_q_s: u64, pkts_q_s: u64) -> Self {
        // 换算到 100ms 片的配额（向上取整）
        let to_slice = |per_s: u64| -> u64 {
            if per_s == 0 {
                0
            } else {
                (per_s + 9) / 10
            }
        };
        Self {
            epoch_tick: AtomicU64::new(Self::now_tick()),
            bytes_used: AtomicU64::new(0),
            pkts_used: AtomicU64::new(0),
            bytes_q: to_slice(bytes_q_s),
            pkts_q: to_slice(pkts_q_s),
        }
    }

    #[inline]
    fn now_tick() -> u64 {
        // 100ms tick（相对进程启动，不用系统时钟）
        static START: OnceLock<Instant> = OnceLock::new();
        let base = START.get_or_init(Instant::now);
        base.elapsed().as_millis() as u64 / 100
    }

    #[inline]
    fn rollover_if_needed(&self, now_tick: u64) {
        let last = self.epoch_tick.load(Ordering::Relaxed);
        if last == now_tick {
            return;
        }
        // 只要有一个线程 CAS 成功就完成翻转与清零
        if self
            .epoch_tick
            .compare_exchange(last, now_tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.bytes_used.store(0, Ordering::Relaxed);
            self.pkts_used.store(0, Ordering::Relaxed);
        }
    }

    /// 尝试消耗一次发送，返回 Ok(()) 允许；Err(reason) 超限。
    fn try_consume(&self, bytes: usize) -> Result<(), &'static str> {
        if self.bytes_q == 0 && self.pkts_q == 0 {
            return Ok(()); // 未启用
        }
        let now = Self::now_tick();
        self.rollover_if_needed(now);
        // 先 pps
        if self.pkts_q > 0 {
            let p = self.pkts_used.fetch_add(1, Ordering::Relaxed) + 1;
            if p > self.pkts_q {
                return Err("pps");
            }
        }
        // 再 bps
        if self.bytes_q > 0 {
            let b = self.bytes_used.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
            if b > self.bytes_q {
                return Err("bps");
            }
        }
        Ok(())
    }
}

fn global_bucket() -> &'static Bucket {
    static B: OnceLock<Bucket> = OnceLock::new();
    B.get_or_init(|| {
        let bps = std::env::var("SB_UDP_OUTBOUND_BPS_MAX")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let pps = std::env::var("SB_UDP_OUTBOUND_PPS_MAX")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        Bucket::new(bps, pps)
    })
}

/// 对外接口：检查是否应当丢弃该 UDP 出站（返回 Some(reason) 表示应丢弃）
pub fn maybe_drop_udp(len: usize) -> Option<&'static str> {
    match global_bucket().try_consume(len) {
        Ok(()) => None,
        Err(reason) => Some(reason),
    }
}
