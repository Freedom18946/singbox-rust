//! Periodic health checks for named outbounds.
//! - 环境变量启用：HEALTH=1
//! - 目标：HEALTH_TARGET（默认 "1.1.1.1:80"）
//! - 间隔：HEALTH_INTERVAL_MS（默认 2000ms）
use crate::adapter::Bridge;
use sb_metrics::registry::global as M;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn target() -> (String, u16) {
    if let Ok(s) = std::env::var("HEALTH_TARGET") {
        if let Some((h, p)) = s.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
    }
    ("1.1.1.1".into(), 80)
}

fn interval() -> Duration {
    let ms = std::env::var("HEALTH_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);
    Duration::from_millis(ms)
}

pub fn spawn_health_task(bridge: Arc<Bridge>) -> thread::JoinHandle<()> {
    let (host, port) = target();
    let iv = interval();
    thread::spawn(move || {
        loop {
            for (name, _kind, conn) in bridge.outbounds.iter() {
                let t0 = Instant::now();
                let ok = conn.connect(&host, port).is_ok();
                let up = if ok { 1.0 } else { 0.0 };
                // 指标：outbound_up{outbound}
                M().proxy_select_score
                    .set(&[("outbound", name.as_str())], up);
                // 兼容导出：同步到 OUTBOUND_UP（gauge）
                M().outbound_up.set(&[("outbound", name.as_str())], up);
                let _ = t0; // 预留耗时：若需要可上报 histogram
            }
            thread::sleep(iv);
        }
    })
}
