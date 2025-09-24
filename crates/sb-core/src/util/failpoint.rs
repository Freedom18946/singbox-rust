#![cfg(feature = "chaos")]
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Panic,
    Delay(u64),
}

static FP_CFG: OnceLock<String> = OnceLock::new();

/// Initialize failpoint configuration from `SB_FAILPOINTS` environment variable.
pub fn init_from_env() {
    if let Ok(cfg) = std::env::var("SB_FAILPOINTS") {
        let _ = FP_CFG.set(cfg);
    }
}

fn decide(site: &str) -> Action {
    let Some(cfg) = FP_CFG.get() else {
        return Action::None;
    };
    for entry in cfg.split(';') {
        let mut kv = entry.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        if key != site {
            continue;
        }
        let val = kv.next().unwrap_or("");
        let mut rate = 1.0f64;
        let mut action = Action::Panic;
        for part in val.split(',') {
            if let Some(x) = part.strip_prefix("rate:") {
                rate = x.parse().unwrap_or(1.0);
            } else if part.eq_ignore_ascii_case("panic") {
                action = Action::Panic;
            } else if part.eq_ignore_ascii_case("none") {
                action = Action::None;
            } else if let Some(ms) = part
                .strip_prefix("delay:")
                .and_then(|m| m.strip_suffix("ms"))
                .and_then(|m| m.parse::<u64>().ok())
            {
                action = Action::Delay(ms);
            }
        }
        if fastrand::f64() <= rate {
            return action;
        }
    }
    Action::None
}

/// Trigger failpoint for the given site if configured.
pub fn hit(site: &str) {
    match decide(site) {
        Action::None => {}
        Action::Panic => panic!("failpoint hit: {site}"),
        Action::Delay(ms) => std::thread::sleep(Duration::from_millis(ms)),
    }
}
