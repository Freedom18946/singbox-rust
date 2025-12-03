//! Minimal structured logging with optional redaction.
//! Fields: ts, level, target, msg, fields...
use std::io::Write;
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct LogConfig {
    level: Level,
    timestamp: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::Info,
            timestamp: true,
        }
    }
}

static CONFIG: OnceLock<RwLock<LogConfig>> = OnceLock::new();

fn get_config() -> LogConfig {
    CONFIG
        .get_or_init(|| RwLock::new(LogConfig::default()))
        .read()
        .unwrap()
        .clone()
}

pub fn configure(ir: &sb_config::ir::LogIR) {
    let mut config = LogConfig::default();
    if let Some(l) = &ir.level {
        if let Some(lvl) = Level::from_str(l) {
            config.level = lvl;
        }
    }
    if let Some(ts) = ir.timestamp {
        config.timestamp = ts;
    }

    let lock = CONFIG.get_or_init(|| RwLock::new(LogConfig::default()));
    *lock.write().unwrap() = config;
}

fn redact(s: &str) -> String {
    if std::env::var("LOG_REDACT").ok().as_deref() == Some("1") {
        let n = s.len();
        if n <= 4 {
            "***".into()
        } else {
            format!("{}***{}", &s[..2], &s[n.saturating_sub(2)..])
        }
    } else {
        s.to_string()
    }
}

fn ts_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis(),
        Err(_) => 0,
    }
}

static TARGET: OnceLock<String> = OnceLock::new();
pub fn init(target: &str) {
    let _ = TARGET.set(target.to_string());
}

pub fn log(level: Level, msg: &str, kv: &[(&str, &str)]) {
    let config = get_config();

    // Filter by level
    if level > config.level {
        return;
    }

    let target = TARGET.get().cloned().unwrap_or_else(|| "app".into());
    let mut out = String::new();

    if config.timestamp {
        out.push_str(&format!("ts={} ", ts_ms()));
    }

    out.push_str(&format!(
        "level={} target={} msg={}",
        level.as_str(),
        target,
        msg
    ));

    for (k, v) in kv {
        out.push(' ');
        out.push_str(k);
        out.push('=');
        out.push_str(&redact(v));
    }
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{out}");
}

#[macro_export]
macro_rules! slog {
    (info, $($tt:tt)*) => { $crate::log::log($crate::log::Level::Info, &format!($($tt)*), &[]) };
    (warn, $($tt:tt)*) => { $crate::log::log($crate::log::Level::Warn, &format!($($tt)*), &[]) };
    (error, $($tt:tt)*) => { $crate::log::log($crate::log::Level::Error, &format!($($tt)*), &[]) };
    (debug, $($tt:tt)*) => { $crate::log::log($crate::log::Level::Debug, &format!($($tt)*), &[]) };
    (trace, $($tt:tt)*) => { $crate::log::log($crate::log::Level::Trace, &format!($($tt)*), &[]) };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redact_basic() {
        std::env::set_var("LOG_REDACT", "1");
        assert!(redact("password123").contains("***"));
        std::env::remove_var("LOG_REDACT");
    }

    #[test]
    fn test_level_ordering() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
    }
}
