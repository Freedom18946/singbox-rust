//! Minimal structured logging with optional redaction.
//! Fields: ts, level, target, msg, fields...
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
impl Level {
    fn as_str(&self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
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
    let target = TARGET.get().cloned().unwrap_or_else(|| "app".into());
    let mut out = String::new();
    out.push_str(&format!(
        "ts={} level={} target={} msg={}",
        ts_ms(),
        level.as_str(),
        target,
        msg
    ));
    for (k, v) in kv.iter() {
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
}
