use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::path::Path;
use std::time::SystemTime;

pub fn install() {
    if std::env::var("SB_PANIC_LOG").ok().as_deref() != Some("1") {
        return;
    }
    let git = option_env!("SB_GIT_SHA").unwrap_or("unknown").to_string();
    std::panic::set_hook(Box::new(move |info| {
        let dir = Path::new("target/crash");
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let file = format!("target/crash/crash-{ts}-{git}.log");
        let thread = std::thread::current()
            .name().map_or_else(|| "unnamed".to_string(), std::string::ToString::to_string);
        let trace_id = if std::env::var("SB_TRACE_ID").ok().as_deref() == Some("1") {
            Some(crate::telemetry::next_trace_id())
        } else {
            None
        };
        let mut body = String::new();
        let _ = writeln!(body, "ts={ts}");
        let _ = writeln!(body, "git={git}");
        let _ = writeln!(body, "thread={thread}");
        if let Some(tid) = trace_id.as_ref() {
            let _ = writeln!(body, "trace_id={tid}");
        }
        let _ = writeln!(body, "panic={info}");
        let _ = writeln!(body, "backtrace={:?}", Backtrace::capture());
        if std::fs::write(&file, body).is_ok() {
            let max_keep = std::env::var("SB_PANIC_LOG_MAX")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(10);
            if max_keep > 0 {
                if let Ok(read_dir) = std::fs::read_dir(dir) {
                    let mut entries: Vec<_> = read_dir
                        .filter_map(std::result::Result::ok)
                        .filter(|e| {
                            e.path()
                                .extension()
                                .and_then(|ext| ext.to_str())
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
                        })
                        .collect();
                    entries.sort_by_key(|entry| {
                        entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(SystemTime::UNIX_EPOCH)
                    });
                    let excess = entries.len().saturating_sub(max_keep);
                    for entry in entries.into_iter().take(excess) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }));
}
