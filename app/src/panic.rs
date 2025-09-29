use std::backtrace::Backtrace;
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
        let file = format!("target/crash/crash-{}-{}.log", ts, git);
        let thread = std::thread::current()
            .name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unnamed".to_string());
        let trace_id = if std::env::var("SB_TRACE_ID").ok().as_deref() == Some("1") {
            Some(crate::telemetry::next_trace_id())
        } else {
            None
        };
        let mut body = String::new();
        body.push_str(&format!("ts={}\n", ts));
        body.push_str(&format!("git={}\n", git));
        body.push_str(&format!("thread={}\n", thread));
        if let Some(tid) = trace_id.as_ref() {
            body.push_str(&format!("trace_id={}\n", tid));
        }
        body.push_str(&format!("panic={}\n", info));
        body.push_str(&format!("backtrace={:?}\n", Backtrace::capture()));
        if std::fs::write(&file, body).is_ok() {
            let max_keep = std::env::var("SB_PANIC_LOG_MAX")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(10);
            if max_keep > 0 {
                if let Ok(read_dir) = std::fs::read_dir(dir) {
                    let mut entries: Vec<_> = read_dir
                        .filter_map(|e| e.ok())
                        .filter(|e| {
                            e.path()
                                .extension()
                                .and_then(|ext| ext.to_str())
                                .map(|ext| ext.eq_ignore_ascii_case("log"))
                                .unwrap_or(false)
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
