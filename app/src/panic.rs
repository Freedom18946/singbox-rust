//! Panic Handling and Crash Reporting
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module implements the **Last Resort Error Handling** mechanism.
//! It captures panic information, writes it to disk, and ensures critical debug data is preserved.
//!
//! 本模块实现了 **最后手段错误处理** 机制。
//! 它捕获 panic 信息，将其写入磁盘，并确保保留关键调试数据。
//!
//! ## Strategic Features / 战略特性
//! - **Crash Logging / 崩溃日志**: Automatically saves panic details (stack trace, thread name, git SHA) to `target/crash`.
//!   自动保存 panic 详情（堆栈跟踪、线程名称、git SHA）到 `target/crash`。
//! - **Trace ID Correlation / 追踪 ID 关联**: If enabled, correlates the crash with the current trace ID for distributed debugging.
//!   如果启用，将崩溃与当前追踪 ID 关联，以便进行分布式调试。
//! - **Log Rotation / 日志轮转**: Automatically cleans up old crash logs to prevent disk exhaustion.
//!   自动清理旧的崩溃日志以防止磁盘耗尽。

use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::path::Path;
use std::time::SystemTime;

pub fn install() {
    // 1. Basic check for crash logging feature flag (env var)
    let crash_enabled = std::env::var("SB_PANIC_LOG").ok().as_deref() == Some("1");

    // 2. Capture the previous hook to chain it?
    // Actually, for a service, we usually want to control the output format.
    // But chaining is safer to respect other libs.
    let next = std::panic::take_hook();

    let git = option_env!("SB_GIT_SHA").unwrap_or("unknown").to_string();

    std::panic::set_hook(Box::new(move |info| {
        // A. Standard Output (Stderr) - Mimic default behavior or better
        eprintln!("[PANIC] {info}");

        // B. Tracing
        tracing::error!("panic: {}", info);

        // C. Crash Report (if enabled)
        if crash_enabled {
            let dir = Path::new("target/crash");
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!("Failed to create crash directory: {e}");
                // Don't return, call next hook
            } else {
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                let file = format!("target/crash/crash-{ts}-{git}.log");
                let thread = std::thread::current()
                    .name()
                    .map_or_else(|| "unnamed".to_string(), std::string::ToString::to_string);
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

                match std::fs::write(&file, body) {
                    Ok(()) => {
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
                    Err(e) => {
                        eprintln!("Failed to write crash log to {file}: {e}");
                    }
                }
            }
        }

        // D. Call next hook (e.g. default one that prints to stderr?
        // Wait, default hook prints to stderr. If we print to stderr above, we might duplicate.
        // However, default hook output is "thread 'main' panicked at ..." which is nice.
        // Our 'eprintln!("[PANIC] ...")' is simpler.
        // Let's rely on chaining for standard output if we want standard format.
        // But `tracing::error` is added by us.
        // If we call `next(info)`, it will print to stderr again.
        // To avoid duplication, we can skip our explicit eprintln if we chain.
        // But checking `crash_enabled` logic suggests we want full control.
        // Let's call `next(info)` at the end to ensure standard behavior (like exit code? No, panic always aborts/unwinds).
        // Calling `next` ensures other hooks (e.g. testing) work.
        next(info);
    }));
}
