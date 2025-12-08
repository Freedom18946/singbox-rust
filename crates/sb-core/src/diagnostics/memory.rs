//! Memory statistics module.
//!
//! Provides memory usage information similar to Go's runtime.MemStats.
//! Since Rust has no GC, we provide system memory info instead.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global allocated bytes counter (can be updated by custom allocators).
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Memory statistics.
///
/// Mirrors Go's `/debug/memory` endpoint output.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryStats {
    /// Heap in use (allocated but not freed).
    pub heap: String,
    /// Stack in use (estimated from thread count).
    pub stack: String,
    /// Idle memory (not applicable in Rust, placeholder).
    pub idle: String,
    /// Number of active tokio tasks (analog to goroutines).
    pub tasks: u64,
    /// Resident set size (RSS) from OS.
    pub rss: String,
    /// Total allocated bytes (if tracked).
    pub allocated: u64,
    /// System memory info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemMemory>,
}

/// System memory information.
#[derive(Debug, Clone, Serialize)]
pub struct SystemMemory {
    /// Total physical memory.
    pub total: String,
    /// Available memory.
    pub available: String,
    /// Used memory.
    pub used: String,
}

impl MemoryStats {
    /// Collect current memory statistics.
    pub fn collect() -> Self {
        let allocated = ALLOCATED_BYTES.load(Ordering::Relaxed);
        let rss = get_rss_bytes();
        let tasks = get_task_count();

        // Estimate stack usage (tokio default stack is 2MB per worker thread)
        let thread_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1) as u64;
        let stack_estimate = thread_count * 2 * 1024 * 1024;

        Self {
            heap: format_bytes(allocated),
            stack: format_bytes(stack_estimate),
            idle: "N/A".to_string(),
            tasks,
            rss: format_bytes(rss),
            allocated,
            system: get_system_memory(),
        }
    }
}

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Get RSS (Resident Set Size) from OS.
#[cfg(target_os = "linux")]
fn get_rss_bytes() -> u64 {
    // Read from /proc/self/statm
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            // Second field is RSS in pages
            parts.get(1)?.parse::<u64>().ok()
        })
        .map(|pages| pages * 4096) // Assume 4KB pages
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn get_rss_bytes() -> u64 {
    use std::mem::MaybeUninit;

    #[repr(C)]
    struct RUsage {
        ru_utime: libc::timeval,
        ru_stime: libc::timeval,
        ru_maxrss: libc::c_long,
        // ... other fields we don't need
        _padding: [u8; 128],
    }

    let mut usage = MaybeUninit::<RUsage>::uninit();
    unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr() as *mut _) == 0 {
            // On macOS, ru_maxrss is in bytes
            usage.assume_init().ru_maxrss as u64
        } else {
            0
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_rss_bytes() -> u64 {
    0
}

/// Get approximate tokio task count.
fn get_task_count() -> u64 {
    // Tokio doesn't expose task count directly.
    // We could use metrics crate if enabled, otherwise estimate.
    // For now, return thread count as a baseline.
    std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
}

/// Get system memory info.
fn get_system_memory() -> Option<SystemMemory> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut total = 0u64;
        let mut available = 0u64;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total = parse_meminfo_value(line);
            } else if line.starts_with("MemAvailable:") {
                available = parse_meminfo_value(line);
            }
        }

        let used = total.saturating_sub(available);

        Some(SystemMemory {
            total: format_bytes(total),
            available: format_bytes(available),
            used: format_bytes(used),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// Update global allocated bytes (called by custom allocator if enabled).
pub fn update_allocated_bytes(bytes: u64) {
    ALLOCATED_BYTES.store(bytes, Ordering::Relaxed);
}

/// Add to global allocated bytes.
pub fn add_allocated_bytes(delta: i64) {
    if delta >= 0 {
        ALLOCATED_BYTES.fetch_add(delta as u64, Ordering::Relaxed);
    } else {
        ALLOCATED_BYTES.fetch_sub((-delta) as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_memory_stats_collect() {
        let stats = MemoryStats::collect();
        assert!(!stats.heap.is_empty());
        assert!(!stats.stack.is_empty());
        assert!(!stats.rss.is_empty());
    }
}
