// L10.2.2 — Resource leak detector.
//
// Analyses memory series and fd counts to detect upward trends that suggest
// leaks during long-running (soak) test cases.

use serde::{Deserialize, Serialize};

use crate::snapshot::MemoryPoint;

/// Result of a leak analysis check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakSignal {
    pub kind: LeakKind,
    pub message: String,
    /// Linear regression slope (units per sample).
    pub slope: f64,
    /// Threshold that was exceeded.
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeakKind {
    Memory,
    FileDescriptor,
}

/// Default slope threshold for memory leak detection (bytes per sample).
/// A steady increase of >100 KB per sample point is suspicious.
const DEFAULT_MEMORY_SLOPE_THRESHOLD: f64 = 100_000.0;

/// Default slope threshold for fd leak detection (fds per sample).
#[allow(dead_code)]
const DEFAULT_FD_SLOPE_THRESHOLD: f64 = 1.0;

/// Detect a memory leak from a series of `MemoryPoint` samples.
///
/// Uses simple linear regression on the `inuse` field.  If the slope
/// exceeds the threshold the function returns `Some(LeakSignal)`.
pub fn detect_memory_leak(series: &[MemoryPoint], threshold: Option<f64>) -> Option<LeakSignal> {
    let threshold = threshold.unwrap_or(DEFAULT_MEMORY_SLOPE_THRESHOLD);
    if series.len() < 3 {
        return None;
    }

    let values: Vec<f64> = series.iter().map(|p| p.inuse as f64).collect();
    let slope = linear_regression_slope(&values);

    if slope > threshold {
        Some(LeakSignal {
            kind: LeakKind::Memory,
            message: format!(
                "memory inuse slope {slope:.1} bytes/sample exceeds threshold {threshold:.1}"
            ),
            slope,
            threshold,
        })
    } else {
        None
    }
}

/// Detect a file descriptor leak from a series of fd-count samples.
///
/// Expects samples taken at regular intervals (e.g. via `lsof -p`).
#[allow(dead_code)]
pub fn detect_fd_leak(fd_samples: &[u64], threshold: Option<f64>) -> Option<LeakSignal> {
    let threshold = threshold.unwrap_or(DEFAULT_FD_SLOPE_THRESHOLD);
    if fd_samples.len() < 3 {
        return None;
    }

    let values: Vec<f64> = fd_samples.iter().map(|&v| v as f64).collect();
    let slope = linear_regression_slope(&values);

    if slope > threshold {
        Some(LeakSignal {
            kind: LeakKind::FileDescriptor,
            message: format!(
                "fd count slope {slope:.2} fds/sample exceeds threshold {threshold:.2}"
            ),
            slope,
            threshold,
        })
    } else {
        None
    }
}

/// Sample fd count for a process using `lsof -p <pid>`.
///
/// Returns `None` if the process doesn't exist or lsof is unavailable.
#[allow(dead_code)]
pub async fn sample_fd_count(pid: u32) -> Option<u64> {
    let output = tokio::process::Command::new("lsof")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // lsof outputs one line per fd, minus the header line.
    let count = output.stdout.iter().filter(|&&b| b == b'\n').count();
    Some(count.saturating_sub(1) as u64)
}

/// Simple linear regression slope: Σ((x-x̄)(y-ȳ)) / Σ((x-x̄)²)
fn linear_regression_slope(values: &[f64]) -> f64 {
    let n = values.len() as f64;
    if n < 2.0 {
        return 0.0;
    }

    let x_mean = (n - 1.0) / 2.0;
    let y_mean: f64 = values.iter().sum::<f64>() / n;

    let mut numerator = 0.0;
    let mut denominator = 0.0;

    for (i, &y) in values.iter().enumerate() {
        let x = i as f64;
        numerator += (x - x_mean) * (y - y_mean);
        denominator += (x - x_mean) * (x - x_mean);
    }

    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::MemoryPoint;

    #[test]
    fn stable_memory_no_leak() {
        let series: Vec<MemoryPoint> = (0..10)
            .map(|_| MemoryPoint {
                inuse: 1_000_000,
                oslimit: 0,
            })
            .collect();
        assert!(detect_memory_leak(&series, None).is_none());
    }

    #[test]
    fn rising_memory_detected() {
        let series: Vec<MemoryPoint> = (0..10)
            .map(|i| MemoryPoint {
                inuse: 1_000_000 + i * 500_000,
                oslimit: 0,
            })
            .collect();
        let signal = detect_memory_leak(&series, None);
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().kind, LeakKind::Memory);
    }

    #[test]
    fn too_few_samples_no_signal() {
        let series = vec![
            MemoryPoint {
                inuse: 1_000_000,
                oslimit: 0,
            },
            MemoryPoint {
                inuse: 2_000_000,
                oslimit: 0,
            },
        ];
        assert!(detect_memory_leak(&series, None).is_none());
    }

    #[test]
    fn stable_fds_no_leak() {
        let samples = vec![50, 50, 51, 50, 50, 51, 50];
        assert!(detect_fd_leak(&samples, None).is_none());
    }

    #[test]
    fn rising_fds_detected() {
        let samples = vec![50, 55, 60, 65, 70, 75, 80];
        let signal = detect_fd_leak(&samples, None);
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().kind, LeakKind::FileDescriptor);
    }

    #[test]
    fn linear_regression_exact() {
        // y = 2x + 1 → slope = 2.0
        let values = vec![1.0, 3.0, 5.0, 7.0, 9.0];
        let slope = linear_regression_slope(&values);
        assert!((slope - 2.0).abs() < 0.001);
    }

    #[test]
    fn linear_regression_flat() {
        let values = vec![5.0, 5.0, 5.0, 5.0];
        let slope = linear_regression_slope(&values);
        assert!(slope.abs() < 0.001);
    }
}
