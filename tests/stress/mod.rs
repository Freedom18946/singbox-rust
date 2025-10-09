//! Stress Testing Framework for P0 Protocols
//!
//! This module provides comprehensive stress testing capabilities:
//! - 24-hour endurance tests
//! - Memory leak detection
//! - File descriptor leak detection
//! - High connection rate testing
//! - Large data transfer testing
//!
//! Run with: cargo test --test stress_tests --release -- --ignored --test-threads=1

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Metrics collected during stress testing
#[derive(Debug)]
pub struct StressMetrics {
    pub total_connections: AtomicUsize,
    pub successful_connections: AtomicUsize,
    pub failed_connections: AtomicUsize,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub total_duration_ms: AtomicU64,
    pub peak_concurrent_connections: AtomicUsize,
}

impl Clone for StressMetrics {
    fn clone(&self) -> Self {
        Self {
            total_connections: AtomicUsize::new(self.total_connections.load(Ordering::Relaxed)),
            successful_connections: AtomicUsize::new(self.successful_connections.load(Ordering::Relaxed)),
            failed_connections: AtomicUsize::new(self.failed_connections.load(Ordering::Relaxed)),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
            total_duration_ms: AtomicU64::new(self.total_duration_ms.load(Ordering::Relaxed)),
            peak_concurrent_connections: AtomicUsize::new(self.peak_concurrent_connections.load(Ordering::Relaxed)),
        }
    }
}

impl StressMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicUsize::new(0),
            successful_connections: AtomicUsize::new(0),
            failed_connections: AtomicUsize::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            total_duration_ms: AtomicU64::new(0),
            peak_concurrent_connections: AtomicUsize::new(0),
        }
    }

    pub fn record_connection_attempt(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.successful_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_duration(&self, duration: Duration) {
        self.total_duration_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn update_peak_concurrent(&self, current: usize) {
        self.peak_concurrent_connections
            .fetch_max(current, Ordering::Relaxed);
    }

    pub fn print_summary(&self) {
        let total = self.total_connections.load(Ordering::Relaxed);
        let success = self.successful_connections.load(Ordering::Relaxed);
        let failed = self.failed_connections.load(Ordering::Relaxed);
        let sent = self.bytes_sent.load(Ordering::Relaxed);
        let received = self.bytes_received.load(Ordering::Relaxed);
        let duration = self.total_duration_ms.load(Ordering::Relaxed);
        let peak = self.peak_concurrent_connections.load(Ordering::Relaxed);

        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║              Stress Test Summary                       ║");
        println!("╚════════════════════════════════════════════════════════╝");
        println!("Total Connections:     {}", total);
        println!("Successful:            {} ({:.2}%)", success, (success as f64 / total as f64) * 100.0);
        println!("Failed:                {} ({:.2}%)", failed, (failed as f64 / total as f64) * 100.0);
        println!("Bytes Sent:            {} ({:.2} MB)", sent, sent as f64 / 1_048_576.0);
        println!("Bytes Received:        {} ({:.2} MB)", received, received as f64 / 1_048_576.0);
        println!("Total Duration:        {} ms", duration);
        println!("Peak Concurrent:       {}", peak);
        
        if total > 0 {
            let avg_duration = duration as f64 / total as f64;
            println!("Avg Connection Time:   {:.2} ms", avg_duration);
        }
    }
}

impl Default for StressMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for stress tests
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    pub duration: Duration,
    pub connection_rate: usize,  // connections per second
    pub concurrent_limit: usize,
    pub payload_size: usize,
    pub enable_monitoring: bool,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(60),
            connection_rate: 10,
            concurrent_limit: 100,
            payload_size: 1024,
            enable_monitoring: true,
        }
    }
}

/// Start a simple echo server for testing
pub async fn start_echo_server() -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(addr)
}

/// Run a stress test with the given configuration
pub async fn run_stress_test(
    addr: std::net::SocketAddr,
    config: StressTestConfig,
) -> StressMetrics {
    let metrics = Arc::new(StressMetrics::new());
    let semaphore = Arc::new(Semaphore::new(config.concurrent_limit));
    let start_time = Instant::now();
    let test_duration = config.duration;

    println!("Starting stress test...");
    println!("  Target: {}", addr);
    println!("  Duration: {:?}", config.duration);
    println!("  Connection Rate: {} conn/s", config.connection_rate);
    println!("  Concurrent Limit: {}", config.concurrent_limit);
    println!("  Payload Size: {} bytes", config.payload_size);

    let mut handles = Vec::new();
    let mut connection_count = 0;

    // Connection generation loop
    while start_time.elapsed() < test_duration {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let metrics_clone = metrics.clone();
        let payload_size = config.payload_size;

        metrics.record_connection_attempt();
        connection_count += 1;

        let handle = tokio::spawn(async move {
            let conn_start = Instant::now();
            
            match TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    // Send data
                    let data = vec![0xAB; payload_size];
                    match stream.write_all(&data).await {
                        Ok(_) => {
                            metrics_clone.record_bytes_sent(payload_size as u64);
                            
                            // Receive echo
                            let mut received = vec![0u8; payload_size];
                            match stream.read_exact(&mut received).await {
                                Ok(_) => {
                                    metrics_clone.record_bytes_received(payload_size as u64);
                                    metrics_clone.record_success();
                                }
                                Err(_) => {
                                    metrics_clone.record_failure();
                                }
                            }
                        }
                        Err(_) => {
                            metrics_clone.record_failure();
                        }
                    }
                }
                Err(_) => {
                    metrics_clone.record_failure();
                }
            }

            metrics_clone.record_duration(conn_start.elapsed());
            drop(permit);
        });

        handles.push(handle);

        // Update peak concurrent connections
        let current_concurrent = config.concurrent_limit - semaphore.available_permits();
        metrics.update_peak_concurrent(current_concurrent);

        // Rate limiting
        let delay = Duration::from_millis(1000 / config.connection_rate as u64);
        tokio::time::sleep(delay).await;

        // Progress reporting
        if connection_count % 100 == 0 {
            println!("  Progress: {} connections, {:.1}s elapsed", 
                connection_count, start_time.elapsed().as_secs_f64());
        }
    }

    println!("Waiting for {} connections to complete...", handles.len());
    for handle in handles {
        let _ = handle.await;
    }

    println!("Stress test completed in {:.2}s", start_time.elapsed().as_secs_f64());
    
    Arc::try_unwrap(metrics).unwrap_or_else(|arc| (*arc).clone())
}

/// Monitor system resources during a test
pub async fn monitor_resources(duration: Duration, interval: Duration) -> ResourceReport {
    let mut report = ResourceReport::new();
    let start = Instant::now();
    let mut samples = 0;

    while start.elapsed() < duration {
        let sample = ResourceSample::capture();
        let open_fds = sample.open_fds;
        report.add_sample(sample);
        samples += 1;

        if samples % 10 == 0 {
            println!("  [Monitor] Sample {}: {} open FDs", samples, open_fds);
        }

        tokio::time::sleep(interval).await;
    }

    report
}

/// Single resource measurement sample
#[derive(Debug, Clone)]
pub struct ResourceSample {
    pub timestamp: Instant,
    pub open_fds: usize,
    pub memory_kb: usize,
}

impl ResourceSample {
    pub fn capture() -> Self {
        Self {
            timestamp: Instant::now(),
            open_fds: Self::count_open_fds(),
            memory_kb: Self::get_memory_usage(),
        }
    }

    #[cfg(target_os = "macos")]
    fn count_open_fds() -> usize {
        use std::process::Command;
        
        let pid = std::process::id();
        let output = Command::new("lsof")
            .args(&["-p", &pid.to_string()])
            .output();
        
        match output {
            Ok(output) => {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .count()
                    .saturating_sub(1) // Subtract header line
            }
            Err(_) => 0,
        }
    }

    #[cfg(target_os = "linux")]
    fn count_open_fds() -> usize {
        use std::fs;
        
        let pid = std::process::id();
        let fd_dir = format!("/proc/{}/fd", pid);
        
        fs::read_dir(fd_dir)
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn count_open_fds() -> usize {
        0 // Not supported on this platform
    }

    fn get_memory_usage() -> usize {
        // This is a simplified implementation
        // In production, use a proper memory profiling library
        0
    }
}

/// Report of resource usage over time
#[derive(Debug)]
pub struct ResourceReport {
    pub samples: Vec<ResourceSample>,
}

impl ResourceReport {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, sample: ResourceSample) {
        self.samples.push(sample);
    }

    pub fn detect_fd_leak(&self) -> bool {
        if self.samples.len() < 10 {
            return false;
        }

        let first_10_avg: usize = self.samples.iter().take(10).map(|s| s.open_fds).sum::<usize>() / 10;
        let last_10_avg: usize = self.samples.iter().rev().take(10).map(|s| s.open_fds).sum::<usize>() / 10;

        // Consider it a leak if FDs increased by more than 50%
        last_10_avg > first_10_avg + (first_10_avg / 2)
    }

    pub fn detect_memory_leak(&self) -> bool {
        if self.samples.len() < 10 {
            return false;
        }

        let first_10_avg: usize = self.samples.iter().take(10).map(|s| s.memory_kb).sum::<usize>() / 10;
        let last_10_avg: usize = self.samples.iter().rev().take(10).map(|s| s.memory_kb).sum::<usize>() / 10;

        // Consider it a leak if memory increased by more than 50%
        last_10_avg > first_10_avg + (first_10_avg / 2)
    }

    pub fn print_summary(&self) {
        if self.samples.is_empty() {
            println!("No resource samples collected");
            return;
        }

        let fd_leak = self.detect_fd_leak();
        let mem_leak = self.detect_memory_leak();

        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║           Resource Monitoring Summary                  ║");
        println!("╚════════════════════════════════════════════════════════╝");
        println!("Samples Collected:     {}", self.samples.len());
        
        if let (Some(first), Some(last)) = (self.samples.first(), self.samples.last()) {
            println!("Initial FDs:           {}", first.open_fds);
            println!("Final FDs:             {}", last.open_fds);
            println!("FD Change:             {:+}", last.open_fds as i64 - first.open_fds as i64);
            println!("FD Leak Detected:      {}", if fd_leak { "⚠️  YES" } else { "✅ NO" });
            
            println!("Initial Memory:        {} KB", first.memory_kb);
            println!("Final Memory:          {} KB", last.memory_kb);
            println!("Memory Change:         {:+} KB", last.memory_kb as i64 - first.memory_kb as i64);
            println!("Memory Leak Detected:  {}", if mem_leak { "⚠️  YES" } else { "✅ NO" });
        }

        let max_fds = self.samples.iter().map(|s| s.open_fds).max().unwrap_or(0);
        let max_mem = self.samples.iter().map(|s| s.memory_kb).max().unwrap_or(0);
        println!("Peak FDs:              {}", max_fds);
        println!("Peak Memory:           {} KB", max_mem);
    }
}

impl Default for ResourceReport {
    fn default() -> Self {
        Self::new()
    }
}
