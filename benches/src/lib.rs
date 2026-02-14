//! Shared utilities for sing-box benchmarks

use bytes::Bytes;
use rand::Rng;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Generate random data of specified size
pub fn generate_random_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Generate random bytes
pub fn generate_random_bytes(size: usize) -> Bytes {
    Bytes::from(generate_random_data(size))
}

/// Simple echo server for testing throughput
pub async fn run_echo_server(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

/// Measure throughput by sending data and receiving echo
pub async fn measure_throughput(
    mut stream: TcpStream,
    data: &[u8],
) -> anyhow::Result<(usize, std::time::Duration)> {
    let start = std::time::Instant::now();

    stream.write_all(data).await?;

    let mut received = vec![0u8; data.len()];
    stream.read_exact(&mut received).await?;

    let duration = start.elapsed();
    Ok((data.len(), duration))
}

/// Calculate throughput in MB/s
pub fn calculate_mbps(bytes: usize, duration: std::time::Duration) -> f64 {
    let bytes_f64 = bytes as f64;
    let seconds = duration.as_secs_f64();
    (bytes_f64 / seconds) / (1024.0 * 1024.0)
}

/// Setup tracing for benchmarks
pub fn setup_tracing() {
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .try_init();
}

/// Compute percentiles (P50, P95, P99) from a vector of durations.
/// Returns (p50, p95, p99) or None if the input is empty.
pub fn compute_percentiles(
    durations: &[std::time::Duration],
) -> Option<(
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
)> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted: Vec<std::time::Duration> = durations.to_vec();
    sorted.sort();
    let len = sorted.len();
    let p50 = sorted[len * 50 / 100];
    let p95 = sorted[len * 95 / 100];
    let p99 = sorted[len.saturating_sub(1).min(len * 99 / 100)];
    Some((p50, p95, p99))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_data() {
        let data = generate_random_data(1024);
        assert_eq!(data.len(), 1024);
    }

    #[test]
    fn test_calculate_mbps() {
        let mbps = calculate_mbps(1_048_576, std::time::Duration::from_secs(1));
        assert!((mbps - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_compute_percentiles() {
        let durations: Vec<std::time::Duration> = (1..=100)
            .map(|i| std::time::Duration::from_micros(i * 10))
            .collect();
        let (p50, p95, p99) = compute_percentiles(&durations).unwrap();
        assert_eq!(p50, std::time::Duration::from_micros(510));
        assert_eq!(p95, std::time::Duration::from_micros(960));
        assert_eq!(p99, std::time::Duration::from_micros(1000));
    }

    #[test]
    fn test_compute_percentiles_empty() {
        assert!(compute_percentiles(&[]).is_none());
    }
}
