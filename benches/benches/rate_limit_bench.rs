//! Rate Limiting Performance Benchmarks
//!
//! Measures performance of TcpRateLimiter under various scenarios:
//! - Per-connection overhead
//! - Concurrent access performance
//! - Memory footprint with many tracked IPs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use sb_core::net::tcp_rate_limit::{TcpRateLimiter, TcpRateLimitConfig};

/// Benchmark: allow_connection() latency (target: <1μs)
fn bench_allow_connection(c: &mut Criterion) {
    let config = TcpRateLimitConfig {
        max_connections: 100,
        window: Duration::from_secs(10),
        max_tracked_ips: 10000,
        max_auth_failures: 10,
        auth_failure_window: Duration::from_secs(60),
        max_qps: None,
    };
    
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    c.bench_function("allow_connection_single_ip", |b| {
        b.iter(|| {
            black_box(limiter.allow_connection(ip));
        });
    });
}

/// Benchmark: concurrent access from multiple IPs
fn bench_concurrent_ips(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_ips");
    
    for num_ips in [10, 100, 1000] {
        let config = TcpRateLimitConfig {
            max_connections: 100,
            window: Duration::from_secs(10),
            max_tracked_ips: num_ips * 2,
            max_auth_failures: 10,
            auth_failure_window: Duration::from_secs(60),
            max_qps: None,
        };
        
        let limiter = TcpRateLimiter::new(config);
        
        group.bench_with_input(BenchmarkId::from_parameter(num_ips), &num_ips, |b, &num_ips| {
            b.iter(|| {
                for i in 0..num_ips {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        (i >> 24) as u8,
                        (i >> 16) as u8,
                        (i >> 8) as u8,
                        i as u8,
                    ));
                    black_box(limiter.allow_connection(ip));
                }
            });
        });
    }
    
    group.finish();
}

/// Benchmark: QPS limiting performance
fn bench_qps_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("qps_limiting");
    
    for qps_limit in [10, 100, 1000] {
        let config = TcpRateLimitConfig {
            max_connections: 0, // Disable connection limit
            window: Duration::from_secs(1),
            max_tracked_ips: 10000,
            max_auth_failures: 0,
            auth_failure_window: Duration::from_secs(60),
            max_qps: Some(qps_limit),
        };
        
        let limiter = TcpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        group.bench_with_input(BenchmarkId::from_parameter(qps_limit), &qps_limit, |b, _| {
            b.iter(|| {
                black_box(limiter.allow_request(ip));
            });
        });
    }
    
    group.finish();
}

/// Benchmark: auth failure tracking performance
fn bench_auth_failure_tracking(c: &mut Criterion) {
    let config = TcpRateLimitConfig {
        max_connections: 0,
        window: Duration::from_secs(1),
        max_tracked_ips: 10000,
        max_auth_failures: 10,
        auth_failure_window: Duration::from_secs(60),
        max_qps: None,
    };
    
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

    c.bench_function("record_auth_failure", |b| {
        b.iter(|| {
            black_box(limiter.record_auth_failure(ip));
        });
    });
    
    c.bench_function("is_banned_check", |b| {
        b.iter(|| {
            black_box(limiter.is_banned(ip));
        });
    });
}

/// Benchmark: overhead with many tracked IPs (simulating production load)
fn bench_memory_footprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_footprint");
    group.sample_size(10); // Fewer samples for heavy tests
    
    for tracked_ips in [1000, 5000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(tracked_ips), &tracked_ips, |b, &tracked_ips| {
            b.iter(|| {
                let config = TcpRateLimitConfig {
                    max_connections: 100,
                    window: Duration::from_secs(10),
                    max_tracked_ips: tracked_ips,
                    max_auth_failures: 10,
                    auth_failure_window: Duration::from_secs(60),
                    max_qps: None,
                };
                
                let limiter = TcpRateLimiter::new(config);
                
                // Populate with many IPs
                for i in 0..tracked_ips {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        (i >> 24) as u8,
                        (i >> 16) as u8,
                        (i >> 8) as u8,
                        i as u8,
                    ));
                    limiter.allow_connection(ip);
                }
                
                black_box(limiter);
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_allow_connection,
    bench_concurrent_ips,
    bench_qps_limiting,
    bench_auth_failure_tracking,
    bench_memory_footprint
);
criterion_main!(benches);
