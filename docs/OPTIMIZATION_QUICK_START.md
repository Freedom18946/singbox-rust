# P0 Protocol Optimizations - Quick Start Guide

## Overview

This guide provides quick examples for using the optimization utilities in P0 protocols.

## Buffer Pool

### Basic Usage

```rust
use sb_core::outbound::optimizations::PROTOCOL_BUFFER_POOL;

// Get a buffer from the pool
let mut buf = PROTOCOL_BUFFER_POOL.get(4096);

// Use the buffer
buf.extend_from_slice(b"Hello, World!");

// Return it to the pool when done
PROTOCOL_BUFFER_POOL.put(buf);
```

### Configuration

```bash
# Set maximum pool size (default: 100)
export SB_BUFFER_POOL_SIZE=200

# Set maximum buffer capacity (default: 1MB)
export SB_BUFFER_POOL_MAX_CAPACITY=2097152
```

## Bandwidth Limiter

### Basic Usage

```rust
use sb_core::outbound::optimizations::FastBandwidthLimiter;

// Create limiter with 100 Mbps up/down
let limiter = FastBandwidthLimiter::new(100, 100);

// Try to consume tokens before sending
if limiter.consume_up(1024) {
    // Send 1024 bytes
    stream.write_all(&data).await?;
} else {
    // Rate limited, wait or queue
}

// Check available tokens
let available = limiter.up_tokens();
```

### Integration Example (Hysteria2)

```rust
pub struct Hysteria2Outbound {
    bandwidth_limiter: Option<Arc<FastBandwidthLimiter>>,
    // ... other fields
}

impl Hysteria2Outbound {
    async fn send_data(&self, data: &[u8]) -> io::Result<()> {
        if let Some(ref limiter) = self.bandwidth_limiter {
            if !limiter.consume_up(data.len() as u32) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Bandwidth limit exceeded",
                ));
            }
        }
        // Send data...
        Ok(())
    }
}
```

## Connection Pool

### Basic Usage

```rust
use sb_core::outbound::optimizations::ConnectionPool;
use std::sync::Arc;

// Create pool with max size 8
let pool = ConnectionPool::new(8);

// Add connections
pool.put(Arc::new(connection));

// Get a healthy connection
if let Some(conn) = pool.get(|c| c.is_healthy()) {
    // Use connection
    conn.send_data(&data).await?;
}

// Cleanup stale connections
pool.cleanup(|c| c.is_healthy());
```

### Integration Example (SSH)

```rust
pub struct SshOutbound {
    connection_pool: Arc<Mutex<ConnectionPool<SshConnection>>>,
    round_robin: AtomicUsize,
    // ... other fields
}

impl SshOutbound {
    async fn get_connection(&self) -> io::Result<Arc<SshConnection>> {
        let pool = self.connection_pool.lock().await;
        
        // Try to get existing connection
        if let Some(conn) = pool.get(|c| c.is_connected()) {
            return Ok(conn);
        }
        
        // Create new connection if pool not full
        let conn = Arc::new(SshConnection::new(&self.config).await?);
        pool.put(conn.clone());
        Ok(conn)
    }
}
```

## TTL Cache

### Basic Usage

```rust
use sb_core::outbound::optimizations::TtlCache;
use std::time::Duration;

// Create cache with 5-minute TTL
let cache = TtlCache::new(Duration::from_secs(300));

// Put a value
cache.put("key1", expensive_computation());

// Get a value
if let Some(value) = cache.get(&"key1") {
    // Use cached value
}

// Get or insert
let value = cache.get_or_insert("key2", || {
    expensive_computation()
});

// Cleanup expired entries
cache.cleanup();
```

### Integration Example (REALITY)

```rust
use once_cell::sync::Lazy;

static AUTH_CACHE: Lazy<TtlCache<String, RealityAuth>> = Lazy::new(|| {
    TtlCache::new(Duration::from_secs(300)) // 5 minutes
});

impl RealityConnector {
    fn get_auth(&self) -> Arc<RealityAuth> {
        let key = format!("{}:{}", self.config.server, self.config.public_key);
        
        AUTH_CACHE.get_or_insert(key, || {
            RealityAuth::generate()
        })
    }
}
```

## Metrics

### Enable Metrics

```toml
[dependencies]
sb-core = { version = "0.1", features = ["metrics"] }
```

### Record Metrics

```rust
#[cfg(feature = "metrics")]
{
    use sb_core::outbound::optimizations::metrics;
    
    // Record buffer pool metrics
    metrics::record_buffer_pool_metrics();
    
    // Record connection pool metrics
    metrics::record_connection_pool_metrics(&pool, "hysteria2");
    
    // Record bandwidth metrics
    metrics::record_bandwidth_metrics(&limiter, "hysteria2");
    
    // Record cache metrics
    metrics::record_cache_metrics(&cache, "reality_auth");
}
```

## Performance Tips

### 1. Buffer Management

**DO:**
- Use the global buffer pool for temporary buffers
- Return buffers to the pool when done
- Pre-allocate buffers with expected size

**DON'T:**
- Create new buffers for every operation
- Keep buffers longer than necessary
- Use buffers larger than 1MB (won't be pooled)

### 2. Connection Pooling

**DO:**
- Set pool size based on expected concurrency
- Implement health checks for connections
- Clean up stale connections periodically

**DON'T:**
- Create new connections for every request
- Keep unhealthy connections in the pool
- Set pool size too large (wastes resources)

### 3. Bandwidth Limiting

**DO:**
- Use atomic operations for high-throughput scenarios
- Check tokens before sending data
- Handle rate limiting gracefully

**DON'T:**
- Use locks in the hot path
- Ignore rate limit errors
- Set limits too low (causes frequent blocking)

### 4. Caching

**DO:**
- Cache expensive computations (crypto, parsing)
- Set appropriate TTL based on data freshness
- Clean up expired entries periodically

**DON'T:**
- Cache data that changes frequently
- Set TTL too long (stale data)
- Cache large objects (memory pressure)

## Benchmarking

### Run Benchmarks

```bash
# Run all P0 protocol benchmarks
cargo bench --bench bench_p0_protocols

# Run specific protocol benchmark
cargo bench --bench bench_p0_protocols -- reality

# Compare with baseline
cargo bench --bench bench_p0_protocols -- --save-baseline before
# ... make changes ...
cargo bench --bench bench_p0_protocols -- --baseline before
```

### Profile Performance

```bash
# CPU profiling with flamegraph
cargo flamegraph --bin singbox-rust -- run --config test.json

# Memory profiling with valgrind
valgrind --tool=massif cargo run --release --bin singbox-rust -- run --config test.json

# Linux perf profiling
perf record -g cargo run --release --bin singbox-rust -- run --config test.json
perf report
```

## Troubleshooting

### High Memory Usage

1. Check buffer pool size: `SB_BUFFER_POOL_SIZE`
2. Check connection pool sizes
3. Clean up caches more frequently
4. Reduce buffer pool max capacity

### Low Throughput

1. Increase buffer sizes
2. Increase connection pool sizes
3. Check bandwidth limiter settings
4. Profile for bottlenecks

### High CPU Usage

1. Enable hardware crypto acceleration
2. Reduce cache cleanup frequency
3. Increase connection pool reuse
4. Profile for hot paths

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SB_BUFFER_POOL_SIZE` | 100 | Maximum buffer pool size |
| `SB_BUFFER_POOL_MAX_CAPACITY` | 1048576 | Maximum buffer capacity (bytes) |
| `SB_HYSTERIA2_MAX_RETRIES` | 3 | Connection retry limit |
| `SB_HYSTERIA2_BACKOFF_MS_BASE` | 200 | Base backoff delay (ms) |
| `SB_HYSTERIA2_BACKOFF_MS_MAX` | 2000 | Max backoff delay (ms) |

## Further Reading

- [P0 Protocol Optimizations](./P0_PROTOCOL_OPTIMIZATIONS.md) - Detailed optimization guide
- [Task 9.3 Summary](../.kiro/specs/p0-production-parity/task-9.3-summary.md) - Implementation summary
- [Optimization Module](../crates/sb-core/src/outbound/optimizations.rs) - Source code

## Support

For questions or issues:
1. Check the detailed optimization guide
2. Review the source code and tests
3. Profile your specific use case
4. Open an issue with benchmark results
