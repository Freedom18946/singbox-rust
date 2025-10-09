# Performance Optimization Guide

This document outlines optimization strategies for P0 protocols in singbox-rust.

## Overview

Performance optimization focuses on four key areas:
1. **Buffer Management** - Zero-copy operations where possible
2. **Crypto Operations** - Hardware acceleration
3. **Connection Pooling** - Efficient connection reuse
4. **Memory Allocations** - Reduce allocations in hot paths

## Buffer Management Optimization

### Current State

- Buffers are allocated per-request
- Data is copied between layers
- No buffer pooling

### Optimization Strategies

#### 1. Zero-Copy Buffers

Use `bytes::Bytes` and `bytes::BytesMut` for zero-copy operations:

```rust
use bytes::{Bytes, BytesMut, Buf, BufMut};

// Instead of Vec<u8>
let data: Vec<u8> = vec![0; 1024];

// Use Bytes for zero-copy
let data: Bytes = Bytes::from_static(b"data");
let mut buf = BytesMut::with_capacity(1024);
```

#### 2. Buffer Pooling

Implement buffer pools to reuse allocations:

```rust
use std::sync::Arc;
use tokio::sync::Mutex;

struct BufferPool {
    buffers: Arc<Mutex<Vec<BytesMut>>>,
    buffer_size: usize,
}

impl BufferPool {
    fn new(size: usize, count: usize) -> Self {
        let buffers = (0..count)
            .map(|_| BytesMut::with_capacity(size))
            .collect();
        
        Self {
            buffers: Arc::new(Mutex::new(buffers)),
            buffer_size: size,
        }
    }
    
    async fn acquire(&self) -> BytesMut {
        let mut buffers = self.buffers.lock().await;
        buffers.pop().unwrap_or_else(|| {
            BytesMut::with_capacity(self.buffer_size)
        })
    }
    
    async fn release(&self, mut buf: BytesMut) {
        buf.clear();
        let mut buffers = self.buffers.lock().await;
        if buffers.len() < 100 { // Max pool size
            buffers.push(buf);
        }
    }
}
```

#### 3. Vectored I/O

Use `writev` for efficient multi-buffer writes:

```rust
use tokio::io::AsyncWriteExt;

async fn write_vectored(
    stream: &mut impl AsyncWriteExt,
    bufs: &[Bytes],
) -> std::io::Result<()> {
    // Convert to IoSlice
    let slices: Vec<_> = bufs.iter()
        .map(|b| std::io::IoSlice::new(b))
        .collect();
    
    stream.write_vectored(&slices).await?;
    Ok(())
}
```

### Implementation Checklist

- [ ] Replace `Vec<u8>` with `Bytes`/`BytesMut` in hot paths
- [ ] Implement buffer pool for common buffer sizes
- [ ] Use vectored I/O for multi-buffer writes
- [ ] Profile buffer allocation overhead
- [ ] Measure improvement in throughput

## Crypto Operations Optimization

### Current State

- Software-only crypto implementations
- No hardware acceleration detection
- Crypto operations in hot path

### Optimization Strategies

#### 1. Hardware Acceleration

Use CPU crypto instructions (AES-NI, etc.):

```rust
// Use ring or rustls with hardware acceleration
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

fn create_cipher() -> LessSafeKey {
    let key_bytes = [0u8; 32]; // Your key
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .expect("key");
    LessSafeKey::new(unbound_key)
}

// ring automatically uses AES-NI when available
```

#### 2. Crypto Offloading

Move crypto operations off the hot path:

```rust
use tokio::task;

async fn encrypt_async(data: Bytes) -> Result<Bytes, Error> {
    // Offload to blocking thread pool
    task::spawn_blocking(move || {
        // Expensive crypto operation
        encrypt_data(&data)
    }).await?
}
```

#### 3. Session Caching

Cache TLS sessions to avoid handshakes:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

struct SessionCache {
    cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl SessionCache {
    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.cache.read().await.get(key).cloned()
    }
    
    async fn put(&self, key: String, session: Vec<u8>) {
        self.cache.write().await.insert(key, session);
    }
}
```

### Implementation Checklist

- [ ] Enable hardware crypto acceleration in dependencies
- [ ] Implement session caching for TLS
- [ ] Profile crypto operation overhead
- [ ] Consider crypto offloading for expensive operations
- [ ] Measure improvement in latency

## Connection Pooling Optimization

### Current State

- Connections created per-request
- No connection reuse
- High connection establishment overhead

### Optimization Strategies

#### 1. Connection Pool

Implement connection pooling:

```rust
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

struct Connection {
    stream: TcpStream,
    last_used: Instant,
}

struct ConnectionPool {
    connections: Arc<Mutex<VecDeque<Connection>>>,
    max_size: usize,
    max_idle_time: Duration,
}

impl ConnectionPool {
    async fn acquire(&self, addr: SocketAddr) -> Result<TcpStream, Error> {
        let mut conns = self.connections.lock().await;
        
        // Try to reuse existing connection
        while let Some(conn) = conns.pop_front() {
            if conn.last_used.elapsed() < self.max_idle_time {
                return Ok(conn.stream);
            }
        }
        
        // Create new connection
        TcpStream::connect(addr).await
    }
    
    async fn release(&self, stream: TcpStream) {
        let mut conns = self.connections.lock().await;
        
        if conns.len() < self.max_size {
            conns.push_back(Connection {
                stream,
                last_used: Instant::now(),
            });
        }
    }
}
```

#### 2. Connection Multiplexing

Use HTTP/2 or QUIC multiplexing:

```rust
// For HTTP/2
use h2::client;

async fn create_h2_connection(addr: SocketAddr) -> Result<client::SendRequest<Bytes>, Error> {
    let tcp = TcpStream::connect(addr).await?;
    let (send_request, connection) = client::handshake(tcp).await?;
    
    // Spawn connection driver
    tokio::spawn(async move {
        let _ = connection.await;
    });
    
    Ok(send_request)
}
```

#### 3. Keep-Alive

Enable TCP keep-alive:

```rust
use tokio::net::TcpStream;
use socket2::{Socket, TcpKeepalive};
use std::time::Duration;

fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    let socket = Socket::from(stream.as_raw_fd());
    
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    
    socket.set_tcp_keepalive(&keepalive)?;
    Ok(())
}
```

### Implementation Checklist

- [ ] Implement connection pool for each protocol
- [ ] Enable connection multiplexing where supported
- [ ] Configure TCP keep-alive
- [ ] Profile connection establishment overhead
- [ ] Measure improvement in connection time

## Memory Allocation Optimization

### Current State

- Frequent allocations in hot paths
- No allocation reuse
- High allocation overhead

### Optimization Strategies

#### 1. Pre-allocation

Pre-allocate buffers with known sizes:

```rust
// Instead of
let mut vec = Vec::new();
for i in 0..1000 {
    vec.push(i);
}

// Pre-allocate
let mut vec = Vec::with_capacity(1000);
for i in 0..1000 {
    vec.push(i);
}
```

#### 2. Stack Allocation

Use stack allocation for small buffers:

```rust
// Instead of heap allocation
let buf: Vec<u8> = vec![0; 64];

// Use stack array
let buf: [u8; 64] = [0; 64];
```

#### 3. Arena Allocation

Use arena allocators for temporary allocations:

```rust
use bumpalo::Bump;

fn process_request(arena: &Bump) {
    // Allocations from arena are freed all at once
    let data = arena.alloc_slice_fill_default(1024);
    // Use data...
    // Arena is cleared after function returns
}
```

#### 4. Object Pooling

Pool frequently allocated objects:

```rust
use std::sync::Arc;
use tokio::sync::Mutex;

struct ObjectPool<T> {
    objects: Arc<Mutex<Vec<T>>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T: Send> ObjectPool<T> {
    async fn acquire(&self) -> T {
        let mut objects = self.objects.lock().await;
        objects.pop().unwrap_or_else(|| (self.factory)())
    }
    
    async fn release(&self, obj: T) {
        let mut objects = self.objects.lock().await;
        if objects.len() < 100 {
            objects.push(obj);
        }
    }
}
```

### Implementation Checklist

- [ ] Pre-allocate buffers with known sizes
- [ ] Use stack allocation for small buffers
- [ ] Implement object pools for frequently allocated types
- [ ] Profile allocation overhead
- [ ] Measure improvement in memory usage

## Profiling and Measurement

### Tools

#### 1. Flamegraph

Generate CPU flamegraphs:

```bash
# Install cargo-flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --test bench_p0_protocols -- bench_direct_tcp --nocapture
```

#### 2. Valgrind/Heaptrack

Profile memory usage:

```bash
# Install heaptrack
# macOS: brew install heaptrack
# Linux: apt-get install heaptrack

# Profile memory
heaptrack cargo test --test bench_p0_protocols
```

#### 3. perf

Use Linux perf for detailed profiling:

```bash
# Record performance data
perf record -g cargo test --test bench_p0_protocols

# Analyze results
perf report
```

### Benchmarking

Use criterion for micro-benchmarks:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_buffer_copy(c: &mut Criterion) {
    c.bench_function("buffer_copy", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            let copy = data.clone();
            black_box(copy);
        });
    });
}

criterion_group!(benches, benchmark_buffer_copy);
criterion_main!(benches);
```

## Optimization Workflow

### 1. Profile

Identify hot paths using profiling tools:

```bash
# Generate flamegraph
cargo flamegraph --test bench_p0_protocols -- bench_direct_tcp

# Identify functions consuming most CPU time
```

### 2. Optimize

Apply optimization strategies to hot paths:

- Start with highest-impact optimizations
- Focus on hot paths identified by profiling
- Measure impact of each optimization

### 3. Verify

Verify improvements with benchmarks:

```bash
# Run benchmarks before optimization
cargo test --test bench_p0_protocols -- --nocapture > before.txt

# Apply optimization

# Run benchmarks after optimization
cargo test --test bench_p0_protocols -- --nocapture > after.txt

# Compare results
diff before.txt after.txt
```

### 4. Iterate

Repeat profile-optimize-verify cycle:

- Continue until performance targets are met
- Document each optimization
- Track performance improvements

## Performance Targets

### Throughput

- **Target**: ≥90% of baseline for TLS protocols
- **Current**: TBD (requires protocol benchmarks)
- **Gap**: TBD

### Latency

- **Target**: P95 ≤110% of baseline
- **Current**: TBD (requires protocol benchmarks)
- **Gap**: TBD

### Memory

- **Target**: <100MB per 1000 connections
- **Current**: 10MB estimated (needs accurate measurement)
- **Gap**: TBD

### Connection Time

- **Target**: <500ms for all protocols
- **Current**: 0.03ms for baseline
- **Gap**: TBD (requires protocol benchmarks)

## Next Steps

1. **Profile existing code**: Identify hot paths
2. **Apply optimizations**: Start with highest-impact areas
3. **Measure improvements**: Run benchmarks
4. **Document results**: Update performance reports
5. **Iterate**: Continue optimization cycle

## References

- **Benchmarks**: `app/tests/bench_p0_protocols.rs`
- **Performance Summary**: `reports/benchmarks/PERFORMANCE_SUMMARY.md`
- **Requirements**: `.kiro/specs/p0-production-parity/requirements.md` (9.1, 9.2, 9.3)

## Revision History

- 2025-10-08: Initial optimization guide created
