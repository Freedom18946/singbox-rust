# Performance Optimization Checklist

This checklist tracks optimization tasks for P0 protocols.

## Buffer Management

### Zero-Copy Operations

- [ ] Replace `Vec<u8>` with `Bytes`/`BytesMut` in protocol implementations
- [ ] Use `bytes::Buf` and `bytes::BufMut` traits for buffer operations
- [ ] Implement zero-copy forwarding between inbound and outbound
- [ ] Use `split_to()` instead of copying buffer slices
- [ ] Verify zero-copy with profiling tools

### Buffer Pooling

- [ ] Implement global buffer pool
- [ ] Configure buffer pool sizes (8KB, 16KB, 64KB)
- [ ] Add buffer pool metrics (hits, misses, size)
- [ ] Integrate buffer pool with all protocols
- [ ] Measure allocation reduction

### Vectored I/O

- [ ] Use `write_vectored()` for multi-buffer writes
- [ ] Use `read_vectored()` for multi-buffer reads
- [ ] Implement scatter-gather I/O where beneficial
- [ ] Measure throughput improvement

## Crypto Operations

### Hardware Acceleration

- [ ] Verify AES-NI is enabled in dependencies
- [ ] Check for hardware crypto support at runtime
- [ ] Use hardware-accelerated crypto libraries (ring, rustls)
- [ ] Profile crypto operations to verify hardware usage
- [ ] Measure crypto performance improvement

### Session Caching

- [ ] Implement TLS session cache
- [ ] Configure session cache size and TTL
- [ ] Add session cache metrics
- [ ] Test session resumption
- [ ] Measure handshake time reduction

### Crypto Offloading

- [ ] Identify expensive crypto operations
- [ ] Move crypto to blocking thread pool where appropriate
- [ ] Measure impact on latency
- [ ] Balance offloading vs inline crypto

## Connection Pooling

### Connection Reuse

- [ ] Implement connection pool for each protocol
- [ ] Configure pool size and idle timeout
- [ ] Add connection pool metrics
- [ ] Test connection reuse
- [ ] Measure connection establishment time reduction

### Multiplexing

- [ ] Enable HTTP/2 multiplexing where supported
- [ ] Enable QUIC stream multiplexing
- [ ] Test concurrent streams
- [ ] Measure throughput improvement

### Keep-Alive

- [ ] Enable TCP keep-alive
- [ ] Configure keep-alive parameters
- [ ] Test connection persistence
- [ ] Measure connection overhead reduction

## Memory Allocations

### Pre-allocation

- [ ] Pre-allocate buffers with known sizes
- [ ] Use `Vec::with_capacity()` instead of `Vec::new()`
- [ ] Pre-allocate collections (HashMap, Vec)
- [ ] Profile allocation overhead
- [ ] Measure allocation reduction

### Stack Allocation

- [ ] Use stack arrays for small buffers (<1KB)
- [ ] Use `SmallVec` for variable-size small collections
- [ ] Avoid heap allocation in hot paths
- [ ] Measure allocation reduction

### Object Pooling

- [ ] Implement object pools for frequently allocated types
- [ ] Pool protocol-specific objects
- [ ] Add object pool metrics
- [ ] Measure allocation reduction

## Protocol-Specific Optimizations

### REALITY TLS

- [ ] Optimize REALITY authentication
- [ ] Cache REALITY keys
- [ ] Optimize TLS handshake
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

### ECH

- [ ] Optimize ECH encryption
- [ ] Cache ECH configurations
- [ ] Optimize TLS handshake
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

### Hysteria v1

- [ ] Optimize QUIC stream handling
- [ ] Tune congestion control parameters
- [ ] Optimize UDP packet processing
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

### Hysteria v2

- [ ] Optimize improved congestion control
- [ ] Tune performance parameters
- [ ] Optimize UDP packet processing
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

### SSH

- [ ] Optimize SSH channel handling
- [ ] Cache SSH sessions
- [ ] Optimize encryption
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

### TUIC

- [ ] Optimize QUIC stream handling
- [ ] Tune TUIC parameters
- [ ] Optimize UDP packet processing
- [ ] Profile hot paths
- [ ] Measure performance vs baseline

## Profiling and Measurement

### CPU Profiling

- [ ] Generate flamegraphs for each protocol
- [ ] Identify hot paths (>5% CPU time)
- [ ] Profile before and after optimizations
- [ ] Document profiling results

### Memory Profiling

- [ ] Profile memory usage with heaptrack
- [ ] Identify allocation hot spots
- [ ] Measure memory usage under load
- [ ] Document memory profiling results

### Benchmarking

- [ ] Run benchmarks before optimizations
- [ ] Run benchmarks after each optimization
- [ ] Compare results with targets
- [ ] Document benchmark results

## Verification

### Performance Targets

- [ ] Verify throughput ≥90% of baseline
- [ ] Verify P95 latency ≤110% of baseline
- [ ] Verify connection time <500ms
- [ ] Verify memory usage <100MB per 1000 connections

### Regression Testing

- [ ] Set up automated performance tests
- [ ] Configure performance regression alerts
- [ ] Run performance tests in CI
- [ ] Document performance baselines

## Documentation

### Optimization Results

- [ ] Document each optimization applied
- [ ] Record performance improvements
- [ ] Update performance reports
- [ ] Share findings with team

### Best Practices

- [ ] Document optimization patterns
- [ ] Create optimization guidelines
- [ ] Share lessons learned
- [ ] Update coding standards

## Priority Matrix

### High Priority (Do First)

1. Buffer pooling - High impact on allocations
2. Connection pooling - High impact on connection time
3. Hardware crypto - High impact on crypto performance
4. Zero-copy buffers - High impact on throughput

### Medium Priority (Do Next)

1. Session caching - Medium impact on handshake time
2. Vectored I/O - Medium impact on throughput
3. Pre-allocation - Medium impact on allocations
4. Keep-alive - Medium impact on connection overhead

### Low Priority (Do Later)

1. Stack allocation - Low impact, specific cases
2. Object pooling - Low impact, specific types
3. Crypto offloading - Low impact, may increase latency
4. Arena allocation - Low impact, specific use cases

## Success Criteria

### Throughput

- [ ] REALITY TLS: ≥8.6 Gbps
- [ ] ECH: ≥8.6 Gbps
- [ ] Hysteria v1: ≥9.5 Gbps
- [ ] Hysteria v2: ≥9.5 Gbps
- [ ] SSH: ≥8.1 Gbps
- [ ] TUIC: ≥9.5 Gbps

### Latency (P95)

- [ ] REALITY TLS: ≤0.077ms
- [ ] ECH: ≤0.077ms
- [ ] Hysteria v1: ≤0.105ms
- [ ] Hysteria v2: ≤0.105ms
- [ ] SSH: ≤0.084ms
- [ ] TUIC: ≤0.105ms

### Connection Time

- [ ] REALITY TLS: <200ms
- [ ] ECH: <150ms
- [ ] Hysteria v1: <100ms
- [ ] Hysteria v2: <100ms
- [ ] SSH: <300ms
- [ ] TUIC: <100ms

### Memory Usage

- [ ] All protocols: <100MB per 1000 connections

## References

- **Optimization Guide**: `docs/performance/OPTIMIZATION_GUIDE.md`
- **Benchmarks**: `app/tests/bench_p0_protocols.rs`
- **Performance Summary**: `reports/benchmarks/PERFORMANCE_SUMMARY.md`
- **Requirements**: `.kiro/specs/p0-production-parity/requirements.md` (9.1, 9.2, 9.3)

## Revision History

- 2025-10-08: Initial checklist created
