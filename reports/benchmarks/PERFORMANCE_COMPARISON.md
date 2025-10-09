# Performance Comparison: singbox-rust vs sing-box

This document compares the performance of singbox-rust (Rust implementation) with upstream sing-box (Go implementation).

## Comparison Methodology

### Test Setup

- **Environment**: Same hardware, OS, and network conditions
- **Test Data**: Identical test payloads and iteration counts
- **Protocols**: All P0 protocols tested with same configurations
- **Metrics**: Throughput, latency, connection time, memory usage

### Performance Goals

- **Throughput**: ≥90% of sing-box performance
- **Latency P95**: ≤110% of sing-box performance
- **Memory**: ≤sing-box memory usage
- **Connection Time**: Within 10% of sing-box

## Baseline Comparison

### Direct TCP (Baseline)

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | 9531.40 Mbps | TBD | TBD | ⏳ |
| Latency P50 | 0.02 ms | TBD | TBD | ⏳ |
| Latency P95 | 0.07 ms | TBD | TBD | ⏳ |
| Latency P99 | 0.09 ms | TBD | TBD | ⏳ |
| Connection Time | 0.03 ms | TBD | TBD | ⏳ |
| Memory Usage | 10.00 MB | TBD | TBD | ⏳ |

## Protocol Comparison

### REALITY TLS

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

### ECH

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

### Hysteria v1

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

### Hysteria v2

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

### SSH Outbound

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

### TUIC

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | TBD | TBD | TBD | ⏳ |
| Latency P95 | TBD | TBD | TBD | ⏳ |
| Connection Time | TBD | TBD | TBD | ⏳ |
| Memory Usage | TBD | TBD | TBD | ⏳ |

## Stress Test Comparison

### High Connection Rate

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Connections/sec | 7546.97 | TBD | TBD | ⏳ |
| Time for 1000 | 0.13s | TBD | TBD | ⏳ |

### Large Data Transfer

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| Throughput | 3252.31 MB/s | TBD | TBD | ⏳ |
| Time for 200MB | 0.06s | TBD | TBD | ⏳ |

### Concurrent Connections

| Metric | singbox-rust | sing-box | Ratio | Status |
|--------|-------------|----------|-------|--------|
| 500 connections | 1.03s | TBD | TBD | ⏳ |

## Expected Differences

### Rust Advantages

1. **Zero-cost abstractions**: Better optimization potential
2. **Memory safety**: No garbage collection overhead
3. **Predictable performance**: No GC pauses
4. **Lower memory usage**: More efficient memory management

### Go Advantages

1. **Mature ecosystem**: More battle-tested libraries
2. **Simpler concurrency**: Goroutines are easier to use
3. **Faster compilation**: Go compiles faster than Rust

## Performance Analysis

### Throughput

**Expected**: Rust should match or exceed Go performance
- Rust's zero-cost abstractions enable better optimization
- No GC overhead in hot paths
- Better control over memory layout

### Latency

**Expected**: Rust should have lower tail latencies
- No GC pauses
- More predictable performance
- Better control over allocations

### Memory Usage

**Expected**: Rust should use less memory
- No GC overhead
- More efficient memory management
- Better control over allocations

### Connection Time

**Expected**: Similar performance
- Both use same underlying protocols
- Handshake time dominated by network and crypto

## Running Comparisons

### Prerequisites

```bash
# Set path to sing-box binary
export GO_SINGBOX_BIN=/path/to/sing-box

# Ensure both implementations are built with optimizations
cargo build --release
```

### Run Comparison

```bash
# Run singbox-rust benchmarks
./scripts/run_p0_benchmarks.sh --full

# Run sing-box benchmarks (if available)
# TODO: Add sing-box benchmark script
```

## Optimization Opportunities

Based on comparison results, potential optimization areas:

1. **Buffer management**: Implement zero-copy where possible
2. **Crypto operations**: Use hardware acceleration
3. **Connection pooling**: Optimize connection reuse
4. **Memory allocations**: Reduce allocations in hot paths
5. **Async runtime**: Tune tokio configuration

## Continuous Monitoring

Performance comparisons should be run:

- **Before each release**: Full comparison
- **Weekly**: Automated comparison runs
- **After performance changes**: Targeted comparisons

## References

- singbox-rust benchmarks: `app/tests/bench_p0_protocols.rs`
- Baseline results: `reports/benchmarks/BASELINE_RESULTS.md`
- Documentation: `docs/benchmarks/P0_PROTOCOL_BENCHMARKS.md`

## Revision History

- 2025-10-08: Initial comparison framework created
