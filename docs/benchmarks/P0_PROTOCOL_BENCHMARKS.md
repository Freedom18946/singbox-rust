# P0 Protocol Performance Benchmarks

This document describes the performance benchmark suite for P0 protocols in singbox-rust.

## Overview

The benchmark suite measures performance characteristics of all P0 protocols:
- **REALITY TLS**: Advanced traffic obfuscation
- **ECH (Encrypted Client Hello)**: SNI encryption
- **Hysteria v1/v2**: High-performance UDP-based protocols
- **SSH**: Secure shell tunneling
- **TUIC**: QUIC-based proxy protocol

## Metrics Measured

### 1. Throughput
- Measures data transfer rate (MB/s)
- Tests with various payload sizes: 1KB, 10KB, 100KB, 1MB
- Compares against baseline TCP performance

### 2. Latency
- Measures round-trip time (RTT) in milliseconds
- Captures P50, P90, P95, P99 percentiles
- Small payload (13 bytes) for realistic latency measurement

### 3. Connection Establishment
- Measures time to establish connection
- Includes handshake overhead
- Critical for protocols with complex handshakes (REALITY, ECH, TUIC)

### 4. Memory Usage
- Measures memory consumption under load
- Tests with concurrent connections: 10, 50, 100, 500
- Monitors for memory leaks

## Running Benchmarks

### Basic Usage

Run all benchmarks:
```bash
cargo bench --bench bench_p0_protocols
```

Run specific benchmark group:
```bash
# Baseline benchmarks only
cargo bench --bench bench_p0_protocols baseline

# REALITY benchmarks (requires tls_reality feature)
cargo bench --bench bench_p0_protocols --features tls_reality reality

# ECH benchmarks (requires tls_ech feature)
cargo bench --bench bench_p0_protocols --features tls_ech ech
```

### With Protocol Features

Enable specific protocol features:
```bash
# Hysteria v1
cargo bench --bench bench_p0_protocols --features adapter-hysteria

# Hysteria v2
cargo bench --bench bench_p0_protocols --features adapter-hysteria2

# SSH
cargo bench --bench bench_p0_protocols --features adapter-ssh

# TUIC
cargo bench --bench bench_p0_protocols --features sb-core/out_tuic

# All P0 protocols
cargo bench --bench bench_p0_protocols --features "tls_reality,tls_ech,adapter-hysteria,adapter-hysteria2,adapter-ssh,sb-core/out_tuic"
```

### Test Mode

Run benchmarks in test mode (faster, for CI):
```bash
cargo bench --bench bench_p0_protocols -- --test
```

### Save Results

Save benchmark results for comparison:
```bash
cargo bench --bench bench_p0_protocols -- --save-baseline p0-baseline
```

Compare with previous baseline:
```bash
cargo bench --bench bench_p0_protocols -- --baseline p0-baseline
```

## Benchmark Structure

### Baseline Benchmarks
Always run, provide reference performance:
- `baseline_throughput`: TCP throughput with various payload sizes
- `baseline_latency`: TCP latency with small payloads
- `baseline_connection`: TCP connection establishment time
- `memory_usage`: Memory usage with concurrent connections

### Protocol-Specific Benchmarks

#### REALITY TLS
- `reality/config_validation`: Config parsing and validation overhead
- `reality/handshake`: Full REALITY handshake (requires server)
- `reality/throughput`: Data transfer through REALITY tunnel (requires server)

#### ECH
- `ech/config_validation`: ECH config validation
- `ech/keypair_generation`: X25519 keypair generation
- `ech/encryption`: ClientHello encryption overhead

#### Hysteria v1
- `hysteria_v1/throughput`: Data transfer performance
- `hysteria_v1/latency`: Round-trip latency
- `hysteria_v1/connection`: Connection establishment time

#### Hysteria v2
- `hysteria_v2/throughput`: Data transfer performance
- `hysteria_v2/udp_relay`: UDP relay performance
- `hysteria_v2/connection`: Connection establishment time

#### SSH
- `ssh/connection`: SSH connection establishment
- `ssh/throughput`: Data transfer through SSH tunnel
- `ssh/pooling`: Connection pool performance

#### TUIC
- `tuic/connection`: TUIC connection establishment
- `tuic/throughput`: Data transfer performance
- `tuic/udp_over_stream`: UDP over stream performance

## Implementation Status

### ✅ Implemented
- Baseline benchmarks (TCP throughput, latency, connection, memory)
- Benchmark framework with feature-gated protocol support
- Config validation benchmarks for REALITY and ECH
- Crypto operation benchmarks (keypair generation)

### 🚧 Requires Server Setup
Most protocol-specific benchmarks require running servers:
- REALITY: Requires REALITY TLS server
- Hysteria v1/v2: Requires Hysteria server
- SSH: Requires SSH server
- TUIC: Requires TUIC server

These benchmarks are currently placeholders and will be implemented when server infrastructure is available.

## Performance Targets

Based on upstream sing-box performance:

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | ≥90% of upstream | Within 10% of Go implementation |
| Latency P95 | ≤110% of upstream | Acceptable overhead for Rust safety |
| Connection Time | ≤120% of upstream | Handshake complexity acceptable |
| Memory Usage | ≤100% of upstream | Rust should be more efficient |

## Interpreting Results

### Throughput
- Higher is better (MB/s)
- Compare against baseline TCP to measure protocol overhead
- Expect 10-30% overhead for encrypted protocols

### Latency
- Lower is better (ms)
- Focus on P95/P99 for production scenarios
- Expect 1-5ms overhead for complex protocols

### Connection Establishment
- Lower is better (ms)
- Critical for short-lived connections
- REALITY/ECH may have higher overhead due to handshake complexity

### Memory Usage
- Lower is better (MB)
- Monitor for linear growth with connection count
- Watch for memory leaks in long-running tests

## Continuous Integration

Benchmarks can be run in CI with test mode:
```bash
cargo bench --bench bench_p0_protocols -- --test
```

This runs a quick validation without full statistical analysis.

## Future Enhancements

1. **Server Infrastructure**: Set up test servers for full protocol benchmarks
2. **Comparison Reports**: Automated comparison with upstream sing-box
3. **Regression Detection**: Alert on performance degradation
4. **Profiling Integration**: Flamegraph generation for hot paths
5. **Stress Testing**: Long-running benchmarks for stability testing

## Related Documentation

- [Performance Baseline](../performance/BASELINE.md)
- [Stress Testing Guide](../testing/STRESS_TESTING.md)
- [Optimization Guide](../performance/OPTIMIZATION.md)

## Contributing

When adding new protocol benchmarks:
1. Follow the existing pattern in `app/benches/bench_p0_protocols.rs`
2. Use feature gates for optional protocols
3. Add placeholder benchmarks if server setup is required
4. Document server requirements in this file
5. Update performance targets based on upstream comparison
