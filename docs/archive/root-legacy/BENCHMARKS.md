# Performance Benchmarks

Comprehensive performance benchmarking for singbox-rust implementation vs Go sing-box 1.12.12 baseline.

历史基线: This archived doc references the 1.12.12 Go baseline for prior results.

## Quick Start

```bash
# Run smoke test (fast, ~2 minutes)
./scripts/run_benchmarks.sh --smoke-test

# Run quick benchmarks (~10 minutes)
./scripts/run_benchmarks.sh --quick

# Run full benchmark suite (~30-60 minutes)
./scripts/run_benchmarks.sh --full

# Run specific protocol benchmark
./scripts/run_benchmarks.sh --protocol socks5

# Compare with Go baseline (if available)
./scripts/run_benchmarks.sh --compare-go
```

## Benchmark Coverage

### Protocol Benchmarks

#### Inbound Protocols (17 total)

| Protocol | Benchmark Coverage | Status |
|----------|-------------------|--------|
| SOCKS5 | ✅ Handshake, Throughput | Implemented |
| HTTP | ✅ Throughput | Implemented |
| Mixed | ✅ Throughput | Implemented |
| Shadowsocks | ✅ Encryption, Throughput | Implemented |
| VMess | ✅ AEAD, Throughput | Implemented |
| VLESS | ✅ Throughput | Implemented |
| Trojan | ✅ Throughput | Implemented |
| Naive | 🔄 Placeholder | Planned |
| ShadowTLS | 🔄 Placeholder | Planned |
| AnyTLS | 🔄 Placeholder | Planned |
| Hysteria v1 | 🔄 QUIC setup | Planned |
| Hysteria2 | 🔄 QUIC setup | Planned |
| TUIC | 🔄 QUIC setup | Planned |
| TUN | 🔄 Packet processing | Planned |
| Redirect | 🔄 iptables overhead | Planned |
| TProxy | 🔄 iptables overhead | Planned |
| Direct | ✅ Baseline | Implemented |

#### Outbound Protocols (19 total)

| Protocol | Benchmark Coverage | Status |
|----------|-------------------|--------|
| Direct | ✅ Baseline | Implemented |
| Block | ✅ Baseline | Implemented |
| HTTP | ✅ Throughput | Implemented |
| SOCKS5 | ✅ Throughput | Implemented |
| Shadowsocks | ✅ Encryption | Implemented |
| VMess | ✅ AEAD | Implemented |
| VLESS | ✅ Throughput | Implemented |
| Trojan | ✅ Throughput | Implemented |
| SSH | 🔄 Auth overhead | Planned |
| ShadowTLS | 🔄 TLS masquerading | Planned |
| Tor | 🔄 SOCKS5 proxy | Planned |
| DNS | ✅ Query performance | Implemented |
| AnyTLS | 🔄 Session multiplex | Planned |
| Hysteria v1 | 🔄 QUIC + obfs | Planned |
| Hysteria2 | 🔄 QUIC + congestion | Planned |
| TUIC | 🔄 QUIC + UDP relay | Planned |
| WireGuard | 🔄 Interface binding | Planned |
| Selector | 🔄 Selection overhead | Planned |
| URLTest | 🔄 Health check | Planned |

### DNS Benchmarks

| Metric | Status |
|--------|--------|
| Query parsing | ✅ Implemented |
| Response building | ✅ Implemented |
| Cache lookup | ✅ Implemented |
| UDP transport | 🔄 Planned |
| TCP transport | 🔄 Planned |
| DoH transport | 🔄 Planned |
| DoT transport | 🔄 Planned |
| DoQ transport | 🔄 Planned |
| DoH3 transport | 🔄 Planned |
| FakeIP allocation | 🔄 Planned |

### Resource Usage Benchmarks

| Metric | Status |
|--------|--------|
| Memory allocation patterns | ✅ Implemented |
| Concurrent connections | ✅ Implemented |
| Routing decision overhead | ✅ Implemented |
| Crypto operations (AES-GCM, ChaCha20) | ✅ Implemented |
| Zero-copy vs copy | ✅ Implemented |
| Connection pool overhead | 🔄 Planned |
| File descriptor usage | 🔄 Planned |

**Documentation:**
- [PERFORMANCE_REPORT.md](reports/PERFORMANCE_REPORT.md) - Latest results and analysis

## Methodology

### Benchmark Framework

We use [Criterion.rs](https://github.com/bheisler/criterion.rs) for all Rust benchmarks:
- Statistical analysis with confidence intervals
- Automatic outlier detection
- HTML reports with charts
- Regression detection
- Warmup iterations for JIT stabilization

### Test Scenarios

#### Throughput Tests

Different payload sizes to measure scaling:
- **Small packets**: 1KB (typical TCP control messages)
- **Medium packets**: 64KB (common buffer size)
- **Large transfers**: 1MB (bulk data transfer)

#### Latency Tests

Connection establishment and first-byte latency:
- TCP handshake time
- TLS negotiation overhead
- QUIC 0-RTT / 1-RTT connection setup
- Request-response round-trip time

#### Concurrent Load

Simulating real-world concurrent connections:
- 10 connections (light load)
- 100 connections (moderate load)
- 1000 connections (heavy load)

### Environment

**Important**: Benchmark results are sensitive to:
- CPU frequency scaling (disable turbo boost for stability)
- Background processes (close unnecessary applications)
- Network conditions (use localhost for consistency)
- Thermal throttling (ensure adequate cooling)

For reproducible results:
```bash
# macOS: Check energy settings
sudo pmset -g

# Linux: Set CPU governor to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Performance Goals

Target performance relative to Go sing-box 1.12.12:

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Throughput** | ≥90% of Go | TBD | 🔄 Measuring |
| **Latency** | ≤120% of Go | TBD | 🔄 Measuring |
| **Memory** | ≤100% of Go | TBD | 🔄 Measuring |
| **CPU Usage** | ≤110% of Go | TBD | 🔄 Measuring |

### Detailed Targets

#### Proxy Protocols (SOCKS5, HTTP)
- **Handshake latency**: <100µs
- **Throughput**: >500 MB/s (localhost)

#### Encrypted Protocols (Shadowsocks, VMess, VLESS, Trojan)
- **Encryption overhead**: <10% vs Direct
- **Throughput**: >300 MB/s (AES-GCM), >400 MB/s (ChaCha20)

#### QUIC Protocols (Hysteria, Hysteria2, TUIC)
- **Connection setup**: <5ms (0-RTT), <10ms (1-RTT)
- **Throughput**: >200 MB/s

#### DNS Resolution
- **Query parsing**: <1µs
- **Cache lookup**: <100ns (warm cache)
- **Transport overhead**: <2ms (DoH), <1ms (UDP)

## Current Results

> **Note**: Initial benchmark results will be populated after first full benchmark run.

Last updated: _Not yet run_

### Summary

```
No benchmark results available yet.
Run: ./scripts/run_benchmarks.sh --full
```

### Detailed Results

View interactive HTML reports: `target/criterion/index.html`

## Interpreting Results

### Criterion Output

Example output:
```
socks5_handshake        time:   [45.2 µs 46.1 µs 47.0 µs]
                        change: [-2.5% +0.1% +2.8%] (p = 0.89 > 0.05)
                        No change in performance detected.
```

- **time**: [lower bound, estimate, upper bound] with 95% confidence
- **change**: Performance change vs. previous baseline
- **p-value**: Statistical significance (p < 0.05 = significant change)

### Throughput Metrics

For data-processing benchmarks:
```
socks5_throughput/65536 time:   [183.42 µs 184.21 µs 185.05 µs]
                        thrpt:  [346.13 MiB/s 347.72 MiB/s 349.22 MiB/s]
```

- **thrpt**: Throughput in MiB/s (1 MiB = 1,048,576 bytes)
- Higher is better
- Compare across different payload sizes to identify scaling issues

## Comparison with Go

### Running Go Benchmarks

To establish Go baseline metrics:

1. Navigate to Go source:
   ```bash
   cd go_fork_source/sing-box-1.12.12
   ```

2. Run Go benchmarks:
   ```bash
   go test -bench=. -benchmem -benchtime=10s ./...
   ```

3. Save results:
   ```bash
   go test -bench=. -benchmem -benchtime=10s ./... > ../../benchmark_results/go_baseline.txt
   ```

### Manual Comparison

For end-to-end comparison:

1. **Setup test environment**:
   - Identical hardware
   - Same test data
   - Isolated network (localhost)

2. **Run equivalent operations**:
   - Same protocol configuration
   - Same payload sizes
   - Same concurrent connection counts

3. **Collect metrics**:
   - Throughput (MB/s)
   - Latency (µs, ms)
   - Memory usage (MB)
   - CPU usage (%)

## Continuous Integration

### CI Benchmark Workflow

Automated benchmarks run:
- **On-demand**: Manual workflow dispatch
- **Scheduled**: Weekly on `main` branch
- **Optional**: PR with `benchmark` label

See: `.github/workflows/benchmarks.yml`

### Performance Regression Detection

CI will fail if:
- Throughput drops >15% vs. baseline
- Latency increases >20% vs. baseline
- Memory usage increases >25% vs. baseline

## Troubleshooting

### Compilation Errors

```bash
# Check benchmark package
cargo check --package sb-benches

# Build with verbose output
cargo build --package sb-benches --release --verbose
```

### Unstable Results

High variance (>10%) indicates:
- Background processes interfering
- Thermal throttling
- Power management (CPU frequency scaling)

Solutions:
- Close unnecessary programs
- Run multiple times and average
- Increase sample size: `--sample-size 200`
- Increase measurement time: `--measurement-time 20`

### Missing Dependencies

Some benchmarks require specific features:
```bash
# Enable all DNS transports
cargo bench --package sb-benches --features dns_doh,dns_dot,dns_doq

# Enable QUIC protocols
cargo bench --package sb-benches --features out_tuic,out_hysteria2
```

## Adding New Benchmarks

### Step 1: Create Benchmark File

```rust
// benches/benches/my_new_benchmark.rs
use criterion::{criterion_group, criterion_main, Criterion};
use sb_benches::setup_tracing;

fn my_benchmark(c: &mut Criterion) {
    setup_tracing();
    
    c.bench_function("my_operation", |b| {
        b.iter(|| {
            // Code to benchmark
        });
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

### Step 2: Register in Cargo.toml

```toml
[[bench]]
name = "my_new_benchmark"
harness = false
```

### Step 3: Run

```bash
cargo bench --bench my_new_benchmark
```

## References

- [Criterion.rs Book](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Go Benchmarking Guide](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)
- [sing-box Documentation](https://sing-box.sagernet.org/)

## Contributing

When adding benchmarks:
1. Use realistic test scenarios
2. Document methodology
3. Compare with Go implementation
4. Add to CI workflow
5. Update this document

---

**Last Updated**: 2025-11-26  
**Go Baseline**: sing-box 1.12.12  
**Rust Version**: 1.90+
