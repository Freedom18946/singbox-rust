# Performance Benchmarks

This directory contains performance benchmarks for sing-box Rust implementation, allowing comparison with the Go version.

## Quick Start

```bash
# Run all benchmarks
cargo bench --package sb-benches

# Run specific benchmark
cargo bench --package sb-benches --bench socks5_throughput

# Run with comparison script (includes system info and reporting)
./scripts/bench_vs_go.sh

# Quick mode (faster, less accurate)
./scripts/bench_vs_go.sh --quick
```

## Available Benchmarks

### Protocol Benchmarks

1. **SOCKS5** (`benches/socks5_throughput.rs`)
   - Handshake latency
   - Data throughput (1KB, 64KB, 1MB)

2. **Shadowsocks** (`benches/shadowsocks_throughput.rs`)
   - Encryption performance (AES-256-GCM, ChaCha20-Poly1305)
   - Decryption performance
   - Different payload sizes

3. **VMess** (`benches/vmess_throughput.rs`)
   - Header encoding
   - AEAD encryption/decryption
   - Throughput across payload sizes

4. **DNS** (`benches/dns_performance.rs`)
   - Query parsing
   - Response building
   - Cache lookup performance

## Benchmark Output

Results are saved in multiple formats:

- **HTML Reports**: `target/criterion/` - Interactive charts and detailed analysis
- **Console Output**: Real-time progress during benchmark runs
- **Comparison Report**: `bench_results/comparison_report.md` (when using script)

## Interpreting Results

### Criterion Output

Criterion provides:
- **Time**: Mean execution time with confidence intervals
- **Throughput**: MB/s for data-processing benchmarks
- **Change Detection**: Automatic regression detection vs. previous runs

Example output:
```
socks5_handshake        time:   [45.2 µs 46.1 µs 47.0 µs]
                        change: [-2.5% +0.1% +2.8%] (p = 0.89 > 0.05)
                        No change in performance detected.
```

### Throughput Metrics

For data processing benchmarks, look for:
- **MB/s**: Higher is better
- **Comparison to Go**: Should be >=80% of Go performance
- **Scaling**: Performance should scale reasonably with data size

## Adding New Benchmarks

1. Create a new file in `benches/benches/`
2. Add `[[bench]]` entry in `Cargo.toml`
3. Use the shared utilities from `src/lib.rs`

Example:
```rust
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

## Performance Goals

Target performance relative to Go sing-box 1.12.12:

- **Latency**: Within 20% (preferably better)
- **Throughput**: >= 80% (target: 100%+)
- **Memory**: Lower or equal allocation rates
- **CPU**: Comparable or better efficiency

## Continuous Monitoring

Set up CI to run benchmarks:
- On every push to main (quick mode)
- Weekly full benchmark run
- PR comments with performance impact

See `.github/workflows/benchmark.yml` (to be added)

## Troubleshooting

### Benchmark Fails to Compile

Check that required features are enabled:
```bash
cargo check --package sb-benches --all-features
```

### Unstable Results

- Close other applications
- Run with `--sample-size 100` for more samples
- Use `--measurement-time 20` for longer measurements
- Check CPU governor: `cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`

### Go Comparison Not Available

The Go binary is gitignored. To enable comparison:
1. Obtain Go sing-box 1.12.12 source
2. Place in `go_fork_source/sing-box-1.12.12/`
3. Build or provide pre-built binary

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [sing-box Project](https://github.com/SagerNet/sing-box)
