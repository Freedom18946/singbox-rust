# Performance Benchmarks

This directory contains documentation for performance benchmarks in singbox-rust.

## Available Benchmarks

### P0 Protocol Benchmarks
See [P0_PROTOCOL_BENCHMARKS.md](./P0_PROTOCOL_BENCHMARKS.md) for comprehensive documentation on:
- REALITY TLS performance
- ECH (Encrypted Client Hello) performance
- Hysteria v1/v2 performance
- SSH tunnel performance
- TUIC protocol performance

## Quick Start

Run baseline benchmarks:
```bash
./scripts/run_p0_benchmarks.sh --baseline
```

Run in test mode (faster, for CI):
```bash
./scripts/run_p0_benchmarks.sh --baseline --test
```

View results:
```bash
open app/target/criterion/report/index.html
```

## Benchmark Structure

```
app/benches/
├── bench_p0_protocols.rs    # P0 protocol benchmarks
└── performance_baseline.rs  # Basic TCP benchmarks

docs/benchmarks/
├── README.md                      # This file
└── P0_PROTOCOL_BENCHMARKS.md     # P0 benchmark documentation

scripts/
└── run_p0_benchmarks.sh     # Benchmark automation script
```

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | ≥90% of upstream | Within 10% of Go sing-box |
| Latency P95 | ≤110% of upstream | Acceptable overhead |
| Connection Time | ≤120% of upstream | Handshake complexity |
| Memory Usage | ≤100% of upstream | Rust efficiency |

## Contributing

When adding new benchmarks:
1. Follow the pattern in existing benchmark files
2. Use feature gates for optional protocols
3. Document in this directory
4. Update automation scripts
5. Add performance targets

## Related Documentation

- [Performance Baseline](../performance/BASELINE.md) (if exists)
- [Optimization Guide](../performance/OPTIMIZATION.md) (if exists)
- [Testing Guide](../testing/) (if exists)
