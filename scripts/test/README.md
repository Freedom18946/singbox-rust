# Testing Scripts

Comprehensive testing infrastructure including acceptance, benchmarks, stress tests, and fuzzing.

## Overview

This directory organizes all testing scripts by category:
- **acceptance/** - Formal acceptance test suite
- **bench/** - Performance benchmarking
- **stress/** - Stress and load testing
- **fuzz/** - Fuzz testing tools

## Acceptance Tests (`acceptance/`)

Formal acceptance test suite (A1-A5 series) validating Go parity and correctness.

### `explain-replay.sh` (A1)
Go vs Rust `route --explain` compatibility replay testing.

```bash
./scripts/test/acceptance/explain-replay.sh
```

Exit codes:
- 0: All tests passed
- 1: Some validation failed
- 77: Skipped (GO_SINGBOX_BIN not available)

### `schema-v2.sh` (A2)
Schema v2 validation acceptance testing.

```bash
./scripts/test/acceptance/schema-v2.sh
```

Tests:
- Valid v2 config validation
- Unknown field detection
- Required field validation
- Type mismatch detection

### `udp-stress-metrics.sh` (A3)
UDP stress testing with comprehensive metrics sampling.

```bash
./scripts/test/acceptance/udp-stress-metrics.sh
```

Features:
- High-volume UDP load
- Metrics validation
- Performance regression detection

### `prom-noise-regression.sh` (A4)
Prometheus metrics noise and regression testing.

```bash
./scripts/test/acceptance/prom-noise-regression.sh
```

### `rc-package-verify.sh` (A5)
Release candidate package verification.

```bash
./scripts/test/acceptance/rc-package-verify.sh
```

Validates:
- Binary completeness
- Version metadata
- Checksums
- Documentation

## Benchmarks (`bench/`)

Performance benchmarking suite.

### `run.sh`
Main benchmark runner.

```bash
./scripts/test/bench/run.sh
```

### `p0-protocols.sh`
P0 (priority 0) protocol benchmarks - critical protocols only.

```bash
./scripts/test/bench/p0-protocols.sh
```

Benchmarks:
- SOCKS5
- HTTP CONNECT
- Shadowsocks
- VMess/VLESS
- Trojan

### `guard.sh`
Performance regression guard - fails if performance degrades.

```bash
./scripts/test/bench/guard.sh
```

### `run-p0.sh`
Automated P0 benchmark execution.

```bash
./scripts/test/bench/run-p0.sh
```

## Stress Tests (`stress/`)

Load and stress testing infrastructure.

### `run.sh`
Main stress test runner.

```bash
./scripts/test/stress/run.sh
```

### `pressure-smoke.sh`
Quick pressure test smoke suite.

```bash
./scripts/test/stress/pressure-smoke.sh
```

### `prometheus-robustness.sh`
Prometheus metrics under stress conditions.

```bash
./scripts/test/stress/prometheus-robustness.sh
```

### `monitor.sh`
Real-time stress test monitoring.

```bash
./scripts/test/stress/monitor.sh
```

## Fuzz Tests (`fuzz/`)

Fuzzing test infrastructure.

### `analysis.sh`
Fuzz coverage analysis and status reporting.

```bash
# Show current fuzz coverage
./scripts/test/fuzz/analysis.sh status

# Run quick fuzz test (30s each)
./scripts/test/fuzz/analysis.sh quick

# Run specific target
./scripts/test/fuzz/analysis.sh run fuzz_dns_message

# List all targets
./scripts/test/fuzz/analysis.sh list
```

### `smoke.sh`
Quick fuzz smoke test.

```bash
./scripts/test/fuzz/smoke.sh
```

### `generate-corpus.sh`
Generate fuzz corpus seeds.

```bash
./scripts/test/fuzz/generate-corpus.sh
```

## Other Tests

### `mutants-smoke.sh`
Mutation testing smoke suite.

```bash
./scripts/test/mutants-smoke.sh
```

### `cov.sh`
Code coverage collection and reporting.

```bash
./scripts/test/cov.sh
```

Generates coverage reports in `target/coverage/`.

## Running Tests

### Run All Acceptance Tests

```bash
for test in scripts/test/acceptance/*.sh; do
    "$test" || echo "FAILED: $test"
done
```

### Run Benchmarks

```bash
./scripts/test/bench/run.sh
```

### Run Stress Tests

```bash
./scripts/test/stress/run.sh
```

### Run Fuzz Analysis

```bash
./scripts/test/fuzz/analysis.sh status
```

## Environment Variables

- `GO_SINGBOX_BIN` - Path to Go sing-box for comparison tests
- `RUST_BACKTRACE` - Enable backtraces
- `CARGO_PROFILE` - Cargo profile (release/dev)
- `BENCH_DURATION` - Benchmark duration

## Test Reports

Test results are stored in:
- `.e2e/reports/` - Test reports
- `.e2e/logs/` - Test logs
- `target/criterion/` - Benchmark results
- `fuzz/artifacts/` - Fuzz failures

## Exit Codes

Standard exit codes:
- `0` - All tests passed
- `1` - Some tests failed
- `2` - Invalid arguments
- `77` - Skipped (optional dependencies missing)

## Writing New Tests

1. Choose appropriate category subdirectory
2. Follow naming conventions
3. Include usage documentation
4. Implement cleanup traps
5. Return standard exit codes
6. Generate reports in standard locations

## CI Integration

Tests run in GitHub Actions:

```yaml
- name: Acceptance Tests
  run: |
    for test in scripts/test/acceptance/*.sh; do
      "$test"
    done

- name: Benchmarks
  run: ./scripts/test/bench/run.sh

- name: Fuzz Smoke
  run: ./scripts/test/fuzz/smoke.sh
```

## Dependencies

- `cargo` - Rust toolchain
- `jq` - JSON processing
- `curl` - HTTP requests
- `cargo-fuzz` - For fuzz tests (nightly)
- `cargo-criterion` - For benchmarks
- Optional: `cargo-mutants` for mutation testing
- Optional: `tarpaulin` or `llvm-cov` for coverage
