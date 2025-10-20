# Reports Directory

This directory contains runtime-generated test reports and logs.

## Directory Structure

```
reports/
├── README.md           # This file
└── stress-tests/       # Stress test execution logs (runtime-generated)
```

## Stress Tests

The `stress-tests/` directory contains logs generated during stress test execution.

### Running Stress Tests

```bash
# Quick 5-minute test
./scripts/test/stress/run.sh short

# 1-hour test
./scripts/test/stress/run.sh medium

# 6-hour test
./scripts/test/stress/run.sh long

# Full 24-hour endurance test
./scripts/test/stress/run.sh endurance
```

### Log Files

Generated files (not tracked in git):
- `stress_test_[type]_[timestamp].log` - Full test output
- `monitor_[timestamp].log` - Resource monitoring data

### Monitoring Active Tests

```bash
# Monitor running stress test
./scripts/test/stress/monitor.sh [PID]
```

## Performance Benchmarks

Performance benchmarks use Criterion and output to `target/criterion/`.

### Running Benchmarks

```bash
# Run baseline TCP benchmarks
./scripts/test/bench/run-p0.sh --baseline

# Run all protocol benchmarks (requires features)
./scripts/test/bench/run-p0.sh --all

# View HTML reports
open target/criterion/report/index.html
```

### Benchmark Source

- Test file: `app/tests/bench_p0_protocols.rs`
- Runner script: `scripts/test/bench/run-p0.sh`
- Output: `target/criterion/` (Criterion default)

## Important Notes

- ✅ This directory contains **runtime-generated logs only**
- ✅ Benchmark results are in `target/criterion/` (not here)
- ❌ Do not commit log files to git
- ❌ Do not create manual documentation here (use `/docs/` instead)

## See Also

- [Main README](/README.md) - Project overview
- [Development Guide](/docs/04-development/) - Development documentation
- [Parity Matrix](/GO_PARITY_MATRIX.md) - Implementation status
- [Roadmap](/NEXT_STEPS.md) - Planned work

---

**Last updated**: 2025-10-19
**Purpose**: Runtime test logs and monitoring data
