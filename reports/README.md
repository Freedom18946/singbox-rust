# Reports Directory

This directory contains curated project reports (tracked) plus runtime-generated logs.

## Directory Structure

```
reports/
├── README.md                      # This file
├── ACCEPTANCE_QC_2025-11-24.md    # QA acceptance report (tracked)
├── GO_DIFF_ANALYSIS_2026-01-31.md # Go vs Rust parity analysis (tracked)
├── L4_QUALITY_RECHECK_2026-02-10.md # L4 质量复验（双轨口径）
├── PX015_LINUX_VALIDATION_2026-02-10.md # PX-015 Linux 双场景补证记录
├── PERFORMANCE_REPORT.md          # Performance baseline summary (tracked)
├── TEST_COVERAGE.md               # Test coverage map (tracked)
├── VERIFICATION_RECORD.md         # Verification evidence (tracked)
└── stress-tests/                  # Stress test execution logs (runtime-generated)
```

## Tracked Reports

Tracked reports provide authoritative status snapshots and verification evidence:

- `ACCEPTANCE_QC_2025-11-24.md`: QA acceptance evidence
- `GO_DIFF_ANALYSIS_2026-01-31.md`: Go vs Rust parity analysis
- `L4_QUALITY_RECHECK_2026-02-10.md`: quality recheck with `PASS-STRICT` / `PASS-ENV-LIMITED` labels
- `PX015_LINUX_VALIDATION_2026-02-10.md`: Linux runtime/system bus validation evidence for PX-015
- `PERFORMANCE_REPORT.md`: performance baseline summary
- `TEST_COVERAGE.md`: test coverage map
- `VERIFICATION_RECORD.md`: verification record

## Acceptance Status Labels

Report-level acceptance outcomes use:

- `PASS-STRICT`: no skip, no environment waivers.
- `PASS-ENV-LIMITED`: main path passes but environment restrictions cause skips; raw evidence required.
- `FAIL`: blocking failure not explained by environment constraints.

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

- ✅ Tracked reports live here and are maintained over time
- ✅ Runtime-generated logs belong under `stress-tests/`
- ✅ Benchmark results are in `target/criterion/` (not here)
- ❌ Do not commit runtime log files to git
- ❌ Do not place general documentation here (use `/docs/` instead)

## See Also

- [Main README](/README.md) - Project overview
- [Development Guide](/docs/04-development/) - Development documentation
- [Parity Matrix](/GO_PARITY_MATRIX.md) - Implementation status
- [Roadmap](/NEXT_STEPS.md) - Planned work

---

**Last updated**: 2026-02-10
**Purpose**: Curated reports plus runtime test logs
