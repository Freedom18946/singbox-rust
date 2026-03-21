# Performance Report (Historical Snapshot)

> WARNING: This file is a historical benchmark summary. It is not the current source of truth for performance closure.
>
> Earlier versions of this report mixed real measurements, placeholder benchmarks, and obsolete workflow references. Those obsolete status claims have been removed. Workflow automation is disabled in this repository.

## What This File Covers

- Historical benchmark setup around the benchmark workspace and tracked result exports
- Early protocol and crypto benchmark observations
- Evidence that benchmark tooling existed and produced tracked outputs

## What This File Does Not Prove

This file does not by itself prove:

- current Go-vs-Rust performance parity
- current regression-gate health
- current benchmark completeness
- current release readiness

For current benchmark artifacts, inspect:

- `benchmark_results/`
- `reports/benchmarks/`
- `scripts/test/bench/`

## Historical Notes Kept From Earlier Versions

- Bench results were collected on Apple Silicon and tracked under `reports/benchmarks/` and `benchmark_results/`.
- Criterion exports under `reports/benchmarks/criterion_data/` are retained as historical generated output.
- Some early benchmark rows were placeholders rather than completed protocol implementations; they must not be counted as completed coverage.
- Earlier text comparing AES and ChaCha should be read as point-in-time observations, not a current product recommendation.

## Current Reading Rule

Use this file only as a historical benchmark index. Any active performance claim should cite current artifacts or rerun commands, not this snapshot.

---

**Status**: Historical / stale snapshot  
**Last reviewed**: 2026-03-21
