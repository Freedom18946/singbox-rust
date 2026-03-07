# WP-J2: L18 Phase 2 Performance Gate Report

- **Date**: 2026-03-07T10:16:05Z
- **Platform**: Darwin-arm64
- **Verdict**: **PASS** (all thresholds met)

---

## Methodology

- **Aggregation**: median of trimmed rounds (3 rounds, trim 1 each side = 1 effective round)
- **Latency**: 120 sample requests per round, 20 warmup requests, SOCKS5 proxy via curl
- **Startup**: 7 sample runs per round, 1 warmup run, measured as time-to-port-open
- **RSS**: peak across idle / 100 connections / 1000 connections (bench_memory.sh)

---

## Go vs Rust Metrics (Aggregated)

| Metric | Rust | Go | Regression % | Threshold | Result |
|--------|------|----|-------------|-----------|--------|
| p95 latency (ms) | 1.370 | 1.448 | **-5.39%** (Rust faster) | <= +5% | PASS |
| RSS peak (KB) | 1,552 | 1,664 | **-6.73%** (Rust smaller) | <= +10% | PASS |
| Startup time (ms) | 113.0 | 112.0 | **+0.89%** | <= +10% | PASS |

---

## Per-Round Breakdown

### Latency p95 (ms)

| Round | Rust | Go | Regression % |
|-------|------|----|-------------|
| Round 1 | 3.023 | 3.025 | -0.07% |
| Round 2 | 1.370 | 1.448 | -5.39% |
| Round 3 | 1.333 | 1.385 | -3.75% |

Sorted: Rust [1.333, 1.370, 3.023] / Go [1.385, 1.448, 3.025]
Trimmed (used for median): Rust [1.370] / Go [1.448]

### Startup (ms)

| Round | Rust | Go | Regression % |
|-------|------|----|-------------|
| Round 1 | 112.0 | 111.0 | +0.90% |
| Round 2 | 123.0 | 112.0 | +9.82% |
| Round 3 | 113.0 | 115.0 | -1.74% |

Sorted: Rust [112.0, 113.0, 123.0] / Go [111.0, 112.0, 115.0]
Trimmed (used for median): Rust [113.0] / Go [112.0]

### RSS Memory (KB)

| State | Rust | Go | Delta |
|-------|------|----|-------|
| Idle | 1,552 | 1,648 | -96 KB |
| 100 connections | 1,552 | 1,648 | -96 KB |
| 1000 connections | 1,552 | 1,664 | -112 KB |

Peak: Rust 1,552 KB vs Go 1,664 KB (-6.73%)

---

## Threshold Summary

| Check | Value | Limit | Status |
|-------|-------|-------|--------|
| latency_p95 | -5.39% | +5.0% | PASS |
| rss_peak | -6.73% | +10.0% | PASS |
| startup | +0.89% | +10.0% | PASS |

---

## Test Configuration

| Parameter | Value |
|-----------|-------|
| Perf rounds | 3 |
| Round trim (each side) | 1 |
| Sample requests/round | 120 |
| Warmup requests/round | 20 |
| Startup sample runs | 7 |
| Startup warmup runs | 1 |
| Connect timeout | 3s |
| Max request time | 8s |
| Go proxy port | 11811 |
| Rust proxy port | 11810 |
| Local HTTP target | http://127.0.0.1:18080/ |

---

## Artifacts

- Report JSON: `reports/l18/perf_gate.json`
- Lock file: `reports/l18/perf/perf_gate.lock.json`
- Memory report: `reports/l18/perf/memory_comparison.json`
- Round data: `reports/l18/perf/round_01/` through `round_03/`
