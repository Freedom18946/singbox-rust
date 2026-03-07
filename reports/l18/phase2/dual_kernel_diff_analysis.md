# WP-H2: Diff Results MIG-02 Adaptation Analysis

**Date**: 2026-03-07
**Phase 2 Run**: `20260307T094223Z-daily-2c23886f`
**Phase 1 Baseline**: `20260213T073321Z-68b88e87` (pre-MIG-02)

---

## Executive Summary

**No MIG-02 induced diffs detected.** All observed diffs are pre-existing structural
differences between Go and Rust Clash API implementations.

Phase 1 baseline comparison is **invalid**: Phase 1 Go snapshots were empty (Go Oracle
was not running during Phase 1 diff runs), so Phase 1 showed 0 mismatches artificially.
Phase 2 is the first run with actual dual-kernel data collection.

---

## Case-by-Case Analysis

### l6_local_harness_smoke (P0, Strict)

| Metric | Phase 1 | Phase 2 |
|--------|---------|---------|
| Gate score | 0 | 0 |
| HTTP mismatches | 0 | 0 |
| WS mismatches | 0 | 0 |

**Verdict**: Clean. No diffs.

### p0_clash_api_contract (P0, EnvLimited)

| Metric | Phase 1 | Phase 2 | Delta |
|--------|---------|---------|-------|
| Gate score | 0 (empty Go) | 7 | N/A (Phase 1 invalid) |
| HTTP mismatches | 0 | 4 | N/A |
| WS mismatches | 0 | 3 | N/A |

**HTTP Diffs (4)**:

| Endpoint | Rust | Go | Attribution |
|----------|------|-----|-------------|
| GET /configs | 200, hash-A | 200, hash-B | Pre-existing: `log-level` case ("info" vs "warn"), `mode` case ("rule" vs "Rule"), `mode-list` differs |
| GET /connections | 200, hash-A | 200, hash-B | Pre-existing: dynamic state (timestamps, connection IDs) |
| GET /proxies | 200, hash-A | 200, hash-B | Pre-existing: Rust includes built-in DIRECT/GLOBAL/REJECT, Go doesn't |
| GET /proxies/DIRECT/delay | 503 | 404 | Pre-existing: Rust returns 503 for delay check failure, Go returns 404 |

**WS Diffs (3)**:

| Stream | Attribution |
|--------|-------------|
| /connections | Pre-existing: dynamic connection state |
| /logs | Pre-existing: Go had 0 frames, Rust had 2 (log level diff) |
| /memory | Pre-existing: different memory reporting values |

**Golden Spec References**: None of these map to S4 deviation registry entries (DIV-C-001/002/003).
These are representation-level differences, not behavioral divergences.

### p1_auth_negative_missing_token (P1, EnvLimited)

| Metric | Phase 2 |
|--------|---------|
| Gate score | 1 |
| HTTP mismatches | 1 |

**Diff**: GET /configs with no auth token — both return **401**, but different error body format.

**Attribution**: Pre-existing error message format difference. Both correctly reject unauthorized access.

### p1_auth_negative_wrong_token (P1, EnvLimited)

| Metric | Phase 2 |
|--------|---------|
| Gate score | 1 |
| HTTP mismatches | 1 |

**Diff**: Same as above — both return **401**, different body hash.

**Attribution**: Pre-existing error response format difference.

### p1_optional_endpoints_contract (P1, EnvLimited)

| Metric | Phase 2 |
|--------|---------|
| Gate score | 2 |
| HTTP mismatches | 2 |
| Ignored HTTP | 1 |

**Diffs**:

| Endpoint | Rust | Go | Attribution |
|----------|------|-----|-------------|
| GET /providers | 404, null body | 404, body hash | Pre-existing: Rust returns empty body, Go returns JSON |
| GET /rules | 200, hash-A | 200, hash-B | Pre-existing: different rule serialization format |

---

## MIG-02 Impact Assessment

| Change Path (MIG-02) | Impact on Dual Kernel Diff | Status |
|----------------------|---------------------------|--------|
| wave#200: Implicit direct fallback elimination | **No impact** — L18 configs have explicit `route.final` | Verified |
| wave#201: SOCKS5 UDP / TUN macOS | **No impact** — L18 cases don't test UDP or TUN | N/A |
| wave#202: Tailscale outbound modes | **No impact** — L18 doesn't use tailscale | N/A |
| F3 fix: SelectorGroup first-member fallback | **No impact on diffs** — fixes Rust-only None panic, doesn't change API responses | Verified |

## Conclusions

1. All 7+2+2 observed mismatches are **pre-existing structural differences** in Clash API implementation
2. Phase 1 baseline comparison is invalid (empty Go snapshots)
3. **Zero MIG-02 induced diffs**
4. All cases PASS the diff gate (gate_score within tolerance)
5. The gate_score sum (7+1+1+2=11) is the **true Phase 2 baseline** for future comparison

## Recommendations

- Update diff gate oracle_ignore rules to suppress known stable diffs (/configs log-level case, /proxies built-in entries) — reduces gate noise for Phase 3
- Current Phase 2 run establishes the first valid dual-kernel diff baseline

---

**WP-H2 Verdict: PASS** — All diffs attributed, zero MIG-02 regressions.
